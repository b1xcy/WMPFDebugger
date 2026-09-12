import { promises } from "node:fs";
import { EventEmitter } from "node:events";
import path from "node:path";
import * as frida from "frida";
import WebSocket, { WebSocketServer } from "ws";

import { platform } from "./platform";
import { parse_cli_options, CliOptions } from "./cli";
import { create_logger, Logger } from "./logger";

const codex = require("./third-party/RemoteDebugCodex.js");
const messageProto = require("./third-party/WARemoteDebugProtobuf.js");

class DebugMessageEmitter extends EventEmitter {}

type HookConfig = {
    Version: number;
    LoadStartHookOffset: string;
    CDPFilterHookOffset: string;
    SceneOffsets: number[];
};

const debugMessageEmitter = new DebugMessageEmitter();

type CdpTargetInfo = {
    targetId?: string;
    type?: string;
    title?: string;
    url?: string;
};

let miniappConnected = false;
let h5Session: { targetId: string; sessionId: string } | null = null;
const pendingCdp = new Map<number, (msg: Record<string, unknown>) => void>();
let cdpReqId = 900000;
let inspectWss: WebSocketServer | null = null;

const parseCdp = (message: unknown): Record<string, unknown> | null => {
    if (typeof message === "object" && message !== null) {
        return message as Record<string, unknown>;
    }
    if (typeof message !== "string") {
        return null;
    }
    try {
        return JSON.parse(message) as Record<string, unknown>;
    } catch {
        return null;
    }
};

const sendCdp = (
    method: string,
    params?: Record<string, unknown>,
): Promise<Record<string, unknown>> =>
    new Promise((resolve, reject) => {
        if (!miniappConnected) {
            reject(new Error("miniapp debug session not connected"));
            return;
        }
        const id = ++cdpReqId;
        const timer = setTimeout(() => {
            pendingCdp.delete(id);
            reject(new Error(`CDP timeout: ${method}`));
        }, 4000);
        pendingCdp.set(id, (msg) => {
            clearTimeout(timer);
            resolve(msg);
        });
        debugMessageEmitter.emit(
            "proxymessage",
            JSON.stringify({ id, method, params: params ?? {} }),
        );
    });

const scoreH5Target = (target: CdpTargetInfo, urls: string[]): number => {
    const url = target.url || "";
    const type = (target.type || "page").toLowerCase();
    if (type !== "page" && type !== "webview") {
        return -100;
    }
    if (!url) {
        return -100;
    }
    const value = url.toLowerCase();
    if (
        value.includes("servicewechat.com") ||
        value.includes("appindex") ||
        value.startsWith("chrome://") ||
        value.startsWith("devtools://") ||
        value.startsWith("about:") ||
        value.startsWith("weixin://") ||
        value.includes("wxa.wxs.qq.com/tmpl") ||
        value.includes("/preload-")
    ) {
        return -50;
    }
    if (value.includes("mp.weixin.qq.com/s/index.html")) {
        return -10;
    }
    let score = 10;
    if (value.startsWith("https://") || value.startsWith("http://")) {
        score += 40;
    }
    if (/mp\.weixin\.qq\.com\/s\/[A-Za-z0-9_-]+/.test(url)) {
        score += 50;
    }
    const normalize = (item: string) => item.split("#")[0].replace(/\/$/, "");
    for (const wanted of urls) {
        if (!wanted) {
            continue;
        }
        if (normalize(url) === normalize(wanted)) {
            score += 100;
        } else if (url.includes(wanted) || wanted.includes(url.split("?")[0])) {
            score += 60;
        }
    }
    return score;
};

const matchH5Target = (
    targets: CdpTargetInfo[],
    urls: string[],
): CdpTargetInfo | null => {
    let best: CdpTargetInfo | null = null;
    let bestScore = 0;
    for (const target of targets) {
        const score = scoreH5Target(target, urls);
        if (score > bestScore) {
            best = target;
            bestScore = score;
        }
    }
    return best;
};

const attachH5Target = async (urls: string[], logger: Logger) => {
    const response = await sendCdp("Target.getTargets");
    if (response.error) {
        throw new Error(JSON.stringify(response.error));
    }
    const result = (response.result || {}) as { targetInfos?: CdpTargetInfo[] };
    const targets = result.targetInfos || [];
    logger.info(
        `[inspect] ${targets.length} targets: ${targets
            .map((target) => `${target.type || "?"}:${target.url || target.title || ""}`)
            .join(" | ")}`,
    );
    const target = matchH5Target(targets, urls);
    if (!target || !target.targetId) {
        throw new Error(
            "no H5 page target found; keep the miniapp open and open the web page first",
        );
    }
    logger.info(`[inspect] attaching ${target.type} ${target.url}`);
    const attach = await sendCdp("Target.attachToTarget", {
        targetId: target.targetId,
        flatten: true,
    });
    if (attach.error) {
        throw new Error(JSON.stringify(attach.error));
    }
    const attachResult = (attach.result || {}) as { sessionId?: string };
    if (!attachResult.sessionId) {
        throw new Error("attachToTarget returned no sessionId");
    }
    h5Session = {
        targetId: target.targetId,
        sessionId: attachResult.sessionId,
    };
    logger.info(`[inspect] attached session=${h5Session.sessionId}`);
};

const openInspectFrontend = (inspectPort: number, logger: Logger) => {
    const url = `devtools://devtools/bundled/inspector.html?ws=127.0.0.1:${inspectPort}`;
    logger.info(`[inspect] DevTools: ${url}`);
};

const bufferToHexString = (buffer: ArrayBuffer) => {
    return Array.from(new Uint8Array(buffer))
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("");
};

const debugServer = (options: CliOptions, logger: Logger): WebSocketServer  => {
    const wss = new WebSocketServer({ port: options.debugPort });
    logger.info(
        `[server] debug server running on ws://localhost:${options.debugPort}`,
    );
    logger.info(`[server] debug server waiting for miniapp to connect...`);

    let messageCounter = 0;

    const onMessage = (message: ArrayBuffer) => {
        logger.main_debug(
            `[miniapp] client received raw message (hex): ${bufferToHexString(message)}`,
        );
        let unwrappedData: any = null;
        try {
            const decodedData =
                messageProto.mmbizwxadevremote.WARemoteDebug_DebugMessage.decode(
                    message,
                );
            unwrappedData = codex.unwrapDebugMessageData(decodedData);
            logger.main_debug(`[miniapp] [DEBUG] decoded data:`);
            logger.main_debug(unwrappedData);
        } catch (e) {
            logger.error(`[miniapp] miniapp client err: ${e}`);
        }

        if (unwrappedData === null) {
            return;
        }

        if (unwrappedData.category === "chromeDevtoolsResult") {
            // need to proxy to CDP client
            debugMessageEmitter.emit("cdpmessage", unwrappedData.data.payload);
        }
    };

    wss.on("connection", (ws: WebSocket) => {
        miniappConnected = true;
        logger.info("[miniapp] miniapp client connected");
        ws.on("message", onMessage);
        ws.on("error", (err) => {
            logger.error("[miniapp] miniapp client err:", err);
        });
        ws.on("close", () => {
            miniappConnected = wss.clients.size > 0;
            logger.info("[miniapp] miniapp client disconnected");
        });
    });

    debugMessageEmitter.on("proxymessage", (message: string) => {
        wss &&
            wss.clients.forEach((client) => {
                if (client.readyState === WebSocket.OPEN) {
                    // encode CDP and send to miniapp
                    // wrapDebugMessageData(data, category, compressAlgo)
                    const rawPayload = {
                        jscontext_id: "",
                        op_id: Math.round(100 * Math.random()),
                        payload: message.toString(),
                    };
                    logger.main_debug(rawPayload);
                    const wrappedData = codex.wrapDebugMessageData(
                        rawPayload,
                        "chromeDevtools",
                        0,
                    );
                    const outData = {
                        seq: ++messageCounter,
                        category: "chromeDevtools",
                        data: wrappedData.buffer,
                        compressAlgo: 0,
                        originalSize: wrappedData.originalSize,
                    };
                    const encodedData =
                        messageProto.mmbizwxadevremote.WARemoteDebug_DebugMessage.encode(
                            outData,
                        ).finish();
                    client.send(encodedData, { binary: true });
                }
            });
    });
    return wss;
};

const proxyServer = (options: CliOptions, logger: Logger): WebSocketServer => {
    const wss = new WebSocketServer({ port: options.cdpPort });
    logger.info(
        `[server] proxy server running on ws://localhost:${options.cdpPort}`,
    );
    logger.info(
        `[server] link: devtools://devtools/bundled/inspector.html?ws=127.0.0.1:${options.cdpPort}`,
    );

    const onMessage = (message: string) => {
        debugMessageEmitter.emit("proxymessage", message);
    };

    wss.on("connection", (ws: WebSocket) => {
        logger.info("[cdp] CDP client connected");
        ws.on("message", onMessage);
        ws.on("error", (err) => {
            logger.error("[cdp] CDP client err:", err);
        });
        ws.on("close", () => {
            logger.info("[cdp] CDP client disconnected");
        });
    });

    debugMessageEmitter.on("cdpmessage", (message: string) => {
        wss &&
            wss.clients.forEach((client) => {
                if (client.readyState === WebSocket.OPEN) {
                    // send CDP message to devtools
                    client.send(message);
                }
            });
    });
    return wss;
};

const setupCdpInspectBridge = () => {
    debugMessageEmitter.on("cdpmessage", (message: string) => {
        const msg = parseCdp(message);
        if (!msg) {
            return;
        }
        if (typeof msg.id === "number" && pendingCdp.has(msg.id)) {
            pendingCdp.get(msg.id)!(msg);
            pendingCdp.delete(msg.id);
        }
        if (
            h5Session &&
            inspectWss &&
            msg.sessionId === h5Session.sessionId
        ) {
            const copy: Record<string, unknown> = { ...msg };
            delete copy.sessionId;
            const out = JSON.stringify(copy);
            inspectWss.clients.forEach((client) => {
                if (client.readyState === WebSocket.OPEN) {
                    client.send(out);
                }
            });
        }
    });
};

const ensureInspectServer = (
    inspectPort: number,
    logger: Logger,
): WebSocketServer => {
    if (inspectWss) {
        return inspectWss;
    }
    const wss = new WebSocketServer({ port: inspectPort });
    inspectWss = wss;
    wss.on("connection", (ws: WebSocket) => {
        logger.info("[inspect] H5 DevTools connected");
        ws.on("message", (data) => {
            let raw = data.toString();
            try {
                const msg = JSON.parse(raw) as Record<string, unknown>;
                if (h5Session && !msg.sessionId) {
                    msg.sessionId = h5Session.sessionId;
                    raw = JSON.stringify(msg);
                }
            } catch {
                // forward as-is
            }
            debugMessageEmitter.emit("proxymessage", raw);
        });
        ws.on("error", (err) => {
            logger.error("[inspect] H5 DevTools err:", err);
        });
        ws.on("close", () => {
            logger.info("[inspect] H5 DevTools disconnected");
        });
    });
    return wss;
};

const autoDetectConfig = async (
    session: frida.Session,
    projectRoot: string,
    wmpfVersion: number,
): Promise<HookConfig> => {
    let detectorContent: string;
    try {
        detectorContent = (
            await promises.readFile(
                path.join(
                    projectRoot,
                    "frida/autodetect",
                    `${process.platform}.js`,
                ),
            )
        ).toString();
    } catch (e) {
        throw new Error("[frida] auto-detect script not found");
    }

    const detector = await session.createScript(detectorContent);
    const detectedConfig = new Promise<Omit<HookConfig, "Version">>(
        (resolve, reject) => {
            detector.message.connect((message: frida.Message) => {
                if (message.type === "error") {
                    reject(
                        new Error(
                            `[frida] auto-detect failed: ${message.description}`,
                        ),
                    );
                    return;
                }

                const payload = message.payload as {
                    type?: string;
                    config?: Omit<HookConfig, "Version">;
                    error?: string;
                };
                if (payload.type === "wmpf-offsets" && payload.config) {
                    resolve(payload.config);
                } else if (payload.type === "wmpf-offsets-error") {
                    reject(
                        new Error(
                            `[frida] auto-detect failed: ${payload.error ?? "unknown error"}`,
                        ),
                    );
                }
            });
        },
    );

    try {
        await detector.load();
        return { Version: wmpfVersion, ...(await detectedConfig) };
    } finally {
        await detector.unload();
    }
};

const fridaServer = async (options: CliOptions, logger: Logger): Promise<frida.Session> => {
    const localDevice = await frida.getLocalDevice();
    const { pid: wmpfPid, version: wmpfVersion } = await platform.findWmpfProcess()

    // attach to process
    const session = await localDevice.attach(wmpfPid);

    // find hook script
    const projectRoot = path.join(
        path.dirname(
            (require.main && require.main.filename) ||
                (process.mainModule && process.mainModule.filename) ||
                process.cwd(),
        ),
        "..",
    );
    let scriptContent: string | null = null;
    try {
        scriptContent = (
            await promises.readFile(path.join(projectRoot, "frida/hook.js"))
        ).toString();
    } catch (e) {
        throw new Error("[frida] hook script not found");
    }

    let configContent: string | null = null;
    if (options.autoDetect) {
        logger.info(`[frida] auto-detecting hook offsets...`);
        const config = await autoDetectConfig(session, projectRoot, wmpfVersion);
        configContent = JSON.stringify(config);
        logger.info(`[frida] detected hook offsets: ${configContent}`);
    } else {
        try {
            configContent = (
                await promises.readFile(
                    path.join(
                        projectRoot,
                        `frida/config/${process.platform}`,
                        `addresses.${wmpfVersion}.json`,
                    ),
                )
            ).toString();
            configContent = JSON.stringify(JSON.parse(configContent));
        } catch (e) {
            throw new Error(`[frida] version config not found: ${wmpfVersion}`);
        }
    }

    if (scriptContent === null || configContent === null) {
        throw new Error("[frida] unable to find hook script");
    }

    // load script
    const script = await session.createScript(
        scriptContent.replace("@@CONFIG@@", configContent),
    );
    script.message.connect((message: frida.Message) => {
        if (message.type === "error") {
            logger.error("[frida client]", message);
            return;
        }

        const payload = message.payload;
        if (typeof payload === "string" && payload.includes("[patch] inspect")) {
            logger.info("[frida]", payload);
            if (payload.includes("inspect clicked")) {
                const matched = payload.match(/url=(.*)$/);
                const urls = matched && matched[1]
                    ? matched[1]
                          .split(" | ")
                          .map((item) => item.trim())
                          .filter(Boolean)
                    : [];
                void (async () => {
                    try {
                        await attachH5Target(urls, logger);
                        const inspectPort = options.cdpPort + 1;
                        ensureInspectServer(inspectPort, logger);
                        openInspectFrontend(inspectPort, logger);
                    } catch (error) {
                        logger.error(`[inspect] ${error}`);
                        logger.info(
                            "[inspect] 先打开任意小程序保持调试通道，再打开内置浏览器页面，然后右键「检查」",
                        );
                    }
                })();
            }
            return;
        }

        logger.frida_debug("[frida client]", payload);
    });
    await script.load();
    logger.info(
        `[frida] script loaded, WMPF version: ${wmpfVersion}, pid: ${wmpfPid}`,
    );
    logger.info(`[frida] you can now open any miniapps`);
    return session;
};

const main = async () => {
    const options = parse_cli_options();
    const logger = create_logger(options);
    const debugWss = debugServer(options, logger);
    const proxyWss = proxyServer(options, logger);
    setupCdpInspectBridge();
    const fridaSession = await fridaServer(options, logger);

    process.on("SIGINT", async () => {
        logger.info("[server] shutting down...");
        debugWss.close();
        proxyWss.close();
        inspectWss?.close();
        await fridaSession.detach();
        process.exit(0);
    });
};

(async () => {
    await main();
})();
