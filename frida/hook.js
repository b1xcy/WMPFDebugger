const getPlatform = () => {
    // retval: "windows" | "linux" | "darwin"
    return Process.platform;
}

const getMainModule = (version) => {
    const osPlatform = getPlatform();
    if (osPlatform === 'windows') {
        if (version >= 13331) {
            return Process.findModuleByName("flue.dll");
        }
        return Process.findModuleByName("WeChatAppEx.exe");
    } else if (osPlatform === 'linux') {
        return Process.findModuleByName("WeChatAppEx");
    } else if (osPlatform === 'darwin') {
        return Process.findModuleByName("WeChatAppEx Framework");
    }
};

const patchCDPFilter = (base, config) => {
    // xref: SendToClientFilter OR devtools_message_filter_applet_webview.cc
    const offset = config.CDPFilterHookOffset;
    Interceptor.attach(base.add(offset), {
        onLeave(retval_) {
            // see https://github.com/evi0s/WMPFDebugger/pull/262
            const retval = getPlatform() == 'windows'
                ? retval_.readPointer()
                : retval_;
            if (retval.isNull()) return;
            try {
                const val = retval.add(8).readU32();
                send(`[patch] CDP filter on leave, retval+8 = ${val}`);
                if (val === 6) {
                    retval.add(8).writeU32(0x0);
                    send("[patch] CDP filter patched");
                }
            } catch (e) {
                send(`[patch] CDP filter error: ${e}`);
            }
        }
    });
};

const hookOnLoadScene = (a1, sceneOffsets) => {
    const miniappConfigPtr = a1
        .add(sceneOffsets[0])
        .readPointer()
        .add(sceneOffsets[1])
        .readPointer();
    const miniappScenePtr = miniappConfigPtr
        .add(sceneOffsets[2])
        .readPointer()
        .add(sceneOffsets[3])
        .readPointer()
        .add(sceneOffsets[4])
        .readPointer()
        .add(sceneOffsets[5]);
    send(`[hook] scene: ${miniappScenePtr.readInt()}`);

    // 1000: from issue #83 <-- will crash the process
    // 1007: from issue #80
    // 1008: from issue #53
    // 1011: scan QR code
    // 1012: recognize QR code from long-pressed image (issue #128)
    // 1027: from issue #78
    // 1035: from issue #78
    // 1037: opened from another mini program
    // 1053: from issue #25
    // 1074: from issue #32
    // 1145: from search
    // 1178: from phone (issue #117)
    // 1256: from recent
    // 1260: from frequently used
    // 1302: from services
    // 1308: minigame?
    const sceneNumberArray = [
        1005, 1007, 1008, 1011, 1012, 1027, 1035, 1037, 1053, 1074, 1145, 1178,
        1256, 1260, 1302, 1308,
    ];
    if (!sceneNumberArray.includes(miniappScenePtr.readInt())) {
        return;
    }
    send("[hook] hook scene condition -> 1101");
    miniappScenePtr.writeInt(1101);

    // TODO: customize debugging endpoint
    // const websocketServerStringPtr = passArgs.add(8).readPointer().add(520);
    // VERBOSE && console.log("[hook] hook websocket server, original: ", websocketServerStringPtr.readUtf8String());
    // websocketServerStringPtr.writeUtf8String("ws://127.0.0.1:8189/");
};

const asciiPattern = (value) =>
    Array.from(value)
        .map((character) => character.charCodeAt(0).toString(16).padStart(2, "0"))
        .join(" ");

const scanSync = (module, prot, pattern) => {
    const hits = [];
    for (const range of module.enumerateRanges(prot)) {
        try {
            const matches = Memory.scanSync(range.base, range.size, pattern);
            for (const match of matches) {
                hits.push(match.address);
            }
        } catch (_) {}
    }
    return hits;
};

const findStringAddress = (module, value) => {
    const hits = scanSync(module, "r--", asciiPattern(`${value}\0`));
    return hits.length > 0 ? hits[0] : null;
};

const nextCallTarget = (addr, maxInsns) => {
    let cursor = addr;
    for (let i = 0; i < maxInsns; i++) {
        let ins;
        try {
            ins = Instruction.parse(cursor);
        } catch (_) {
            return null;
        }
        if (ins.mnemonic === "call") {
            const direct = ins.opStr.match(/^(0x[0-9a-f]+)$/i);
            return direct ? ptr(direct[1]) : null;
        }
        cursor = cursor.add(ins.size);
    }
    return null;
};

const scanForLeaTarget = (module, stringAddr, onHit) => {
    const leaPattern = getPlatform() === "windows" ? "48 8d 15" : "48 8d 35";
    const windowSize = 0x400000;
    const overlap = 16;
    for (const range of module.enumerateRanges("r-x")) {
        let offset = 0;
        while (offset < range.size) {
            const size = Math.min(windowSize, range.size - offset);
            let matches = [];
            try {
                matches = Memory.scanSync(range.base.add(offset), size, leaPattern);
            } catch (_) {}
            for (const match of matches) {
                const addr = match.address;
                if (addr.add(7).compare(range.base.add(range.size)) > 0) {
                    continue;
                }
                const dest = addr.add(7).add(addr.add(3).readS32());
                if (dest.compare(stringAddr) !== 0) {
                    continue;
                }
                if (onHit(addr)) {
                    return true;
                }
            }
            if (size <= overlap) {
                break;
            }
            offset += size - overlap;
        }
    }
    return false;
};

const findHasSwitch = (module, stringAddr) => {
    let target = null;
    scanForLeaTarget(module, stringAddr, (addr) => {
        target = nextCallTarget(addr.add(7), 8);
        return target !== null;
    });
    return target;
};

const findPdataFunction = (module, address) => {
    const pdata = module.enumerateSections().find((section) => section.name === ".pdata");
    if (!pdata) {
        return null;
    }
    const bytes = pdata.address.readByteArray(pdata.size);
    if (bytes === null) {
        return null;
    }
    const view = new DataView(bytes);
    const off = address.sub(module.base).toUInt32();
    let lo = 0;
    let hi = Math.floor(pdata.size / 12) - 1;
    while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        const begin = view.getUint32(mid * 12, true);
        const end = view.getUint32(mid * 12 + 4, true);
        if (off < begin) {
            hi = mid - 1;
        } else if (off >= end) {
            lo = mid + 1;
        } else {
            return {
                begin: module.base.add(begin),
                size: end - begin,
            };
        }
    }
    return null;
};

const CMD_BACK = 0x80e8;
const CMD_PRINT = 0x88bb;
const CMD_INSPECT = 0xc3e2;
const CMD_DEV_TOOLS = 0x9c44;
const CMD_DEV_TOOLS_CONSOLE = 0x9c45;
const CMD_DEV_TOOLS_DEVICES = 0x9c47;
const CMD_DEV_TOOLS_INSPECT = 0x9c57;
const CMD_DEV_TOOLS_TOGGLE = 0x9d2d;
const DEVTOOLS_COMMANDS = [
    CMD_DEV_TOOLS,
    CMD_DEV_TOOLS_CONSOLE,
    CMD_DEV_TOOLS_DEVICES,
    CMD_DEV_TOOLS_INSPECT,
    CMD_DEV_TOOLS_TOGGLE,
    CMD_INSPECT,
];

const patchInspectMenu = (module) => {
    // xref: enable-chrome-inspector / IDC_CONTENT_CONTEXT_INSPECTELEMENT
    if (Process.arch !== "x64" || getPlatform() !== "windows") {
        send("[patch] inspect menu skipped: requires windows x64");
        return;
    }

    const stringAddr = findStringAddress(module, "enable-chrome-inspector");
    if (stringAddr !== null) {
        const hasSwitch = findHasSwitch(module, stringAddr);
        if (hasSwitch !== null) {
            const inspectSwitches = [
                "enable-chrome-inspector",
                "xweb-enable-inspect",
                "remote-debugging-port",
                "auto-launch-devtools",
            ];
            Interceptor.attach(hasSwitch, {
                onEnter(args) {
                    this.force = false;
                    const namePtr = args[1];
                    if (namePtr.isNull()) {
                        return;
                    }
                    try {
                        const first = namePtr.readU8();
                        if (
                            first !== 0x65 &&
                            first !== 0x78 &&
                            first !== 0x72 &&
                            first !== 0x61
                        ) {
                            return;
                        }
                        const name = namePtr.readUtf8String();
                        if (name && inspectSwitches.includes(name)) {
                            this.force = true;
                        }
                    } catch (_) {}
                },
                onLeave(retval) {
                    if (this.force) {
                        retval.replace(1);
                    }
                },
            });
            send(`[patch] inspect HasSwitch hooked @ ${hasSwitch}`);
        }
    }

    const addItemTargets = [];
    const addItemSeen = {};
    const findAddItemFromMovEdx = (edxPattern) => {
        for (const addr of scanSync(module, "r-x", edxPattern)) {
            if (addr.add(5).readU8() !== 0x41 || addr.add(6).readU8() !== 0xb8) {
                continue;
            }
            if (addr.add(7).readU32() <= 0x100) {
                continue;
            }
            if (addr.add(11).readU8() !== 0xe8) {
                continue;
            }
            const dest = addr.add(16).add(addr.add(12).readS32());
            const key = dest.toString();
            if (addItemSeen[key]) {
                continue;
            }
            addItemSeen[key] = true;
            addItemTargets.push(dest);
        }
    };
    findAddItemFromMovEdx("ba e8 80 00 00");
    findAddItemFromMovEdx("ba ea 80 00 00");
    findAddItemFromMovEdx("ba bb 88 00 00");

    let inspectStringId = 0xb466;
    if (addItemTargets.length === 0) {
        send("[patch] inspect AddItem not found");
    }
    for (const addItem of addItemTargets) {
        const addItemFn = new NativeFunction(addItem, "void", [
            "pointer",
            "int",
            "int",
        ]);
        let injecting = false;
        Interceptor.attach(addItem, {
            onEnter(args) {
                this.model = args[0];
                this.cmd = args[1].toInt32() >>> 0;
                if (this.cmd === CMD_BACK) {
                    inspectStringId = (args[2].toInt32() >>> 0) - 4;
                }
            },
            onLeave() {
                if (injecting || this.cmd !== CMD_PRINT) {
                    return;
                }
                injecting = true;
                try {
                    addItemFn(this.model, CMD_INSPECT, inspectStringId);
                    send(
                        `[patch] inspect item injected str=${inspectStringId}`,
                    );
                } catch (e) {
                    send(`[patch] inspect AddItem failed: ${e}`);
                }
                injecting = false;
            },
        });
        send(`[patch] inspect AddItem hooked @ ${addItem}`);
    }

    const unhandled = findStringAddress(module, "Unhandled id: ");
    if (unhandled !== null) {
        const xrefs = [];
        scanForLeaTarget(module, unhandled, (addr) => {
            xrefs.push(addr);
            return xrefs.length >= 2;
        });
        for (const xref of xrefs) {
            const fn = findPdataFunction(module, xref);
            if (fn === null) {
                continue;
            }
            Interceptor.attach(fn.begin, {
                onEnter(args) {
                    this.cmd = args[1].toInt32() >>> 0;
                    this.inspect =
                        this.cmd === CMD_DEV_TOOLS || this.cmd === CMD_INSPECT;
                    if (this.inspect && fn.size >= 0x800) {
                        send(`[patch] inspect clicked id=${this.cmd}`);
                    }
                },
                onLeave(retval) {
                    if (this.inspect && fn.size < 0x800) {
                        retval.replace(1);
                    }
                },
            });
            send(
                `[patch] inspect command hooked @ ${fn.begin} size=${fn.size}`,
            );
        }
    }

    const enableDevTools = scanSync(module, "r-x", "ba 44 9c 00 00 45 33 c0");
    if (enableDevTools.length > 0) {
        const setEnabled = nextCallTarget(enableDevTools[0].add(8), 4);
        if (setEnabled !== null) {
            Interceptor.attach(setEnabled, {
                onEnter(args) {
                    const id = args[1].toInt32() >>> 0;
                    if (DEVTOOLS_COMMANDS.indexOf(id) !== -1) {
                        args[2] = ptr(1);
                    }
                },
            });
            send(`[patch] inspect SetCommandEnabled hooked @ ${setEnabled}`);
        }
    }

    let browserExec = null;
    const execPat = scanSync(
        module,
        "r-x",
        "b8 e8 80 00 00 41 b9 01 00 00 00",
    );
    if (execPat.length > 0) {
        browserExec = nextCallTarget(execPat[0].add(11), 2);
    }
    if (browserExec !== null) {
        const isEnabled = nextCallTarget(browserExec, 24);
        if (isEnabled !== null) {
            Interceptor.attach(isEnabled, {
                onEnter(args) {
                    this.force =
                        DEVTOOLS_COMMANDS.indexOf(args[1].toInt32() >>> 0) !==
                        -1;
                },
                onLeave(retval) {
                    if (this.force) {
                        retval.replace(1);
                    }
                },
            });
            send(`[patch] inspect IsCommandEnabled hooked @ ${isEnabled}`);
        }
    }
};

const patchOnLoadStart = (base, config) => {
    // xref: AppletIndexContainer::OnLoadStart
    Interceptor.attach(base.add(config.LoadStartHookOffset), {
        onEnter(args) {
            send(
                `[inteceptor] AppletIndexContainer::OnLoadStart onEnter, ` +
                    `indexContainer.this: ${args[0]}`,
            );
            // write debug_flag to 0x1
            if (args[1].and(0xff).toInt32() !== 1) {
                args[1] = args[1].and(ptr("0xffffffffffffff00")).or(1);
            }
            // handle onLoad scene
            hookOnLoadScene(args[0], config.SceneOffsets);
        },
        onLeave(retval) {
            // do nothing
        },
    });
};

const parseConfig = () => {
    const rawConfig = `@@CONFIG@@`;
    if (rawConfig.includes("@@")) {
        // test addresses
        return {
            Version: 18955,
            LoadStartHookOffset: "0x25B52C0",
            CDPFilterHookOffset: "0x30248B0",
            SceneOffsets: [1408, 1344, 488],
        };
    }
    return JSON.parse(rawConfig);
};

const main = () => {
    const config = parseConfig();
    const mainModule = getMainModule(config.Version);
    patchOnLoadStart(mainModule.base, config);
    patchCDPFilter(mainModule.base, config);
    patchInspectMenu(mainModule);
};

main();
