
rpc.exports.t = function () {
    return Il2Cpp.perform(() => {
        const tid = Il2Cpp.mainThread.id;
        globalThis.__f = 0;
        const r = Process.runOnThread(tid, () => { globalThis.__f = 42; return 99; });
        return { r: '' + r, f: globalThis.__f };
    });
};
rpc.exports.t2 = function () {
    return Il2Cpp.perform(() => {
        const tid = Il2Cpp.mainThread.id;
        globalThis.__f = 0;
        Process.runOnThread(tid, () => { globalThis.__f = 42; return 99; });
        Thread.sleep(1.0);
        return { f: globalThis.__f };
    });
};
