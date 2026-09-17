
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
function rawStr(hex) {
    const n = hex.length / 2;
    const buf = Memory.alloc(n * 2 + 2);
    for (let i = 0; i < n; i++) buf.add(i * 2).writeU16(parseInt(hex.substr(i * 2, 2), 16));
    buf.add(n * 2).writeU16(0);
    return Il2Cpp.exports.stringNew(buf);
}
rpc.exports.s1raw = function (cls, method, hex) {
    return onMain(() => {
        try {
            const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
            const k = img.class(cls);
            const m = k.methods.find(x => x.name === method && x.parameterCount === 1);
            if (!m) return { err: 'no method' };
            const out = m.invoke(rawStr(hex));
            let s = null; try { s = out === null ? null : out.content; } catch (e) { s = '' + out; }
            let pr = 0; if (s) { let n = 0; const L = Math.min(s.length, 200); for (let i = 0; i < L; i++) { const c = s.charCodeAt(i); if (c >= 32 && c < 127) n++; } pr = n / L; }
            return { len: s === null ? -1 : s.length, pr: pr, head: s === null ? 'NULL' : s.slice(0, 64) };
        } catch (e) { return { err: '' + (e && e.message ? e.message : e) }; }
    });
};
