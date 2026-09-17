
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
function hx(o, n) {
    if (o === null || o === undefined) return null;
    if (typeof o === 'string') return o;
    try {
        let len = -1; try { len = o.length; } catch (e) {}
        let p; try { p = o.elements.handle; } catch (e) { p = o.handle.add(0x20); }
        const u8 = new Uint8Array(p.readByteArray(Math.min(len < 0 ? n : len, n)));
        let h = ''; for (let i = 0; i < u8.length; i++) h += u8[i].toString(16).padStart(2, '0');
        return { len: len, hex: h };
    } catch (e) { return 'ERR:' + e; }
}
rpc.exports.rbc = function (cls, instField) {
    return onMain(() => {
        try {
            const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
            const inst = img.class(cls).field(instField).value;
            const out = {};
            for (const f of inst.class.fields) {
                if (!f.type || f.type.name !== 'System.Byte[]') continue;
                try { out[f.name] = hx(inst.field(f.name).value, 80); } catch (e) {}
            }
            try { const v = inst.field('bundleCryptKey').value; out.bundleCryptKey_len = v ? v.length : -1; out.bundleCryptKey = hx(v, 80); } catch (e) { out.bckErr = '' + e; }
            return out;
        } catch (e) { return { err: '' + (e && e.message ? e.message : e) }; }
    });
};
