
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
rpc.exports.findInst = function (cls) {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const k = img.class(cls);
        const out = { statics: [] };
        for (const f of k.fields) {
            if (!f.isStatic) continue;
            out.statics.push(f.name + ':' + f.type.name);
            try { const v = f.value; if (v && v.handle && v.class && (v.class.name === cls || ('' + v.class.name).indexOf(cls) >= 0)) { out.instField = f.name; out.instHandle = v.handle.toString(); } } catch (e) {}
        }
        return out;
    });
};
rpc.exports.readBCK = function (cls, instField) {
    return onMain(() => {
        try {
            const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
            const k = img.class(cls);
            const inst = k.field(instField).value;
            const out = {};
            for (const f of inst.class.fields) {
                if (!f.type || f.type.name !== 'System.Byte[]') continue;
                try { out[f.name] = hx(inst.field(f.name).value, 80); } catch (e) {}
            }
            for (const nm of ['bundleCryptKey', 'ez_url', 'ezi_url']) { try { const v = inst.field(nm).value; out[nm] = (typeof v === 'string') ? v : (v === null ? null : ('' + v).slice(0, 120)); } catch (e) {} }
            return out;
        } catch (e) { return { err: '' + (e && e.message ? e.message : e) }; }
    });
};
