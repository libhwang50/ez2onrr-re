
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
function dat(a) { try { return a.elements.handle; } catch (e) { return a.handle.add(0x20); } }
rpc.exports.collect = function () {
    return onMain(() => {
        const out = { bytes: [], strings: [] };
        const walk = (k, p, d) => {
            let cls = p + '/' + k.name;
            try {
                for (const f of k.fields) {
                    if (!f.isStatic) continue;
                    const t = '' + f.type.name;
                    if (t === 'System.Byte[]' || t === 'System.UInt32[]' || t === 'System.Int32[]') {
                        try {
                            const a = f.value;
                            if (a === null) continue;
                            const n = a.length;
                            if (n < 8 || n > 4096) continue;
                            const u = new Uint8Array(dat(a).readByteArray(Math.min(n, 512)));
                            let h = ''; for (let i=0;i<u.length;i++) h += u[i].toString(16).padStart(2,'0');
                            out.bytes.push({ cls: cls, field: f.name, type: t, len: n, hex: h });
                        } catch (e) {}
                    } else if (t === 'System.String') {
                        try {
                            const v = f.value;
                            if (v === null) continue;
                            const s = v.content;
                            if (typeof s === 'string' && s.length >= 16 && s.length <= 128) out.strings.push({ cls: cls, field: f.name, s: s });
                        } catch (e) {}
                    }
                }
            } catch (e) {}
            if (d > 0) { try { for (const n of k.nestedClasses) walk(n, cls, d - 1); } catch (e) {} }
        };
        for (const a of Il2Cpp.domain.assemblies) { let i; try { i = a.image; } catch (e) { continue; } for (const k of i.classes) walk(k, a.name, 1); }
        return out;
    });
};
