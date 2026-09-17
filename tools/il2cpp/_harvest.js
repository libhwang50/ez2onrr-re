
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
function dat(a) { try { return a.elements.handle; } catch (e) { return a.handle.add(0x20); } }
function hx(a) { if (a===null) return null; try { const u=new Uint8Array(dat(a).readByteArray(Math.min(a.length,64))); let h=''; for(let i=0;i<u.length;i++) h+=u[i].toString(16).padStart(2,'0'); return {len:a.length, hex:h}; } catch(e){ return 'ERR'; } }
function walk(o, tag, depth, out) {
    if (!o || depth < 0) return;
    try {
        for (const f of o.class.fields) {
            let v; try { v = o.field(f.name).value; } catch (e) { continue; }
            const t = '' + f.type.name;
            if (t === 'System.Byte[]') out.push({ tag: tag + '.' + f.name, val: hx(v) });
            else if (t === 'System.String') { try { if (v) out.push({ tag: tag + '.' + f.name, s: v.content }); } catch (e) {} }
            else if (depth > 0 && v && v.handle && !t.startsWith('System.')) walk(v, tag + '.' + f.name, depth - 1, out);
        }
    } catch (e) {}
}
rpc.exports.h = function () {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const out = [];
        // zf statics + vy/member chain
        try {
            const zf = img.class('zf');
            for (const f of zf.fields) {
                if (!f.isStatic) continue;
                try {
                    const v = f.value;
                    const t = '' + f.type.name;
                    if (t === 'System.String' && v) out.push({ tag: 'zf.' + f.name, s: v.content });
                    else if (t === 'System.Byte[]') out.push({ tag: 'zf.' + f.name, val: hx(v) });
                    else if (v && v.handle) walk(v, 'zf.' + f.name, 2, out);
                } catch (e) {}
            }
        } catch (e) {}
        // da statics (aes_key/aes_iv), qe, bbk
        for (const cn of ['da','qe','bbk','InGameCore']) {
            try {
                const k = img.class(cn);
                for (const f of k.fields) {
                    if (!f.isStatic) continue;
                    const t = '' + f.type.name;
                    if (t !== 'System.String' && t !== 'System.Byte[]') continue;
                    try {
                        const v = f.value;
                        if (v === null) continue;
                        if (t === 'System.String') out.push({ tag: cn + '.' + f.name, s: v.content });
                        else out.push({ tag: cn + '.' + f.name, val: hx(v) });
                    } catch (e) {}
                }
            } catch (e) {}
        }
        return out;
    });
};
