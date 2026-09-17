
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
rpc.exports.read = function () {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const out = {};
        try { out.bundleCryptKey = hx(img.class('InGameCore').field('bundleCryptKey').value, 64); } catch (e) { out.bundleCryptKey = 'ERR:' + e; }
        // find zf.vy instance field named member, and vy.member -> vx
        try {
            const zf = img.class('zf');
            const vyCls = zf.nestedClasses.find(n => n.name === 'vy');
            out.vyStaticFields = vyCls.fields.filter(f => f.isStatic).map(f => f.name + ':' + f.type.name);
            const vyStatic = vyCls.fields.find(f => f.isStatic);
            let vy = null;
            for (const f of vyCls.fields) { if (!f.isStatic) continue; try { const v = f.value; if (v && v.class) { vy = v; out.vyInst = f.name; break; } } catch (e) {} }
            if (!vy) { const sInst = zf.fields.find(f => f.isStatic && f.type.name.indexOf('vy') >= 0); if (sInst) { vy = sInst.value; out.vyInst = 'zf.' + sInst.name; } }
            if (vy) {
                out.vyFields = vy.class.fields.map(f => f.name);
                const mem = (function(){ for (const f of vy.class.fields) { try { const v = vy.field(f.name).value; if (v && v.class && v.class.name === 'vx') return v; } catch (e) {} } return null; })();
                if (mem) { out.vxFields = mem.class.fields.map(f => f.name); for (const f of mem.class.fields) { try { const v = mem.field(f.name).value; out['vx_' + f.name] = hx(v, 64); } catch (e) {} } }
            }
        } catch (e) { out.zfErr = '' + e; }
        return out;
    });
};
