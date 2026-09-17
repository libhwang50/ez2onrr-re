
rpc.exports.readKey = function () {
    return Il2Cpp.perform(() => {
        const out = {};
        function hexOf(o) { try { const n = o.length; let p; try { p = o.elements.handle; } catch (e) { p = o.handle.add(0x20); } const u8 = new Uint8Array(p.readByteArray(Math.min(n, 256))); let h = ''; for (let i = 0; i < u8.length; i++) h += u8[i].toString(16).padStart(2, '0'); return { len: n, hex: h }; } catch (e) { return { err: '' + e }; } }
        try {
            const da = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("da");
            const fld = da.fields.find(f => f.name === 'rus');
            out.rusType = fld.type.name;
            out.rusStatic = fld.isStatic;
            let coObj;
            if (fld.isStatic) { coObj = fld.value; }
            else { const inst = da.field('instance') ? da.field('instance').value : null; out.daInst = inst ? inst.handle.toString() : null; coObj = inst ? inst.field('rus').value : null; }
            out.coObj = coObj ? coObj.handle.toString() : null;
            if (coObj) {
                const co = coObj.class;
                out.coFields = co.fields.map(f => f.name);
                for (const nm of ['rjl', 'rjm', 'rjn']) {
                    try { const v = coObj.field(nm).value; out[nm] = hexOf(v); } catch (e) { out[nm] = { err: '' + e }; }
                }
            }
            return out;
        } catch (e) { out.error = '' + (e && e.message ? e.message : e); return out; }
    });
};
