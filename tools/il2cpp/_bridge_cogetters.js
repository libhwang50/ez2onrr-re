
rpc.exports.getters = function () {
    return Il2Cpp.perform(() => {
        const out = {};
        function hexOf(o) { try { const n = o.length; let p; try { p = o.elements.handle; } catch (e) { p = o.handle.add(0x20); } const u8 = new Uint8Array(p.readByteArray(Math.min(n, 128))); let h = ''; for (let i = 0; i < u8.length; i++) h += u8[i].toString(16).padStart(2, '0'); return { len: n, hex: h }; } catch (e) { return { err: '' + e }; } }
        try {
            const da = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("da");
            const coObj = da.fields.find(f => f.name === 'rus').value;
            const co = coObj.class;
            for (const m of co.methods) {
                if (m.parameterCount === 0 && m.returnType.name === 'System.Byte[]') {
                    try { const v = coObj.method(m.name, 0).invoke(); out[m.name] = hexOf(v); }
                    catch (e) { out[m.name] = { err: '' + (e && e.message ? e.message : e) }; }
                }
            }
            return out;
        } catch (e) { out.error = '' + (e && e.message ? e.message : e); return out; }
    });
};
