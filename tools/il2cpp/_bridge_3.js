
rpc.exports.try3 = function (cls, methodName, hexArgs) {
    return Il2Cpp.perform(() => {
        const res = { cls: cls, method: methodName, n: hexArgs.length };
        try {
            const byteClass = Il2Cpp.corlib.class("System.Byte");
            const args = hexArgs.map(h => { const a = []; for (let i = 0; i < h.length; i += 2) a.push(parseInt(h.substr(i, 2), 16)); return Il2Cpp.array(byteClass, a); });
            const klass = Il2Cpp.domain.assembly("Assembly-CSharp").image.class(cls);
            const out = klass.method(methodName, hexArgs.length).invoke(...args);
            const n = out.length; let p; try { p = out.elements.handle; } catch (e) { p = out.handle.add(0x20); }
            const u8 = new Uint8Array(p.readByteArray(Math.min(n, 48))); let hex = ''; for (let i = 0; i < u8.length; i++) hex += u8[i].toString(16).padStart(2, '0');
            res.len = n; res.head = hex;
            return res;
        } catch (e) { res.error = '' + (e && e.message ? e.message : e); return res; }
    });
};
