
rpc.exports.snap = function () {
    return Il2Cpp.perform(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const da = img.class('da');
        const sfd = da.staticFieldsData;
        const p = sfd.add(840).readPointer();
        const o = { co: p.toString() };
        if (p.isNull()) return o;
        const co = new Il2Cpp.Object(p);
        for (const nm of ['rjl', 'rjm', 'rjn']) {
            try {
                const a = co.field(nm).value;
                let dp; try { dp = a.elements.handle; } catch (e) { dp = a.handle.add(0x20); }
                const u = new Uint8Array(dp.readByteArray(Math.min(a.length, 32)));
                let h = ''; for (let i = 0; i < u.length; i++) h += u[i].toString(16).padStart(2, '0');
                o[nm] = { len: a.length, ptr: dp.toString(), head: h };
            } catch (e) { o[nm] = 'ERR'; }
        }
        return o;
    });
};
rpc.exports.dumpfull = function (which) {
    return Il2Cpp.perform(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const da = img.class('da');
        const co = new Il2Cpp.Object(da.staticFieldsData.add(840).readPointer());
        const a = co.field(which).value;
        let dp; try { dp = a.elements.handle; } catch (e) { dp = a.handle.add(0x20); }
        const u = new Uint8Array(dp.readByteArray(a.length));
        let h = ''; for (let i = 0; i < u.length; i++) h += u[i].toString(16).padStart(2, '0');
        return h;
    });
};
