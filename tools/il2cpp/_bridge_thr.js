
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
function arr(hex) {
    const bc = Il2Cpp.corlib.class("System.Byte");
    const a = []; for (let i = 0; i < hex.length; i += 2) a.push(parseInt(hex.substr(i, 2), 16));
    return Il2Cpp.array(bc, a);
}
function head(o, n) {
    if (o === null) return { len: -1, head: 'NULL' };
    let len = -1; try { len = o.length; } catch (e) {}
    let p; try { p = o.elements.handle; } catch (e) { p = o.handle.add(0x20); }
    const u8 = new Uint8Array(p.readByteArray(Math.min(len < 0 ? n : len, n)));
    let h = ''; for (let i = 0; i < u8.length; i++) h += u8[i].toString(16).padStart(2, '0');
    return { len: len, head: h };
}
rpc.exports.bi = function (cls, method, hex, field) {
    return onMain(() => {
        try {
            const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
            const k = img.class(cls);
            const m = k.method(method, 1);
            if (m.isStatic) return head(m.invoke(arr(hex)), 48);
            const inst = field ? k.field(field).value : k.field('instance').value;
            return head(inst.method(method, 1).invoke(arr(hex)), 48);
        } catch (e) { return { err: '' + (e && e.message ? e.message : e) }; }
    });
};
rpc.exports.si = function (cls, method, s) {
    return onMain(() => {
        try {
            const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
            const out = img.class(cls).method(method, 1).invoke(Il2Cpp.string(s));
            return out === null ? 'NULL' : ('' + out).slice(0, 120);
        } catch (e) { return { err: '' + (e && e.message ? e.message : e) }; }
    });
};
