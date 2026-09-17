
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
function arr(hex) {
    const bc = Il2Cpp.corlib.class("System.Byte");
    const a = []; for (let i = 0; i < hex.length; i += 2) a.push(parseInt(hex.substr(i, 2), 16));
    return Il2Cpp.array(bc, a);
}
function dump(o, n) {
    if (o === null) return { len: -1 };
    let len = -1; try { len = o.length; } catch (e) {}
    let p; try { p = o.elements.handle; } catch (e) { p = o.handle.add(0x20); }
    const u = new Uint8Array(p.readByteArray(Math.min(len < 0 ? n : len, n)));
    let h = ''; for (let i = 0; i < u.length; i++) h += u[i].toString(16).padStart(2, '0');
    let asc = ''; for (let i = 0; i < u.length; i++) asc += (u[i] >= 32 && u[i] < 127) ? String.fromCharCode(u[i]) : '.';
    return { len: len, head: h, ascii: asc };
}
rpc.exports.call3 = function (cls, method, h1, h2, h3) {
    return onMain(() => {
        try {
            const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
            const out = img.class(cls).method(method, 3).invoke(arr(h1), arr(h2), arr(h3));
            return dump(out, 96);
        } catch (e) { return { err: '' + (e && e.message ? e.message : e) }; }
    });
};
