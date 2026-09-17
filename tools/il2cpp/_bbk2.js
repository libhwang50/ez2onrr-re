
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
function dat(a) { try { return a.elements.handle; } catch (e) { return a.handle.add(0x20); } }
function hexOf(a, n) {
    if (a === null) return null;
    const u = new Uint8Array(dat(a).readByteArray(Math.min(a.length, n||256)));
    let h=''; for (let i=0;i<u.length;i++) h+=u[i].toString(16).padStart(2,'0');
    return { len: a.length, hex: h };
}
rpc.exports.init = function () {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const k = img.class('bbk');
        const out = {};
        for (const m of ['fxr','gva']) {
            try { k.method(m, 0).invoke(); out['called_' + m] = true; } catch (e) { out['called_' + m] = '' + (e && e.message ? e.message : e); }
        }
        for (const f of k.fields) {
            try {
                if (('' + f.type.name) === 'System.Byte[]') out[f.name] = hexOf(f.value, 256);
                else if (('' + f.type.name) === 'System.String') { const v = f.value; out[f.name] = v === null ? null : v.content; }
            } catch (e) { out[f.name] = 'ERR:' + (e && e.message ? e.message : e); }
        }
        return out;
    });
};
