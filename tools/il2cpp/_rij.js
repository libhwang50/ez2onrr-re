
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
function arr(hex) {
    const bc = Il2Cpp.corlib.class("System.Byte");
    const a = []; for (let i = 0; i < hex.length; i += 2) a.push(parseInt(hex.substr(i, 2), 16));
    return Il2Cpp.array(bc, a);
}
function bytesOf(o, n) {
    if (o === null) return null;
    let len = -1; try { len = o.length; } catch (e) {}
    let p; try { p = o.elements.handle; } catch (e) { p = o.handle.add(0x20); }
    const u = new Uint8Array(p.readByteArray(Math.min(len < 0 ? (n||64) : len, n||64)));
    let h=''; for (let i=0;i<u.length;i++) h+=u[i].toString(16).padStart(2,'0');
    let asc=''; for (let i=0;i<u.length;i++) asc+=(u[i]>=32&&u[i]<127)?String.fromCharCode(u[i]):'.';
    return { len: len, head: h, ascii: asc };
}
rpc.exports.find = function (name) {
    return onMain(() => {
        const out = {};
        for (const asm of Il2Cpp.domain.assemblies) {
            try {
                const k = asm.image.tryClass ? null : null;
            } catch (e) {}
        }
        for (const asmName of ['mscorlib', 'System.Core', 'System']) {
            try {
                const img = Il2Cpp.domain.assembly(asmName).image;
                for (const c of img.classes) if (c.name === 'RijndaelManaged' || c.name === 'AesManaged' || c.name === 'Rijndael') out[asmName + ':' + c.name] = c.handle.toString();
            } catch (e) {}
        }
        return out;
    });
};
rpc.exports.dec = function (dataHex, keyHex, ivHex, blocksize) {
    return onMain(() => {
        try {
            const img = Il2Cpp.domain.assembly("mscorlib").image;
            let k = null;
            for (const c of img.classes) if (c.name === 'RijndaelManaged') { k = c; break; }
            if (!k) return { err: 'no RijndaelManaged' };
            const obj = k.new();
            obj.method('set_KeySize', 1).invoke(128);
            obj.method('set_BlockSize', 1).invoke(blocksize || 256);
            obj.method('set_Key', 1).invoke(arr(keyHex));
            obj.method('set_IV', 1).invoke(arr(ivHex));
            obj.method('set_Mode', 1).invoke(1);
            obj.method('set_Padding', 1).invoke(2);
            const tr = obj.method('CreateDecryptor', 0).invoke();
            const data = arr(dataHex);
            const out = tr.method('TransformFinalBlock', 3).invoke(data, 0, data.length);
            return bytesOf(out, 96);
        } catch (e) { return { err: '' + (e && e.message ? e.message : e) }; }
    });
};
