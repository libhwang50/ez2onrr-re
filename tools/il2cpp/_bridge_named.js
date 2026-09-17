
rpc.exports.named = function () {
    return Il2Cpp.perform(() => {
        const out = [];
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const re = /AES|Encrypt|Decrypt|Zip|Compress|Base64|Md5|MD5|Sha|SHA|Rsa|RSA|Crypt|Key|Iv|IV/i;
        for (const k of img.classes) {
            let ms; try { ms = k.methods; } catch (e) { continue; }
            for (const m of ms) {
                if (re.test(m.name) && !/^[a-z]{3}$/.test(m.name)) {
                    out.push({ cls: k.name, name: m.name, params: m.parameterCount, ret: m.returnType.name, statik: m.isStatic });
                }
            }
        }
        return out;
    });
};
