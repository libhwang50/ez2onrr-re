
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
rpc.exports.f = function () {
    return onMain(() => {
        const out = {};
        const want = { 'mscorlib': ['Rijndael','Aes','SymmetricAlgorithm','TripleDES','DES','RC2','HashAlgorithm','MD5','SHA1','SHA256','Rfc2898DeriveBytes'],
                       'System.Core': ['AesManaged','AesCryptoServiceProvider'],
                       'System': ['HMACSHA1'] };
        for (const asm in want) {
            let img; try { img = Il2Cpp.domain.assembly(asm).image; } catch (e) { continue; }
            for (const cn of want[asm]) {
                let k = null;
                for (const c of img.classes) if (c.name === cn) { k = c; break; }
                if (!k) continue;
                for (const m of k.methods) {
                    if (!m.isStatic) continue;
                    if (m.name !== 'Create' && m.name !== 'CreateDecryptor' && m.name !== 'CreateEncryptor') continue;
                    out[asm + ':' + cn + '.' + m.name + '/' + m.parameterCount] = m.virtualAddress.toString();
                }
            }
        }
        return out;
    });
};
