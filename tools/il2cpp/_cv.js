function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
rpc.exports.v = function () {
    return onMain(() => {
        const out = {};
        const spec = {
            'mscorlib': ['Aes', 'Rijndael', 'RijndaelManaged', 'RijndaelManagedTransform', 'SymmetricAlgorithm',
                          'CryptoConfig', 'SymmetricTransform', 'MD5', 'SHA1', 'SHA256', 'SHA512',
                          'Rfc2898DeriveBytes', 'PasswordDeriveBytes', 'DES', 'TripleDES', 'RC2', 'RandomNumberGenerator'],
            'System.Core': ['AesCryptoServiceProvider', 'AesManaged', 'AesTransform', 'AesManaged', 'SHA256Managed', 'MD5CryptoServiceProvider'],
        };
        const wanted = ['Create', '.ctor', 'CreateDecryptor', 'CreateEncryptor', 'DecryptData', 'EncryptData',
                        'CreateFromName', 'TransformFinalBlock', 'TransformBlock', 'GetBytes', 'ComputeHash', 'NewEncryptor', 'NewDecryptor'];
        for (const asm in spec) {
            let img; try { img = Il2Cpp.domain.assembly(asm).image; } catch (e) { continue; }
            for (const cn of spec[asm]) {
                let k = null;
                for (const c of img.classes) if (c.name === cn) { k = c; break; }
                if (!k) continue;
                for (const m of k.methods) {
                    if (wanted.indexOf(m.name) < 0) continue;
                    try { out[asm + ':' + cn + '.' + m.name + '/' + m.parameterCount] = m.virtualAddress.toString(); } catch (e) {}
                }
            }
        }
        return out;
    });
};
