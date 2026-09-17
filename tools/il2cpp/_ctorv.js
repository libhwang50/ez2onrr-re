
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
rpc.exports.v = function () {
    return onMain(() => {
        const out = {};
        const spec = { 'mscorlib': ['RijndaelManaged','Rijndael','SymmetricAlgorithm','RijndaelManagedTransform','CryptoConfig'],
                       'System.Core': ['AesCryptoServiceProvider','AesManaged','AesTransform'],
                       'System': ['AesCryptoServiceProvider'] };
        for (const asm in spec) {
            let img; try { img = Il2Cpp.domain.assembly(asm).image; } catch (e) { continue; }
            for (const cn of spec[asm]) {
                let k = null;
                for (const c of img.classes) if (c.name === cn) { k = c; break; }
                if (!k) continue;
                for (const m of k.methods) {
                    if (m.name === '.ctor' || m.name === 'CreateFromName' || m.name === 'CreateDecryptor' || m.name === 'CreateEncryptor')
                        out[asm + ':' + cn + '.' + m.name + '/' + m.parameterCount] = m.virtualAddress.toString();
                }
            }
        }
        return out;
    });
};
