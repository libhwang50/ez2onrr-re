
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
rpc.exports.slot = function () {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const da = img.class('da');
        const out = { staticFieldsData: da.staticFieldsData ? da.staticFieldsData.toString() : null };
        for (const f of da.fields) {
            if (!f.isStatic) continue;
            if (f.name === 'rus' || f.name === 'rjl' || f.name === 'rjm' || f.name === 'rjn' || f.name === 'aes_key' || f.name === 'aes_iv') {
                let off = null; try { off = f.offset; } catch (e) { off = 'ERR'; }
                out[f.name] = { offset: off, type: f.type.name };
            }
        }
        // also count static byte[] fields
        out.byteFields = da.fields.filter(f => f.isStatic && f.type.name === 'System.Byte[]').map(f => f.name);
        out.coFields = da.fields.filter(f => f.isStatic && ('' + f.type.name).indexOf('.co') >= 0).map(f => f.name + ':' + f.type.name);
        return out;
    });
};
