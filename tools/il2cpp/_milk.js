
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
function dat(a) { try { return a.elements.handle; } catch (e) { return a.handle.add(0x20); } }
rpc.exports.info = function () {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const out = {};
        try {
            const zf = img.class('zf');
            for (const n of ['aes_key','aes_iv']) { try { out['zf_'+n] = zf.field(n).value.content; } catch (e) { out['zf_'+n] = 'ERR'; } }
        } catch (e) {}
        const slot = img.class('da').staticFieldsData.add(840);
        const p = slot.readPointer();
        out.co = p.toString();
        if (!p.isNull()) {
            const c = new Il2Cpp.Object(p);
            for (const nm of ['rjl','rjm','rjn']) {
                try {
                    const a = c.field(nm).value;
                    const u = new Uint8Array(dat(a).readByteArray(16));
                    let h=''; for (let i=0;i<u.length;i++) h+=u[i].toString(16).padStart(2,'0');
                    out[nm] = { len: a.length, head: h };
                } catch (e) { out[nm] = 'ERR'; }
            }
        }
        try { const igc = img.class('InGameCore').field('instance').value;
              const bc = igc.field('bundleCryptKey').value;
              if (bc) { const u = new Uint8Array(dat(bc).readByteArray(bc.length)); let h=''; for (let i=0;i<u.length;i++) h+=u[i].toString(16).padStart(2,'0'); out.bundleCryptKey = { len: bc.length, hex: h }; }
              else out.bundleCryptKey = null;
        } catch (e) { out.bundleCryptKey = 'ERR'; }
        return out;
    });
};
