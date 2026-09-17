function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
function dat(a) { try { return a.elements.handle; } catch (e) { return a.handle.add(0x20); } }
function hex(a, n) { if (a === null) return null; try { const u = new Uint8Array(dat(a).readByteArray(Math.min(a.length, n || 256))); let h = ''; for (let i = 0; i < u.length; i++) h += u[i].toString(16).padStart(2, '0'); return { len: a.length, hex: h }; } catch (e) { return 'ERR'; } }

rpc.exports.k = function () {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const out = {};
        const statics = (cn, names, kind) => {
            let k; try { k = img.class(cn); } catch (e) { return; }
            for (const nm of names) {
                try {
                    const f = k.field(nm);
                    const v = f.value;
                    if (v === null) { out[cn + '.' + nm] = null; continue; }
                    if (kind === 'bytes') out[cn + '.' + nm] = hex(v, 512);
                    else out[cn + '.' + nm] = v.content;
                } catch (e) { out[cn + '.' + nm] = 'ERR:' + (e && e.message ? e.message : e); }
            }
        };
        statics('da', ['aes_key', 'aes_iv'], 'str');
        statics('zf', ['aes_key', 'aes_iv'], 'str');
        statics('qe', ['aes_key', 'aes_iv'], 'str');
        statics('bbk', ['wdp', 'wdq'], 'bytes');
        statics('bbk', ['wdr', 'wds'], 'str');
        // da.rus
        try {
            const da = img.class('da');
            const p = da.staticFieldsData.add(840).readPointer();
            out['da.rus'] = p.toString();
            if (!p.isNull()) {
                const co = new Il2Cpp.Object(p);
                for (const nm of ['rjl', 'rjm', 'rjn']) out['da.rus.' + nm] = hex(co.field(nm).value, 512);
            }
        } catch (e) { out['da.rus'] = 'ERR:' + e; }
        // InGameCore instance
        try {
            const inst = img.class('InGameCore').field('instance').value;
            out['InGameCore.instance'] = inst ? inst.handle.toString() : null;
            if (inst) {
                try { out.ez_url = inst.field('ez_url').value.content; } catch (e) {}
                try { out.ezi_url = inst.field('ezi_url').value.content; } catch (e) {}
                out.bundleCryptKey = hex(inst.field('bundleCryptKey').value, 512);
                for (const nm of ['normalNoteData', 'longNoteData', 'bpmNoteData', 'instrumentDic']) {
                    try { out[nm] = inst.field(nm).value.method('get_Count', 0).invoke(); } catch (e) { out[nm] = 'ERR'; }
                }
            }
        } catch (e) { out.instanceErr = '' + e; }
        // InGameCore statics svk..svr
        try {
            const k = img.class('InGameCore');
            for (const nm of ['svk', 'svl', 'svm', 'svn', 'svo', 'svp', 'svq', 'svr']) {
                try { out['InGameCore.' + nm] = hex(k.field(nm).value, 128); } catch (e) {}
            }
        } catch (e) {}
        return out;
    });
};
