
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
rpc.exports.s = function () {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const inst = img.class('InGameCore').field('instance').value;
        const out = {};
        const cnt = (o) => { try { return o.method('get_Count',0).invoke(); } catch(e){ return -1; } };
        for (const nm of ['instrumentDic','normalNoteData','longNoteData','bpmNoteData','MeasureScaleData']) {
            try { const v = inst.field(nm).value; out[nm] = v === null ? null : cnt(v); } catch (e) { out[nm] = 'ERR'; }
        }
        // per-lane note counts
        try {
            const nnd = inst.field('normalNoteData').value;
            const lanes = [];
            const inner = nnd.method('get_Item',1);
            for (let i = 0; i < out.normalNoteData; i++) { const l = nnd.method('get_Item',1).invoke(i); lanes.push(l === null ? -1 : l.method('get_Count',0).invoke()); }
            out.lanes = lanes;
        } catch (e) { out.lanes = 'ERR'; }
        try { out.ez_url = inst.field('ez_url').value.content.slice(0,60); } catch (e) {}
        return out;
    });
};
