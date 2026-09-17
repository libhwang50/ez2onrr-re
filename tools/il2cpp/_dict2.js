
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
rpc.exports.dict = function () {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const igc = img.class('InGameCore');
        const inst = igc.field('instance').value;
        let fld = null;
        for (const f of inst.class.fields) {
            if (f.type.name.indexOf('Dictionary') >= 0 && f.type.name.indexOf('String') >= 0) { fld = f.name; break; }
        }
        const d = inst.field(fld).value;
        const out = { field: fld, type: d.class.name };
        // Dictionary: _buckets/_entries; easiest: invoke get_Count and copy via keys
        const cnt = d.method('get_Count', 0).invoke();
        out.count = cnt;
        const items = [];
        const keys = d.method('get_Keys', 0).invoke();
        const vit = keys.method('GetEnumerator', 0).invoke();
        for (let i = 0; i < cnt && i < 60; i++) {
            vit.method('MoveNext', 0).invoke();
            const cur = vit.method('get_Current', 0).invoke();
            const val = d.method('get_Item', 1).invoke(cur);
            items.push([cur.value, '' + val]);
        }
        out.sample = items;
        return out;
    });
};
