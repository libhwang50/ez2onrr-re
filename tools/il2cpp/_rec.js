
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
rpc.exports.rec = function () {
    return onMain(() => {
        const out = {};
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const da = img.class('da');
        const rd = da.nestedClasses.find(n => n.name === 'RecordData');
        out.recordData = rd ? { fields: rd.fields.map(f => (f.isStatic ? '[S]' : '') + f.name + ':' + f.type.name), methods: rd.methods.map(m => (m.isStatic ? 'S' : 'I') + m.name + '(' + m.parameterCount + ')->' + m.returnType.name) } : null;
        // dump fai list
        const qe = img.class('qe');
        const inst = qe.field('instance').value;
        const lst = inst.method('fai', 0).invoke();
        const size = (function () { try { return lst.field('_size').value; } catch (e) { return -1; } })();
        out.faiSize = size;
        const items = (function () { try { return lst.field('_items').value; } catch (e) { return null; } })();
        out.items = [];
        if (items) {
            for (let i = 0; i < size; i++) {
                try {
                    const o = items[i + 0];
                    if (!o || !o.handle) { out.items.push(null); continue; }
                    const rec = {};
                    rec.class = o.class.name;
                    for (const f of o.class.fields) {
                        try {
                            const v = o.field(f.name);
                            if (f.type.name === 'da.RecordData') { rec[f.name] = v.value ? v.value.handle.toString() : null; }
                            else if (f.type.name === 'System.Int32') rec[f.name] = v.value;
                            else rec[f.name] = '<' + f.type.name + '>';
                        } catch (e) { rec[f.name] = 'ERR'; }
                    }
                    out.items.push(rec);
                } catch (e) { out.items.push('ERR:' + e); }
            }
        }
        return out;
    });
};
