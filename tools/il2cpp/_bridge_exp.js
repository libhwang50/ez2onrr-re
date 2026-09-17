
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
rpc.exports.cls = function (name, parent) {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        let k = null;
        if (parent) { const p = img.class(parent); try { k = p.nestedClasses.find(n => n.name === name); } catch (e) {} }
        else { k = img.classes.find(c => c.name === name); }
        if (!k) return { err: 'not found' };
        return { name: k.name, fields: k.fields.map(f => (f.isStatic ? '[S]' : '') + f.name + ':' + f.type.name), methods: k.methods.map(m => (m.isStatic ? 'S' : 'I') + m.name + '(' + m.parameterCount + ')->' + m.returnType.name) };
    });
};
rpc.exports.instBB = function () {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const out = [];
        for (const k of img.classes) {
            let ms; try { ms = k.methods; } catch (e) { continue; }
            for (const m of ms) {
                if (!m.isStatic && m.returnType.name === 'System.Byte[]') {
                    let ps = []; try { for (let i = 0; i < m.parameterCount; i++) ps.push(m.parameters[i].type.name.replace('System.','')); } catch (e) { continue; }
                    out.push(k.name + '.' + m.name + '(' + ps.join(',') + ')');
                }
            }
        }
        return out;
    });
};
rpc.exports.list0 = function (cls, method, field) {
    return onMain(() => {
        try {
            const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
            const k = img.class(cls);
            const inst = field ? k.field(field).value : k.field('instance').value;
            const lst = inst.method(method, 0).invoke();
            const n = lst.length !== undefined ? lst.length : (function(){ try { return lst.field('_size').value; } catch(e){ return -1; } })();
            const info = { count: n };
            try { info.elemType = lst.class.name; } catch (e) {}
            // dump first element fields
            try {
                const items = lst.field('_items').value;
                info.item0 = (function(){ try { return items[0].class.name; } catch (e) { return null; } })();
            } catch (e) {}
            return info;
        } catch (e) { return { err: '' + (e && e.message ? e.message : e) }; }
    });
};
