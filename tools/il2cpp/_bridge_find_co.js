
rpc.exports.findCo = function () {
    return Il2Cpp.perform(() => {
        const out = [];
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        for (const k of img.classes) {
            if (k.name === 'co') out.push({ full: k.name, fields: k.fields.map(f => f.name) });
            try {
                for (const n of k.nestedClasses) {
                    if (n.name === 'co') out.push({ full: (k.name + '/' + n.name), fields: n.fields.map(f => f.name), methods: n.methods.map(m => m.name + '(' + m.parameterCount + ')->' + m.returnType.name) });
                }
            } catch (e) {}
        }
        return out;
    });
};
rpc.exports.dumpClass = function (name) {
    return Il2Cpp.perform(() => {
        try {
            const k = Il2Cpp.domain.assembly("Assembly-CSharp").image.class(name);
            return { name: k.nestedName || k.name, fields: k.fields.map(f => f.name + ":" + f.type.name), methods: k.methods.map(m => m.name + "(" + m.parameterCount + ")->" + m.returnType.name) };
        } catch (e) { return { error: '' + e }; }
    });
};
