
rpc.exports.daCo = function () {
    return Il2Cpp.perform(() => {
        const out = {};
        try {
            const da = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("da");
            out.daFieldsCo = da.fields.filter(f => ('' + f.type.name).indexOf('co') >= 0).map(f => f.name + ":" + f.type.name);
            // try static fields named like instance? look for any field of type da.co
            out.coClass = null;
            const co = da.nestedClasses && da.nestedClasses.find(n => n.name === 'co');
            if (co) {
                out.coFields = co.fields.map(f => f.name + ":" + f.type.name);
                out.coStaticFields = co.fields.filter(f => f.isStatic).map(f => f.name);
            }
            // search all da static fields for a da.co value
            const instFields = da.fields.filter(f => ('' + f.type.name).indexOf('/co') >= 0 || ('' + f.type.name) === 'da.co');
            out.instFields = instFields.map(f => f.name + ":" + f.type.name);
            return out;
        } catch (e) { out.error = '' + (e && e.message ? e.message : e); return out; }
    });
};
