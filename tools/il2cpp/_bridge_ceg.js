
rpc.exports.ceg = function (argKind) {
    return Il2Cpp.perform(() => {
        const out = {};
        try {
            const da = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("da");
            const coObj = da.fields.find(f => f.name === 'rus').value;
            const rjn = coObj.field('rjn').value;
            const rjm = coObj.field('rjm').value;
            const arg = argKind === 'rjn' ? rjn : rjm;
            const res = coObj.method('ceg', 1).invoke(arg);
            out.resType = res && res.class ? res.class.name : ('' + res);
            out.handle = res && res.handle ? res.handle.toString() : null;
            return out;
        } catch (e) { out.error = '' + (e && e.message ? e.message : e); return out; }
    });
};
rpc.exports.daMethods = function () {
    return Il2Cpp.perform(() => {
        const da = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("da");
        return da.methods.filter(m => m.returnType.name.indexOf('Byte') >= 0 || m.parameterCount >= 1 && m.parameterCount <= 2).map(m => m.name + "(" + m.parameterCount + ")->" + m.returnType.name).slice(0, 80);
    });
};
