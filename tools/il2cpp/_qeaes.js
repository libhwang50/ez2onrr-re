
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
rpc.exports.s1 = function (cls, method, str) {
    return onMain(() => {
        try {
            const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
            const k = img.class(cls);
            const m = k.methods.find(x => x.name === method && x.parameterCount === 1);
            if (!m) return { err: 'no method' };
            let p = null; try { p = m.parameters[0].type.name; } catch (e) {}
            const out = m.invoke(Il2Cpp.string(str));
            let s = null;
            try { s = out === null ? 'NULL' : out.content; } catch (e) { s = '' + out; }
            return { param: p, ret: m.returnType.name, len: s === null ? -1 : s.length, head: s === null ? null : s.slice(0, 48), pr: s === null ? 0 : (function () { let n = 0; for (let i = 0; i < Math.min(s.length, 200); i++) { const c = s.charCodeAt(i); if (c >= 32 && c < 127) n++; } return n / Math.min(s.length, 200); })() };
        } catch (e) { return { err: '' + (e && e.message ? e.message : e) }; }
    });
};
