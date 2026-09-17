
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
rpc.exports.call0s = function (cls, methods) {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        let k = null;
        for (const c of img.classes) if (c.name === cls) { k = c; break; }
        if (!k) return { __err: 'class not found: ' + cls };
        const out = {};
        for (const nm of methods) {
            try {
                const m = k.methods.find(x => x.name === nm && x.parameterCount === 0);
                if (!m) { out[nm] = '(none)'; continue; }
                const r = m.invoke();
                out[nm] = r === null ? 'NULL' : (('' + r).slice(0, 80));
            } catch (e) { out[nm] = 'ERR:' + (e && e.message ? e.message : e); }
        }
        return out;
    });
};
