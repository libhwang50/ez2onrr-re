
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
rpc.exports.dump = function (cls) {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        let k = null;
        for (const c of img.classes) if (c.name === cls) { k = c; break; }
        if (!k) return { __err: 'no class' };
        const out = {};
        let n = 0, err = 0;
        for (const m of k.methods) {
            if (!m.isStatic || m.parameterCount !== 0) continue;
            if (m.returnType.name !== 'System.String') continue;
            n++;
            try {
                const r = m.invoke();
                if (r === null) continue;
                const s = r.content;
                if (typeof s === 'string' && s.length >= 8) out[m.name] = s;
            } catch (e) { err++; }
        }
        out.__n = n; out.__err = err;
        return out;
    });
};
