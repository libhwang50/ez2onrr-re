
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
rpc.exports.t = function (method, b64) {
    return onMain(() => {
        try {
            const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
            const k = img.class('bbk');
            let m = null;
            for (const mm of k.methods) if (mm.name === method && mm.parameterCount === 1) { m = mm; break; }
            if (!m) return { err: 'no method ' + method };
            const out = m.invoke(Il2Cpp.string(b64));
            if (out === null) return { r: 'NULL' };
            let len = -1, s = null;
            try { len = out.length; s = out.content; } catch (e) {}
            return { len: len, s: s === null ? null : s.slice(0, 90) };
        } catch (e) { return { err: '' + (e && e.message ? e.message : e) }; }
    });
};
