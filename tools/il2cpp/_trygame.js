
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
rpc.exports.t = function (cls, method, b64) {
    return onMain(() => {
        try {
            const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
            const k = img.class(cls);
            let m = null;
            for (const mm of k.methods) if (mm.name === method && mm.parameterCount === 1) { m = mm; break; }
            if (!m) return { err: 'no method' };
            const out = m.invoke(Il2Cpp.string(b64));
            if (out === null) return { ret: 'NULL' };
            let len = -1; try { len = out.length; } catch (e) {}
            // read raw UTF-16 units
            let h = '';
            try {
                const chars = Il2Cpp.exports.stringGetChars(out);
                const u = new Uint8Array(chars.readByteArray(Math.min(len, 64) * 2));
                for (let i = 0; i < u.length; i++) h += u[i].toString(16).padStart(2, '0');
            } catch (e) { h = 'ERR'; }
            return { retLen: len, raw64: h };
        } catch (e) { return { err: '' + (e && e.message ? e.message : e) }; }
    });
};
