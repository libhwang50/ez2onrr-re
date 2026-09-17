
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
rpc.exports.verify = function () {
    return onMain(() => {
        const out = {};
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const da = img.class('da');
        const sfd = da.staticFieldsData;
        out.staticFieldsData = sfd.toString();
        for (const nm of ['aes_key', 'aes_iv', 'rus', 'rop', 'rpr']) {
            const f = da.fields.find(x => x.name === nm);
            if (!f) continue;
            out[nm] = { offset: f.offset };
            try { const at = sfd.add(f.offset).readPointer(); out[nm].atSlot = at.toString(); } catch (e) { out[nm].atSlot = 'ERR'; }
            try {
                const v = f.value;
                if (v === null) out[nm].bridgeVal = 'null';
                else if (f.type.name === 'System.String') out[nm].bridgeVal = v.content;
                else out[nm].bridgeVal = v.handle.toString();
            } catch (e) { out[nm].bridgeVal = 'ERR'; }
        }
        return out;
    });
};
rpc.exports.encl = function (addr) {
    return onMain(() => {
        const arr = [];
        const walk = (k, d) => {
            const kn = k.name;
            let ms; try { ms = k.methods; } catch (e) { return; }
            for (const m of ms) {
                let va; try { va = m.virtualAddress; } catch (e) { continue; }
                if (va.isNull()) continue;
                let nm; try { nm = m.name; } catch (e) { nm = '?'; }
                arr.push([parseInt(va.toString(), 16), kn + '.' + nm]);
            }
            if (d > 0) { try { for (const x of k.nestedClasses) walk(x, d - 1); } catch (e) {} }
        };
        for (const asm of Il2Cpp.domain.assemblies) { let i; try { i = asm.image; } catch (e) { continue; } for (const k of i.classes) walk(k, 1); }
        arr.sort((a, b) => a[0] - b[0]);
        const v = parseInt(addr, 16);
        let lo = 0, hi = arr.length - 1, best = -1;
        while (lo <= hi) { const mid = (lo + hi) >> 1; if (arr[mid][0] <= v) { best = mid; lo = mid + 1; } else hi = mid - 1; }
        return best >= 0 ? { m: arr[best][1], at: '0x' + arr[best][0].toString(16), off: v - arr[best][0] } : null;
    });
};
