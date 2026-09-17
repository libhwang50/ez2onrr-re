
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
rpc.exports.encl = function (sites) {
    return onMain(() => {
        const arr = [];
        const walk = (k, d) => {
            const kn = k.name;
            let ms; try { ms = k.methods; } catch (e) { return; }
            for (const m of ms) {
                let va; try { va = m.virtualAddress; } catch (e) { continue; }
                if (va.isNull()) continue;
                const n = parseInt(va.toString(), 16);
                let nm; try { nm = m.name; } catch (e) { nm = '?'; }
                arr.push([n, kn + '.' + nm]);
            }
            if (d > 0) { try { for (const x of k.nestedClasses) walk(x, d - 1); } catch (e) {} }
        };
        for (const asm of Il2Cpp.domain.assemblies) {
            let img; try { img = asm.image; } catch (e) { continue; }
            for (const k of img.classes) walk(k, 1);
        }
        arr.sort((a, b) => a[0] - b[0]);
        const vas = arr.map(_ => _[0]);
        const out = {};
        for (const s of sites) {
            const v = parseInt(s, 16);
            let lo = 0, hi = vas.length - 1, best = -1;
            while (lo <= hi) { const mid = (lo + hi) >> 1; if (vas[mid] <= v) { best = mid; lo = mid + 1; } else hi = mid - 1; }
            out[s] = best >= 0 ? { m: arr[best][1], at: arr[best][0], off: v - arr[best][0] } : null;
        }
        out.__count = arr.length;
        return out;
    });
};
