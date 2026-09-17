
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
rpc.exports.asms = function () {
    return onMain(() => Il2Cpp.domain.assemblies.map(a => { try { return a.name + '#' + a.image.classes.length; } catch (e) { return a.name + '#?'; } }));
};
rpc.exports.sym = function (addrs) {
    return onMain(() => {
        const want = {};
        for (const a of addrs) want[a.toLowerCase()] = true;
        const out = {};
        const walk = (k, depth) => {
            let ms; try { ms = k.methods; } catch (e) { return; }
            for (const m of ms) {
                let va; try { va = m.virtualAddress; } catch (e) { continue; }
                if (va.isNull()) continue;
                const key = va.toString().toLowerCase();
                if (want[key]) { try { out[key] = k.name + '.' + m.name; } catch (e) { } }
            }
            if (depth > 0) { try { for (const n of k.nestedClasses) walk(n, depth - 1); } catch (e) {} }
        };
        for (const asm of Il2Cpp.domain.assemblies) {
            let img; try { img = asm.image; } catch (e) { continue; }
            for (const k of img.classes) walk(k, 1);
        }
        return out;
    });
};
