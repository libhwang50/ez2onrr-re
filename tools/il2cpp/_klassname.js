
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
rpc.exports.byPtr = function (targets) {
    return onMain(() => {
        const want = {};
        for (const t of targets) want[('' + t).toLowerCase()] = true;
        const out = {};
        const walk = (k, path, depth) => {
            let h; try { h = k.handle.toString().toLowerCase(); } catch (e) { return; }
            if (want[h]) {
                const methods = [];
                try { for (const m of k.methods) methods.push((m.isStatic ? 'S ' : 'I ') + m.name + '(' + m.parameterCount + ')->' + m.returnType.name); } catch (e) {}
                const fields = [];
                try { for (const f of k.fields) fields.push(f.name + ':' + f.type.name); } catch (e) {}
                out[h] = { full: path + '/' + k.name, methods: methods, fields: fields };
            }
            if (depth > 0) { try { for (const n of k.nestedClasses) walk(n, path + '/' + k.name, depth - 1); } catch (e) {} }
        };
        for (const asm of Il2Cpp.domain.assemblies) {
            let img; try { img = asm.image; } catch (e) { continue; }
            for (const k of img.classes) walk(k, asm.name, 1);
        }
        return out;
    });
};
