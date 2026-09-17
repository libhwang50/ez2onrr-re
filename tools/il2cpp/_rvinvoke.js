
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
rpc.exports.ri = function (cls, method, hexes, instField) {
    return onMain(() => {
        const out = { tr: [] };
        try {
            const mod = Process.getModuleByName("GameAssembly.dll");
            let addr = null;
            try { addr = mod.getExportByName('il2cpp_runtime_invoke'); } catch (e) { addr = mod.findExportByName('il2cpp_runtime_invoke'); }
            out.tr.push('export=' + addr);
            const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
            const k = img.class(cls);
            let m = null;
            for (const mm of k.methods) if (mm.name === method && mm.parameterCount === hexes.length) { m = mm; break; }
            const mi = m.handle;
            const bc = Il2Cpp.corlib.class("System.Byte");
            const objs = hexes.map(h => { const a = []; for (let i = 0; i < h.length; i += 2) a.push(parseInt(h.substr(i, 2), 16)); return Il2Cpp.array(bc, a); });
            let inst = NULL;
            if (!m.isStatic) { inst = instField ? k.field(instField).value.handle : k.field('instance').value.handle; }
            const args = Memory.alloc(Process.pointerSize * hexes.length);
            for (let i = 0; i < hexes.length; i++) args.add(i * Process.pointerSize).writePointer(objs[i].handle);
            const exc = Memory.alloc(Process.pointerSize);
            exc.writePointer(NULL);
            const fn = new NativeFunction(addr, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);
            const res = fn(mi, inst, args, exc);
            const e = exc.readPointer();
            out.threw = !e.isNull();
            out.exc = e.toString();
            out.res = res.toString();
            if (!e.isNull()) {
                const eo = new Il2Cpp.Object(e);
                try { out.excType = eo.class.name; } catch (x) { out.excType = '?'; }
                try { const msg = eo.method('get_Message', 0).invoke(); out.excMsg = msg === null ? 'NULL' : ('' + msg); } catch (x) { out.excMsg = 'ERR:' + x; }
                try { out.excStr = '' + eo; } catch (x) {}
            }
            return out;
        } catch (e) { out.err = '' + (e && e.message ? e.message : e); return out; }
    });
};
