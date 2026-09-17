
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
function dat(a) { try { return a.elements.handle; } catch (e) { return a.handle.add(0x20); } }
rpc.exports.s = function () {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const inst = img.class('InGameCore').field('instance').value;
        const out = { inst: inst ? inst.handle.toString() : null };
        if (!inst) return out;
        try { out.ez_url = inst.field('ez_url').value.content.slice(0,70); } catch (e) {}
        try { out.ezi_url = inst.field('ezi_url').value.content.slice(0,70); } catch (e) {}
        try {
            const bc = inst.field('bundleCryptKey').value;
            if (bc) { const u = new Uint8Array(dat(bc).readByteArray(bc.length)); let h=''; for (let i=0;i<u.length;i++) h+=u[i].toString(16).padStart(2,'0'); out.bundleCryptKey = h; out.bckLen = bc.length; }
        } catch (e) {}
        try {
            const lst = inst.field('patternFileInfo').value;
            const n = lst.method('get_Count',0).invoke();
            out.patternCount = n;
            const items = [];
            for (let i = 0; i < n && i < 4; i++) {
                const e = lst.method('get_Item',1).invoke(i);
                const o = {};
                for (const f of e.class.fields) { try { const v = e.field(f.name).value; o[f.name] = ('' + f.type.name) === 'System.String' ? (v ? v.content : null) : ('' + v); } catch (x) {} }
                items.push(o);
            }
            out.patterns = items;
        } catch (e) { out.patternErr = '' + e; }
        return out;
    });
};
