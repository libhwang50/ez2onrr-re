
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
const MARK = 'e25a00ff112233445566778899aabbcc';
function mkArr(hexpat, total) {
    const bc = Il2Cpp.corlib.class("System.Byte");
    const unit = []; for (let i = 0; i < hexpat.length; i += 2) unit.push(parseInt(hexpat.substr(i, 2), 16));
    const a = []; for (let i = 0; i < total; i++) a.push(unit[i % unit.length]);
    return Il2Cpp.array(bc, a);
}
function dat(a) { try { return a.elements.handle; } catch (e) { return a.handle.add(0x20); } }
rpc.exports.install = function () {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const da = img.class('da');
        const slot = da.staticFieldsData.add(840);
        const old = slot.readPointer();
        const saved = [];
        if (!old.isNull()) {
            const oc = new Il2Cpp.Object(old);
            for (const nm of ['rjl','rjm','rjn']) {
                const a = oc.field(nm).value;
                const p = dat(a); const u = new Uint8Array(p.readByteArray(a.length));
                let h=''; for (let i=0;i<u.length;i++) h+=u[i].toString(16).padStart(2,'0');
                saved.push(h);
            }
        }
        const coCls = da.nestedClasses.find(n => n.name === 'co');
        const a1 = mkArr(MARK, 256), a2 = mkArr(MARK, 256), a3 = mkArr(MARK, 48);
        const obj = coCls.new(a1, a2, a3);
        // write into slot + write barrier
        slot.writePointer(obj.handle);
        return { oldCo: old.toString(), newCo: obj.handle.toString(),
                 a1: dat(a1).toString(), a2: dat(a2).toString(), a3: dat(a3).toString(),
                 savedLens: saved.map(s => s.length/2) };
    });
};
rpc.exports.state = function () {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const slot = img.class('da').staticFieldsData.add(840);
        const p = slot.readPointer();
        const o = { co: p.toString() };
        if (p.isNull()) return o;
        const c = new Il2Cpp.Object(p);
        for (const nm of ['rjl','rjm','rjn']) {
            try {
                const a = c.field(nm).value;
                const u = new Uint8Array(dat(a).readByteArray(16));
                let h=''; for (let i=0;i<u.length;i++) h+=u[i].toString(16).padStart(2,'0');
                o[nm] = { len: a.length, head: h };
            } catch (e) { o[nm] = 'ERR'; }
        }
        return o;
    });
};
rpc.exports.find = function () {
    const hits = [];
    for (const r of Process.enumerateRanges({ protection: 'rw-', coalesce: true })) {
        if (r.size < 64) continue;
        try { for (const m of Memory.scanSync(r.base, r.size, MARK)) hits.push(m.address.toString()); } catch (e) {}
    }
    return hits;
};
