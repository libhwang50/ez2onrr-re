
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
rpc.exports.sanity = function () {
    return onMain(() => {
        const out = {};
        try {
            const s = Il2Cpp.string('ABCDEFGH');
            out.strObj = s.handle.toString();
            out.strFirstQword = s.handle.readPointer().toString();
            const img = Il2Cpp.domain.assembly("mscorlib").image;
            let sk = null;
            for (const c of img.classes) if (c.name === 'String') { sk = c; break; }
            out.stringClass = sk ? sk.handle.toString() : null;
            out.match = sk ? s.handle.readPointer().equals(sk.handle) : null;
        } catch (e) { out.err = '' + e; }
        return out;
    });
};
rpc.exports.map = function () {
    return onMain(() => {
        const m = {};
        const walk = (k, p, d) => {
            try { m[k.handle.toString().toLowerCase()] = p + '/' + k.name; } catch (e) {}
            if (d > 0) { try { for (const n of k.nestedClasses) walk(n, p + '/' + k.name, d - 1); } catch (e) {} }
        };
        for (const a of Il2Cpp.domain.assemblies) { let i; try { i = a.image; } catch (e) { continue; } for (const k of i.classes) walk(k, a.name, 1); }
        return m;
    });
};
rpc.exports.scan = function (hexpat) {
    const parts = []; for (let i = 0; i < hexpat.length; i += 2) parts.push(hexpat.substr(i, 2));
    const pat = parts.join(' ');
    const hits = [];
    for (const r of Process.enumerateRanges({ protection: 'r--', coalesce: true })) {
        if (r.size < 512) continue;
        try { for (const x of Memory.scanSync(r.base, r.size, pat)) hits.push(x.address.toString()); } catch (e) {}
    }
    return hits;
};
rpc.exports.clsOf = function (addr) {
    try {
        const obj = ptr(addr).sub(0x20);
        const len = obj.add(0x18).readS32();
        return { obj: obj.toString(), len: len, klass: obj.readPointer().toString() };
    } catch (e) { return { err: '' + e }; }
};
