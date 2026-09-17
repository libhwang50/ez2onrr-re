
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
function leBytes(hexstr) {
    let s = hexstr.replace(/^0x/i,''); while (s.length < 16) s = '0' + s;
    const out = []; for (let i = 0; i < 8; i++) out.push(s.substr(16 - 2 - i*2, 2).toLowerCase());
    return out.join(' ');
}
rpc.exports.refs = function (ptrval) {
    const pat = leBytes(ptrval);
    const hits = [];
    for (const r of Process.enumerateRanges({ protection: 'rw-', coalesce: true })) {
        if (r.size < 8) continue;
        try { for (const m of Memory.scanSync(r.base, r.size, pat)) hits.push(m.address.toString()); } catch (e) {}
    }
    return { pattern: pat, hits: hits };
};
// map every static-field slot address -> "Asm/Class.field"
rpc.exports.slots = function () {
    return onMain(() => {
        const m = {};
        const walk = (k, p, d) => {
            try {
                const sfd = k.staticFieldsData;
                if (sfd && !sfd.isNull()) {
                    for (const f of k.fields) {
                        if (!f.isStatic) continue;
                        try { m[sfd.add(f.offset).toString().toLowerCase()] = p + '/' + k.name + '.' + f.name; } catch (e) {}
                    }
                }
            } catch (e) {}
            if (d > 0) { try { for (const n of k.nestedClasses) walk(n, p + '/' + k.name, d - 1); } catch (e) {} }
        };
        for (const a of Il2Cpp.domain.assemblies) { let i; try { i = a.image; } catch (e) { continue; } for (const k of i.classes) walk(k, a.name, 1); }
        return m;
    });
};
