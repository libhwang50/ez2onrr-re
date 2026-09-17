
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
function ptrBytes(h) {
    let s = ('' + h).replace(/^0x/i, '');
    while (s.length < 16) s = '0' + s;
    if (s.length > 16) s = s.slice(s.length - 16);
    const bytes = [];
    for (let i = 0; i < 8; i++) {
        const byteHex = s.substr(s.length - 2 - i * 2, 2);
        bytes.push(byteHex.toLowerCase());
    }
    return bytes.join(' ');
}
rpc.exports.pt = ptrBytes;
rpc.exports.cls = function () {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const out = {};
        for (const c of img.classes) if (['bbl', 'bkm', 'vx', 'vy', 'da'].indexOf(c.name) >= 0) out[c.name] = c.handle.toString();
        return out;
    });
};
rpc.exports.scan = function (klassptr) {
    const pat = ptrBytes(klassptr);
    const hits = [];
    for (const r of Process.enumerateRanges({ protection: 'rw-', coalesce: true })) {
        if (r.size < 16) continue;
        try { for (const m of Memory.scanSync(r.base, r.size, pat)) hits.push(m.address.toString()); } catch (e) {}
    }
    return { pattern: pat, hits: hits };
};
rpc.exports.readObj = function (addr) {
    return onMain(() => {
        try {
            const o = new Il2Cpp.Object(ptr(addr));
            const out = { cls: o.class.name };
            for (const f of o.class.fields) {
                try { const v = o.field(f.name).value; out[f.name] = (f.type.name === 'System.String') ? (v === null ? null : v.content) : ('<' + f.type.name + '>'); } catch (e) { out[f.name] = 'ERR'; }
            }
            return out;
        } catch (e) { return { err: '' + e }; }
    });
};
