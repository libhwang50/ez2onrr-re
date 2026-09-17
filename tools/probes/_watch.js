
globalThis.__log = [];
globalThis.__armed = null;
globalThis.__last = null;

function L(obj) { obj.t = Date.now(); globalThis.__log.push(obj); send(obj); }
function dataPtr(a) { try { return a.elements.handle; } catch (e) { return a.handle.add(0x20); } }
function hexhead(a, n) {
    try { const p = dataPtr(a); const u = new Uint8Array(p.readByteArray(Math.min(n, a.length))); let h = ''; for (let i = 0; i < u.length; i++) h += u[i].toString(16).padStart(2, '0'); return h; } catch (e) { return 'ERR'; }
}
function snap() {
    const da = Il2Cpp.domain.assembly("Assembly-CSharp").image.class('da');
    const slot = da.staticFieldsData.add(840);
    const coptr = slot.readPointer();
    const out = { co: coptr.toString(), slot: slot.toString() };
    if (!coptr.isNull()) {
        const co = new Il2Cpp.Object(coptr);
        for (const nm of ['rjl', 'rjm', 'rjn']) {
            try { const a = co.field(nm).value; out[nm] = { len: a.length, ptr: dataPtr(a).toString(), head: hexhead(a, 16) }; } catch (e) { out[nm] = 'ERR'; }
        }
    }
    return out;
}
function arm(extra) {
    const ranges = [];
    ranges.push({ base: ptr(globalThis.__armed.slot), size: 0x1000 });
    for (const nm of ['rjl', 'rjm', 'rjn']) {
        const f = globalThis.__armed[nm];
        if (!f || typeof f !== 'object') continue;
        const st = ptr(f.ptr).and(ptr('0xfffffffffffff000'));
        const end = ptr(f.ptr).add(f.len).and(ptr('0xfffffffffffff000'));
        for (let p = st; p.compare(end) <= 0; p = p.add(0x1000)) ranges.push({ base: p, size: 0x1000 });
    }
    try { MemoryAccessMonitor.disable(); } catch (e) {}
    try {
        MemoryAccessMonitor.enable(ranges, {
            onAccess(d) { L({ tag: 'ACC', op: d.operation, from: d.from.toString(), addr: d.address.toString(), idx: d.rangeIndex }); }
        });
        L({ tag: 'armed', ranges: ranges.length });
    } catch (e) { L({ tag: 'armErr', err: '' + e }); }
}
rpc.exports.arm = function () {
    return Il2Cpp.perform(() => {
        const s = snap();
        globalThis.__armed = s;
        globalThis.__last = JSON.stringify({ co: s.co, a: s.rjl && s.rjl.head, b: s.rjm && s.rjm.head, c: s.rjn && s.rjn.head });
        L({ tag: 'initial', state: s });
        arm();
        return s;
    });
};
rpc.exports.poll = function () {
    return Il2Cpp.perform(() => {
        const s = snap();
        const k = JSON.stringify({ co: s.co, a: s.rjl && s.rjl.head, b: s.rjm && s.rjm.head, c: s.rjn && s.rjn.head });
        if (k !== globalThis.__last) {
            globalThis.__last = k;
            L({ tag: 'CHANGE', state: s });
            globalThis.__armed = s;
            arm();
        }
        return s.co;
    });
};
rpc.exports.log = function () { return globalThis.__log; };
