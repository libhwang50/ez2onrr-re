
globalThis.__n = 0;
globalThis.__slot = null;
globalThis.__page = null;
globalThis.__on = false;
globalThis.__seen = {};

function handler(d) {
    globalThis.__n++;
    const hit = (d.address.toString().toLowerCase() === globalThis.__slot);
    const key = d.from.toString();
    globalThis.__seen[key] = (globalThis.__seen[key] || 0) + 1;
    send({ tag: 'acc', n: globalThis.__n, op: d.operation, from: d.from.toString(), addr: d.address.toString(), hit: hit });
    if (globalThis.__n >= 400) {
        try { MemoryAccessMonitor.disable(); } catch (e) {}
        globalThis.__on = false;
        send({ tag: 'disabled', n: globalThis.__n, seen: globalThis.__seen });
        return;
    }
    // re-arm immediately (page guard is consumed after each fault)
    try {
        MemoryAccessMonitor.disable();
        MemoryAccessMonitor.enable({ base: globalThis.__page, size: 0x1000 }, { onAccess: handler });
    } catch (e) { send({ tag: 'rearmErr', err: '' + e }); }
}
rpc.exports.arm = function () {
    return Il2Cpp.perform(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const da = img.class('da');
        const slot = da.staticFieldsData.add(840);
        const page = slot.and(ptr('0xfffffffffffff000'));
        globalThis.__slot = slot.toString().toLowerCase();
        globalThis.__page = page;
        globalThis.__n = 0;
        let cur = 'ERR'; try { cur = slot.readPointer().toString(); } catch (e) {}
        MemoryAccessMonitor.enable({ base: page, size: 0x1000 }, { onAccess: handler });
        globalThis.__on = true;
        return { slot: globalThis.__slot, page: page.toString(), current: cur };
    });
};
rpc.exports.state = function () {
    return Il2Cpp.perform(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const slot = img.class('da').staticFieldsData.add(840);
        let p = null; try { p = slot.readPointer(); } catch (e) { return { err: '' + e }; }
        return { co: p.toString(), n: globalThis.__n, on: globalThis.__on, seen: globalThis.__seen };
    });
};
