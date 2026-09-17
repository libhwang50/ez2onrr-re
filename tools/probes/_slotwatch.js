
globalThis.__n = 0;
globalThis.__slot = null;
globalThis.__page = null;
globalThis.__on = false;

rpc.exports.arm = function () {
    return Il2Cpp.perform(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const da = img.class('da');
        const slot = da.staticFieldsData.add(840);
        const page = slot.and(ptr('0xfffffffffffff000'));
        globalThis.__slot = slot.toString().toLowerCase();
        globalThis.__page = page.toString();
        // report current value
        let cur = 'ERR'; try { cur = slot.readPointer().toString(); } catch (e) {}
        MemoryAccessMonitor.enable([{ base: page, size: 0x1000 }], {
            onAccess(d) {
                globalThis.__n++;
                const hit = (d.address.toString().toLowerCase() === globalThis.__slot);
                send({ tag: 'acc', n: globalThis.__n, op: d.operation, from: d.from.toString(), addr: d.address.toString(), hit: hit });
                if (globalThis.__n >= 300) {
                    try { MemoryAccessMonitor.disable(); send({ tag: 'disabled', n: globalThis.__n }); globalThis.__on = false; } catch (e) {}
                }
            }
        });
        globalThis.__on = true;
        return { slot: globalThis.__slot, page: globalThis.__page, current: cur };
    });
};
rpc.exports.state = function () {
    return Il2Cpp.perform(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const da = img.class('da');
        const slot = da.staticFieldsData.add(840);
        let p = null, head = null;
        try { p = slot.readPointer(); } catch (e) { return { err: '' + e }; }
        if (!p.isNull()) {
            try {
                const co = new Il2Cpp.Object(p);
                const a = co.field('rjm').value;
                let dp; try { dp = a.elements.handle; } catch (e) { dp = a.handle.add(0x20); }
                const u = new Uint8Array(dp.readByteArray(16));
                head = ''; for (let i = 0; i < u.length; i++) head += u[i].toString(16).padStart(2, '0');
            } catch (e) { head = 'ERR'; }
        }
        return { co: p.toString(), rjmhead: head, n: globalThis.__n, on: globalThis.__on };
    });
};
