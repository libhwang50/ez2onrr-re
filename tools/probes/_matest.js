
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
globalThis.__hits = [];
rpc.exports.test = function () {
    return Il2Cpp.perform(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const da = img.class('da');
        const co = da.fields.find(f => f.name === 'rus').value;
        const rjm = co.field('rjm').value;
        let dataPtr; try { dataPtr = rjm.elements.handle; } catch (e) { dataPtr = rjm.handle.add(0x20); }
        const info = { rjmLen: rjm.length, dataPtr: dataPtr.toString() };
        // pick the page containing dataPtr
        const page = dataPtr.and(ptr('0xfffffffffffff000'));
        info.page = page.toString();
        try {
            MemoryAccessMonitor.enable({ base: page, size: 0x1000 }, {
                onAccess(d) {
                    globalThis.__hits.push({ op: d.operation, from: d.from.toString(), addr: d.address.toString() });
                }
            });
            info.armed = true;
        } catch (e) { info.armErr = '' + e; }
        return info;
    });
};
rpc.exports.readIt = function () {
    return Il2Cpp.perform(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const co = img.class('da').fields.find(f => f.name === 'rus').value;
        const rjm = co.field('rjm').value;
        let p; try { p = rjm.elements.handle; } catch (e) { p = rjm.handle.add(0x20); }
        const b = new Uint8Array(p.readByteArray(16));
        let h = ''; for (let i = 0; i < 16; i++) h += b[i].toString(16).padStart(2, '0');
        return { read: h, hits: globalThis.__hits };
    });
};
rpc.exports.hits = function () { return globalThis.__hits; };
