// _mem.js — generic read-only memory helpers + static key-table extraction.
function hex(p, n) {
  const u = new Uint8Array(p.readByteArray(n));
  let h = ''; for (let i = 0; i < u.length; i++) h += u[i].toString(16).padStart(2, '0');
  return h;
}

rpc.exports.ptr = function (addr) {
  return { at: addr, value: ptr(addr).readPointer().toString() };
};

rpc.exports.bytes = function (addr, len) {
  return { at: addr, len: len, hex: hex(ptr(addr), len) };
};

// Read the class name pointed to by a slot (Il2CppClass: name @ +0x10, ns @ +0x18).
rpc.exports.clsname = function (classPtr) {
  const kp = ptr(classPtr);
  const out = { cls: classPtr };
  try { out.name = kp.add(0x10).readPointer().readUtf8String(); } catch (e) { out.nameErr = '' + e; }
  try { out.ns = kp.add(0x18).readPointer().readUtf8String(); } catch (e) { out.nsErr = '' + e; }
  try { out.staticFields = kp.add(0xb8).readPointer().toString(); } catch (e) { out.sfErr = '' + e; }
  return out;
};

// Dump a managed System.Byte[] object (len @ +0x18, data @ +0x20).
rpc.exports.array = function (objPtr, maxLen) {
  const op = ptr(objPtr);
  if (op.isNull()) return { err: 'null' };
  let len; try { len = op.add(0x18).readS32(); } catch (e) { return { err: 'len: ' + e }; }
  const n = Math.min(len, maxLen || 4096);
  const out = { len: len, klass: (() => { try { return op.readPointer().toString(); } catch (e) { return null; } })(), hex: null };
  try { out.hex = hex(op.add(0x20), n); } catch (e) { out.err = 'data: ' + e; }
  return out;
};

// Read a class's static fields at byte offsets and dump any pointer slots that look like arrays.
rpc.exports.statics = function (classPtr, offsets) {
  const kp = ptr(classPtr);
  const sf = kp.add(0xb8).readPointer();
  const out = { staticFields: sf.toString(), slots: {} };
  for (const off of offsets) {
    const slot = sf.add(off);
    let p = null; let pstr = 'null';
    try { p = slot.readPointer(); pstr = p.toString(); } catch (e) { continue; }
    out.slots['0x' + off.toString(16)] = { ptr: pstr };
    if (!p.isNull()) {
      try {
        const a = p;
        const len = a.add(0x18).readS32();
        const n = Math.min(len, 64);
        out.slots['0x' + off.toString(16)].len = len;
        out.slots['0x' + off.toString(16)].head = hex(a.add(0x20), n);
      } catch (e) { out.slots['0x' + off.toString(16)].err = '' + e; }
    }
  }
  return out;
};
