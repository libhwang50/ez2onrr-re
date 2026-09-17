// _musicdic.js — read da.MUSIC_NAME_DIC (music id -> name) and related runtime state.
// Read-only.
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }

function dicEntries(d, limit) {
  const out = [];
  const n = d.method('get_Count', 0).invoke();
  const keys = d.method('get_Keys', 0).invoke();
  const it = keys.method('GetEnumerator', 0).invoke();
  for (let i = 0; i < n && out.length < (limit || 20000); i++) {
    if (!it.method('MoveNext', 0).invoke()) break;
    try {
      const k = it.method('get_Current', 0).invoke();
      const v = d.method('get_Item', 1).invoke(k);
      let kn, vn;
      try { kn = parseInt(('' + k).match(/-?\d+/)[0], 10); } catch (e) { kn = -1; }
      try { vn = v === null ? null : v.content; } catch (e) { vn = '' + v; }
      out.push([kn, vn]);
    } catch (e) { out.push([-1, 'ERR:' + e]); }
  }
  return out;
}

rpc.exports.musicdic = function (needle, limit) {
  return onMain(() => {
    const img = Il2Cpp.domain.assembly('Assembly-CSharp').image;
    const daStatics = img.class('da').staticFieldsData;
    const d = new Il2Cpp.Object(daStatics.add(0x350).readPointer());
    const all = dicEntries(d, limit || 20000);
    const low = (needle || '').toLowerCase();
    const hits = low ? all.filter(r => (r[1] || '').toLowerCase().indexOf(low) >= 0) : all;
    return { count: all.length, hits: hits.slice(0, 100) };
  });
};

// Dump a class's fields, searching nested classes too.
rpc.exports.clsfields = function (asmName, className) {
  return onMain(() => {
    const img = Il2Cpp.domain.assembly(asmName).image;
    let found = null;
    const walk = (k) => {
      if (found) return;
      if (k.name === className) { found = k; return; }
      let ns = null; try { ns = k.nestedClasses; } catch (e) { return; }
      for (const n of ns) walk(n);
    };
    for (const k of img.classes) { walk(k); if (found) break; }
    if (!found) return { err: 'not found' };
    return { klass: found.handle.toString(), name: found.name,
             fields: found.fields.map(f => ({ name: f.name, off: f.offset, type: '' + f.type.name })) };
  });
};

// Dump MUSIC_NAME_DIC entries as {key, <field>: value} using the value class's fields.
rpc.exports.musicdata = function (needle, limit) {
  return onMain(() => {
    const img = Il2Cpp.domain.assembly('Assembly-CSharp').image;
    const d = new Il2Cpp.Object(img.class('da').staticFieldsData.add(0x350).readPointer());
    const n = d.method('get_Count', 0).invoke();
    const keys = d.method('get_Keys', 0).invoke();
    const it = keys.method('GetEnumerator', 0).invoke();
    const low = (needle || '').toLowerCase();
    const out = [];
    for (let i = 0; i < n && out.length < (limit || 30000); i++) {
      if (!it.method('MoveNext', 0).invoke()) break;
      let key, val; try {
        key = it.method('get_Current', 0).invoke();
        val = d.method('get_Item', 1).invoke(key);
      } catch (e) { continue; }
      const rec = { key: '' + key };
      try {
        for (const f of val.class.fields) {
          try {
            const v = val.field(f.name).value;
            rec[f.name] = ('' + f.type.name) === 'System.String' ? (v ? v.content : null) : ('' + v);
          } catch (e) { rec[f.name] = 'ERR'; }
        }
      } catch (e) { rec.err = '' + e; }
      const blob = JSON.stringify(rec).toLowerCase();
      if (!low || blob.indexOf(low) >= 0) out.push(rec);
    }
    return { count: n, hits: out.slice(0, 100) };
  });
};
rpc.exports.state = function (needle) {
  return onMain(() => {
    const img = Il2Cpp.domain.assembly('Assembly-CSharp').image;
    const low = (needle || '').toLowerCase();
    const out = [];
    const check = (label, obj) => {
      if (!obj) return;
      for (const f of obj.class.fields) {
        try {
          const v = obj.field(f.name).value;
          if (v === null || v === undefined) continue;
          let s = null;
          try { if ('' + f.type.name === 'System.String') s = v.content; } catch (e) {}
          if (s === null) { try { const t = '' + v; if (t && t.indexOf('Rebind') >= 0) s = t; } catch (e) {} }
          if (s && s.toLowerCase().indexOf(low) >= 0) {
            out.push({ where: label, field: f.name, type: '' + f.type.name, value: String(s).slice(0, 120) });
          }
        } catch (e) {}
      }
    };
    check('da', img.class('da').field('instance').value);
    check('InGameCore', img.class('InGameCore').field('instance').value);
    return out;
  });
};

// Integer-valued instance fields, optionally filtered to values in `want`.
rpc.exports.ints = function (asmName, clsName, want) {
  return onMain(() => {
    const img = Il2Cpp.domain.assembly(asmName).image;
    let k = null; for (const c of img.classes) if (c.name === clsName) { k = c; break; }
    if (!k) return { err: 'no class' };
    const inst = k.field('instance').value;
    if (!inst) return { err: 'no instance' };
    const w = (want || []).map(Number);
    const out = [];
    for (const f of inst.class.fields) {
      const t = '' + f.type.name;
      if (['System.Int32','System.UInt32','System.Int16','System.Int64','System.Single'].indexOf(t) < 0) continue;
      let v; try { v = inst.field(f.name).value; } catch (e) { continue; }
      const rec = { field: f.name, type: t, value: '' + v };
      if (w.length && w.indexOf(Number('' + v)) >= 0) out.push(rec);
      else if (!w.length) out.push(rec);
    }
    return { n: out.length, fields: out };
  });
};

// Static System.String fields of a class.
rpc.exports.strstatics = function (asmName, clsName) {
  return onMain(() => {
    const img = Il2Cpp.domain.assembly(asmName).image;
    let k = null; for (const c of img.classes) if (c.name === clsName) { k = c; break; }
    if (!k) return { err: 'no class' };
    const out = [];
    for (const f of k.fields) {
      if (!f.isStatic || ('' + f.type.name) !== 'System.String') continue;
      try { const v = f.value; out.push({ field: f.name, value: v ? v.content : null }); }
      catch (e) { out.push({ field: f.name, err: '' + e }); }
    }
    return out;
  });
};
