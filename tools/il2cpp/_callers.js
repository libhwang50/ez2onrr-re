// _callers.js — scan the GameAssembly code region for direct call sites (E8/E9 rel32)
// targeting given VAs, and attribute each site to its enclosing method.
// Read-only: no hooks, no writes.  ~100 s for a full sweep.
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }

// Build [{va:Number, name:String}] for every IL2CPP method, sorted by VA.
rpc.exports.symmap = function () {
  return onMain(() => {
    const rows = [];
    for (const asm of Il2Cpp.domain.assemblies) {
      let img; try { img = asm.image; } catch (e) { continue; }
      const walk = (k, depth) => {
        let ms; try { ms = k.methods; } catch (e) { return; }
        for (const m of ms) {
          let va; try { va = m.virtualAddress; } catch (e) { continue; }
          if (va.isNull()) continue;
          const n = Number(va.toString());
          if (n === 0) continue;
          let nm; try { nm = k.name + '.' + m.name; } catch (e) { continue; }
          rows.push({ va: n, name: nm });
        }
        if (depth > 0) { try { for (const nn of k.nestedClasses) walk(nn, depth - 1); } catch (e) {} }
      };
      for (const k of img.classes) walk(k, 1);
    }
    rows.sort((a, b) => a.va - b.va);
    return rows;
  });
};

// Build the symmap internally then scan — avoids shipping 176k rows over JSON.
rpc.exports.all = function (targets) {
  return onMain(() => {
    const rows = [];
    for (const asm of Il2Cpp.domain.assemblies) {
      let img; try { img = asm.image; } catch (e) { continue; }
      const walk = (k, depth) => {
        let ms; try { ms = k.methods; } catch (e) { return; }
        for (const m of ms) {
          let va; try { va = m.virtualAddress; } catch (e) { continue; }
          if (va.isNull()) continue;
          const n = Number(va.toString());
          if (n === 0) continue;
          let nm; try { nm = k.name + '.' + m.name; } catch (e) { continue; }
          rows.push({ va: n, name: nm });
        }
        if (depth > 0) { try { for (const nn of k.nestedClasses) walk(nn, depth - 1); } catch (e) {} }
      };
      for (const k of img.classes) walk(k, 1);
    }
    rows.sort((a, b) => a.va - b.va);
    const res = scanImpl(targets, rows);
    res.methods = rows.length;
    return res;
  });
};

// Scan for direct calls to targets.  attrRows (optional) = sorted symmap for attribution.
rpc.exports.scan = function (targets, attrRows) { return scanImpl(targets, attrRows); };

function scanImpl(targets, attrRows) {
  const m = Process.getModuleByName('GameAssembly.dll');
  const base = Number(m.base.toString());
  const size = m.size;
  const CH = 0x100000;
  const tset = {};
  for (const t of targets) tset[parseInt(t, 16)] = true;

  // attribution table
  let vas = null, names = null;
  if (attrRows && attrRows.length) {
    vas = attrRows.map(r => r.va);
    names = attrRows.map(r => r.name);
  }
  const attribute = (site) => {
    if (!vas) return null;
    let lo = 0, hi = vas.length - 1, best = -1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (vas[mid] <= site) { best = mid; lo = mid + 1; } else { hi = mid - 1; }
    }
    if (best < 0) return null;
    return { name: names[best], va: '0x' + vas[best].toString(16), delta: site - vas[best] };
  };

  const hits = [];
  let scanned = 0, bad = 0;
  for (let off = 0; off < size; off += CH) {
    let buf;
    try { buf = new Uint8Array(ptr(base + off).readByteArray(Math.min(CH, size - off))); }
    catch (e) { bad++; continue; }
    scanned += buf.length;
    for (let i = 0; i + 5 <= buf.length; i++) {
      const op = buf[i];
      if (op !== 0xe8 && op !== 0xe9) continue;
      const rel = (buf[i + 1] | (buf[i + 2] << 8) | (buf[i + 3] << 16) | (buf[i + 4] << 24));
      const site = base + off + i;
      const dest = site + 5 + rel;
      if (tset[dest] !== true) continue;
      hits.push({
        dest: '0x' + dest.toString(16),
        site: '0x' + site.toString(16),
        siteRva: '0x' + (site - base).toString(16),
        op: op === 0xe8 ? 'call' : 'jmp',
        enc: attribute(site)
      });
    }
  }
  return { base: '0x' + base.toString(16), size: size, scanned: scanned, bad: bad, hits: hits };
}
