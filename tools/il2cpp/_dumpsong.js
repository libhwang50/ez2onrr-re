
function onMain(fn) { return Il2Cpp.perform(() => Process.runOnThread(Il2Cpp.mainThread.id, () => fn())); }
function dat(a) { try { return a.elements.handle; } catch (e) { return a.handle.add(0x20); } }
function hexOf(a, n) {
    try { const p = dat(a); const u = new Uint8Array(p.readByteArray(Math.min(a.length, n || 32)));
          let h = ''; for (let i = 0; i < u.length; i++) h += u[i].toString(16).padStart(2, '0'); return h; } catch (e) { return null; }
}
rpc.exports.ident = function (withLanes) {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const inst = img.class('InGameCore').field('instance').value;
        const o = { hasInst: !!inst };
        if (!inst) return o;
        try { o.ez_url  = inst.field('ez_url').value  ? inst.field('ez_url').value.content  : null; } catch (e) {}
        try { o.ezi_url = inst.field('ezi_url').value ? inst.field('ezi_url').value.content : null; } catch (e) {}
        try { o.ready = inst.field('ReadyToURL').value; } catch (e) {}
        try { const bc = inst.field('bundleCryptKey').value; o.bundleCryptKey = bc ? hexOf(bc, 64) : null; } catch (e) {}
        try {
            const lst = inst.field('patternFileInfo').value;
            if (lst) {
                const n = lst.method('get_Count', 0).invoke();
                o.patternCount = n;
                const items = [];
                for (let i = 0; i < n && i < 4; i++) {
                    try {
                        const e = lst.method('get_Item', 1).invoke(i);
                        const rec = {};
                        for (const f of e.class.fields) {
                            try { const v = e.field(f.name).value;
                                  rec[f.name] = ('' + f.type.name) === 'System.String' ? (v ? v.content : null) : ('' + v); } catch (x) {}
                        }
                        items.push(rec);
                    } catch (x) {}
                }
                o.patterns = items;
            }
        } catch (e) { o.patternErr = '' + (e && e.message ? e.message : e); }
        // da.rus: the raw downloaded buffers + key
        try {
            const slot = img.class('da').staticFieldsData.add(840);
            const p = slot.readPointer();
            o.daRus = p.isNull() ? null : {};
            if (!p.isNull()) {
                const c = new Il2Cpp.Object(p);
                for (const nm of ['rjl','rjm','rjn']) {
                    try { const a = c.field(nm).value;
                          o.daRus[nm] = a === null ? null : { len: a.length, head: hexOf(a, 32) }; } catch (x) { o.daRus[nm] = 'ERR'; }
                }
            }
        } catch (e) { o.daRusErr = '' + (e && e.message ? e.message : e); }
        const cnt = (o2) => { try { return o2.method('get_Count', 0).invoke(); } catch (e) { return -1; } };
        for (const nm of ['instrumentDic','normalNoteData','longNoteData','bpmNoteData','MeasureScaleData']) {
            try { const v = inst.field(nm).value; o[nm + 'Count'] = v === null ? null : cnt(v); } catch (e) { o[nm + 'Count'] = 'ERR'; }
        }
        // normalLanes is the only invoke-heavy part of this snapshot (one get_Item +
        // get_Count per lane), and it is only needed once, at capture time — so it is
        // opt-in. The watch loop calls ident() with no argument every poll; making this
        // unconditional means invoking list methods several times a second while the
        // player is scrolling the song list and assets are loading.
        if (withLanes) {
            try {
                const nnd = inst.field('normalNoteData').value;
                o.normalLanes = [];
                for (let i = 0; i < (o.normalNoteDataCount || 0); i++) {
                    try { const l = nnd.method('get_Item', 1).invoke(i); o.normalLanes.push(l === null ? -1 : l.method('get_Count', 0).invoke()); } catch (e) {}
                }
            } catch (e) {}
        }
        return o;
    });
};
rpc.exports.daRusFull = function () {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const p = img.class('da').staticFieldsData.add(840).readPointer();
        if (p.isNull()) return null;
        const c = new Il2Cpp.Object(p);
        const o = {};
        for (const nm of ['rjl','rjm','rjn']) {
            try { const a = c.field(nm).value;
                  const u = new Uint8Array(dat(a).readByteArray(a.length));
                  let h = ''; for (let i = 0; i < u.length; i++) h += u[i].toString(16).padStart(2, '0');
                  o[nm] = h; } catch (e) { o[nm] = null; }
        }
        return o;
    });
};
rpc.exports.instrumentDic = function () {
    return onMain(() => {
        const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        const inst = img.class('InGameCore').field('instance').value;
        const d = inst.field('instrumentDic').value;
        const n = d.method('get_Count', 0).invoke();
        const out = [];
        const keys = d.method('get_Keys', 0).invoke();
        const vit = keys.method('GetEnumerator', 0).invoke();
        for (let i = 0; i < n; i++) {
            if (!vit.method('MoveNext', 0).invoke()) break;
            try {
                const k = vit.method('get_Current', 0).invoke();
                const v = d.method('get_Item', 1).invoke(k);
                const key = ('' + k).match(/-?\d+/) ? parseInt(('' + k).match(/-?\d+/)[0], 10) : i;
                out.push([key, v ? v.content : null]);
            } catch (e) { }
        }
        return out;
    });
};
