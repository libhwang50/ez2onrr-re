
rpc.exports.edump = function (addr, n) {
    try {
        const a = ptr(addr);
        const b = a.readByteArray(n);
        const u = new Uint8Array(b);
        const hist = new Array(256).fill(0);
        for (let i = 0; i < u.length; i++) hist[u[i]]++;
        let ent = 0;
        for (let i = 0; i < 256; i++) { if (hist[i]) { const p = hist[i] / u.length; ent -= p * Math.log2(p); } }
        let h = ''; for (let i = 0; i < Math.min(32, u.length); i++) h += u[i].toString(16).padStart(2, '0');
        return { entropy: ent, head: h };
    } catch (e) { return { err: '' + e }; }
};
