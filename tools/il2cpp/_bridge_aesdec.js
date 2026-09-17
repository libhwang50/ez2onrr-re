
rpc.exports.dec = function (cls, method, argKind, hexArg) {
    return Il2Cpp.perform(() => {
        const res = { cls: cls, method: method, argKind: argKind };
        try {
            const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
            const k = img.class(cls);
            const m = k.method(method, 1);
            res.paramType = (function(){ try { return m.parameters[0].type.name; } catch(e){ return null; } })();
            let arg;
            if (argKind === 'string') {
                let s = '';
                if (hexArg) { for (let i = 0; i < hexArg.length; i += 2) s += String.fromCharCode(parseInt(hexArg.substr(i, 2), 16)); }
                arg = Il2Cpp.string(s);
            } else if (argKind === 'base64') {
                const b64 = (function(hex){ const b = []; for (let i=0;i<hex.length;i+=2) b.push(parseInt(hex.substr(i,2),16)); const u = new Uint8Array(b); let bin=''; for (let i=0;i<u.length;i++) bin+=String.fromCharCode(u[i]); return bin; })(hexArg);
                // encode base64 in JS
                const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
                let out=''; let i=0; const bytes=[]; for (let j=0;j<hexArg.length;j+=2) bytes.push(parseInt(hexArg.substr(j,2),16));
                for (; i+2 < bytes.length; i+=3) { const n=(bytes[i]<<16)|(bytes[i+1]<<8)|bytes[i+2]; out+=chars[(n>>18)&63]+chars[(n>>12)&63]+chars[(n>>6)&63]+chars[n&63]; }
                if (i < bytes.length) { if (i+1<bytes.length){ const n=(bytes[i]<<16)|(bytes[i+1]<<8); out+=chars[(n>>18)&63]+chars[(n>>12)&63]+chars[(n>>6)&63]+'='; } else { const n=bytes[i]<<16; out+=chars[(n>>18)&63]+chars[(n>>12)&63]+'=='; } }
                arg = Il2Cpp.string(out);
            } else {
                res.error = 'unknown argKind'; return res;
            }
            const out = k.method(method, 1).invoke(arg);
            res.out = '' + out;
            return res;
        } catch (e) { res.error = '' + (e && e.message ? e.message : e); return res; }
    });
};
