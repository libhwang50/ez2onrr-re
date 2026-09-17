/* In-process HTTP GET via WinHTTP (same stack the game uses).
 * Read-only: resolves exports from the module object, no code patched.
 *
 * Notes:
 *  - The game defines its own global `Module`, shadowing Frida's. Use
 *    Process.getModuleByName / Process.enumerateModules + module.getExportByName.
 *  - Wine's WINHTTP.dll exports are Pascal-case (WinHttpOpen, not winhttp_open).
 *  - Resolve the module lazily (inside the function): top-level
 *    Array.prototype.find is unreliable under the game's shadowed globals.
 *  - Send step logs via send() so the host can see exactly where a request stalls.
 */
if (typeof rpc.exports === "undefined") rpc.exports = {};

var WINHTTP_ACCESS_TYPE_NO_PROXY = 3;
var WINHTTP_SERVICE_HTTP = 1;

var _WH = null;
function getWh() {
    var arr = Process.enumerateModules();
    for (var i = 0; i < arr.length; i++) {
        if (arr[i] && arr[i].name === "WINHTTP.dll") return arr[i];
    }
    throw new Error("WINHTTP.dll not loaded");
}
function ex(name) { if (!_WH) _WH = getWh(); return _WH.getExportByName(name); }

rpc.exports.downloadWinHttp = function (url) {
    try {
        send("[wh] start url=" + url.slice(0, 60) + "...");
        var host = url.slice(8).split("/")[0];
        var port = 443;
        var hm = host.match(/:(\d+)$/);
        var hostPort = host;
        if (hm) { port = parseInt(hm[1], 10); hostPort = host.slice(0, host.length - hm[0].length); }
        var pathQuery = url.slice(8 + host.length);
        if (pathQuery.charAt(0) !== "/") pathQuery = "/" + pathQuery;

        var open = new NativeFunction(ex("WinHttpOpen"), "pointer", ["pointer", "int", "pointer", "pointer", "int"]);
        var connect = new NativeFunction(ex("WinHttpConnect"), "pointer", ["pointer", "pointer", "int", "int", "pointer"]);
        var openReq = new NativeFunction(ex("WinHttpOpenRequest"), "pointer", ["pointer", "pointer", "pointer", "pointer", "pointer", "pointer", "int"]);
        var sendReq = new NativeFunction(ex("WinHttpSendRequest"), "bool", ["pointer", "pointer", "uint32", "pointer", "pointer"]);
        var read = new NativeFunction(ex("WinHttpReadData"), "bool", ["pointer", "pointer", "uint32", "pointer"]);
        var queryOption = new NativeFunction(ex("WinHttpQueryOption"), "bool", ["pointer", "int", "pointer", "pointer"]);
        var close = new NativeFunction(ex("WinHttpCloseHandle"), "bool", ["pointer"]);
        var setOpt = new NativeFunction(ex("WinHttpSetOption"), "bool", ["pointer", "int", "pointer", "uint32"]);
        var recvResp = new NativeFunction(ex("WinHttpReceiveResponse"), "bool", ["pointer", "pointer"]);
        var qda = new NativeFunction(ex("WinHttpQueryDataAvailable"), "void", ["pointer", "pointer"]);
        var k32 = Process.enumerateModules().filter(function (x) { return x.name === "kernel32.dll"; })[0];
        var getLastError = new NativeFunction(k32.getExportByName("GetLastError"), "uint32", []);

        var ua = "UnityPlayer/2021.3.16f1 (UnityWebRequest/1.0, libcurl/7.84.0-DEV)";
        var uaPtr = Memory.allocUtf16String(ua);
        var hSession = open(uaPtr, WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
        send("[wh] open hSession=" + (hSession ? hSession.toString() : "null"));
        if (!hSession || hSession.isNull()) return { ok: false, err: "WinHttpOpen failed" };
        var hConnect = connect(hSession, Memory.allocUtf16String(hostPort), port, WINHTTP_SERVICE_HTTP, NULL);
        send("[wh] connect hConnect=" + (hConnect ? hConnect.toString() : "null"));
        if (!hConnect || hConnect.isNull()) { close(hSession); return { ok: false, err: "WinHttpConnect failed" }; }
        var WINHTTP_FLAG_SECURE = 0x00800000;
        var hReq = openReq(hConnect, NULL, Memory.allocUtf16String(pathQuery), NULL, NULL, NULL, WINHTTP_FLAG_SECURE);
        send("[wh] openReq hReq=" + (hReq ? hReq.toString() : "null"));
        if (!hReq || hReq.isNull()) { close(hConnect); close(hSession); return { ok: false, err: "WinHttpOpenRequest failed" }; }

        var uaLen = (ua.length + 1) * 2;
        var uaBuf = Memory.alloc(uaLen);
        Memory.copy(uaBuf, uaPtr, uaLen);
        setOpt(hReq, 6, uaBuf, uaLen); // WINHTTP_OPTION_USER_AGENT
        // Add a couple of common headers some edge servers require before they
        // will respond (otherwise they can hold the connection).
        try {
            var hdrs = Memory.allocUtf16String("Accept: */*\r\nAccept-Encoding: identity\r\n");
            var hdrsLen = ("Accept: */*\r\nAccept-Encoding: identity\r\n".length + 1) * 2;
            setOpt(hReq, 32, hdrs, hdrsLen); // WINHTTP_OPTION_HTTP_HEADERS = 32
        } catch (e) { send("[wh] set headers err: " + e); }
        send("[wh] set UA + headers");

        if (!sendReq(hReq, NULL, 0, NULL, NULL)) {
            var se = getLastError();
            close(hReq); close(hConnect); close(hSession);
            return { ok: false, err: "WinHttpSendRequest failed win32=" + se };
        }
        send("[wh] send OK");

        // Wait for the response to begin being received. Some stacks need this
        // explicitly for the response to be processed before reading.
        try {
            recvResp(hReq, NULL);
            send("[wh] recvResp OK");
        } catch (e) { send("[wh] recvResp err: " + e); }

        // WinHTTP async request: after SendRequest the response arrives later.
        // QueryDataAvailable is non-blocking here (returns 0 while in progress),
        // so poll for data to actually arrive, with a bounded wait. Once a chunk
        // is available we read it and keep polling until the stream ends (n==0).
        var chunks = [];
        var total = 0;
        var tries = 0;
        while (true) {
            var nPtr = Memory.alloc(4);
            qda(hReq, nPtr);
            var n = nPtr.readU32();
            send("[wh] qda n=" + n + " total=" + total + " tries=" + tries);
            if (n > 0) {
                var buf = Memory.alloc(n);
                var gotPtr = Memory.alloc(4);
                if (!read(hReq, buf, n, gotPtr)) { send("[wh] read failed"); break; }
                var got = gotPtr.readU32();
                chunks.push(buf.readByteArray(got));
                total += got;
                tries = 0; // reset inactivity counter on progress
            } else if (++tries > 4000) {
                // ~20s of no data -> treat as stalled
                send("[wh] qda timeout: no data in 20s, status still 0");
                break;
            } else {
                Thread.sleep(5);
            }
        }

        // HTTP status code (WINHTTP_OPTION_STATUS_CODE = 95)
        var status = 0;
        try {
            var codePtr = Memory.alloc(4);
            queryOption(hReq, 95, codePtr, Memory.alloc(4));
            status = codePtr.readU32();
        } catch (e) { send("[wh] status query err: " + e); }
        send("[wh] done status=" + status + " bytes=" + total);

        var bodyBase64 = "";
        if (total > 0) {
            var out = Memory.alloc(total);
            var off = 0;
            for (var i = 0; i < chunks.length; i++) { Memory.copy(out.add(off), chunks[i], chunks[i].length); off += chunks[i].length; }
            bodyBase64 = out.readByteArray(total).toBase64();
        }
        close(hReq); close(hConnect); close(hSession);
        return { ok: true, status: status, bytes: total, bodyBase64: bodyBase64 };
    } catch (e) {
        send("[wh] catch: " + (e && e.stack ? e.stack : e));
        return { ok: false, err: "" + (e && e.stack ? e.stack : e) };
    }
};
