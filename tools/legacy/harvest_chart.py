#!/usr/bin/env python3
"""
EZ2ON REBOOT: R - Zero-Hook Chart & Keysound Harvester
Monitors memory via Frida Gadget without modifying code bytes (avoids Anti-Cheat crash).
Captures dynamically delivered .ezi chart and .ez keysound index files upon song load.
"""

import os
import sys
import time
import threading
import signal
import json
import urllib.request
import struct

try:
    import frida
except ImportError:
    print("[!] Error: 'frida' package not found. Run with '.venv/bin/python harvest_chart.py'")
    sys.exit(1)

# Track the live session so a SIGTERM (e.g. `timeout`) can detach cleanly.
# SIGTERM does NOT run Python finally blocks, so without this an agent is left
# resident and wedges the gadget's message loop.
_LIVE_SESSION = None

def _cleanup():
    if _LIVE_SESSION is not None:
        try:
            _LIVE_SESSION.detach()
        except Exception:
            pass

def _on_sigterm(signum, frame):
    _cleanup()
    os._exit(0)
    sys.exit(1)

OUTPUT_DIR = "extracted_charts"

FRIDA_JS_SCRIPT = """
rpc.exports = {
    checkInGameCore: function() {
        const mod = Process.getModuleByName("GameAssembly.dll");
        if (!mod) return { error: "GameAssembly.dll not found" };

        const getExp = (name, ret, args) => new NativeFunction(mod.getExportByName(name), ret, args);

        const il2cpp_domain_get = getExp("il2cpp_domain_get", "pointer", []);
        const il2cpp_domain_get_assemblies = getExp("il2cpp_domain_get_assemblies", "pointer", ["pointer", "pointer"]);
        const il2cpp_assembly_get_image = getExp("il2cpp_assembly_get_image", "pointer", ["pointer"]);
        const il2cpp_image_get_name = getExp("il2cpp_image_get_name", "pointer", ["pointer"]);
        const il2cpp_image_get_class_count = getExp("il2cpp_image_get_class_count", "uint32", ["pointer"]);
        const il2cpp_image_get_class = getExp("il2cpp_image_get_class", "pointer", ["pointer", "uint32"]);
        const il2cpp_class_get_name = getExp("il2cpp_class_get_name", "pointer", ["pointer"]);
        const il2cpp_class_get_fields = getExp("il2cpp_class_get_fields", "pointer", ["pointer", "pointer"]);
        const il2cpp_field_get_name = getExp("il2cpp_field_get_name", "pointer", ["pointer"]);
        const il2cpp_field_get_offset = getExp("il2cpp_field_get_offset", "uint32", ["pointer"]);
        const il2cpp_field_static_get_value = getExp("il2cpp_field_static_get_value", "void", ["pointer", "pointer"]);
        const il2cpp_string_chars = getExp("il2cpp_string_chars", "pointer", ["pointer"]);
        const il2cpp_string_length = getExp("il2cpp_string_length", "int32", ["pointer"]);

        function readIl2CppString(p) {
            if (!p || p.isNull()) return null;
            try {
                const len = il2cpp_string_length(p);
                if (len <= 0 || len > 4096) return null;
                return il2cpp_string_chars(p).readUtf16String(len);
            } catch (e) {
                return null;
            }
        }

        const domain = il2cpp_domain_get();
        const sizePtr = Memory.alloc(8);
        const assemblies = il2cpp_domain_get_assemblies(domain, sizePtr);
        const num = sizePtr.readU64().toNumber();

        for (let i = 0; i < num; i++) {
            const asm = assemblies.add(i * Process.pointerSize).readPointer();
            const img = il2cpp_assembly_get_image(asm);
            if (il2cpp_image_get_name(img).readUtf8String() !== "Assembly-CSharp.dll") continue;

            const classCount = il2cpp_image_get_class_count(img);
            for (let c = 0; c < classCount; c++) {
                const klass = il2cpp_image_get_class(img, c);
                if (klass.isNull()) continue;
                if (il2cpp_class_get_name(klass).readUtf8String() === "InGameCore") {
                    let fiter = Memory.alloc(Process.pointerSize);
                    fiter.writePointer(NULL);
                    let f;
                    let instField = null;
                    let ezUrlOff = 0x820;
                    let eziUrlOff = 0x828;
                    let readyOff = 0x81d;
                    let patternInfoOff = 0x838;

                    while (!(f = il2cpp_class_get_fields(klass, fiter)).isNull()) {
                        const fn = il2cpp_field_get_name(f).readUtf8String();
                        if (fn === "instance") instField = f;
                        else if (fn === "ez_url") ezUrlOff = il2cpp_field_get_offset(f);
                        else if (fn === "ezi_url") eziUrlOff = il2cpp_field_get_offset(f);
                        else if (fn === "ReadyToURL") readyOff = il2cpp_field_get_offset(f);
                        else if (fn === "patternFileInfo") patternInfoOff = il2cpp_field_get_offset(f);
                    }

                    if (!instField) return { error: "InGameCore.instance field not found" };

                    const valPtr = Memory.alloc(Process.pointerSize);
                    il2cpp_field_static_get_value(instField, valPtr);
                    const instObj = valPtr.readPointer();
                    if (instObj.isNull()) return { status: "not_in_game" };

                    const ready = instObj.add(readyOff).readU8() !== 0;
                    const ez_p = instObj.add(ezUrlOff).readPointer();
                    const ezi_p = instObj.add(eziUrlOff).readPointer();

                    const ez_url = readIl2CppString(ez_p);
                    const ezi_url = readIl2CppString(ezi_p);

                    let metadata = [];
                    const pList = instObj.add(patternInfoOff).readPointer();
                    if (!pList.isNull()) {
                        try {
                            const items = pList.add(0x10).readPointer();
                            const count = pList.add(0x18).readS32();
                            for (let idx = 0; idx < Math.min(count, 8); idx++) {
                                const elem = items.add(0x20 + idx * Process.pointerSize).readPointer();
                                if (!elem.isNull()) {
                                    metadata.push({
                                        appid: readIl2CppString(elem.add(0x10).readPointer()),
                                        song: readIl2CppString(elem.add(0x18).readPointer()),
                                        keymode: readIl2CppString(elem.add(0x20).readPointer()),
                                        diff: readIl2CppString(elem.add(0x28).readPointer()),
                                        mode: readIl2CppString(elem.add(0x30).readPointer())
                                    });
                                }
                            }
                        } catch(e) {}
                    }

                    return {
                        status: "active",
                        ready: ready,
                        ez_url: ez_url,
                        ezi_url: ezi_url,
                        metadata: metadata
                    };
                }
            }
        }
        return { error: "InGameCore class not found" };
    },

    scanEzffInHeap: function() {
        const ranges = Process.enumerateRanges({ protection: "---", coalesce: true });
        let results = [];
        for (let i = 0; i < ranges.length; i++) {
            const r = ranges[i];
            if (r.protection.indexOf("r") === -1) continue;
            if (r.size < 4096 || r.size > 64 * 1024 * 1024) continue;
            try {
                const matches = Memory.scanSync(r.base, r.size, "45 5a 46 46");
                for (let j = 0; j < matches.length; j++) {
                    const m = matches[j];
                    const header = m.address.readByteArray(150);
                    results.push({
                        address: m.address.toString(),
                        header: Array.from(new Uint8Array(header))
                    });
                }
            } catch(e) {}
            if (results.length >= 10) break;
        }
        return results;
    }
};
"""

def download_file(url, out_path):
    print(f"[*] Downloading {url} -> {out_path}...")
    headers = {
        "User-Agent": "UnityPlayer/2021.3.16f1 (UnityWebRequest/1.0, libcurl/7.84.0-DEV)",
        "Referer": "https://www.ez2game.co.kr/",
    }
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = resp.read()
    except urllib.error.HTTPError as e:
        # Dump CloudFront diagnostics so we can see why it's denied.
        print(f"[!] HTTP Error {e.code}: {e.reason}")
        try:
            print(f"    Body: {e.read().decode('utf-8', 'ignore').strip()}")
        except Exception:
            pass
        raise
    with open(out_path, "wb") as f:
        f.write(data)
    print(f"[+] Successfully saved {len(data):,} bytes to {out_path}!")
    return data

def validate_ezff(data):
    if len(data) < 150:
        return False, "File too small"
    if data[:4] != b"EZFF":
        return False, f"Invalid magic: {data[:4]}"
    
    name1 = data[6:70].split(b"\x00")[0].decode("latin-1", errors="ignore")
    name2 = data[70:134].split(b"\x00")[0].decode("latin-1", errors="ignore")
    bpm = struct.unpack("<f", data[136:140])[0]
    channels = struct.unpack("<H", data[140:142])[0]
    
    return True, f"Name1: '{name1}', Name2: '{name2}', BPM: {bpm:.1f}, Channels: {channels}"

def _with_timeout(fn, seconds, label="op"):
    """Run a blocking Frida call with a timeout; raise TimeoutError if it hangs."""
    result = {"error": None, "value": None}
    def target():
        try:
            result["value"] = fn()
        except Exception as e:
            result["error"] = e
    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(seconds)
    if t.is_alive():
        raise TimeoutError(f"{label} timed out after {seconds}s (gadget loop wedged?)")
    if result["error"]:
        raise result["error"]
    return result["value"]

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print("=" * 65)
    print("  EZ2ON REBOOT: R - Zero-Hook Chart Harvester")
    print("  Safe mode: No inline hooks. Polling RAM read-only.")
    print("=" * 65)

    print("\n[+] Connecting to Frida Gadget at 127.0.0.1:27042...")
    session = None
    for attempt in range(15):
        try:
            device = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
            session = device.attach("Gadget")
            global _LIVE_SESSION
            _LIVE_SESSION = session
            signal.signal(signal.SIGTERM, _on_sigterm)
            print("[+] Successfully connected to Frida Gadget!")
            break
        except Exception:
            time.sleep(1)

    if not session:
        print("[!] Failed to connect to Frida Gadget. Is EZ2ON running with WINEDLLOVERRIDES=\"version=n,b\"?")
        sys.exit(1)

    # create_script + load block until the agent acks. If the gadget's loop is
    # wedged (e.g. a previous agent wasn't detached cleanly), this hangs forever.
    # Bound it and fail fast with a clear message instead.
    try:
        script = _with_timeout(lambda: session.create_script(FRIDA_JS_SCRIPT), 30.0)
        _with_timeout(script.load, 30.0)
    except TimeoutError:
        print("[!] Timed out loading the Frida agent. The gadget loop appears wedged; "
              "restart EZ2ON and try again.")
        try:
            session.detach()
        except Exception:
            pass
        sys.exit(2)

    print("[*] Monitoring InGameCore for pattern URLs & active songs...")
    print("[*] Launch a song or enter gameplay in EZ2ON...")

    seen_urls = set()
    seen_ezff_addrs = set()

    try:
        while True:
            try:
                res = script.exports_sync.check_in_game_core()
                if res.get("status") == "active":
                    ezi_url = res.get("ezi_url")
                    ez_url = res.get("ez_url")
                    meta = res.get("metadata", [])

                    song_id = "unknown"
                    if meta and len(meta) > 0:
                        song_id = meta[0].get("song") or meta[0].get("appid") or "song"
                        diff = meta[0].get("diff") or ""
                        keymode = meta[0].get("keymode") or ""
                        print(f"\n[+] Active Song Detected: {song_id} ({keymode} {diff})")

                    if ezi_url and ezi_url not in seen_urls:
                        seen_urls.add(ezi_url)
                        print(f"[+] Found ezi_url: {ezi_url}")
                        target_dir = os.path.join(OUTPUT_DIR, song_id)
                        os.makedirs(target_dir, exist_ok=True)
                        filename = os.path.basename(ezi_url.split("?")[0]) or f"{song_id}.ezi"
                        out_path = os.path.join(target_dir, filename)
                        try:
                            chart_bytes = download_file(ezi_url, out_path)
                            valid, info = validate_ezff(chart_bytes)
                            if valid:
                                print(f"    [✔ Valid EZFF] {info}")
                            else:
                                print(f"    [!] Warning: {info}")
                        except Exception as e:
                            print(f"[!] Failed to download .ezi: {e}")

                    if ez_url and ez_url not in seen_urls:
                        seen_urls.add(ez_url)
                        print(f"[+] Found ez_url: {ez_url}")
                        target_dir = os.path.join(OUTPUT_DIR, song_id)
                        os.makedirs(target_dir, exist_ok=True)
                        filename = os.path.basename(ez_url.split("?")[0]) or f"{song_id}.ez"
                        out_path = os.path.join(target_dir, filename)
                        try:
                            download_file(ez_url, out_path)
                        except Exception as e:
                            print(f"[!] Failed to download .ez: {e}")

            except Exception:
                pass

            # Heap scan for EZFF headers
            if not seen_urls:
                try:
                    ezff_matches = script.exports_sync.scan_ezff_in_heap()
                    for m in ezff_matches:
                        addr = m["address"]
                        if addr in seen_ezff_addrs:
                            continue
                        seen_ezff_addrs.add(addr)
                        header = bytes(m["header"])
                        valid, info = validate_ezff(header)
                        if valid:
                            print(f"\n[+] Detected in-memory EZFF chart at {addr}!")
                            print(f"    {info}")
                except Exception:
                    pass

            time.sleep(1.0)

    except KeyboardInterrupt:
        print("\n[+] Harvester stopped by user.")
    finally:
        # Always detach so the Frida agent unloads cleanly. An abrupt client exit
        # (Ctrl+C / SIGTERM) that leaves the agent resident can wedge the gadget's
        # message loop, making the next create_script hang until the game is restarted.
        try:
            session.detach()
        except Exception:
            pass

if __name__ == "__main__":
    main()
