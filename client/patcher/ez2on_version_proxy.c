/*
 * ez2on_version_proxy.c — drop-in `version.dll` for EZ2ON REBOOT:R.
 *
 * The game loads `version.dll` from its own directory.  This DLL takes that
 * slot and, on a background thread, rewrites the client's baked-in RSA public
 * key to *ours*.  The client's `c2s_login.data` block is then encrypted to our
 * key, which the private server decrypts (`server/_rsa.py`) to learn the API
 * session key.  No Frida, no hooks, no code patches, no root.
 *
 * There are two copies of the key to deal with:
 *   * the ASCII metadata literal (in a small rw- mapping) — zf converts this
 *     to the managed string and builds its RSACryptoServiceProvider at static
 *     init, so patching only the managed copy is too late (observed live:
 *     the managed string was ours, yet the login block was encrypted to the
 *     original key).  The literal is the one that must be patched *early*.
 *   * the UTF-16 managed string — patch it too, as a fallback.
 *
 * UnityPlayer.dll imports GetFileVersionInfoSizeA/GetFileVersionInfoA/
 * VerQueryValueA from version.dll, so those (and the usual family) are
 * forwarded to the system copy.
 *
 * Build:  bash client/patcher/build.sh
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdio.h>

#include "pubkey_blob.h"   /* EZ2_PUB_MODULUS / _A, EZ2_PUB_EXPONENT / _A */

static HINSTANCE g_self = NULL;
static volatile LONG g_hits = 0;

/* ---------------- tiny log file (next to the DLL) ---------------- */
static void dlog(const char* msg) {
    WCHAR path[MAX_PATH];
    DWORD n = GetModuleFileNameW(g_self, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return;
    WCHAR* slash = wcsrchr(path, L'\\');
    if (!slash) return;
    wcscpy(slash + 1, L"ez2on_patch.log");
    HANDLE h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    char line[256];
    _snprintf(line, sizeof(line), "[pid %lu] %s", (unsigned long)GetCurrentProcessId(), msg);
    DWORD w;
    SetFilePointer(h, 0, NULL, FILE_END);
    WriteFile(h, line, (DWORD)strlen(line), &w, NULL);
    WriteFile(h, "\r\n", 2, &w, NULL);
    CloseHandle(h);
}

/* ---------------- scanning ---------------- */
/* Find an ASCII tag inside a narrow or UTF-16LE buffer.  Returns byte offset
 * (via *out_off) and tag length in units/chars (via *out_len). */
static int find_tag(unsigned char* s, size_t nbytes, int wide,
                    const char* tag, size_t* out_off, size_t* out_len) {
    size_t tl = strlen(tag);
    if (wide) {
        WCHAR w[32];
        if (tl >= 32) return 0;
        for (size_t i = 0; i < tl; i++) w[i] = (WCHAR)(unsigned char)tag[i];
        for (size_t i = 0; i + tl * 2 <= nbytes; i += 2) {
            if (memcmp(s + i, w, tl * 2) == 0) {
                *out_off = i; *out_len = tl; return 1;
            }
        }
    } else {
        for (size_t i = 0; i + tl <= nbytes; i++) {
            if (memcmp(s + i, tag, tl) == 0) {
                *out_off = i; *out_len = tl; return 1;
            }
        }
    }
    return 0;
}

/* Patch one <RSAKeyValue> blob found in the *snapshot* buffer `buf`; `live`
 * points at the same bytes in the real mapping.  `wide` = UTF-16LE.  Returns 1
 * if a value was written.  Reads come from the snapshot and writes go through
 * WriteProcessMemory, so a region that is unmapped under us between the
 * VirtualQuery and the scan can no longer fault the process (that TOCTOU was a
 * real crash: `VERSION.dll+0x194d`, the UTF-16 `cmpb $0x3c,(%rbx)` below). */
static int patch_at(unsigned char* live, unsigned char* buf, size_t avail, int wide) {
    size_t unit = wide ? 2 : 1;
    size_t window = 4096 * unit;                 /* bound false-positive walks */
    if (avail > window) avail = window;

    size_t off, len;
    if (!find_tag(buf, avail, wide, "</RSAKeyValue>", &off, &len))
        return 0;
    size_t n = off + len * unit;                 /* length through close tag */

    const char* opens[2]  = {"<Modulus>", "<Exponent>"};
    const char* closes[2] = {"</Modulus>", "</Exponent>"};
    const void* vals[2] = {
        wide ? (const void*)EZ2_PUB_MODULUS : (const void*)EZ2_PUB_MODULUS_A,
        wide ? (const void*)EZ2_PUB_EXPONENT : (const void*)EZ2_PUB_EXPONENT_A};

    int changed = 0;
    for (int t = 0; t < 2; t++) {
        size_t oo, ol, co, cl;
        if (!find_tag(buf, n, wide, opens[t], &oo, &ol)) continue;
        size_t voff = oo + ol * unit;
        if (!find_tag(buf + voff, n - voff, wide, closes[t], &co, &cl)) continue;
        size_t oldlen = co / unit;               /* characters */
        size_t newlen = wide ? wcslen((const WCHAR*)vals[t])
                             : strlen((const char*)vals[t]);
        if (oldlen != newlen) continue;
        size_t bytes = newlen * unit;
        if (memcmp(buf + voff, vals[t], bytes) == 0) continue;   /* already ours */
        SIZE_T wrote = 0;
        if (WriteProcessMemory(GetCurrentProcess(), live + voff, vals[t], bytes, &wrote)
                && wrote == bytes)
            changed = 1;
    }
    return changed;
}

/* Scan one snapshot `buf` (matching the live mapping at `live`). */
static int scan_buffer(unsigned char* live, unsigned char* buf, size_t size) {
    static const char NEED_A[] = "<RSAKeyValue>";
    static const WCHAR NEED_W[] = L"<RSAKeyValue>";
    const size_t nl = sizeof(NEED_A) - 1;   /* 13 chars, no NUL */
    int changed = 0;

    /* ASCII literal (any alignment) */
    for (size_t i = 0; i + nl <= size; ) {
        const unsigned char* p = (const unsigned char*)memchr(buf + i, '<', size - i - nl + 1);
        if (!p) break;
        size_t at = (size_t)(p - buf);
        if (memcmp(buf + at, NEED_A, nl) == 0 && patch_at(live + at, buf + at, size - at, 0))
            changed = 1;
        i = at + 1;
    }
    /* UTF-16LE managed string (2-byte aligned) */
    for (size_t i = 0; i + nl * 2 <= size; i += 2) {
        if (buf[i] != '<' || buf[i + 1] != 0) continue;
        if (memcmp(buf + i, NEED_W, nl * 2) == 0 && patch_at(live + i, buf + i, size - i, 1))
            changed = 1;
    }
    return changed;
}

#define SCAN_CHUNK   (8u * 1024 * 1024)
#define SCAN_OVERLAP 16384u

static int patch_once(void) {
    static unsigned char* chunk = NULL;
    MEMORY_BASIC_INFORMATION mbi;
    unsigned char* addr = NULL;
    int found = 0;
    if (!chunk) chunk = (unsigned char*)malloc(SCAN_CHUNK);
    if (!chunk) return 0;

    while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        int writable = (mbi.State == MEM_COMMIT) &&
                       (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY |
                                       PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) &&
                       !(mbi.Protect & PAGE_GUARD) && !(mbi.Protect & PAGE_NOACCESS);
        if (writable && mbi.RegionSize > 0) {
            unsigned char* base = (unsigned char*)mbi.BaseAddress;
            size_t reg = (size_t)mbi.RegionSize, off = 0;
            while (off < reg) {
                size_t want = reg - off;
                size_t copy = want > SCAN_CHUNK ? SCAN_CHUNK : want;
                SIZE_T got = 0;
                if (ReadProcessMemory(GetCurrentProcess(), base + off, chunk, copy, &got)
                        && got > 0) {
                    if (scan_buffer(base + off, chunk, (size_t)got))
                        found = 1;
                }
                if (copy <= SCAN_OVERLAP) break;
                off += copy - SCAN_OVERLAP;
            }
        }
        unsigned char* next = (unsigned char*)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }
    return found;
}

static DWORD WINAPI patch_thread(LPVOID arg) {
    (void)arg;
    dlog("patcher thread started");
    /* The literal appears once GameAssembly's metadata is mapped, before zf's
     * static ctor builds the RSACryptoServiceProvider, so poll early.  Reads
     * are snapshot-based, so a region being unmapped under us cannot fault the
     * process - the old in-place scan could.  Stop 3 s after the last patch. */
    int patched = 0;
    DWORD start = GetTickCount(), last = start;
    dlog(patch_once() ? "first pass: patched" : "first pass: nothing yet");
    while (GetTickCount() - start < 60000) {
        if (patch_once()) {
            patched++;
            last = GetTickCount();
            if (patched <= 4) {
                char b[64];
                _snprintf(b, sizeof(b), "patched key copy #%d", patched);
                dlog(b);
            }
        }
        if (patched && GetTickCount() - last > 3000) break;
        Sleep(250);
    }
    dlog(patched ? "poller exiting (key rewritten)"
                 : "gave up: no <RSAKeyValue> found");
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE self, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        g_self = self;
        DisableThreadLibraryCalls(self);
        dlog("version.dll proxy attached");
        HANDLE t = CreateThread(NULL, 0, patch_thread, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
    return TRUE;
}

/* ---------------- real version.dll forwarding ---------------- */
static HMODULE real_version(void) {
    static HMODULE h = NULL;
    if (!h) {
        WCHAR sys[MAX_PATH];
        UINT n = GetSystemDirectoryW(sys, MAX_PATH);
        if (n == 0 || n + 16 >= MAX_PATH) return NULL;
        wcscat(sys, L"\\version.dll");
        h = LoadLibraryW(sys);
    }
    return h;
}

#define FORWARD(ret, name, args, callargs)                        \
    typedef ret (WINAPI *pfn_##name) args;                        \
    __declspec(dllexport) ret WINAPI name args {                  \
        HMODULE h = real_version();                               \
        if (!h) return (ret)0;                                    \
        pfn_##name f = (pfn_##name)GetProcAddress(h, #name);      \
        return f ? f callargs : (ret)0;                           \
    }

FORWARD(BOOL, GetFileVersionInfoA, (LPCSTR a, DWORD b, DWORD c, LPVOID d), (a,b,c,d))
FORWARD(BOOL, GetFileVersionInfoW, (LPCWSTR a, DWORD b, DWORD c, LPVOID d), (a,b,c,d))
FORWARD(DWORD, GetFileVersionInfoSizeA, (LPCSTR a, LPDWORD b), (a,b))
FORWARD(DWORD, GetFileVersionInfoSizeW, (LPCWSTR a, LPDWORD b), (a,b))
FORWARD(BOOL, GetFileVersionInfoExA, (DWORD a, LPCSTR b, DWORD c, DWORD d, LPVOID e), (a,b,c,d,e))
FORWARD(BOOL, GetFileVersionInfoExW, (DWORD a, LPCWSTR b, DWORD c, DWORD d, LPVOID e), (a,b,c,d,e))
FORWARD(DWORD, GetFileVersionInfoSizeExA, (DWORD a, LPCSTR b, LPDWORD c), (a,b,c))
FORWARD(DWORD, GetFileVersionInfoSizeExW, (DWORD a, LPCWSTR b, LPDWORD c), (a,b,c))
FORWARD(BOOL, VerQueryValueA, (LPCVOID a, LPCSTR b, LPVOID* c, PUINT d), (a,b,c,d))
FORWARD(BOOL, VerQueryValueW, (LPCVOID a, LPCWSTR b, LPVOID* c, PUINT d), (a,b,c,d))
FORWARD(DWORD, VerLanguageNameA, (DWORD a, LPSTR b, DWORD c), (a,b,c))
FORWARD(DWORD, VerLanguageNameW, (DWORD a, LPWSTR b, DWORD c), (a,b,c))
