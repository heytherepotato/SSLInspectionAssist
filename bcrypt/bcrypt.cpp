// bcrypt.cpp : CA bundle patch + connect hook + bcrypt proxy DLL.
//
// Workflow:
//   1. Drop bcrypt.dll next to an app that searches for it in its own folder.
//   2. First run: no bcrypt_hook.cfg, or BundleMarkerRVA=0 => DISCOVERY mode.
//      The DLL waits for an outbound connect, scans the process image for the
//      Mozilla CA bundle marker, and logs every discovered RVA to the log file.
//   3. Close the app. Open the log, find "DISCOVERY: marker at RVA 0x..."
//   4. Create bcrypt_hook.cfg next to the DLL:
//          BundleMarkerRVA=0x<value from log>
//   5. Run again: PATCH mode -- direct probe at the known RVA, no scan.
//

#include "pch.h"
#include "MinHook.h"
#include <psapi.h>
#include <atomic>
#include <intrin.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <sstream>
#include <iomanip>

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
static const size_t LOG_BUF = 1024;

#define RING_CAP  4096
#define RING_MASK (RING_CAP - 1)
#define RING_TEXT 1024

// ---------------------------------------------------------------------------
// Ring log (SPSC, non-blocking producer)
// ---------------------------------------------------------------------------
struct LogRecord {
    uint64_t rdtsc;
    DWORD    tid;
    uint32_t pad;
    char     text[RING_TEXT];
};

static alignas(64) LogRecord g_ring[RING_CAP];
static std::atomic<uint64_t> g_wCursor{ 0 };
static std::atomic<uint64_t> g_rCursor{ 0 };
static std::atomic<uint32_t> g_dropped{ 0 };

static void RingLog(const char* text) {
    uint64_t tail = g_wCursor.fetch_add(1, std::memory_order_relaxed);
    if (tail - g_rCursor.load(std::memory_order_acquire) >= RING_CAP) {
        g_dropped.fetch_add(1, std::memory_order_relaxed);
        g_wCursor.store(tail, std::memory_order_relaxed);
        return;
    }
    LogRecord* r = &g_ring[tail & RING_MASK];
    r->rdtsc = __rdtsc();
    r->tid   = GetCurrentThreadId();
    r->pad   = 0;
    size_t len = strlen(text);
    if (len >= RING_TEXT) len = RING_TEXT - 1;
    memcpy(r->text, text, len);
    r->text[len] = '\0';
}

// ---------------------------------------------------------------------------
// State globals
// ---------------------------------------------------------------------------
static HMODULE   g_hSelf        = nullptr;   // our DLL handle (from DllMain)
static HMODULE   g_hRealBcrypt  = nullptr;   // C:\Windows\System32\bcrypt.dll
static char      g_dllDir[MAX_PATH] = {};    // directory containing our DLL (no trailing slash)
static char      g_exeName[MAX_PATH] = {};
static uintptr_t g_baseAddress  = 0;         // host exe image base
static size_t    g_bundleMarkerRva = 0;       // 0 = discovery mode

// ---------------------------------------------------------------------------
// Ring-log consumer thread
// ---------------------------------------------------------------------------
static DWORD WINAPI RingLogConsumerThread(LPVOID) {
    // Create logs sub-folder next to the DLL.
    char logsDir[MAX_PATH];
    sprintf_s(logsDir, sizeof(logsDir), "%s\\logs", g_dllDir);
    CreateDirectoryA(logsDir, NULL);

    char path[MAX_PATH];
    SYSTEMTIME st;
    GetLocalTime(&st);
    sprintf_s(path, sizeof(path),
        "%s\\ring_%04d%02d%02d_%02d%02d%02d_%lu.log",
        logsDir, st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond, GetCurrentProcessId());

    HANDLE hF = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ,
                            NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hF == INVALID_HANDLE_VALUE) return 0;

    while (true) {
        uint64_t head = g_rCursor.load(std::memory_order_acquire);
        uint64_t tail = g_wCursor.load(std::memory_order_acquire);
        if (head == tail) { Sleep(10); continue; }
        while (head < tail) {
            const LogRecord* rec = &g_ring[head & RING_MASK];
            SYSTEMTIME s2; GetLocalTime(&s2);
            char line[RING_TEXT + 128];
            _snprintf_s(line, sizeof(line), _TRUNCATE,
                "[%04d-%02d-%02d %02d:%02d:%02d.%03d] [%lu] [tid=%lu] %s\n",
                s2.wYear, s2.wMonth, s2.wDay,
                s2.wHour, s2.wMinute, s2.wSecond, s2.wMilliseconds,
                GetCurrentProcessId(), (unsigned long)rec->tid, rec->text);
            DWORD w = 0;
            WriteFile(hF, line, (DWORD)strlen(line), &w, NULL);
            head++;
        }
        g_rCursor.store(head, std::memory_order_release);
        uint32_t drop = g_dropped.load(std::memory_order_acquire);
        if (drop) {
            char msg[128];
            sprintf_s(msg, sizeof(msg), "[ringlog] dropped %u\n", drop);
            DWORD w = 0; WriteFile(hF, msg, (DWORD)strlen(msg), &w, NULL);
            g_dropped.store(0, std::memory_order_release);
        }
    }
    CloseHandle(hF);
    return 0;
}

// ---------------------------------------------------------------------------
// Config reader  -- bcrypt_hook.cfg next to the DLL
// ---------------------------------------------------------------------------
// Supported keys:
//   BundleMarkerRVA=0x<hex>   RVA of "## Certificate data from Mozilla"
//                             Set to 0 (or omit) for discovery/scan mode.
//
static void LoadConfig() {
    char cfgPath[MAX_PATH];
    sprintf_s(cfgPath, sizeof(cfgPath), "%s\\bcrypt_hook.cfg", g_dllDir);

    HANDLE hF = CreateFileA(cfgPath, GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hF == INVALID_HANDLE_VALUE) {
        RingLog("[config] bcrypt_hook.cfg not found -- running in discovery mode");
        return;
    }

    char buf[4096] = {};
    DWORD read = 0;
    ReadFile(hF, buf, sizeof(buf) - 1, &read, NULL);
    CloseHandle(hF);

    // Parse line by line.
    char* ctx = nullptr;
    char* line = strtok_s(buf, "\r\n", &ctx);
    while (line) {
        // Skip comments and blanks.
        while (*line == ' ' || *line == '\t') ++line;
        if (*line == '#' || *line == ';' || *line == '\0') {
            line = strtok_s(NULL, "\r\n", &ctx);
            continue;
        }
        char key[128] = {}, val[256] = {};
        if (sscanf_s(line, " %127[^=] = %255[^\r\n]", key, (unsigned)sizeof(key), val, (unsigned)sizeof(val)) == 2) {
            // Trim trailing whitespace from key and val.
            for (int i = (int)strlen(key) - 1; i >= 0 && (key[i] == ' ' || key[i] == '\t'); --i) key[i] = '\0';
            for (int i = (int)strlen(val) - 1; i >= 0 && (val[i] == ' ' || val[i] == '\t'); --i) val[i] = '\0';

            if (_stricmp(key, "BundleMarkerRVA") == 0) {
                g_bundleMarkerRva = (size_t)strtoull(val, nullptr, 0);
                char msg[LOG_BUF];
                sprintf_s(msg, sizeof(msg),
                    "[config] BundleMarkerRVA=0x%zx (%s mode)",
                    g_bundleMarkerRva,
                    g_bundleMarkerRva ? "fast patch" : "discovery");
                RingLog(msg);
            }
        }
        line = strtok_s(NULL, "\r\n", &ctx);
    }
}

// ---------------------------------------------------------------------------
// IsReadablePage -- VirtualQuery-based, never generates a first-chance AV
// ---------------------------------------------------------------------------
static bool IsReadablePage(const void* addr, SIZE_T need = 1) {
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(addr, &mbi, sizeof(mbi)) != sizeof(mbi)) return false;
    if (mbi.State != MEM_COMMIT) return false;
    DWORD p = mbi.Protect & 0xFF;
    if (p == PAGE_NOACCESS || p == PAGE_EXECUTE) return false;
    if (mbi.Protect & (PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE)) return false;
    uintptr_t end = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    return (reinterpret_cast<uintptr_t>(addr) + need) <= end;
}

// ---------------------------------------------------------------------------
// FastMarkerProbe -- O(1) check at known RVA
// ---------------------------------------------------------------------------
static const unsigned char* FastMarkerProbe() {
    if (!g_baseAddress || !g_bundleMarkerRva) return nullptr;
    static const char* TAG = "## Certificate data from Mozilla";
    const auto* p = reinterpret_cast<const unsigned char*>(g_baseAddress + g_bundleMarkerRva);
    if (!IsReadablePage(p, 32)) return nullptr;
    if (memcmp(p, TAG, 32) == 0) return p;
    return nullptr;
}

// ---------------------------------------------------------------------------
// PatchCABundle
// ---------------------------------------------------------------------------
static volatile LONG g_patched = 0;

static void PatchCABundle() {
    if (g_patched) return;
    if (!g_baseAddress) { RingLog("[bundle] skipped: base=0"); return; }

    const bool fast = (g_bundleMarkerRva != 0);
    if (fast) {
        if (!FastMarkerProbe()) return;
        RingLog("[bundle] fast probe hit -- attempting patch");
    } else {
        RingLog("[bundle] scanning image (discovery mode)");
    }

    char certPath[MAX_PATH];
    sprintf_s(certPath, sizeof(certPath), "%s\\ca-cert.pem", g_dllDir);
    HANDLE hF = CreateFileA(certPath, GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hF == INVALID_HANDLE_VALUE) {
        char msg[LOG_BUF];
        sprintf_s(msg, sizeof(msg), "[bundle] cert not found: %s (err=%lu)", certPath, GetLastError());
        RingLog(msg);
        return;
    }
    char certBuf[4096] = {};
    DWORD certLen = 0;
    ReadFile(hF, certBuf, sizeof(certBuf) - 1, &certLen, NULL);
    CloseHandle(hF);
    if (certLen < 100 || certLen > 4000) {
        char msg[LOG_BUF];
        sprintf_s(msg, sizeof(msg), "[bundle] cert size suspicious: %lu", certLen);
        RingLog(msg); return;
    }

    // Get image extents.
    MODULEINFO mi = {};
    if (!GetModuleInformation(GetCurrentProcess(),
            reinterpret_cast<HMODULE>(g_baseAddress), &mi, sizeof(mi))) {
        char msg[LOG_BUF];
        sprintf_s(msg, sizeof(msg), "[bundle] GetModuleInformation failed: err=%lu", GetLastError());
        RingLog(msg); return;
    }

    const char* MARKER = "## Certificate data from Mozilla";
    const size_t MLEN  = strlen(MARKER);
    const auto* base   = reinterpret_cast<const unsigned char*>(g_baseAddress);
    const auto* imgEnd = base + mi.SizeOfImage;

    // Locate the Mozilla marker.
    const unsigned char* markerAt = nullptr;
    if (fast) {
        markerAt = FastMarkerProbe();
    } else {
        const unsigned char* cur = base;
        while (cur < imgEnd && !markerAt) {
            MEMORY_BASIC_INFORMATION mbi2 = {};
            if (VirtualQuery(cur, &mbi2, sizeof(mbi2)) != sizeof(mbi2)) break;
            const auto* rEnd = reinterpret_cast<const unsigned char*>(mbi2.BaseAddress) + mbi2.RegionSize;
            if (rEnd > imgEnd) rEnd = imgEnd;
            DWORD p2 = mbi2.Protect & 0xFF;
            bool readable = (mbi2.State == MEM_COMMIT) &&
                p2 != PAGE_NOACCESS && p2 != PAGE_EXECUTE &&
                !(mbi2.Protect & PAGE_GUARD);
            if (readable && (rEnd - cur) >= (ptrdiff_t)MLEN) {
                for (size_t off = 0, span = (size_t)(rEnd - cur) - MLEN; off <= span; ++off) {
                    if (cur[off] == '#' && memcmp(cur + off, MARKER, MLEN) == 0) {
                        markerAt = cur + off; break;
                    }
                }
            }
            cur = rEnd;
        }
    }

    if (!markerAt) { RingLog("[bundle] Mozilla marker not found"); return; }

    // Log discovery RVA so the user can add it to the config.
    size_t discoveredRva = (size_t)(markerAt - base);
    char msg[LOG_BUF];
    sprintf_s(msg, sizeof(msg),
        "[bundle] DISCOVERY: %s -- marker at RVA 0x%zx -- add BundleMarkerRVA=0x%zx to bcrypt_hook.cfg",
        g_exeName, discoveredRva, discoveredRva);
    RingLog(msg);

    // Find first and second BEGIN CERTIFICATE to bound the slot.
    const char* BEGIN    = "-----BEGIN CERTIFICATE-----";
    const size_t BLEN   = strlen(BEGIN);
    const unsigned char* first  = nullptr;
    const unsigned char* second = nullptr;

    {
        size_t cap = (imgEnd > markerAt + BLEN) ? (size_t)(imgEnd - markerAt - BLEN) : 0;
        if (cap > 0x20000) cap = 0x20000;
        for (size_t off = 0; off < cap && !first; ++off) {
            if ((off & 0xFFF) == 0 && !IsReadablePage(markerAt + off, BLEN)) break;
            if (markerAt[off] == '-' && memcmp(markerAt + off, BEGIN, BLEN) == 0)
                first = markerAt + off;
        }
    }
    if (!first) { RingLog("[bundle] first BEGIN CERTIFICATE not found"); return; }

    {
        size_t cap = (imgEnd > first + BLEN) ? (size_t)(imgEnd - first - BLEN) : 0;
        if (cap > 0x20000) cap = 0x20000;
        for (size_t off = BLEN; off < cap && !second; ++off) {
            if ((off & 0xFFF) == 0 && !IsReadablePage(first + off, BLEN)) break;
            if (first[off] == '-' && memcmp(first + off, BEGIN, BLEN) == 0)
                second = first + off;
        }
    }
    if (!second) { RingLog("[bundle] second BEGIN CERTIFICATE not found"); return; }

    size_t slotSize = (size_t)(second - first);
    sprintf_s(msg, sizeof(msg),
        "[bundle] slot: first=%p size=%zu cert=%lu",
        first, slotSize, certLen);
    RingLog(msg);

    if (certLen + 16 > slotSize) {
        sprintf_s(msg, sizeof(msg),
            "[bundle] cert (%lu) too big for slot (%zu) -- aborting", certLen, slotSize);
        RingLog(msg); return;
    }

    DWORD old = 0;
    if (!VirtualProtect((LPVOID)first, slotSize, PAGE_READWRITE, &old)) {
        sprintf_s(msg, sizeof(msg), "[bundle] VirtualProtect failed: err=%lu", GetLastError());
        RingLog(msg); return;
    }
    memcpy((void*)first, certBuf, certLen);
    memset((void*)(first + certLen), '\n', slotSize - certLen);
    DWORD dummy = 0;
    VirtualProtect((LPVOID)first, slotSize, old, &dummy);

    RingLog("[bundle] PATCHED: CA cert injected into Mozilla bundle");
    InterlockedExchange(&g_patched, 1);
}

// ---------------------------------------------------------------------------
// BundleWatcherThread
// ---------------------------------------------------------------------------
static DWORD WINAPI BundleWatcherThread(LPVOID) {
    RingLog("[bundle] watcher started");
    const bool fast   = (g_bundleMarkerRva != 0);
    const int  ms     = fast ?  1  : 500;
    const int  maxIt  = fast ? 30000 : 240;
    for (int i = 0; i < maxIt && !g_patched; ++i) {
        if (fast) { if (FastMarkerProbe()) PatchCABundle(); }
        else      { PatchCABundle(); }
        if (g_patched) {
            char msg[LOG_BUF];
            sprintf_s(msg, sizeof(msg),
                "[bundle] watcher patched after %d iters (%dms, %s)",
                i, ms, fast ? "fast" : "discovery");
            RingLog(msg);
            return 0;
        }
        Sleep(ms);
    }
    if (!g_patched) {
        char msg[LOG_BUF];
        sprintf_s(msg, sizeof(msg), "[bundle] watcher gave up after %d iters", maxIt);
        RingLog(msg);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// connect hook
// ---------------------------------------------------------------------------
typedef int (WINAPI* PFN_connect)(UINT_PTR, const void*, int);
static PFN_connect g_origConnect = nullptr;

static int WINAPI MyConnect(UINT_PTR s, const void* name, int namelen) {
    PatchCABundle();
    return g_origConnect(s, name, namelen);
}

static void InstallConnectHook() {
    HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
    if (!hWs2) { RingLog("[hook] ws2_32 not loaded yet -- connect hook skipped"); return; }
    FARPROC pfn = GetProcAddress(hWs2, "connect");
    if (pfn && MH_CreateHook(pfn, &MyConnect, (LPVOID*)&g_origConnect) == MH_OK
            && MH_EnableHook(pfn) == MH_OK) {
        RingLog("[hook] connect hook installed");
    } else {
        RingLog("[hook] connect hook FAILED");
    }
}

// ---------------------------------------------------------------------------
// Helper: ensure real bcrypt.dll is loaded
// ---------------------------------------------------------------------------
static inline HMODULE RealBcrypt() {
    if (!g_hRealBcrypt)
        g_hRealBcrypt = LoadLibraryW(L"C:\\Windows\\System32\\bcrypt.dll");
    return g_hRealBcrypt;
}

// ---------------------------------------------------------------------------
// Bcrypt proxy functions -- all forward to the real System32 bcrypt.dll
// ---------------------------------------------------------------------------

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptAddContextFunction(
    ULONG dwTable, LPCWSTR pszContext, ULONG dwInterface,
    LPCWSTR pszFunction, ULONG dwPosition) {
    typedef NTSTATUS(WINAPI* F)(ULONG,LPCWSTR,ULONG,LPCWSTR,ULONG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptAddContextFunction");
    return fn(dwTable, pszContext, dwInterface, pszFunction, dwPosition);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptCloseAlgorithmProvider(
    BCRYPT_ALG_HANDLE hAlgorithm, ULONG dwFlags) {
    typedef NTSTATUS(WINAPI* F)(BCRYPT_ALG_HANDLE, ULONG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptCloseAlgorithmProvider");
    return fn(hAlgorithm, dwFlags);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptConfigureContext(
    ULONG dwTable, LPCWSTR pszContext, PCRYPT_CONTEXT_CONFIG pConfig) {
    typedef NTSTATUS(WINAPI* F)(ULONG,LPCWSTR,PCRYPT_CONTEXT_CONFIG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptConfigureContext");
    return fn(dwTable, pszContext, pConfig);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptCreateContext(
    ULONG dwTable, LPCWSTR pszContext, PCRYPT_CONTEXT_CONFIG pConfig) {
    typedef NTSTATUS(WINAPI* F)(ULONG,LPCWSTR,PCRYPT_CONTEXT_CONFIG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptCreateContext");
    return fn(dwTable, pszContext, pConfig);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptCreateHash(
    BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_HASH_HANDLE* phHash,
    PUCHAR pbHashObject, ULONG cbHashObject,
    PUCHAR pbSecret, ULONG cbSecret, ULONG dwFlags) {
    typedef NTSTATUS(WINAPI* F)(BCRYPT_ALG_HANDLE,BCRYPT_HASH_HANDLE*,PUCHAR,ULONG,PUCHAR,ULONG,ULONG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptCreateHash");
    return fn(hAlgorithm, phHash, pbHashObject, cbHashObject, pbSecret, cbSecret, dwFlags);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptCreateMultiHash(
    BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_HASH_HANDLE* phHash, ULONG nHashes,
    PUCHAR pbHashObject, ULONG cbHashObject,
    PUCHAR pbSecret, ULONG cbSecret, ULONG dwFlags) {
    typedef NTSTATUS(WINAPI* F)(BCRYPT_ALG_HANDLE,BCRYPT_HASH_HANDLE*,ULONG,PUCHAR,ULONG,PUCHAR,ULONG,ULONG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptCreateMultiHash");
    return fn(hAlgorithm, phHash, nHashes, pbHashObject, cbHashObject, pbSecret, cbSecret, dwFlags);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptDecrypt(
    BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, VOID* pPaddingInfo,
    PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput,
    ULONG* pcbResult, ULONG dwFlags) {
    typedef NTSTATUS(WINAPI* F)(BCRYPT_KEY_HANDLE,PUCHAR,ULONG,VOID*,PUCHAR,ULONG,PUCHAR,ULONG,ULONG*,ULONG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptDecrypt");
    return fn(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptDeleteContext(
    ULONG dwTable, LPCWSTR pszContext) {
    typedef NTSTATUS(WINAPI* F)(ULONG,LPCWSTR);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptDeleteContext");
    return fn(dwTable, pszContext);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptDeriveKey(
    BCRYPT_SECRET_HANDLE hSharedSecret, LPCWSTR pwszKDF,
    BCryptBufferDesc* pParameterList, PUCHAR pbDerivedKey,
    ULONG cbDerivedKey, ULONG* pcbResult, ULONG dwFlags) {
    typedef NTSTATUS(WINAPI* F)(BCRYPT_SECRET_HANDLE,LPCWSTR,BCryptBufferDesc*,PUCHAR,ULONG,ULONG*,ULONG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptDeriveKey");
    return fn(hSharedSecret, pwszKDF, pParameterList, pbDerivedKey, cbDerivedKey, pcbResult, dwFlags);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptDeriveKeyCapi(
    BCRYPT_HASH_HANDLE hHash, BCRYPT_ALG_HANDLE hTargetAlg,
    PUCHAR pbDerivedKey, ULONG cbDerivedKey, ULONG dwFlags) {
    typedef NTSTATUS(WINAPI* F)(BCRYPT_HASH_HANDLE,BCRYPT_ALG_HANDLE,PUCHAR,ULONG,ULONG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptDeriveKeyCapi");
    return fn(hHash, hTargetAlg, pbDerivedKey, cbDerivedKey, dwFlags);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptDeriveKeyPBKDF2(
    BCRYPT_ALG_HANDLE hPrf, PUCHAR pbPassword, ULONG cbPassword,
    PUCHAR pbSalt, ULONG cbSalt, ULONGLONG cIterations,
    PUCHAR pbDerivedKey, ULONG cbDerivedKey, ULONG dwFlags) {
    typedef NTSTATUS(WINAPI* F)(BCRYPT_ALG_HANDLE,PUCHAR,ULONG,PUCHAR,ULONG,ULONGLONG,PUCHAR,ULONG,ULONG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptDeriveKeyPBKDF2");
    return fn(hPrf, pbPassword, cbPassword, pbSalt, cbSalt, cIterations, pbDerivedKey, cbDerivedKey, dwFlags);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptDestroyHash(
    BCRYPT_HASH_HANDLE hHash) {
    typedef NTSTATUS(WINAPI* F)(BCRYPT_HASH_HANDLE);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptDestroyHash");
    return fn(hHash);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptDestroyKey(
    BCRYPT_KEY_HANDLE hKey) {
    typedef NTSTATUS(WINAPI* F)(BCRYPT_KEY_HANDLE);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptDestroyKey");
    return fn(hKey);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptDestroySecret(
    BCRYPT_SECRET_HANDLE hSecret) {
    typedef NTSTATUS(WINAPI* F)(BCRYPT_SECRET_HANDLE);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptDestroySecret");
    return fn(hSecret);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptDuplicateHash(
    BCRYPT_HASH_HANDLE hHash, BCRYPT_HASH_HANDLE* phNewHash,
    PUCHAR pbHashObject, ULONG cbHashObject, ULONG dwFlags) {
    typedef NTSTATUS(WINAPI* F)(BCRYPT_HASH_HANDLE,BCRYPT_HASH_HANDLE*,PUCHAR,ULONG,ULONG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptDuplicateHash");
    return fn(hHash, phNewHash, pbHashObject, cbHashObject, dwFlags);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptDuplicateKey(
    BCRYPT_KEY_HANDLE hKey, BCRYPT_KEY_HANDLE* phNewKey,
    PUCHAR pbKeyObject, ULONG cbKeyObject, ULONG dwFlags) {
    typedef NTSTATUS(WINAPI* F)(BCRYPT_KEY_HANDLE,BCRYPT_KEY_HANDLE*,PUCHAR,ULONG,ULONG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptDuplicateKey");
    return fn(hKey, phNewKey, pbKeyObject, cbKeyObject, dwFlags);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptEncrypt(
    BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, VOID* pPaddingInfo,
    PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput,
    ULONG* pcbResult, ULONG dwFlags) {
    typedef NTSTATUS(WINAPI* F)(BCRYPT_KEY_HANDLE,PUCHAR,ULONG,VOID*,PUCHAR,ULONG,PUCHAR,ULONG,ULONG*,ULONG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptEncrypt");
    return fn(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptEnumAlgorithms(
    ULONG dwAlgOperations, ULONG* pAlgCount,
    BCRYPT_ALGORITHM_IDENTIFIER** ppAlgList, ULONG dwFlags) {
    typedef NTSTATUS(WINAPI* F)(ULONG,ULONG*,BCRYPT_ALGORITHM_IDENTIFIER**,ULONG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptEnumAlgorithms");
    return fn(dwAlgOperations, pAlgCount, ppAlgList, dwFlags);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptEnumContextFunctionProviders(
    ULONG dwTable, LPCWSTR pszContext, ULONG dwInterface,
    LPCWSTR pszFunction, ULONG* pcbBuffer,
    PCRYPT_CONTEXT_FUNCTION_PROVIDERS* ppBuffer) {
    typedef NTSTATUS(WINAPI* F)(ULONG,LPCWSTR,ULONG,LPCWSTR,ULONG*,PCRYPT_CONTEXT_FUNCTION_PROVIDERS*);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptEnumContextFunctionProviders");
    return fn(dwTable, pszContext, dwInterface, pszFunction, pcbBuffer, ppBuffer);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptEnumContextFunctions(
    ULONG dwTable, LPCWSTR pszContext, ULONG dwInterface,
    ULONG* pcbBuffer, PCRYPT_CONTEXT_FUNCTIONS* ppBuffer) {
    typedef NTSTATUS(WINAPI* F)(ULONG,LPCWSTR,ULONG,ULONG*,PCRYPT_CONTEXT_FUNCTIONS*);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptEnumContextFunctions");
    return fn(dwTable, pszContext, dwInterface, pcbBuffer, ppBuffer);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptEnumContexts(
    ULONG dwTable, ULONG* pcbBuffer, PCRYPT_CONTEXTS* ppBuffer) {
    typedef NTSTATUS(WINAPI* F)(ULONG,ULONG*,PCRYPT_CONTEXTS*);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptEnumContexts");
    return fn(dwTable, pcbBuffer, ppBuffer);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptEnumProviders(
    LPCWSTR pszAlgId, ULONG* pImplCount,
    BCRYPT_PROVIDER_NAME** ppImplList, ULONG dwFlags) {
    typedef NTSTATUS(WINAPI* F)(LPCWSTR,ULONG*,BCRYPT_PROVIDER_NAME**,ULONG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptEnumProviders");
    return fn(pszAlgId, pImplCount, ppImplList, dwFlags);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptEnumRegisteredProviders(
    ULONG* pcbBuffer, PCRYPT_PROVIDERS* ppBuffer) {
    typedef NTSTATUS(WINAPI* F)(ULONG*,PCRYPT_PROVIDERS*);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptEnumRegisteredProviders");
    return fn(pcbBuffer, ppBuffer);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptExportKey(
    BCRYPT_KEY_HANDLE hKey, BCRYPT_KEY_HANDLE hExportKey,
    LPCWSTR pszBlobType, PUCHAR pbOutput, ULONG cbOutput,
    ULONG* pcbResult, ULONG dwFlags) {
    typedef NTSTATUS(WINAPI* F)(BCRYPT_KEY_HANDLE,BCRYPT_KEY_HANDLE,LPCWSTR,PUCHAR,ULONG,ULONG*,ULONG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptExportKey");
    return fn(hKey, hExportKey, pszBlobType, pbOutput, cbOutput, pcbResult, dwFlags);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptFinalizeKeyPair(
    BCRYPT_KEY_HANDLE hKey, ULONG dwFlags) {
    typedef NTSTATUS(WINAPI* F)(BCRYPT_KEY_HANDLE,ULONG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptFinalizeKeyPair");
    return fn(hKey, dwFlags);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptFinishHash(
    BCRYPT_HASH_HANDLE hHash, PUCHAR pbOutput, ULONG cbOutput, ULONG dwFlags) {
    typedef NTSTATUS(WINAPI* F)(BCRYPT_HASH_HANDLE,PUCHAR,ULONG,ULONG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptFinishHash");
    return fn(hHash, pbOutput, cbOutput, dwFlags);
}

extern "C" __declspec(dllexport) VOID WINAPI MyBCryptFreeBuffer(PVOID pvBuffer) {
    typedef VOID(WINAPI* F)(PVOID);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptFreeBuffer");
    return fn(pvBuffer);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptGenRandom(
    BCRYPT_ALG_HANDLE hAlgorithm, PUCHAR pbBuffer,
    ULONG cbBuffer, ULONG dwFlags) {
    typedef NTSTATUS(WINAPI* F)(BCRYPT_ALG_HANDLE,PUCHAR,ULONG,ULONG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptGenRandom");
    return fn(hAlgorithm, pbBuffer, cbBuffer, dwFlags);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptGenerateKeyPair(
    BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE* phKey,
    ULONG dwLength, ULONG dwFlags) {
    typedef NTSTATUS(WINAPI* F)(BCRYPT_ALG_HANDLE,BCRYPT_KEY_HANDLE*,ULONG,ULONG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptGenerateKeyPair");
    return fn(hAlgorithm, phKey, dwLength, dwFlags);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptGenerateSymmetricKey(
    BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE* phKey,
    PUCHAR pbKeyObject, ULONG cbKeyObject,
    PUCHAR pbSecret, ULONG cbSecret, ULONG dwFlags) {
    typedef NTSTATUS(WINAPI* F)(BCRYPT_ALG_HANDLE,BCRYPT_KEY_HANDLE*,PUCHAR,ULONG,PUCHAR,ULONG,ULONG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptGenerateSymmetricKey");
    return fn(hAlgorithm, phKey, pbKeyObject, cbKeyObject, pbSecret, cbSecret, dwFlags);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptGetFipsAlgorithmMode(BOOLEAN* pfEnabled) {
    typedef NTSTATUS(WINAPI* F)(BOOLEAN*);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptGetFipsAlgorithmMode");
    return fn(pfEnabled);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptGetProperty(
    BCRYPT_HANDLE hObject, LPCWSTR pszProperty,
    PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags) {
    typedef NTSTATUS(WINAPI* F)(BCRYPT_HANDLE,LPCWSTR,PUCHAR,ULONG,ULONG*,ULONG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptGetProperty");
    return fn(hObject, pszProperty, pbOutput, cbOutput, pcbResult, dwFlags);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptHash(
    BCRYPT_ALG_HANDLE hAlgorithm, PUCHAR pbSecret, ULONG cbSecret,
    PUCHAR pbInput, ULONG cbInput, PUCHAR pbOutput, ULONG cbOutput) {
    typedef NTSTATUS(WINAPI* F)(BCRYPT_ALG_HANDLE,PUCHAR,ULONG,PUCHAR,ULONG,PUCHAR,ULONG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptHash");
    return fn(hAlgorithm, pbSecret, cbSecret, pbInput, cbInput, pbOutput, cbOutput);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptHashData(
    BCRYPT_HASH_HANDLE hHash, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags) {
    typedef NTSTATUS(WINAPI* F)(BCRYPT_HASH_HANDLE,PUCHAR,ULONG,ULONG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptHashData");
    return fn(hHash, pbInput, cbInput, dwFlags);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptImportKey(
    BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE hImportKey,
    LPCWSTR pszBlobType, BCRYPT_KEY_HANDLE* phKey,
    PUCHAR pbKeyObject, ULONG cbKeyObject,
    PUCHAR pbInput, ULONG cbInput, ULONG dwFlags) {
    typedef NTSTATUS(WINAPI* F)(BCRYPT_ALG_HANDLE,BCRYPT_KEY_HANDLE,LPCWSTR,BCRYPT_KEY_HANDLE*,PUCHAR,ULONG,PUCHAR,ULONG,ULONG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptImportKey");
    return fn(hAlgorithm, hImportKey, pszBlobType, phKey, pbKeyObject, cbKeyObject, pbInput, cbInput, dwFlags);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptImportKeyPair(
    BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE hImportKey,
    LPCWSTR pszBlobType, BCRYPT_KEY_HANDLE* phKey,
    PUCHAR pbInput, ULONG cbInput, ULONG dwFlags) {
    typedef NTSTATUS(WINAPI* F)(BCRYPT_ALG_HANDLE,BCRYPT_KEY_HANDLE,LPCWSTR,BCRYPT_KEY_HANDLE*,PUCHAR,ULONG,ULONG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptImportKeyPair");
    return fn(hAlgorithm, hImportKey, pszBlobType, phKey, pbInput, cbInput, dwFlags);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptKeyDerivation(
    BCRYPT_KEY_HANDLE hKey, BCryptBufferDesc* pParameterList,
    PUCHAR pbDerivedKey, ULONG cbDerivedKey,
    ULONG* pcbResult, ULONG dwFlags) {
    typedef NTSTATUS(WINAPI* F)(BCRYPT_KEY_HANDLE,BCryptBufferDesc*,PUCHAR,ULONG,ULONG*,ULONG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptKeyDerivation");
    return fn(hKey, pParameterList, pbDerivedKey, cbDerivedKey, pcbResult, dwFlags);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptOpenAlgorithmProvider(
    BCRYPT_ALG_HANDLE* phAlgorithm, LPCWSTR pszAlgId,
    LPCWSTR pszImplementation, ULONG dwFlags) {
    typedef NTSTATUS(WINAPI* F)(BCRYPT_ALG_HANDLE*,LPCWSTR,LPCWSTR,ULONG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptOpenAlgorithmProvider");
    return fn(phAlgorithm, pszAlgId, pszImplementation, dwFlags);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptProcessMultiOperations(
    BCRYPT_HANDLE hObject, BCRYPT_MULTI_OPERATION_TYPE operationType,
    PVOID pOperations, ULONG cbOperations, ULONG dwFlags) {
    typedef NTSTATUS(WINAPI* F)(BCRYPT_HANDLE,BCRYPT_MULTI_OPERATION_TYPE,PVOID,ULONG,ULONG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptProcessMultiOperations");
    return fn(hObject, operationType, pOperations, cbOperations, dwFlags);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptQueryContextConfiguration(
    ULONG dwTable, LPCWSTR pszContext, ULONG* pcbBuffer,
    PCRYPT_CONTEXT_CONFIG* ppBuffer) {
    typedef NTSTATUS(WINAPI* F)(ULONG,LPCWSTR,ULONG*,PCRYPT_CONTEXT_CONFIG*);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptQueryContextConfiguration");
    return fn(dwTable, pszContext, pcbBuffer, ppBuffer);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptQueryContextFunctionConfiguration(
    ULONG dwTable, LPCWSTR pszContext, ULONG dwInterface,
    LPCWSTR pszFunction, ULONG* pcbBuffer,
    PCRYPT_CONTEXT_FUNCTION_CONFIG* ppBuffer) {
    typedef NTSTATUS(WINAPI* F)(ULONG,LPCWSTR,ULONG,LPCWSTR,ULONG*,PCRYPT_CONTEXT_FUNCTION_CONFIG*);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptQueryContextFunctionConfiguration");
    return fn(dwTable, pszContext, dwInterface, pszFunction, pcbBuffer, ppBuffer);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptQueryContextFunctionProperty(
    ULONG dwTable, LPCWSTR pszContext, ULONG dwInterface,
    LPCWSTR pszFunction, LPCWSTR pszProperty,
    ULONG* pcbValue, PUCHAR* ppbValue) {
    typedef NTSTATUS(WINAPI* F)(ULONG,LPCWSTR,ULONG,LPCWSTR,LPCWSTR,ULONG*,PUCHAR*);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptQueryContextFunctionProperty");
    return fn(dwTable, pszContext, dwInterface, pszFunction, pszProperty, pcbValue, ppbValue);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptQueryProviderRegistration(
    LPCWSTR pszProvider, ULONG dwMode, ULONG dwInterface,
    ULONG* pcbBuffer, PCRYPT_PROVIDER_REG* ppBuffer) {
    typedef NTSTATUS(WINAPI* F)(LPCWSTR,ULONG,ULONG,ULONG*,PCRYPT_PROVIDER_REG*);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptQueryProviderRegistration");
    return fn(pszProvider, dwMode, dwInterface, pcbBuffer, ppBuffer);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptRegisterConfigChangeNotify(HANDLE* phEvent) {
    typedef NTSTATUS(WINAPI* F)(HANDLE*);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptRegisterConfigChangeNotify");
    return fn(phEvent);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptRegisterProvider(
    LPCWSTR pszProvider, ULONG dwFlags, PCRYPT_PROVIDER_REG pProviderReg) {
    typedef NTSTATUS(WINAPI* F)(LPCWSTR,ULONG,PCRYPT_PROVIDER_REG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptRegisterProvider");
    return fn(pszProvider, dwFlags, pProviderReg);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptRemoveContextFunction(
    ULONG dwTable, LPCWSTR pszContext, ULONG dwInterface, LPCWSTR pszFunction) {
    typedef NTSTATUS(WINAPI* F)(ULONG,LPCWSTR,ULONG,LPCWSTR);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptRemoveContextFunction");
    return fn(dwTable, pszContext, dwInterface, pszFunction);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptRemoveContextFunctionProvider(
    ULONG dwTable, LPCWSTR pszContext, ULONG dwInterface,
    LPCWSTR pszFunction, LPCWSTR pszProvider) {
    typedef NTSTATUS(WINAPI* F)(ULONG,LPCWSTR,ULONG,LPCWSTR,LPCWSTR);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptRemoveContextFunctionProvider");
    return fn(dwTable, pszContext, dwInterface, pszFunction, pszProvider);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptResolveProviders(
    LPCWSTR pszContext, ULONG dwInterface, LPCWSTR pszFunction,
    LPCWSTR pszProvider, ULONG dwMode, ULONG dwFlags,
    ULONG* pcbBuffer, PCRYPT_PROVIDER_REFS* ppBuffer) {
    typedef NTSTATUS(WINAPI* F)(LPCWSTR,ULONG,LPCWSTR,LPCWSTR,ULONG,ULONG,ULONG*,PCRYPT_PROVIDER_REFS*);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptResolveProviders");
    return fn(pszContext, dwInterface, pszFunction, pszProvider, dwMode, dwFlags, pcbBuffer, ppBuffer);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptSecretAgreement(
    BCRYPT_KEY_HANDLE hPrivKey, BCRYPT_KEY_HANDLE hPubKey,
    BCRYPT_SECRET_HANDLE* phAgreedSecret, ULONG dwFlags) {
    typedef NTSTATUS(WINAPI* F)(BCRYPT_KEY_HANDLE,BCRYPT_KEY_HANDLE,BCRYPT_SECRET_HANDLE*,ULONG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptSecretAgreement");
    return fn(hPrivKey, hPubKey, phAgreedSecret, dwFlags);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptSetAuditingInterface(
    HANDLE hAudit, ULONG dwFlags) {
    typedef NTSTATUS(WINAPI* F)(HANDLE,ULONG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptSetAuditingInterface");
    if (!fn) return (NTSTATUS)0xC00000BBL; /* STATUS_NOT_SUPPORTED */
    return fn(hAudit, dwFlags);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptSetContextFunctionProperty(
    ULONG dwTable, LPCWSTR pszContext, ULONG dwInterface,
    LPCWSTR pszFunction, LPCWSTR pszProperty,
    ULONG cbValue, PUCHAR pbValue) {
    typedef NTSTATUS(WINAPI* F)(ULONG,LPCWSTR,ULONG,LPCWSTR,LPCWSTR,ULONG,PUCHAR);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptSetContextFunctionProperty");
    return fn(dwTable, pszContext, dwInterface, pszFunction, pszProperty, cbValue, pbValue);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptSetProperty(
    BCRYPT_HANDLE hObject, LPCWSTR pszProperty,
    PUCHAR pbInput, ULONG cbInput, ULONG dwFlags) {
    typedef NTSTATUS(WINAPI* F)(BCRYPT_HANDLE,LPCWSTR,PUCHAR,ULONG,ULONG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptSetProperty");
    return fn(hObject, pszProperty, pbInput, cbInput, dwFlags);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptSignHash(
    BCRYPT_KEY_HANDLE hKey, VOID* pPaddingInfo,
    PUCHAR pbInput, ULONG cbInput,
    PUCHAR pbOutput, ULONG cbOutput,
    ULONG* pcbResult, ULONG dwFlags) {
    typedef NTSTATUS(WINAPI* F)(BCRYPT_KEY_HANDLE,VOID*,PUCHAR,ULONG,PUCHAR,ULONG,ULONG*,ULONG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptSignHash");
    return fn(hKey, pPaddingInfo, pbInput, cbInput, pbOutput, cbOutput, pcbResult, dwFlags);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptUnregisterConfigChangeNotify(HANDLE hEvent) {
    typedef NTSTATUS(WINAPI* F)(HANDLE);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptUnregisterConfigChangeNotify");
    return fn(hEvent);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptUnregisterProvider(LPCWSTR pszProvider) {
    typedef NTSTATUS(WINAPI* F)(LPCWSTR);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptUnregisterProvider");
    return fn(pszProvider);
}

extern "C" __declspec(dllexport) NTSTATUS WINAPI MyBCryptVerifySignature(
    BCRYPT_KEY_HANDLE hKey, VOID* pPaddingInfo,
    PUCHAR pbHash, ULONG cbHash,
    PUCHAR pbSignature, ULONG cbSignature, ULONG dwFlags) {
    typedef NTSTATUS(WINAPI* F)(BCRYPT_KEY_HANDLE,VOID*,PUCHAR,ULONG,PUCHAR,ULONG,ULONG);
    static F fn = (F)GetProcAddress(RealBcrypt(), "BCryptVerifySignature");
    return fn(hKey, pPaddingInfo, pbHash, cbHash, pbSignature, cbSignature, dwFlags);
}

// ---------------------------------------------------------------------------
// DllMain
// ---------------------------------------------------------------------------
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID /*lpReserved*/)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        g_hSelf = hModule;
        DisableThreadLibraryCalls(hModule);

        // Determine the directory this DLL lives in.
        char dllPath[MAX_PATH] = {};
        GetModuleFileNameA(hModule, dllPath, sizeof(dllPath));
        strncpy_s(g_dllDir, sizeof(g_dllDir), dllPath, _TRUNCATE);
        char* lastSlash = strrchr(g_dllDir, '\\');
        if (lastSlash) *lastSlash = '\0';

        // Start log consumer before anything else so all messages reach disk.
        CreateThread(NULL, 0, RingLogConsumerThread, NULL, 0, NULL);

        // Identify host exe.
        HANDLE hProc = GetCurrentProcess();
        HMODULE hMods[1] = {};
        DWORD cbNeeded = 0;
        EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded);
        HMODULE hExe = (cbNeeded >= sizeof(HMODULE)) ? hMods[0] : hModule;
        GetModuleBaseNameA(hProc, hExe, g_exeName, sizeof(g_exeName));
        g_baseAddress = (uintptr_t)hExe;

        char msg[LOG_BUF];
        sprintf_s(msg, sizeof(msg),
            "[init] exe=%s base=%p dllDir=%s",
            g_exeName, (void*)g_baseAddress, g_dllDir);
        RingLog(msg);

        // Load real bcrypt.dll from System32 before any proxy call.
        g_hRealBcrypt = LoadLibraryW(L"C:\\Windows\\System32\\bcrypt.dll");
        if (!g_hRealBcrypt) {
            RingLog("[init] FATAL: could not load System32\\bcrypt.dll");
            return FALSE;
        }

        // Read per-deployment config.
        LoadConfig();

        // Spawn bundle watcher + do an eager patch attempt.
        CreateThread(NULL, 0, BundleWatcherThread, NULL, 0, NULL);
        PatchCABundle();

        // Install MinHook + connect hook.
        if (MH_Initialize() == MH_OK) {
            InstallConnectHook();
        } else {
            RingLog("[init] MH_Initialize failed");
        }

        RingLog("[init] DLL_PROCESS_ATTACH complete");
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        RingLog("[init] DLL_PROCESS_DETACH");
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        break;
    }
    return TRUE;
}
