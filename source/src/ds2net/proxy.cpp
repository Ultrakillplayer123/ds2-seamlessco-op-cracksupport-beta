// ds2net — replacement steam_api64.dll for Dark Souls II: SotFS 1.0.2.0
//
// Stage 1: proxy mode + login redirect.
//
//   1. Every Steam export the game imports is forwarded to an authentic Valve
//      steam_api64.dll renamed to steam_api64_org.dll. This gives us correct
//      interface layouts and real Steam P2P while we prove out the redirect.
//
//   2. The game's DNS lookups for FromSoftware's login host are rewritten to a
//      configured IP (ds2net.ini). That points the client at our own ds3os
//      server without touching the hosts file, DNS, or any system setting -
//      the hook only exists inside this one process.
//
// Later stages replace individual interfaces (SteamNetworking over UDP relay,
// SteamMatchmaking over our own lobby table) without touching the rest.
//
// Build: build.ps1 in ds2-coop/

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <share.h>
#include <cstdarg>
#include <cstdint>
#include <cstring>
#include <cstdlib>

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

static FILE* g_log = nullptr;
static bool  g_log_calls = true;        // log wrapped-interface vtable calls (Stage 2 capture)
static unsigned g_slot_logged[128];     // per-slot throttle
static unsigned g_slot_total[128];

static void Log(const char* fmt, ...);   // defined below; fwd decl for asm helpers

static void GetSelfDir(char* out, size_t len) {
    HMODULE self = nullptr;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCSTR)&GetSelfDir, &self);
    GetModuleFileNameA(self, out, (DWORD)len);
    char* slash = strrchr(out, '\\');
    if (slash) *(slash + 1) = 0;
    else out[0] = 0;
}

// ---------------------------------------------------------------------------
// Stage 2 instrumentation: wrapped SteamNetworking / SteamMatchmaking
//
// We return our own objects with the exact 006/009 vtable layouts (see the
// SDK headers in ref/ds3os/Source/ThirdParty/steam). Every vtable slot is a
// naked trampoline in x64 asm that forwards the real registers/stack untouched
// to LogSlot, then tail-jumps the genuine Valve implementation. This lets us
// learn exactly which methods the 1.0.2.0 client calls and with what arguments
// before we implement our own relay + lobby table.
// ---------------------------------------------------------------------------

// iface: 1 = SteamNetworking (22 slots), 2 = SteamMatchmaking (38 slots)
extern "C" void LogSlot(unsigned slot, unsigned long long a, unsigned long long b,
                        unsigned long long c, unsigned long long d, int iface) {
    unsigned key = (iface == 2) ? 64 + slot : slot;
    if (key >= 128) return;
    g_slot_total[key]++;
    if (!g_log_calls) return;
    if (g_slot_logged[key] >= 6) return;   // log first 6 per slot, then count only
    g_slot_logged[key]++;
    if (iface == 2) {
        Log("mm_vt+%02d a=%llx b=%llx c=%llx d=%llx (call #%u)", slot, a, b, c, d, g_slot_total[key]);
    } else {
        Log("net_vt+%02d a=%llx b=%llx c=%llx d=%llx (call #%u)", slot, a, b, c, d, g_slot_total[key]);
    }
}

void LogSlotSummary() {
    Log("stage2 capture summary (totals per slot):");
    for (int i = 0; i < 64; ++i)
        if (g_slot_total[i])  Log("  net_vt+%02d x%u", i, g_slot_total[i]);
    for (int i = 0; i < 38; ++i)
        if (g_slot_total[64 + i]) Log("  mm_vt+%02d x%u", i, g_slot_total[64 + i]);
}

extern "C" uint64_t g_tramp_target_net[22] = {};
extern "C" uint64_t g_tramp_target_mm[38] = {};

// Each trampoline: save rcx..r9, align, call LogSlot(slot, a, b, c, d, iface)
// (6 args: rcx,rdx,r8,r9 + 2 stack slots at [rsp+0x20],[rsp+0x28]), restore
// the original argument registers and stack untouched, then tail-jump the
// genuine Valve vtable entry. Stack args above rsp are never disturbed.
#define MAKE_TRAMP(FUNC, SLOT, SLOT8, TARGET, IFACE)                       \
extern "C" __attribute__((naked)) void FUNC(void) {                         \
    __asm__ volatile(                                                      \
        "push %rcx\n\t"                                                    \
        "push %rdx\n\t"                                                    \
        "push %r8\n\t"                                                     \
        "push %r9\n\t"                                                     \
        "push %rbp\n\t"                                                    \
        "mov %rsp, %rbp\n\t"                                               \
        "and $-16, %rsp\n\t"                                               \
        "sub $0x30, %rsp\n\t"                                              \
        "movl $" #SLOT ", %ecx\n\t"                                        \
        "movq 32(%rbp), %rdx\n\t"                                          \
        "movq 24(%rbp), %r8\n\t"                                           \
        "movq 16(%rbp), %r9\n\t"                                           \
        "movq 8(%rbp),  %rax\n\t"                                          \
        "movq %rax, 0x20(%rsp)\n\t"                                        \
        "movq $" #IFACE ", %rax\n\t"                                       \
        "movq %rax, 0x28(%rsp)\n\t"                                        \
        "call LogSlot\n\t"                                                 \
        "leave\n\t"                                                        \
        "pop %r9\n\t"                                                      \
        "pop %r8\n\t"                                                      \
        "pop %rdx\n\t"                                                     \
        "pop %rcx\n\t"                                                     \
        "jmp *" #TARGET "+" #SLOT8 "(%rip)\n\t"                           ); \
}

MAKE_TRAMP(TrampolineNet0,  0,   0, g_tramp_target_net, 1)
MAKE_TRAMP(TrampolineNet1,  1,   8, g_tramp_target_net, 1)
MAKE_TRAMP(TrampolineNet2,  2,  16, g_tramp_target_net, 1)
MAKE_TRAMP(TrampolineNet3,  3,  24, g_tramp_target_net, 1)
MAKE_TRAMP(TrampolineNet4,  4,  32, g_tramp_target_net, 1)
MAKE_TRAMP(TrampolineNet5,  5,  40, g_tramp_target_net, 1)
MAKE_TRAMP(TrampolineNet6,  6,  48, g_tramp_target_net, 1)
MAKE_TRAMP(TrampolineNet7,  7,  56, g_tramp_target_net, 1)
MAKE_TRAMP(TrampolineNet8,  8,  64, g_tramp_target_net, 1)
MAKE_TRAMP(TrampolineNet9,  9,  72, g_tramp_target_net, 1)
MAKE_TRAMP(TrampolineNet10, 10, 80, g_tramp_target_net, 1)
MAKE_TRAMP(TrampolineNet11, 11, 88, g_tramp_target_net, 1)
MAKE_TRAMP(TrampolineNet12, 12, 96, g_tramp_target_net, 1)
MAKE_TRAMP(TrampolineNet13, 13, 104, g_tramp_target_net, 1)
MAKE_TRAMP(TrampolineNet14, 14, 112, g_tramp_target_net, 1)
MAKE_TRAMP(TrampolineNet15, 15, 120, g_tramp_target_net, 1)
MAKE_TRAMP(TrampolineNet16, 16, 128, g_tramp_target_net, 1)
MAKE_TRAMP(TrampolineNet17, 17, 136, g_tramp_target_net, 1)
MAKE_TRAMP(TrampolineNet18, 18, 144, g_tramp_target_net, 1)
MAKE_TRAMP(TrampolineNet19, 19, 152, g_tramp_target_net, 1)
MAKE_TRAMP(TrampolineNet20, 20, 160, g_tramp_target_net, 1)
MAKE_TRAMP(TrampolineNet21, 21, 168, g_tramp_target_net, 1)

MAKE_TRAMP(TrampolineMM0,  0,   0, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM1,  1,   8, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM2,  2,  16, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM3,  3,  24, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM4,  4,  32, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM5,  5,  40, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM6,  6,  48, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM7,  7,  56, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM8,  8,  64, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM9,  9,  72, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM10, 10, 80, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM11, 11, 88, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM12, 12, 96, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM13, 13, 104, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM14, 14, 112, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM15, 15, 120, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM16, 16, 128, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM17, 17, 136, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM18, 18, 144, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM19, 19, 152, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM20, 20, 160, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM21, 21, 168, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM22, 22, 176, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM23, 23, 184, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM24, 24, 192, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM25, 25, 200, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM26, 26, 208, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM27, 27, 216, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM28, 28, 224, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM29, 29, 232, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM30, 30, 240, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM31, 31, 248, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM32, 32, 256, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM33, 33, 264, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM34, 34, 272, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM35, 35, 280, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM36, 36, 288, g_tramp_target_mm, 2)
MAKE_TRAMP(TrampolineMM37, 37, 296, g_tramp_target_mm, 2)

static void* g_net_tramps[22] = {
    (void*)TrampolineNet0,  (void*)TrampolineNet1,  (void*)TrampolineNet2,
    (void*)TrampolineNet3,  (void*)TrampolineNet4,  (void*)TrampolineNet5,
    (void*)TrampolineNet6,  (void*)TrampolineNet7,  (void*)TrampolineNet8,
    (void*)TrampolineNet9,  (void*)TrampolineNet10, (void*)TrampolineNet11,
    (void*)TrampolineNet12, (void*)TrampolineNet13, (void*)TrampolineNet14,
    (void*)TrampolineNet15, (void*)TrampolineNet16, (void*)TrampolineNet17,
    (void*)TrampolineNet18, (void*)TrampolineNet19, (void*)TrampolineNet20,
    (void*)TrampolineNet21,
};

static void* g_mm_tramps[38] = {
    (void*)TrampolineMM0,  (void*)TrampolineMM1,  (void*)TrampolineMM2,
    (void*)TrampolineMM3,  (void*)TrampolineMM4,  (void*)TrampolineMM5,
    (void*)TrampolineMM6,  (void*)TrampolineMM7,  (void*)TrampolineMM8,
    (void*)TrampolineMM9,  (void*)TrampolineMM10, (void*)TrampolineMM11,
    (void*)TrampolineMM12, (void*)TrampolineMM13, (void*)TrampolineMM14,
    (void*)TrampolineMM15, (void*)TrampolineMM16, (void*)TrampolineMM17,
    (void*)TrampolineMM18, (void*)TrampolineMM19, (void*)TrampolineMM20,
    (void*)TrampolineMM21, (void*)TrampolineMM22, (void*)TrampolineMM23,
    (void*)TrampolineMM24, (void*)TrampolineMM25, (void*)TrampolineMM26,
    (void*)TrampolineMM27, (void*)TrampolineMM28, (void*)TrampolineMM29,
    (void*)TrampolineMM30, (void*)TrampolineMM31, (void*)TrampolineMM32,
    (void*)TrampolineMM33, (void*)TrampolineMM34, (void*)TrampolineMM35,
    (void*)TrampolineMM36, (void*)TrampolineMM37,
};

static void* g_net_vt[22];
static void* g_mm_vt[38];
static void* g_net_obj[1 + 22];
static void* g_mm_obj[1 + 38];
static bool  g_wrappers_ready = false;

static void* GetIface(const char* name, const char* version, bool userHandleZero);

// Wrap a real interface: copy its vtable, install our trampolines. Returns
// the wrapper object (game sees a normal Steam interface) or nullptr.
static void* MakeWrapper(const char* name, const char* version, bool userZero,
                         int count, void** tramps, uint64_t* target,
                         void** vt, void** obj) {
    void* real = GetIface(name, version, userZero);
    if (!real) return nullptr;
    void** rv = *(void***)real;
    for (int i = 0; i < count; ++i) target[i] = (uint64_t)rv[i];
    memcpy(vt, tramps, sizeof(void*) * (size_t)count);
    obj[0] = (void*)vt;
    return obj;
}

static void EnsureWrappers() {
    if (g_wrappers_ready) return;
    if (MakeWrapper("SteamNetworking", "SteamNetworking006", false, 22, g_net_tramps, g_tramp_target_net, g_net_vt, g_net_obj) &&
        MakeWrapper("SteamMatchmaking", "SteamMatchMaking009", false, 38, g_mm_tramps, g_tramp_target_mm, g_mm_vt, g_mm_obj)) {
        g_wrappers_ready = true;
        Log("stage2 wrappers installed (net=%p mm=%p)", (void*)g_net_obj, (void*)g_mm_obj);
    } else {
        Log("stage2 wrappers FAILED; falling back to raw interfaces");
    }
}

static void LogInit() {
    if (g_log) return;
    char path[MAX_PATH]{};
    GetSelfDir(path, MAX_PATH);
    strncat_s(path, sizeof(path), "ds2net.log", _TRUNCATE);
    // Share-read so a running game's log can be tailed from outside.
    g_log = _fsopen(path, "w", _SH_DENYWR);
}

static void Log(const char* fmt, ...) {
    LogInit();
    if (!g_log) return;
    SYSTEMTIME st{};
    GetLocalTime(&st);
    fprintf(g_log, "[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_log, fmt, ap);
    va_end(ap);
    fputc('\n', g_log);
    fflush(g_log);
}

// ---------------------------------------------------------------------------
// Config: ds2net.ini next to the game exe.
//
//   [ds2net]
//   login_ip = 127.0.0.1      ; the ds3os host (LAN IP, or ZeroTier IP)
//   hook_dns = 1              ; 0 disables the login redirect
//
// Everything is optional; the defaults point at a local server.
// ---------------------------------------------------------------------------

struct Config {
    char login_ip[64] = "127.0.0.1";
    int  login_port   = 50031;
    bool hook_dns     = true;
    char real_dll[64] = "steam_api64_org.dll";
    bool log_packets  = true;
    char server_ip[64] = "127.0.0.1";   // ds2net relay host (ZeroTier/LAN IP)
    int  relay_port    = 27080;         // reserved for Stage 2 relay
    bool log_calls     = true;          // log wrapped vtable calls (Stage 2 capture)
    int  fake_steam    = 0;             // 0 = auto (proxy if org dll loads, fake otherwise), 1 = force fake
    // Optional fake-mode SteamID. Keep the old default so existing packs need
    // no config changes. Set a unique value per synthetic client for bot tests.
    uint64_t fake_steam_id = 0x0110000100000001ULL;
} g_cfg;

static char* Trim(char* s) {
    while (*s == ' ' || *s == '\t') ++s;
    char* end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n'))
        *--end = 0;
    return s;
}

static void LoadConfig() {
    char path[MAX_PATH]{};
    GetSelfDir(path, MAX_PATH);
    strncat_s(path, sizeof(path), "ds2net.ini", _TRUNCATE);

    FILE* f = nullptr;
    fopen_s(&f, path, "r");
    if (!f) {
        Log("no ds2net.ini found, using defaults (login_ip=%s)", g_cfg.login_ip);
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char* p = Trim(line);
        if (*p == 0 || *p == ';' || *p == '#' || *p == '[') continue;
        char* eq = strchr(p, '=');
        if (!eq) continue;
        *eq = 0;
        char* key = Trim(p);
        char* val = Trim(eq + 1);
        // Strip trailing comment.
        char* sc = strchr(val, ';');
        if (sc) *sc = 0;
        val = Trim(val);

        if (_stricmp(key, "login_ip") == 0) {
            strncpy_s(g_cfg.login_ip, val, _TRUNCATE);
        } else if (_stricmp(key, "login_port") == 0) {
            g_cfg.login_port = atoi(val);
        } else if (_stricmp(key, "hook_dns") == 0) {
            g_cfg.hook_dns = (atoi(val) != 0);
        } else if (_stricmp(key, "real_dll") == 0) {
            strncpy_s(g_cfg.real_dll, val, _TRUNCATE);
        } else if (_stricmp(key, "log_packets") == 0) {
            g_cfg.log_packets = (atoi(val) != 0);
        } else if (_stricmp(key, "server_ip") == 0) {
            strncpy_s(g_cfg.server_ip, val, _TRUNCATE);
        } else if (_stricmp(key, "relay_port") == 0) {
            g_cfg.relay_port = atoi(val);
        } else if (_stricmp(key, "log_calls") == 0) {
            g_cfg.log_calls = (atoi(val) != 0);
        } else if (_stricmp(key, "fake_steam") == 0) {
            g_cfg.fake_steam = atoi(val);
        } else if (_stricmp(key, "fake_steam_id") == 0) {
            char* end = nullptr;
            unsigned long long id = strtoull(val, &end, 0);  // 0x hex or decimal
            if (end != val && id != 0) {
                g_cfg.fake_steam_id = (uint64_t)id;
            } else {
                Log("ini: ignoring invalid fake_steam_id '%s'", val);
            }
        } else {
            Log("ini: ignoring unknown key '%s'", key);
        }
    }
    fclose(f);

    Log("config loaded: login_ip=%s login_port=%d hook_dns=%d real_dll=%s server_ip=%s relay_port=%d log_calls=%d fake_steam=%d fake_steam_id=%016llx",
        g_cfg.login_ip, g_cfg.login_port, (int)g_cfg.hook_dns, g_cfg.real_dll,
        g_cfg.server_ip, g_cfg.relay_port, (int)g_cfg.log_calls, g_cfg.fake_steam,
        (unsigned long long)g_cfg.fake_steam_id);
    g_log_calls = g_cfg.log_calls;
}

// ---------------------------------------------------------------------------
// Login host redirect
// ---------------------------------------------------------------------------

static const char kLoginHost[] = "frpg2-steam64-ope-login.fromsoftware-game.net";
static const char kFromSoftDomain[] = "fromsoftware-game.net";

typedef int (WSAAPI *getaddrinfo_t)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
typedef struct hostent* (WSAAPI *gethostbyname_t)(PCSTR);

static getaddrinfo_t    g_orig_getaddrinfo = nullptr;
static gethostbyname_t  g_orig_gethostbyname = nullptr;
static int              g_dns_logs_left = 24;

// The game hardcodes the login port (50031), so rewriting only the IP is not
// enough when ds2net.ini uses a different login_port. Arm a short-lived hint
// when the exact login hostname is resolved; the next connect() then also
// gets our configured port. Normal/production configs are unaffected.
static volatile LONG     g_login_dns_pending = 0;
static volatile ULONGLONG g_login_dns_time = 0;

static void ArmLoginConnectRedirect() {
    g_login_dns_time = (ULONGLONG)GetTickCount64();
    InterlockedExchange(&g_login_dns_pending, 1);
}

static bool IsFromSoftHost(const char* node) {
    if (!node) return false;
    size_t nlen = strlen(node);
    size_t dlen = strlen(kFromSoftDomain);
    if (nlen < dlen) return false;
    const char* tail = node + (nlen - dlen);
    return _stricmp(tail, kFromSoftDomain) == 0;
}

static int WSAAPI Hook_getaddrinfo(PCSTR node, PCSTR service,
                                   const ADDRINFOA* hints, PADDRINFOA* result) {
    if (g_cfg.hook_dns && IsFromSoftHost(node)) {
        if (g_dns_logs_left-- > 0) {
            Log("getaddrinfo(\"%s\", \"%s\") -> rewritten to %s",
                node, service ? service : "(null)", g_cfg.login_ip);
        }
        if (_stricmp(node, kLoginHost) == 0) ArmLoginConnectRedirect();
        return g_orig_getaddrinfo(g_cfg.login_ip, service, hints, result);
    }
    return g_orig_getaddrinfo(node, service, hints, result);
}

static struct hostent* WSAAPI Hook_gethostbyname(PCSTR name) {
    if (g_cfg.hook_dns && IsFromSoftHost(name)) {
        if (g_dns_logs_left-- > 0) {
            Log("gethostbyname(\"%s\") -> rewritten to %s", name, g_cfg.login_ip);
        }
        if (_stricmp(name, kLoginHost) == 0) ArmLoginConnectRedirect();
        return g_orig_gethostbyname(g_cfg.login_ip);
    }
    return g_orig_gethostbyname(name);
}

// Patch every IAT slot in `mod` whose current value equals `target` with
// `replacement`. Matching by resolved address instead of import name is
// required here: DarkSoulsII.exe imports most ws2_32 functions by ordinal, so
// the import-by-name table is empty for things like gethostbyname/connect.
static int PatchIATByAddress(HMODULE mod, const char* dllName, void* target,
                             void* replacement, const char* label) {
    if (!mod || !target) return 0;

    auto base = (uint8_t*)mod;
    auto dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress) return 0;

    int replaced = 0;
    auto imp = (IMAGE_IMPORT_DESCRIPTOR*)(base + dir.VirtualAddress);
    for (; imp->Name; ++imp) {
        const char* name = (const char*)(base + imp->Name);
        if (_stricmp(name, dllName) != 0) continue;
        if (!imp->FirstThunk) continue;

        auto iat = (void**)(base + imp->FirstThunk);
        for (size_t i = 0; iat[i]; ++i) {
            if (iat[i] != target) continue;

            DWORD oldProt = 0;
            if (VirtualProtect(&iat[i], sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProt)) {
                iat[i] = replacement;
                VirtualProtect(&iat[i], sizeof(void*), oldProt, &oldProt);
                ++replaced;
            } else {
                Log("patch: VirtualProtect failed err=%lu", GetLastError());
            }
        }
    }

    if (replaced) {
        Log("IAT hook: %s!%s -> %p in %p (%d slot%s)",
            dllName, label, replacement, (void*)mod, replaced, replaced == 1 ? "" : "s");
    }
    return replaced;
}

// Patch every loaded module, not just the exe: the game may do DNS/connect from
// a helper DLL.
static int PatchAllModules(const char* dllName, void* target, void* replacement,
                           const char* label) {
    HMODULE exe = GetModuleHandleA(nullptr);
    int total = PatchIATByAddress(exe, dllName, target, replacement, label);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 me{};
        me.dwSize = sizeof(me);
        for (BOOL ok = Module32First(snap, &me); ok; ok = Module32Next(snap, &me)) {
            if (me.hModule == exe) continue;
            total += PatchIATByAddress(me.hModule, dllName, target, replacement, label);
        }
        CloseHandle(snap);
    }
    return total;
}

// Last-resort safety net: if the game resolves the real host and dials the
// login port, point that connection at our server too. Also logs everything
// the game connects to, which is how we learn the real flow.
typedef int (WSAAPI *connect_t)(SOCKET, const struct sockaddr*, int);
static connect_t g_orig_connect = nullptr;
static int       g_connect_logs_left = 48;

static int WSAAPI Hook_connect(SOCKET s, const struct sockaddr* name, int namelen) {
    if (!g_orig_connect || !name) return SOCKET_ERROR;

    if (name->sa_family == AF_INET && namelen >= (int)sizeof(sockaddr_in)) {
        auto* in = (const sockaddr_in*)name;
        unsigned short port = ntohs(in->sin_port);
        char ip[64] = {};
        inet_ntop(AF_INET, &in->sin_addr, ip, sizeof(ip));

        // Port match keeps the original behaviour. The DNS hint additionally
        // handles configs where login_port differs from the client's hardcoded
        // port (isolated test servers).
        ULONGLONG now = (ULONGLONG)GetTickCount64();
        bool dnsHint = InterlockedCompareExchange(&g_login_dns_pending, 0, 0) != 0;
        if (dnsHint && now - g_login_dns_time > 5000) {
            InterlockedExchange(&g_login_dns_pending, 0);
            dnsHint = false;
        }
        bool redirect = g_cfg.hook_dns &&
                        (port == (unsigned short)g_cfg.login_port || dnsHint);
        if (redirect) {
            InterlockedExchange(&g_login_dns_pending, 0);
            Log("connect(%s:%u)  -> redirected to login server%s",
                ip, port, dnsHint && port != (unsigned short)g_cfg.login_port ? " (dns hint)" : "");
            sockaddr_in dst = *in;
            dst.sin_port = htons((u_short)g_cfg.login_port);
            inet_pton(AF_INET, g_cfg.login_ip, &dst.sin_addr);
            return g_orig_connect(s, (const sockaddr*)&dst, sizeof(dst));
        }
        if (g_connect_logs_left-- > 0) {
            Log("connect(%s:%u)", ip, port);
        }
    } else if (g_connect_logs_left-- > 0) {
        Log("connect(family=%d len=%d) (not rewritten)", name->sa_family, namelen);
    }

    return g_orig_connect(s, name, namelen);
}

static void InstallRedirect() {
    Log("redirect: begin");

    // Never call LoadLibrary from DllMain: it runs under the loader lock and
    // deadlocks. By the time the game calls any Steam entry point, the exe's
    // own imports (ws2_32 included) are all resolved.
    HMODULE ws2 = GetModuleHandleA("ws2_32.dll");
    if (!ws2) ws2 = LoadLibraryA("ws2_32.dll");
    if (!ws2) {
        Log("FATAL: ws2_32.dll not loaded, cannot install login redirect");
        return;
    }

    g_orig_getaddrinfo   = (getaddrinfo_t)  GetProcAddress(ws2, "getaddrinfo");
    g_orig_gethostbyname = (gethostbyname_t)GetProcAddress(ws2, "gethostbyname");
    g_orig_connect       = (connect_t)      GetProcAddress(ws2, "connect");
    if (!g_orig_getaddrinfo || !g_orig_gethostbyname || !g_orig_connect) {
        Log("FATAL: ws2_32 exports missing (getaddrinfo=%p gethostbyname=%p connect=%p)",
            (void*)g_orig_getaddrinfo, (void*)g_orig_gethostbyname, (void*)g_orig_connect);
        return;
    }

    if (!g_cfg.hook_dns) {
        Log("login redirect disabled by config");
        return;
    }

    int a = PatchAllModules("WS2_32.dll", (void*)g_orig_getaddrinfo,   (void*)Hook_getaddrinfo,   "getaddrinfo");
    int b = PatchAllModules("WS2_32.dll", (void*)g_orig_gethostbyname, (void*)Hook_gethostbyname, "gethostbyname");
    int c = PatchAllModules("WS2_32.dll", (void*)g_orig_connect,       (void*)Hook_connect,       "connect");

    Log("login redirect active: *%s -> %s:%d (getaddrinfo=%d gethostbyname=%d connect=%d)",
        kFromSoftDomain, g_cfg.login_ip, g_cfg.login_port, a, b, c);
}

// ---------------------------------------------------------------------------
// Login server RSA public key
//
// The 1.0.2.0 client encrypts its login hello with a public key baked into
// DarkSoulsII.exe. ds3os generates its own keypair, so the server can never
// decrypt what the client sends unless the client's copy of the public key is
// replaced. Same trick as the reference mod (dinput8.dll): find the PEM in the
// exe's image and overwrite it with our server's public.key.
// ---------------------------------------------------------------------------

static const char kFromSoftRsaKey[] =
    "-----BEGIN RSA PUBLIC KEY-----\n"
    "MIIBCAKCAQEAxSeDuBTm3AytrIOGjDKpwJY+437i1F8leMBASVkknYdzM5HB4z8X\n"
    "YTXDylr/N6XAhgr/LcFFZ68yQNQ4AquriMONB+TWUiX0xu84ixYH3AqRtIVqLQbQ\n"
    "xKZsTfyCRC94n9EnvPeS+ueM495YhLIJQBf9T2aCeoHZBFDh2CghJQCdyd4dOT/E\n"
    "9ZxPImwj1t2fZkkKo4smpGk7GcCask2SGsnk/P2jUJxsOyFlCojaW1IldPxn+lXH\n"
    "dlgHSLjQvMlWiZ2SmOwvJqPWMv6XyUXYqsOdejRJJQjV7jeDzYG8trX+bSQxnTAw\n"
    "ENjvjslEcjBmzOCiqFTA/9H1jMjReZpI/wIBAw==\n"
    "-----END RSA PUBLIC KEY-----\n";

// Overwrite the FromSoft key in the exe's image. `newKey` must be a complete
// PEM (BEGIN..END) and never longer than the original; the tail is zero-filled.
static bool PatchRsaPublicKey(const char* newKey) {
    HMODULE exe = GetModuleHandleA(nullptr);
    if (!exe) { Log("rsa: no exe module"); return false; }

    auto base = (uint8_t*)exe;
    auto dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    size_t oldLen = sizeof(kFromSoftRsaKey) - 1;
    size_t newLen = strlen(newKey);
    if (newLen > oldLen) {
        Log("rsa: new key too long (%zu > %zu)", newLen, oldLen);
        return false;
    }

    // Search the exe's mapped image.
    size_t imageSize = nt->OptionalHeader.SizeOfImage;
    uint8_t* found = nullptr;
    for (size_t off = 0; off + oldLen <= imageSize; ++off) {
        if (memcmp(base + off, kFromSoftRsaKey, oldLen) == 0) { found = base + off; break; }
    }
    if (!found) {
        Log("rsa: original key not found in image (scanned 0x%zx bytes)", imageSize);
        return false;
    }

    DWORD oldProt = 0;
    if (!VirtualProtect(found, oldLen, PAGE_READWRITE, &oldProt)) {
        Log("rsa: VirtualProtect failed at %p err=%lu", (void*)found, GetLastError());
        return false;
    }
    memcpy(found, newKey, newLen);
    if (newLen < oldLen) memset(found + newLen, 0, oldLen - newLen);
    VirtualProtect(found, oldLen, oldProt, &oldProt);

    Log("rsa: patched public key at %p (exe+%p), %zu -> %zu bytes",
        (void*)found, (void*)((uint8_t*)found - base), oldLen, newLen);
    return true;
}

static void PatchRsaKeyFromDisk() {
    char path[MAX_PATH]{};
    GetSelfDir(path, MAX_PATH);
    strncat_s(path, sizeof(path), "ds2net_rsa.pub", _TRUNCATE);

    FILE* f = nullptr;
    fopen_s(&f, path, "rb");
    if (!f) {
        Log("rsa: no ds2net_rsa.pub next to the game (login will fail)");
        return;
    }
    char key[4096]{};
    size_t n = fread(key, 1, sizeof(key) - 1, f);
    fclose(f);
    key[n] = 0;
    // Accept both LF and CRLF files.
    for (size_t i = 0; i < n; ++i) if (key[i] == '\r') memmove(key + i, key + i + 1, n - i);
    PatchRsaPublicKey(key);
}

// ---------------------------------------------------------------------------
// Fake Steam mode (no Valve DLL, no Steam client on the machine)
//
// Friends play with NO Steam installed. We cannot load steam_api64_org.dll,
// so every export is served from built-in stub objects. Each vtable slot is
// a naked trampoline that logs (iface, slot) and returns 0; the handful of
// slots the game actually depends on are overridden with real behaviour:
// Steam identity, login state, app id, language, persona name/state.
// ---------------------------------------------------------------------------

// Fake-mode identity comes from ds2net.ini (default keeps old behaviour):
//   fake_steam_id = 0x0110000100000002
// A stable, well-formed SteamID: universe public, account type individual.

// ds3os does not validate the ticket when Steam auth is disabled, but the game
// still needs a non-zero ticket length before it sends the SteamTicket message.
static const uint32_t kFakeTicketBytes = 128;

// Fake callbacks. Only the one DS2 waits on during login is needed:
//   GetAuthSessionTicketResponse_t = k_iSteamUserCallbacks(100) + 63 = 163
struct FakeCallbackReg {
    void* cb;
    int   id;
};
static FakeCallbackReg g_fake_callbacks[32];
static uint32_t        g_fake_pending_ticket = 0;

enum { FAKE_IFACE_USER = 0, FAKE_IFACE_APPS, FAKE_IFACE_UTILS, FAKE_IFACE_STATS,
       FAKE_IFACE_FRIENDS, FAKE_IFACE_CLIENT, FAKE_IFACE_MM, FAKE_IFACE_NET,
       FAKE_IFACE_COUNT };

static const char* kFakeIfaceNames[FAKE_IFACE_COUNT] = {
    "SteamUser021", "SteamApps008", "SteamUtils010", "SteamUserStats012",
    "SteamFriends017", "SteamClient020", "SteamMatchMaking009", "SteamNetworking006",
};

static unsigned g_fake_total[FAKE_IFACE_COUNT][64];
static unsigned g_fake_logged[FAKE_IFACE_COUNT][64];

extern "C" void FakeSlotLog(unsigned iface, unsigned slot) {
    if (iface >= FAKE_IFACE_COUNT || slot >= 64) return;
    g_fake_total[iface][slot]++;
    if (g_fake_logged[iface][slot] >= 8) return;   // first 8 per slot only
    g_fake_logged[iface][slot]++;
    Log("fake steam: %s vt+%02d called (total #%u)",
        kFakeIfaceNames[iface], slot, g_fake_total[iface][slot]);
}

// One generic trampoline per vtable slot: log, then return 0 / 0.0f.
// The game allocated shadow space for us; FakeSlotLog needs its own, so we
// carve 0x28 bytes (32 shadow + 8 alignment) before the call.
#define MAKE_FAKE(FUNC, IFACE, SLOT)                          \
extern "C" __attribute__((naked)) void FUNC(void) {           \
    __asm__ volatile(                                         \
        "sub $0x28, %rsp\n\t"                                 \
        "movl $" #IFACE ", %ecx\n\t"                          \
        "movl $" #SLOT ", %edx\n\t"                           \
        "call FakeSlotLog\n\t"                                \
        "add $0x28, %rsp\n\t"                                 \
        "xorl %eax, %eax\n\t"                                 \
        "xorps %xmm0, %xmm0\n\t"                              \
        "ret\n\t" );                                          \
}

#define FAKE_SLOTS(NAME, IFACE, COUNT)                       \
    MAKE_FAKE(FakeStub_##NAME##_0,  IFACE,  0)               \
    MAKE_FAKE(FakeStub_##NAME##_1,  IFACE,  1)               \
    MAKE_FAKE(FakeStub_##NAME##_2,  IFACE,  2)               \
    MAKE_FAKE(FakeStub_##NAME##_3,  IFACE,  3)               \
    MAKE_FAKE(FakeStub_##NAME##_4,  IFACE,  4)               \
    MAKE_FAKE(FakeStub_##NAME##_5,  IFACE,  5)               \
    MAKE_FAKE(FakeStub_##NAME##_6,  IFACE,  6)               \
    MAKE_FAKE(FakeStub_##NAME##_7,  IFACE,  7)               \
    MAKE_FAKE(FakeStub_##NAME##_8,  IFACE,  8)               \
    MAKE_FAKE(FakeStub_##NAME##_9,  IFACE,  9)               \
    MAKE_FAKE(FakeStub_##NAME##_10, IFACE, 10)               \
    MAKE_FAKE(FakeStub_##NAME##_11, IFACE, 11)               \
    MAKE_FAKE(FakeStub_##NAME##_12, IFACE, 12)               \
    MAKE_FAKE(FakeStub_##NAME##_13, IFACE, 13)               \
    MAKE_FAKE(FakeStub_##NAME##_14, IFACE, 14)               \
    MAKE_FAKE(FakeStub_##NAME##_15, IFACE, 15)               \
    MAKE_FAKE(FakeStub_##NAME##_16, IFACE, 16)               \
    MAKE_FAKE(FakeStub_##NAME##_17, IFACE, 17)               \
    MAKE_FAKE(FakeStub_##NAME##_18, IFACE, 18)               \
    MAKE_FAKE(FakeStub_##NAME##_19, IFACE, 19)               \
    MAKE_FAKE(FakeStub_##NAME##_20, IFACE, 20)               \
    MAKE_FAKE(FakeStub_##NAME##_21, IFACE, 21)               \
    MAKE_FAKE(FakeStub_##NAME##_22, IFACE, 22)               \
    MAKE_FAKE(FakeStub_##NAME##_23, IFACE, 23)               \
    MAKE_FAKE(FakeStub_##NAME##_24, IFACE, 24)               \
    MAKE_FAKE(FakeStub_##NAME##_25, IFACE, 25)               \
    MAKE_FAKE(FakeStub_##NAME##_26, IFACE, 26)               \
    MAKE_FAKE(FakeStub_##NAME##_27, IFACE, 27)               \
    MAKE_FAKE(FakeStub_##NAME##_28, IFACE, 28)               \
    MAKE_FAKE(FakeStub_##NAME##_29, IFACE, 29)               \
    MAKE_FAKE(FakeStub_##NAME##_30, IFACE, 30)               \
    MAKE_FAKE(FakeStub_##NAME##_31, IFACE, 31)               \
    MAKE_FAKE(FakeStub_##NAME##_32, IFACE, 32)               \
    MAKE_FAKE(FakeStub_##NAME##_33, IFACE, 33)               \
    MAKE_FAKE(FakeStub_##NAME##_34, IFACE, 34)               \
    MAKE_FAKE(FakeStub_##NAME##_35, IFACE, 35)               \
    MAKE_FAKE(FakeStub_##NAME##_36, IFACE, 36)               \
    MAKE_FAKE(FakeStub_##NAME##_37, IFACE, 37)               \
    MAKE_FAKE(FakeStub_##NAME##_38, IFACE, 38)               \
    MAKE_FAKE(FakeStub_##NAME##_39, IFACE, 39)

FAKE_SLOTS(user,    0, 40)
FAKE_SLOTS(apps,    1, 40)
FAKE_SLOTS(utils,   2, 40)
FAKE_SLOTS(stats,   3, 40)
FAKE_SLOTS(friends, 4, 40)
FAKE_SLOTS(client,  5, 40)
FAKE_SLOTS(mm,      6, 40)
FAKE_SLOTS(net,     7, 40)

// Overridden slots with real behaviour.
// GetSteamID follows the hidden-sret convention the 1.0.2.0 client compiles
// against: the game passes the out-pointer in rdx and dereferences the
// returned pointer. Writing the ID through rdx and returning rdx satisfies
// both sret and by-value callers without ever returning a bare integer that
// the game would dereference.
extern "C" void* Fake_GetSteamID(void* self, void* out) {
    (void)self;
    Log("fake steam: GetSteamID -> %016llx (sret=%p)",
        (unsigned long long)g_cfg.fake_steam_id, out);
    if (out) *(uint64_t*)out = g_cfg.fake_steam_id;
    return out;
}

// ISteamUser021 slot 13: GetAuthSessionTicket(void*, int, uint32_t*).
// Fills a deterministic pseudo-random blob so the client sends a non-empty
// SteamTicket message; ds3os accepts it with EnableSteamAuth=false.
extern "C" uint32_t Fake_GetAuthSessionTicket(void* self, void* pTicket,
                                               int cbMaxTicket, uint32_t* pcbTicket) {
    (void)self;
    uint32_t n = (cbMaxTicket > 0) ? (uint32_t)cbMaxTicket : 0;
    if (n > kFakeTicketBytes) n = kFakeTicketBytes;

    static uint32_t s_handle = 1;
    uint32_t handle = s_handle++;

    if (pTicket && n) {
        uint64_t x = g_cfg.fake_steam_id ^ 0x9e3779b97f4a7c15ULL ^
                     ((uint64_t)handle << 32);
        uint8_t* dst = (uint8_t*)pTicket;
        for (uint32_t i = 0; i < n; ++i) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            dst[i] = (uint8_t)(x >> 24);
        }
    }
    if (pcbTicket) *pcbTicket = n;

    Log("fake steam: GetAuthSessionTicket -> handle=%u bytes=%u max=%d",
        handle, n, cbMaxTicket);
    g_fake_pending_ticket = handle;
    return handle;
}

extern "C" uint32_t Fake_GetHSteamUser()      { return 1; }
extern "C" bool     Fake_BLoggedOn()          { return true; }
extern "C" int      Fake_UniversePublic()     { return 1; }  // k_EUniversePublic
extern "C" uint32_t Fake_AppId480()           { return 480; }
extern "C" const char* Fake_LangEnglish()     { return "english"; }
extern "C" const char* Fake_PersonaName()     { return "Player"; }
extern "C" int      Fake_PersonaOnline()      { return 1; }  // k_EPersonaStateOnline
extern "C" bool     Fake_True()               { return true; }
extern "C" uint32_t Fake_Pipe1()              { return 1; }
extern "C" uint32_t Fake_User1()              { return 1; }

#define FAKE_TABLE(TBL, PREFIX)                                      \
static void* TBL##_vt[40] = {                                         \
    (void*)FakeStub_##PREFIX##_0,  (void*)FakeStub_##PREFIX##_1,      \
    (void*)FakeStub_##PREFIX##_2,  (void*)FakeStub_##PREFIX##_3,      \
    (void*)FakeStub_##PREFIX##_4,  (void*)FakeStub_##PREFIX##_5,      \
    (void*)FakeStub_##PREFIX##_6,  (void*)FakeStub_##PREFIX##_7,      \
    (void*)FakeStub_##PREFIX##_8,  (void*)FakeStub_##PREFIX##_9,      \
    (void*)FakeStub_##PREFIX##_10, (void*)FakeStub_##PREFIX##_11,     \
    (void*)FakeStub_##PREFIX##_12, (void*)FakeStub_##PREFIX##_13,     \
    (void*)FakeStub_##PREFIX##_14, (void*)FakeStub_##PREFIX##_15,     \
    (void*)FakeStub_##PREFIX##_16, (void*)FakeStub_##PREFIX##_17,     \
    (void*)FakeStub_##PREFIX##_18, (void*)FakeStub_##PREFIX##_19,     \
    (void*)FakeStub_##PREFIX##_20, (void*)FakeStub_##PREFIX##_21,     \
    (void*)FakeStub_##PREFIX##_22, (void*)FakeStub_##PREFIX##_23,     \
    (void*)FakeStub_##PREFIX##_24, (void*)FakeStub_##PREFIX##_25,     \
    (void*)FakeStub_##PREFIX##_26, (void*)FakeStub_##PREFIX##_27,     \
    (void*)FakeStub_##PREFIX##_28, (void*)FakeStub_##PREFIX##_29,     \
    (void*)FakeStub_##PREFIX##_30, (void*)FakeStub_##PREFIX##_31,     \
    (void*)FakeStub_##PREFIX##_32, (void*)FakeStub_##PREFIX##_33,     \
    (void*)FakeStub_##PREFIX##_34, (void*)FakeStub_##PREFIX##_35,     \
    (void*)FakeStub_##PREFIX##_36, (void*)FakeStub_##PREFIX##_37,     \
    (void*)FakeStub_##PREFIX##_38, (void*)FakeStub_##PREFIX##_39,     \
};                                                                    \
static void* TBL##_obj[1] = { (void*)TBL##_vt };

FAKE_TABLE(g_fake_user,    user)
FAKE_TABLE(g_fake_apps,    apps)
FAKE_TABLE(g_fake_utils,   utils)
FAKE_TABLE(g_fake_stats,   stats)
FAKE_TABLE(g_fake_friends, friends)
FAKE_TABLE(g_fake_client,  client)
FAKE_TABLE(g_fake_mm,      mm)
FAKE_TABLE(g_fake_net,     net)

// Accessors the game can call to fetch sub-interfaces (return interface ptr).
extern "C" void* Fake_GetISteamUserFake()    { return g_fake_user_obj; }
extern "C" void* Fake_GetISteamFriendsFake() { return g_fake_friends_obj; }
extern "C" void* Fake_GetISteamUtilsFake()   { return g_fake_utils_obj; }
extern "C" void* Fake_GetISteamMMFake()      { return g_fake_mm_obj; }

static void FakeSteam_InstallOverrides() {
    // ISteamUser021: 0 GetHSteamUser, 1 BLoggedOn, 2 GetSteamID
    g_fake_user_vt[0] = (void*)Fake_GetHSteamUser;
    g_fake_user_vt[1] = (void*)Fake_BLoggedOn;
    g_fake_user_vt[2] = (void*)Fake_GetSteamID;
    // ISteamUser021: 13 GetAuthSessionTicket (the real call at auth connect).
    g_fake_user_vt[13] = (void*)Fake_GetAuthSessionTicket;
    // ISteamUtils010: 2 GetConnectedUniverse, 8 GetAppID
    g_fake_utils_vt[2] = (void*)Fake_UniversePublic;
    g_fake_utils_vt[8] = (void*)Fake_AppId480;
    // ISteamApps008: 0 BIsSubscribed, 4 GetCurrentGameLanguage,
    //                5 GetAvailableGameLanguages, 6 BIsSubscribedApp, 7 BIsDlcInstalled
    g_fake_apps_vt[0] = (void*)Fake_True;
    g_fake_apps_vt[4] = (void*)Fake_LangEnglish;
    g_fake_apps_vt[5] = (void*)Fake_LangEnglish;
    g_fake_apps_vt[6] = (void*)Fake_True;
    g_fake_apps_vt[7] = (void*)Fake_True;
    // ISteamFriends017: 0 GetPersonaName, 2 GetPersonaState
    g_fake_friends_vt[0] = (void*)Fake_PersonaName;
    g_fake_friends_vt[2] = (void*)Fake_PersonaOnline;
    // ISteamUserStats012: 0 RequestCurrentStats
    g_fake_stats_vt[0] = (void*)Fake_True;
    // ISteamClient020: 0 CreateSteamPipe, 1 BReleaseSteamPipe,
    //                  2 ConnectToGlobalUser, 3 CreateLocalUser,
    //                  5 GetISteamUser, 8 GetISteamFriends, 9 GetISteamUtils,
    //                  10 GetISteamMatchmaking
    g_fake_client_vt[0] = (void*)Fake_Pipe1;
    g_fake_client_vt[1] = (void*)Fake_True;
    g_fake_client_vt[2] = (void*)Fake_User1;
    g_fake_client_vt[3] = (void*)Fake_User1;
    g_fake_client_vt[5] = (void*)Fake_GetISteamUserFake;
    g_fake_client_vt[8] = (void*)Fake_GetISteamFriendsFake;
    g_fake_client_vt[9] = (void*)Fake_GetISteamUtilsFake;
    g_fake_client_vt[10] = (void*)Fake_GetISteamMMFake;
}

// Steam delivers GetAuthSessionTicketResponse_t asynchronously. DS2 registers
// callback 163 before login and waits for it after asking for a ticket, so we
// must invoke CCallbackBase::Run(void*) on that registered object.
static void FakeSteam_DispatchCallbacks() {
    uint32_t handle = g_fake_pending_ticket;
    if (!handle) return;

    struct GetAuthSessionTicketResponseFake {
        uint32_t m_hAuthTicket;
        int      m_eResult;   // k_EResultOK = 1
    } param{ handle, 1 };

    bool delivered = false;
    for (auto& reg : g_fake_callbacks) {
        if (!reg.cb || reg.id != 163) continue;
        auto vt = *(void***)reg.cb;
        if (!vt || !vt[0]) continue;
        auto run = (void (*)(void*, void*))vt[0];
        run(reg.cb, &param);
        Log("fake steam: dispatched callback 163 (ticket=%u, OK) to %p", handle, reg.cb);
        delivered = true;
    }
    if (delivered) g_fake_pending_ticket = 0;
}

// ---------------------------------------------------------------------------
// Steam proxy / fake-mode selection
// ---------------------------------------------------------------------------

static HMODULE g_real = nullptr;
static int     g_mode = -1;   // 1 = proxy (Valve dll), 2 = fake (built-in stubs)

static int Mode();   // defined below; EnsureInit decides the mode

// First-use initialisation. Anything that loads libraries or touches the
// network must happen here, never in DllMain.
static void EnsureInit() {
    static volatile LONG state = 0; // 0 = pending, 1 = in progress, 2 = done
    if (InterlockedCompareExchange(&state, 1, 0) != 0) {
        while (state != 2) Sleep(0);
        return;
    }
    LoadConfig();
    InstallRedirect();
    PatchRsaKeyFromDisk();
    Mode();
    InterlockedExchange(&state, 2);
}

// Decide the serving mode exactly once. Proxy if the Valve dll can be
// loaded, fake otherwise (friends have no Steam installed at all).
static int Mode() {
    if (g_mode != -1) return g_mode;
    if (g_cfg.fake_steam == 1) {
        Log("fake_steam=1 in ini: forcing fake Steam mode");
        g_mode = 2;
    } else {
        g_real = LoadLibraryA(g_cfg.real_dll);
        if (g_real) {
            Log("loaded %s at %p", g_cfg.real_dll, (void*)g_real);
            g_mode = 1;
        } else {
            Log("%s not available (err=%lu): fake Steam mode (no Valve dll needed)",
                g_cfg.real_dll, GetLastError());
            g_mode = 2;
        }
    }
    if (g_mode == 2) FakeSteam_InstallOverrides();
    return g_mode;
}

static FARPROC Real(const char* name) {
    EnsureInit();
    if (Mode() != 1) return nullptr;
    FARPROC p = GetProcAddress(g_real, name);
    if (!p) Log("WARN: %s has no export %s", g_cfg.real_dll, name);
    return p;
}

// Modern valve steam_api64.dlls no longer export the legacy flat accessors
// (SteamUser(), SteamUtils(), ...). They only export
// SteamInternal_FindOrCreateUserInterface, which is exactly what the SDK's own
// accessor macros call:
//
//   S_API ISteamX *SteamX() {
//       return SteamInternal_FindOrCreateUserInterface(
//           SteamAPI_GetHSteamUser(), STEAMX_INTERFACE_VERSION);
//   }
//
// SteamUtils is special-cased in the SDK to pass user handle 0.
typedef void* (*FindOrCreateUserInterface_t)(int hSteamUser, const char* version);
typedef int   (*GetHSteamUser_t)();

static FindOrCreateUserInterface_t g_findUserIface = nullptr;
static GetHSteamUser_t             g_getHSteamUser = nullptr;

static void* GetIface(const char* name, const char* version, bool userHandleZero) {
    if (Mode() == 2) {
        void* fake = nullptr;
        if      (!strcmp(name, "SteamUser"))       fake = g_fake_user_obj;
        else if (!strcmp(name, "SteamApps"))       fake = g_fake_apps_obj;
        else if (!strcmp(name, "SteamUtils"))      fake = g_fake_utils_obj;
        else if (!strcmp(name, "SteamUserStats"))  fake = g_fake_stats_obj;
        else if (!strcmp(name, "SteamFriends"))    fake = g_fake_friends_obj;
        else if (!strcmp(name, "SteamMatchmaking")) fake = g_fake_mm_obj;
        else if (!strcmp(name, "SteamNetworking")) fake = g_fake_net_obj;
        if (fake) {
            static const char* loggedF[8] = {};
            for (int i = 0; i < 8; ++i) {
                if (loggedF[i] == name) break;
                if (!loggedF[i]) {
                    loggedF[i] = name;
                    Log("%s() [%s] -> fake stub object %p", name, version, fake);
                    break;
                }
            }
            return fake;
        }
        Log("fake steam: no stub object for '%s'", name);
        return nullptr;
    }

    if (!g_findUserIface) {
        g_findUserIface = (FindOrCreateUserInterface_t)
            Real("SteamInternal_FindOrCreateUserInterface");
    }
    if (!g_getHSteamUser) {
        g_getHSteamUser = (GetHSteamUser_t)Real("SteamAPI_GetHSteamUser");
    }

    int user = (!userHandleZero && g_getHSteamUser) ? g_getHSteamUser() : 0;
    void* p = g_findUserIface ? g_findUserIface(user, version) : nullptr;

    static const char* logged[16] = {};
    for (int i = 0; i < 16; ++i) {
        if (logged[i] == name) break;
        if (!logged[i]) {
            logged[i] = name;
            Log("%s() [%s, user=%d] -> %p", name, version, user, p);
            break;
        }
    }
    return p;
}

extern "C" {

__declspec(dllexport) bool SteamAPI_Init() {
    EnsureInit();
    Log("SteamAPI_Init()");
    if (Mode() == 2) { Log("SteamAPI_Init -> true (fake steam)"); return true; }
    auto f = (bool(*)())Real("SteamAPI_Init");
    bool ok = f ? f() : false;
    Log("SteamAPI_Init -> %d", (int)ok);
    return ok;
}

__declspec(dllexport) void SteamAPI_Shutdown() {
    EnsureInit();
    Log("SteamAPI_Shutdown()");
    if (Mode() == 2) return;
    auto f = (void(*)())Real("SteamAPI_Shutdown");
    if (f) f();
}

__declspec(dllexport) void SteamAPI_RunCallbacks() {
    static bool once = false;
    if (!once) { once = true; Log("SteamAPI_RunCallbacks() first call"); }
    if (Mode() == 2) {
        FakeSteam_DispatchCallbacks();
        return;
    }
    auto f = (void(*)())Real("SteamAPI_RunCallbacks");
    if (f) f();
}

__declspec(dllexport) void SteamAPI_RegisterCallback(void* cb, int id) {
    Log("SteamAPI_RegisterCallback(%p, %d)", cb, id);
    if (Mode() == 2) {
        for (auto& reg : g_fake_callbacks) {
            if (reg.cb == cb || !reg.cb) {
                reg.cb = cb;
                reg.id = id;
                break;
            }
        }
        return;
    }
    auto f = (void(*)(void*, int))Real("SteamAPI_RegisterCallback");
    if (f) f(cb, id);
}

__declspec(dllexport) void SteamAPI_UnregisterCallback(void* cb) {
    Log("SteamAPI_UnregisterCallback(%p)", cb);
    if (Mode() == 2) {
        for (auto& reg : g_fake_callbacks) {
            if (reg.cb == cb) { reg.cb = nullptr; reg.id = 0; }
        }
        return;
    }
    auto f = (void(*)(void*))Real("SteamAPI_UnregisterCallback");
    if (f) f(cb);
}

__declspec(dllexport) void SteamAPI_RegisterCallResult(void* cb, uint64_t handle) {
    Log("SteamAPI_RegisterCallResult(%p, %llu)", cb, (unsigned long long)handle);
    if (Mode() == 2) return;
    auto f = (void(*)(void*, uint64_t))Real("SteamAPI_RegisterCallResult");
    if (f) f(cb, handle);
}

__declspec(dllexport) void SteamAPI_UnregisterCallResult(void* cb, uint64_t handle) {
    Log("SteamAPI_UnregisterCallResult(%p, %llu)", cb, (unsigned long long)handle);
    if (Mode() == 2) return;
    auto f = (void(*)(void*, uint64_t))Real("SteamAPI_UnregisterCallResult");
    if (f) f(cb, handle);
}

// DS2 passes appid 335300. With a Spacewar (480) session Steam would try to
// relaunch the "real" app and fail, so we never restart.
__declspec(dllexport) bool SteamAPI_RestartAppIfNecessary(uint32_t appid) {
    Log("SteamAPI_RestartAppIfNecessary(%u) -> false (suppressed)", appid);
    return false;
}

// Interface version strings from the SDK headers (steam_api_flat.h macro
// expansion). Newer interfaces are prefix-compatible with what the 2015 game
// expects, because Valve only ever appends vtable slots.
__declspec(dllexport) void* SteamUser()       { return GetIface("SteamUser",       "SteamUser021",                false); }
__declspec(dllexport) void* SteamApps()       { return GetIface("SteamApps",       "STEAMAPPS_INTERFACE_VERSION008", false); }
__declspec(dllexport) void* SteamUtils()      { return GetIface("SteamUtils",      "SteamUtils010",               true);  }
__declspec(dllexport) void* SteamUserStats()  { return GetIface("SteamUserStats",  "STEAMUSERSTATS_INTERFACE_VERSION012", false); }
__declspec(dllexport) void* SteamFriends()    { return GetIface("SteamFriends",    "SteamFriends017",             false); }
__declspec(dllexport) void* SteamClient() {
    if (Mode() == 2) {
        static bool once2 = false;
        if (!once2) { once2 = true; Log("SteamClient() -> fake (SteamClient020) %p", (void*)g_fake_client_obj); }
        return g_fake_client_obj;
    }
    // This one is a real export of the valve DLL, but the SDK obtains it via
    // SteamInternal_CreateInterface("SteamClient020"). Try the export first.
    auto f = (void*(*)())Real("SteamClient");
    void* p = f ? f() : nullptr;
    static bool once = false;
    if (!once) { once = true; Log("SteamClient() -> %p", p); }
    return p;
}
__declspec(dllexport) void* SteamMatchmaking(){
    if (Mode() == 2) return g_fake_mm_obj;
    EnsureWrappers();
    if (g_wrappers_ready) return g_mm_obj;
    return GetIface("SteamMatchmaking","SteamMatchMaking009",        false);
}
__declspec(dllexport) void* SteamNetworking() {
    if (Mode() == 2) return g_fake_net_obj;
    EnsureWrappers();
    if (g_wrappers_ready) return g_net_obj;
    return GetIface("SteamNetworking", "SteamNetworking006",          false);
}

} // extern "C"

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        // Loader lock is held here: log only, no LoadLibrary / network.
        LogInit();
        Log("ds2net attached");
        AddVectoredExceptionHandler(1, [](PEXCEPTION_POINTERS info) -> LONG {
            DWORD code = info->ExceptionRecord->ExceptionCode;
            // Skip the noisy benign ones: SetThreadName (0x406D1388) and
            // OutputDebugString (0x40010006/0x4001000A).
            if (code != 0x406D1388 && code != 0x40010006 && code != 0x4001000A) {
                Log("EXCEPTION code=0x%08lX addr=%p",
                    code, info->ExceptionRecord->ExceptionAddress);
            }
            return EXCEPTION_CONTINUE_SEARCH;
        });
    }
    return TRUE;
}
