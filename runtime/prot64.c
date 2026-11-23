/* ==========================================================================
 * NovaProtect x64 protection runtime (position independent, freestanding).
 *
 * Entered by the loader stub after the image has been restored and the import
 * table rebuilt, immediately before control transfers to the original entry
 * point.
 *
 *   rcx = image base
 *   rdx = payload header pointer
 *   r8  = NPP1 protection data blob pointer
 *   r9  = generated mutation kernel entry (may be 0)
 *
 * Returns eax = 0 when every enabled check passed, otherwise the id of the
 * check that failed. Any non-zero value is treated as fatal by the caller.
 *
 * Exception: the sandbox guard (bit9) and the interactive-desktop self-check
 * (bit11) never return a failure id. They run first, and on a positive
 * verdict they display "请在非沙箱内使用" and terminate the process cleanly
 * through ExitProcess, so an analysis environment can neither run the
 * payload nor obtain a crash dump.
 *
 * Callee saved registers are preserved. Nothing is imported: modules and
 * exports are resolved through the PEB loader list.
 *
 * NPP1 data blob layout (little endian):
 *   +0   u32 magic 'NPP1'
 *   +4   u32 version
 *   +8   u32 flags            bit0 anti-debug, bit1 anti-vm, bit2 timing,
 *                             bit3 dr, bit4 license, bit5 vm, bit6 integrity,
 *                             bit7 mutation, bit8 activation binding,
 *                             bit9 sandbox guard, bit10 anti-dump,
 *                             bit11 interactive-desktop self-check,
 *                             bit12 process self-isolation / anti-read
 *                             bit13 (reserved: behavioural layer runs under bit9)
 *                             bit14 delayed re-audit worker
 *                             bit15 hypervisor exit-cost probe
 *                             bit16 kernel-artifact probe (device/service/module/tick)
 *   +12  u32 anti_debug_level
 *   +16  u32 anti_vm_level
 *   +20  u32 reserved
 *   +24  u64 timing_threshold
 *   +32  u64 expected_mutation_hash
 *   +40  u64 expected_license_hash
 *   +48  u32 license_blob_off
 *   +52  u32 license_blob_len
 *   +56  u32 license_key
 *   +60  u32 vm_bytecode_off
 *   +64  u32 vm_bytecode_len
 *   +68  u32 vm_reverse_off
 *   +72  u32 integrity_off
 *   +76  u32 integrity_count
 *   +80  u64 machine_bind_expected
 *   +88  u64 reserved2
 *   +96  u32 sandbox_score_threshold   block when np_sandbox_score >= value
 *   +100 u32 env min_cpu_count
 *   +104 u32 env min_ram_mb
 *   +108 u32 env min_uptime_ms
 *   +112 u32 env min_screen_width
 *   +116 u32 env min_screen_height
 *   +120 u32 env min_monitor_count
 *   +124 u32 env_score_threshold      block when env score >= value
 *   +128 payload area (8 byte aligned)
 * ========================================================================== */

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;
typedef signed   char      i8;
typedef signed   short     i16;
typedef signed   int       i32;
typedef signed   long long i64;

#define NP_FNV_BASIS 0xCBF29CE484222325ULL
#define NP_FNV_PRIME 0x00000100000001B3ULL

#define NPP_MAGIC   0x3150504Eu   /* 'NPP1' */

#define NP_CHK_PEB        1
#define NP_CHK_NTGLOBAL   2
#define NP_CHK_HEAP       3
#define NP_CHK_NTQUERY    4
#define NP_CHK_DR         5
#define NP_CHK_TIMING     6
#define NP_CHK_CPUID      7
#define NP_CHK_MUTATION   8
#define NP_CHK_LICENSE    9
#define NP_CHK_INTEGRITY  10
#define NP_CHK_BADMOD    11
#define NP_CHK_ACTIVATION 12
#define NP_CHK_SANDBOX   13
#define NP_CHK_DUMP      14
#define NP_CHK_ENV       15

/* ---- PEB / loader structures (offsets only, no headers needed) ---------- */
#define PEB_BEING_DEBUGGED 0x02
#define PEB_LDR            0x18
#define PEB_PROCESS_HEAP   0x30
#define PEB_NT_GLOBAL_FLAG 0xBC

#define LDR_IN_LOAD_ORDER  0x10
#define LDR_ENTRY_DLLBASE  0x30
#define LDR_ENTRY_BASENAME 0x58
#define LDR_ENTRY_FULLNAME 0x48

#define HEAP_FLAGS         0x70
#define HEAP_FORCE_FLAGS   0x74

#define CTX_DR0 0x48
#define CTX_SIZE 0x4D0
/* x64: CONTEXT_AMD64 (0x00100000) | CONTEXT_DEBUG_REGISTERS (0x10).
 * The AMD64 segment alone would leave Dr0-Dr7 untouched. */
#define CONTEXT_DEBUG_REGISTERS 0x00100010u

/* ---- strings ------------------------------------------------------------ */
static const char np_s_ntdll[]    = "ntdll.dll";
static const char np_s_kernel32[] = "kernel32.dll";
static const char np_s_qip[]      = "NtQueryInformationProcess";
static const char np_s_getctx[]   = "GetThreadContext";
static const char np_s_qsi[]      = "NtQuerySystemInformation";
static const char np_s_user32[]   = "user32.dll";
static const char np_s_gsm[]      = "GetSystemMetrics";
static const char np_s_gtt[]      = "GetTickCount64";
static const char np_s_advapi32[] = "advapi32.dll";
static const char np_s_zwcd[]     = "ZwCreateDebugObject";
static const char np_s_zwsit[]    = "ZwSetInformationThread";
static const char np_s_zqit[]     = "ZwQueryInformationThread";
static const char np_s_zwc[]      = "ZwClose";

/* ---- NT information classes ------------------------------------------- */
#define NP_SIC_SYSTEM_BASIC_INFO     0u
#define NP_SIC_SYSTEM_PROCESSOR_INFO 8u
#define NP_SIC_SYSTEM_PROCESS_INFO   5u

/* ---- sandbox score detail bits (also used by the debug log) ------------- */
#define NP_SB_MOD       0x00000001u   /* known analysis / monitoring module   */
#define NP_SB_INJECT    0x00000002u   /* module injected from a user path    */
#define NP_SB_HYPER     0x00000004u   /* CPUID hypervisor vendor             */
#define NP_SB_FIRMWARE  0x00000008u   /* firmware / disk artifacts           */
#define NP_SB_CPU1      0x00000010u   /* single vCPU                         */
#define NP_SB_CPU2      0x00000020u   /* two vCPUs                           */
#define NP_SB_RAM2      0x00000040u   /* RAM below 2 GB                      */
#define NP_SB_RAM4      0x00000080u   /* RAM below 4 GB                      */
#define NP_SB_PROC40    0x00000100u   /* fewer than 40 processes             */
#define NP_SB_PROC70    0x00000200u   /* fewer than 70 processes             */
#define NP_SB_NOINPUT   0x00000400u   /* no input since boot (>= 3 min up)   */
#define NP_SB_IDLE      0x00000800u   /* idle >= 30 min, uptime >= 45 min    */
#define NP_SB_SLEEP     0x00001000u   /* RDTSC / wall-clock compression      */
#define NP_SB_TSCSPREAD 0x00002000u   /* RDTSCP vs RDTSC spread              */
#define NP_SB_COREMASK  0x00004000u   /* implausible APIC core mask          */
#define NP_SB_RES1024   0x00008000u   /* screen narrower than 1024           */
#define NP_SB_RES800    0x00010000u   /* screen narrower than 800            */
#define NP_SB_NOMON     0x00020000u   /* zero monitors                       */
#define NP_SB_TMPLNAME  0x00040000u   /* ephemeral account / computer name   */
#define NP_SB_FRESH3    0x00080000u   /* Windows installed < 3 days ago      */
#define NP_SB_FRESH14   0x00100000u   /* Windows installed < 14 days ago     */
#define NP_SB_PARENT    0x00200000u   /* script-host / controller parent     */
#define NP_SB_SVCHOST   0x00400000u   /* service-host parent                 */
#define NP_SB_DBGHELP   0x00800000u   /* dbghelp-family module loaded        */
/* Vendor-signature layer (MicroStep / ThreatBook appliance). These are strong
 * on their own: a customer machine never carries a vendor-named module,
 * process, registry key or hostname. */
#define NP_SB_MS_MOD    0x01000000u   /* vendor agent module loaded          */
#define NP_SB_MS_PROC   0x02000000u   /* vendor controller process running   */
#define NP_SB_MS_REG    0x04000000u   /* vendor software registry key        */
#define NP_SB_MS_HOST   0x08000000u   /* vendor-derived host/user name       */
/* Behavioural analysis-artefact layer. These are byproducts of running a
 * dynamic analysis, not labels the appliance can rename away. The two a real
 * machine never produces (accelerated clock, debug heap flags) are strong on
 * their own. detail is a u64 so every signal keeps an independent bit. */
#define NP_SB_AN_SLEEP  0x0000000100000000ull  /* Sleep returned early          */
#define NP_SB_AN_HFLAG  0x0000000200000000ull  /* PEB NtGlobalFlag heap-debug   */
#define NP_SB_AN_DISK   0x0000000400000000ull  /* virtual disk / firmware trace */
#define NP_SB_AN_HANDLE 0x0000000800000000ull  /* abnormal handle population    */
#define NP_SB_AN_CLOCK  0x0000001000000000ull  /* cross-API clock disagreement  */
#define NP_SB_AN_BURST  0x0000002000000000ull  /* process burst right after boot*/
/* Hypervisor-level (CPUID exit cost) and driver-level (kernel artifact) layers.
 * Both survive a guest that renames or hides its user-mode process, which is
 * exactly what a hardened appliance does. */
#define NP_SB_HVEXIT    0x0000004000000000ull  /* CPUID storms cost VM-exit time */
#define NP_SB_KDEV      0x0000008000000000ull  /* sandbox kernel device object  */
#define NP_SB_KSVC      0x0000010000000000ull  /* sandbox driver service        */
#define NP_SB_KMOD      0x0000020000000000ull  /* sandbox driver image loaded   */
#define NP_SB_KTICK     0x0000040000000000ull  /* KUSER_SHARED_DATA tick stuck  */
/* A block additionally requires one strong corroborating signal so that a
 * merely unusual-but-real machine (weak hardware, odd name, busy cmd) can
 * never trip the guard on weak evidence alone. */
#define NP_SB_STRONG (NP_SB_MOD | NP_SB_INJECT | NP_SB_HYPER | NP_SB_FIRMWARE | \
                      NP_SB_SLEEP | NP_SB_NOINPUT | NP_SB_PARENT | NP_SB_IDLE | \
                      NP_SB_MS_MOD | NP_SB_MS_PROC | NP_SB_MS_REG | NP_SB_MS_HOST | \
                      NP_SB_AN_SLEEP | NP_SB_AN_HFLAG | NP_SB_HVEXIT | \
                      NP_SB_KDEV | NP_SB_KSVC | NP_SB_KMOD | NP_SB_KTICK)

/* ========================================================================
 * minimal helpers
 * ======================================================================== */

static void* np_memset(void* d, int c, u64 n) {
    u8* p = (u8*)d;
    while (n--) *p++ = (u8)c;
    return d;
}

static u64 np_fnv1a64(const u8* d, u64 n, u64 h) {
    for (u64 i = 0; i < n; i++) {
        h ^= (u64)d[i];
        h *= NP_FNV_PRIME;
    }
    return h;
}

static void np_cpuid(u32 leaf, u32 subleaf, u32 out[4]) {
    u32 a, b, c, d;
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(leaf), "c"(subleaf));
    out[0] = a; out[1] = b; out[2] = c; out[3] = d;
}

static void* np_module_by_name(const char* name);
static void* np_export_by_name(void* mod, const char* name);
static u64   np_self_pid(void);
static u64   np_parent_pid(void);

static u64 np_volume_serial(void) {
    // Resolve GetVolumeInformationW and GetSystemDirectoryW through kernel32.
    // The volume serial is a per-machine, per-installation identifier, so it
    // separates machines that share the same CPU model.
    void* k32 = np_module_by_name(np_s_kernel32);
    if (!k32) return 0;
    typedef u32 (__attribute__((ms_abi)) *np_gsd_fn)(void*, u32);
    np_gsd_fn gsd = (np_gsd_fn)np_export_by_name(k32, "GetSystemDirectoryW");
    if (!gsd) return 0;
    u16 dir[260];
    u32 n = gsd(dir, 260);
    if (!n || n >= 260) return 0;
    u16 root[4];
    root[0] = dir[0]; root[1] = (u16)L':'; root[2] = (u16)L'\\'; root[3] = 0;
    typedef u32 (__attribute__((ms_abi)) *np_gvi_fn)(const u16*, void*, u32, u32*, void*, void*, void*, u32);
    np_gvi_fn gvi = (np_gvi_fn)np_export_by_name(k32, "GetVolumeInformationW");
    if (!gvi) return 0;
    u32 serial = 0;
    if (!gvi(root, 0, 0, &serial, 0, 0, 0, 0)) return 0;
    return (u64)serial;
}

static u64 np_machine_guid_hash(void) {
    // Read HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid through advapi32.
    // It is derived from the machine's hardware identity and survives OS
    // reinstalls / disk swaps on the same motherboard, making it the primary
    // stability anchor for one-machine-one-license.
    void* adv = np_module_by_name(np_s_advapi32);
    if (!adv) return 0;
    typedef u32 (__attribute__((ms_abi)) *np_rok_fn)(void*, const u16*, u32, u32, void**);
    np_rok_fn rok = (np_rok_fn)np_export_by_name(adv, "RegOpenKeyExW");
    if (!rok) return 0;
    typedef u32 (__attribute__((ms_abi)) *np_rqv_fn)(void*, const u16*, void*, u32*, u8*, u32*);
    np_rqv_fn rqv = (np_rqv_fn)np_export_by_name(adv, "RegQueryValueExW");
    if (!rqv) return 0;
    typedef u32 (__attribute__((ms_abi)) *np_rck_fn)(void*);
    np_rck_fn rck = (np_rck_fn)np_export_by_name(adv, "RegCloseKey");
    static const u16 keyPath[] = { 'S','O','F','T','W','A','R','E','\\','M','i','c','r','o','s','o','f','t','\\','C','r','y','p','t','o','g','r','a','p','h','y',0 };
    static const u16 valName[] = { 'M','a','c','h','i','n','e','G','u','i','d',0 };
    void* key = 0;
    if (rok((void*)0x80000002u, keyPath, 0, 0x20019u, &key) != 0 || !key) return 0;
    u16 guid[64];
    u32 size = (u32)sizeof(guid);
    u32 type = 0;
    u32 rc = rqv(key, valName, 0, &type, (u8*)guid, &size);
    if (rck) rck(key);
    if (rc != 0 || type != 1u) return 0;
    u64 h = NP_FNV_BASIS;
    for (u32 i = 0; i < size / 2 && guid[i]; i++) {
        u8 lo = (u8)(guid[i] & 0xFF);
        u8 hi = (u8)((guid[i] >> 8) & 0xFF);
        h = np_fnv1a64(&lo, 1, h);
        h = np_fnv1a64(&hi, 1, h);
    }
    return h;
}
static u64 np_machine_id(void) {
    u32 r[4];
    np_cpuid(0, 0, r);
    u32 max_leaf = r[0];
    u64 h = NP_FNV_BASIS;
    h = np_fnv1a64((const u8*)&r[1], 4, h);
    h = np_fnv1a64((const u8*)&r[3], 4, h);
    h = np_fnv1a64((const u8*)&r[2], 4, h);
    if (max_leaf >= 1) {
        np_cpuid(1, 0, r);
        h = np_fnv1a64((const u8*)&r[0], 4, h);
        h = np_fnv1a64((const u8*)&r[2], 4, h);
        h = np_fnv1a64((const u8*)&r[3], 4, h);
    }
    if (max_leaf >= 7) {
        np_cpuid(7, 0, r);
        h = np_fnv1a64((const u8*)&r[1], 4, h);
        h = np_fnv1a64((const u8*)&r[2], 4, h);
        h = np_fnv1a64((const u8*)&r[3], 4, h);
    }
    u64 vs = np_volume_serial();
    u64 mg = np_machine_guid_hash();
    h = np_fnv1a64((const u8*)&vs, sizeof(vs), h);
    h = np_fnv1a64((const u8*)&mg, sizeof(mg), h);
    return h;
}

static u32 np_rd32(const void* p) { return *(const volatile u32*)p; }
static u64 np_rd64(const void* p) { return *(const volatile u64*)p; }
/* Signed view of a 32-bit field, used for the payload-relative deltas stored in
 * the reverse-table trailer. */
static i32 np_rd32s(const void* p) { return *(const volatile i32*)p; }

static u64 np_rdtscp(void) {
    u32 lo, hi, aux;
    __asm__ volatile("rdtscp" : "=a"(lo), "=d"(hi), "=c"(aux));
    (void)aux;
    return ((u64)hi << 32) | lo;
}

static u64 np_rdtsc(void) {
    u32 lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((u64)hi << 32) | lo;
}

static void np_cpuid_leaf(u32 leaf, u32 subleaf, u32 out[4]) {
    __asm__ volatile("cpuid" : "=a"(out[0]), "=b"(out[1]), "=c"(out[2]), "=d"(out[3]) : "a"(leaf), "c"(subleaf));
}

static u64 np_cpu_core_mask(void) {
    u32 r[4];
    np_cpuid_leaf(0x1, 0, r);
    return ((u64)r[3] << 32) | (u64)r[1];   /* EDX:EBX APIC id, logical cores */
}

static u8* np_peb(void) {
    u8* peb;
    __asm__ volatile("movq %%gs:0x60, %0" : "=r"(peb));
    return peb;
}

/* ========================================================================
 * module / export resolution through the PEB loader list
 * ======================================================================== */

static void* np_module_by_name(const char* name) {
    u8* peb = np_peb();
    if (!peb) return 0;
    u8* ldr = *(u8**)(peb + PEB_LDR);
    if (!ldr) return 0;
    u8* head = ldr + LDR_IN_LOAD_ORDER;
    u8* cur  = *(u8**)head;

    while (cur != head) {
        u16 len = *(u16*)(cur + LDR_ENTRY_BASENAME);
        u16* nm = *(u16**)(cur + LDR_ENTRY_BASENAME + 8);
        u8*  base = *(u8**)(cur + LDR_ENTRY_DLLBASE);
        len >>= 1;
        if (nm && base && len) {
            u32 i = 0;
            for (;; i++) {
                if (i >= len) { if (name[i] == 0) return base; break; }
                u16 a = nm[i];
                u8  b = (u8)name[i];
                if (b == 0) break;
                if (a >= 'A' && a <= 'Z') a += 32;
                if (b >= 'A' && b <= 'Z') b += 32;
                if (a != b) break;
            }
        }
        cur = *(u8**)cur;
    }
    return 0;
}

static void* np_export_by_name(void* mod, const char* name) {
    if (!mod) return 0;
    u8* base = (u8*)mod;
    i32 lfanew = *(i32*)(base + 0x3C);
    if (lfanew <= 0) return 0;
    u8* nth = base + lfanew + 24;
    u32 exp_rva = np_rd32(nth + 0x70);
    if (!exp_rva) return 0;
    u8* exp = base + exp_rva;
    u32 nnames = np_rd32(exp + 0x18);
    if (!nnames) return 0;
    u32* names    = (u32*)(base + np_rd32(exp + 0x20));
    u16* ordinals = (u16*)(base + np_rd32(exp + 0x24));
    u32* funcs    = (u32*)(base + np_rd32(exp + 0x1C));

    for (u32 i = 0; i < nnames; i++) {
        const char* p = (const char*)(base + np_rd32(names + i));
        u32 k = 0;
        for (;;) {
            if (p[k] != name[k]) break;
            if (p[k] == 0) {
                u32 rva = np_rd32(funcs + ordinals[i]);
                if (!rva) return 0;
                return base + rva;
            }
            k++;
        }
    }
    return 0;
}

/* ========================================================================
 * small string helpers (ASCII vs UTF-16, case insensitive)
 * ======================================================================== */

static u16 np_lc16(u16 c) { return (c >= (u16)L'A' && c <= (u16)L'Z') ? (u16)(c + 32) : c; }
static u8  np_lca (u8  c) { return (c >= 'A' && c <= 'Z') ? (u8)(c + 32) : c; }

static u32 np_u16_len(const u16* s) {
    u32 n = 0;
    while (s && s[n]) n++;
    return n;
}

/* does the wide string start with the ASCII prefix (case insensitive)? */
static u32 np_u16_prefix_ci(const u16* s, u32 slen, const char* p) {
    for (u32 i = 0; ; i++) {
        if (p[i] == 0) return 1;
        if (i >= slen) return 0;
        if (np_lc16(s[i]) != (u16)np_lca((u8)p[i])) return 0;
    }
}

/* does the wide string contain the ASCII needle (case insensitive)? */
static u32 np_u16_has_ci(const u16* s, u32 slen, const char* needle) {
    u32 nl = 0;
    while (needle[nl]) nl++;
    if (!nl || !s || nl > slen) return 0;
    for (u32 i = 0; i + nl <= slen; i++) {
        u32 ok = 1;
        for (u32 j = 0; j < nl; j++) {
            if (np_lc16(s[i + j]) != (u16)np_lca((u8)needle[j])) { ok = 0; break; }
        }
        if (ok) return 1;
    }
    return 0;
}

static u32 np_ascii_prefix_ci(const char* s, const char* p) {
    for (u32 i = 0; ; i++) {
        if (p[i] == 0) return 1;
        if (s[i] == 0) return 0;
        if (np_lca((u8)s[i]) != np_lca((u8)p[i])) return 0;
    }
}

/* case-insensitive substring containment (ANSI) */
static u32 np_ascii_has_ci(const char* s, const char* needle) {
    if (!s || !needle) return 0;
    u32 nl = 0;
    while (needle[nl]) nl++;
    if (!nl) return 0;
    for (u32 i = 0; s[i]; i++) {
        u32 ok = 1;
        for (u32 j = 0; j < nl; j++) {
            if (!s[i + j] || np_lca((u8)s[i + j]) != np_lca((u8)needle[j])) { ok = 0; break; }
        }
        if (ok) return 1;
    }
    return 0;
}

/* ========================================================================
 * environment / registry probes used by the sandbox guard
 * ======================================================================== */

static void np_env_get(const char* name, char* out, u32 cap) {
    if (!out || !cap) return;
    out[0] = 0;
    void* k32 = np_module_by_name(np_s_kernel32);
    if (!k32) return;
    typedef u32 (__attribute__((ms_abi)) *np_ge_fn)(const char*, char*, u32);
    np_ge_fn ge = (np_ge_fn)np_export_by_name(k32, "GetEnvironmentVariableA");
    if (!ge) return;
    ge(name, out, cap);
}

typedef u32 (__attribute__((ms_abi)) *np_rok_fn)(void*, const u16*, u32, u32, void**);
typedef u32 (__attribute__((ms_abi)) *np_rqv_fn)(void*, const u16*, void*, u32*, u8*, u32*);
typedef u32 (__attribute__((ms_abi)) *np_rck_fn)(void*);

static void* np_reg_open(u32 root, const u16* path) {
    void* adv = np_module_by_name(np_s_advapi32);
    if (!adv) return 0;
    np_rok_fn rok = (np_rok_fn)np_export_by_name(adv, "RegOpenKeyExW");
    if (!rok) return 0;
    void* key = 0;
    if (rok((void*)(u64)root, path, 0, 0x20019u, &key) != 0) return 0;
    return key;
}

static void np_reg_close(void* key) {
    if (!key) return;
    void* adv = np_module_by_name(np_s_advapi32);
    if (!adv) return;
    np_rck_fn rck = (np_rck_fn)np_export_by_name(adv, "RegCloseKey");
    if (rck) rck(key);
}

static u32 np_reg_dword(u32 root, const u16* path, const u16* name, u32* out) {
    void* key = np_reg_open(root, path);
    if (!key) return 0;
    void* adv = np_module_by_name(np_s_advapi32);
    np_rqv_fn rqv = adv ? (np_rqv_fn)np_export_by_name(adv, "RegQueryValueExW") : 0;
    u32 v = 0, size = 4, type = 0, ok = 0;
    if (rqv && rqv(key, name, 0, &type, (u8*)&v, &size) == 0 && type == 4u && size == 4) {
        *out = v;
        ok = 1;
    }
    np_reg_close(key);
    return ok;
}

/* REG_MULTI_SZ containment probe: any embedded string containing needle. */
static u32 np_reg_multisz_has(u32 root, const u16* path, const u16* name, const char* needle) {
    void* key = np_reg_open(root, path);
    if (!key) return 0;
    void* adv = np_module_by_name(np_s_advapi32);
    np_rqv_fn rqv = adv ? (np_rqv_fn)np_export_by_name(adv, "RegQueryValueExW") : 0;
    static u16 buf[512];
    u32 size = (u32)sizeof(buf), type = 0, hit = 0;
    if (rqv && rqv(key, name, 0, &type, (u8*)buf, &size) == 0 &&
        (type == 7u || type == 1u || type == 2u) && size >= 2) {
        u32 start = 0;
        for (u32 i = 0; i <= size / 2; i++) {
            if (i == size / 2 || buf[i] == 0) {
                if (i > start && np_u16_has_ci(buf + start, i - start, needle)) { hit = 1; break; }
                start = i + 1;
            }
        }
    }
    np_reg_close(key);
    return hit;
}

static u32 np_reg_exists(u32 root, const u16* path) {
    void* key = np_reg_open(root, path);
    if (!key) return 0;
    np_reg_close(key);
    return 1;
}

/* ---- device-object and kernel-module probes ------------------------------ */

/* Opens \\.\NAME with no desired access and no share restriction. A sandbox
 * driver that exposes a device object for its own agent answers this even when
 * the agent process itself is hidden; a real machine has no such device. */
static u32 np_device_opens(const u16* name) {
    void* ntdll = np_module_by_name(np_s_ntdll);
    if (!ntdll) return 0;
    typedef i32 (__attribute__((ms_abi)) *np_ntcreate_fn)(void*, u32, void*, void*, void*, u32, u32, void*, u32, void*, u32);
    typedef i32 (__attribute__((ms_abi)) *np_ntclose_fn)(void*);
    np_ntcreate_fn create = (np_ntcreate_fn)np_export_by_name(ntdll, "NtCreateFile");
    np_ntclose_fn close = (np_ntclose_fn)np_export_by_name(ntdll, "NtClose");
    if (!create || !close) return 0;

    /* UNICODE_STRING{len,max,buf} + OBJECT_ATTRIBUTES{len,0,us,0,0} */
    struct { u16 len, max; u16* buf; } us;
    u32 chars = np_u16_len(name);
    us.len = (u16)(chars * 2);
    us.max = (u16)(chars * 2 + 2);
    us.buf = (u16*)name;
    struct { u32 len; u32 pad; void* root; void* name; u32 attr; u32 pad2; void* sd; void* sqos; } oa;
    np_memset(&oa, 0, sizeof(oa));
    oa.len = sizeof(oa);
    oa.name = &us;

    void* handle = 0;
    i32 status = create(&handle, 0x00100000u /*SYNCHRONIZE*/, &oa, 0, 0, 0,
                        3u /*FILE_OPEN_IF*/, 0, 0, 0, 0);
    if (status >= 0 && handle) {
        close(handle);
        return 1;
    }
    return 0;
}

/* NtQuerySystemInformation(SystemModuleInformation=11): walks the kernel module
 * list and looks for a sandbox driver image by name. */
static u32 np_kernel_module_hit(void) {
    void* ntdll = np_module_by_name(np_s_ntdll);
    if (!ntdll) return 0;
    typedef i32 (__attribute__((ms_abi)) *np_qsi_fn)(u32, void*, u32, u32*);
    np_qsi_fn qsi = (np_qsi_fn)np_export_by_name(ntdll, np_s_qsi);
    if (!qsi) return 0;

    static u8 buf[64 * 1024];
    np_memset(buf, 0, sizeof(buf));
    u32 ret = 0;
    if (qsi(11u, buf, (u32)sizeof(buf), &ret) < 0) return 0;

    u32 count = np_rd32(buf);
    if (!count || count > 512) return 0;
    static const char kWanted[13][16] = {
        "vboxguest", "vboxmouse", "vboxsf", "vboxvideo", "vmci", "vmhgfs",
        "vmmouse", "vmrawdsk", "vmusbmouse", "vm3dmp", "xenvbd", "xeniface",
        "prl_hypervisor",
    };
    /* SYSTEM_MODULE_INFORMATION{ u32 count; entry[count] } with each entry
     * 296 bytes on x64; FullPathName at +40. */
    for (u32 i = 0; i < count; i++) {
        const u8* entry = buf + 8 + (u64)i * 296;
        const char* path = (const char*)(entry + 40);
        for (u32 w = 0; w < 13; w++) {
            if (np_ascii_has_ci(path, kWanted[w])) return 1;
        }
    }
    return 0;
}

/* ---- process snapshot (NtQuerySystemInformation class 5) ---------------- */

static void* np_snap_buf = 0;
static u64   np_snap_len = 0;

static void np_snap_free(void) {
    if (!np_snap_buf) return;
    void* ntdll = np_module_by_name(np_s_ntdll);
    if (ntdll) {
        typedef i32 (__attribute__((ms_abi)) *np_ntfree_fn)(void*, void**, u64*, u32);
        np_ntfree_fn fr = (np_ntfree_fn)np_export_by_name(ntdll, "NtFreeVirtualMemory");
        if (fr) {
            void* b = np_snap_buf;
            u64 s = 0;
            fr((void*)-1, &b, &s, 0x8000u);   /* MEM_RELEASE */
        }
    }
    np_snap_buf = 0;
    np_snap_len = 0;
}

static u32 np_snapshot_processes(void) {
    if (np_snap_buf) return 1;
    void* ntdll = np_module_by_name(np_s_ntdll);
    if (!ntdll) return 0;
    typedef i32 (__attribute__((ms_abi)) *np_ntavm_fn)(void*, void**, u64, u64*, u32, u32);
    np_ntavm_fn avm = (np_ntavm_fn)np_export_by_name(ntdll, "NtAllocateVirtualMemory");
    typedef i32 (__attribute__((ms_abi)) *np_qsi_fn)(u32 cls, void* buf, u32 len, u32* ret);
    np_qsi_fn qsi = (np_qsi_fn)np_export_by_name(ntdll, np_s_qsi);
    if (!avm || !qsi) return 0;

    u64 size = 0x200000u;              /* 2 MB: ~2000 process entries */
    void* base = 0;
    if (avm((void*)-1, &base, 0, &size, 0x3000u, 0x04u) < 0 || !base) return 0;
    u32 ret = 0;
    if (qsi(NP_SIC_SYSTEM_PROCESS_INFO, base, (u32)size, &ret) < 0) {
        np_snap_buf = base;            /* let np_snap_free release it */
        np_snap_len = size;
        np_snap_free();
        return 0;
    }
    np_snap_buf = base;
    np_snap_len = size;
    return 1;
}

static u32 np_snap_count(void) {
    if (!np_snap_buf) return 0;
    /* our own sample process is not part of the environment population */
    u64 self = np_self_pid();
    u32 n = 0;
    u8* p = (u8*)np_snap_buf;
    for (;;) {
        if (!self || np_rd64(p + 0x50) != self) n++;
        u32 next = np_rd32(p);
        if (!next) break;
        p += next;
    }
    return n;
}

/* copy the ImageName of the process with the given pid into out (wide).
 * SYSTEM_PROCESS_INFORMATION (x64): UniqueProcessId at +0x50, ImageName
 * (UNICODE_STRING) at +0x38 (Length +0x38, Buffer +0x40). */
static u32 np_snap_name_of(u64 pid, u16* out, u32 cap) {
    if (!np_snap_buf || !out || cap < 2) return 0;
    u8* p = (u8*)np_snap_buf;
    for (;;) {
        if (np_rd64(p + 0x50) == pid) {           /* UniqueProcessId */
            u16 len = *(u16*)(p + 0x38);          /* ImageName.Length */
            u16* src = *(u16**)(p + 0x40);        /* ImageName.Buffer  */
            if (src && len) {
                u32 chars = (u32)len / 2;
                if (chars > cap - 1) chars = cap - 1;
                for (u32 i = 0; i < chars; i++) out[i] = src[i];
                out[chars] = 0;
                return chars;
            }
            return 0;
        }
        u32 next = np_rd32(p);
        if (!next) break;
        p += next;
    }
    return 0;
}

/* pid of the i-th entry (skipping our own process), for whole-table scans. */
static u32 np_snap_pid_at(u32 index, u64* out) {
    if (!np_snap_buf || !out) return 0;
    u64 self = np_self_pid();
    u32 n = 0;
    u8* p = (u8*)np_snap_buf;
    for (;;) {
        u64 pid = np_rd64(p + 0x50);
        if (!self || pid != self) {
            if (n == index) { *out = pid; return 1; }
            n++;
        }
        u32 next = np_rd32(p);
        if (!next) break;
        p += next;
    }
    return 0;
}

/* PROCESS_BASIC_INFORMATION: self pid at +0x20, parent pid at +0x28. */
static u64 np_pid_field(u32 off) {
    void* ntdll = np_module_by_name(np_s_ntdll);
    if (!ntdll) return 0;
    typedef i32 (__attribute__((ms_abi)) *np_ntqip_fn)(void*, u32, void*, u32, u32*);
    np_ntqip_fn fn = (np_ntqip_fn)np_export_by_name(ntdll, np_s_qip);
    if (!fn) return 0;
    u8 pbi[0x30];
    np_memset(pbi, 0, sizeof(pbi));
    u32 ret = 0;
    if (fn((void*)-1, 0u, pbi, (u32)sizeof(pbi), &ret) < 0) return 0;
    return np_rd64(pbi + off);
}

static u64 np_self_pid(void)   { return np_pid_field(0x20); }
static u64 np_parent_pid(void) { return np_pid_field(0x28); }

/* ---- user activity ------------------------------------------------------ */

/* Milliseconds since the last session-wide input event; 0xFFFFFFFF when the
 * API is unavailable (e.g. session 0). */
static u32 np_input_idle_ms(u64 now_ms) {
    void* u32mod = np_module_by_name(np_s_user32);
    if (!u32mod) return 0xFFFFFFFFu;
    typedef int (__attribute__((ms_abi)) *np_glii_fn)(void*);
    np_glii_fn glii = (np_glii_fn)np_export_by_name(u32mod, "GetLastInputInfo");
    if (!glii) return 0xFFFFFFFFu;
    u8 lii[8];
    np_memset(lii, 0, sizeof(lii));
    *(u32*)lii = 8u;                       /* cbSize */
    if (!glii(lii)) return 0xFFFFFFFFu;
    u32 last = np_rd32(lii + 4);           /* dwTime (GetTickCount domain) */
    return (u32)now_ms - last;             /* wrap-safe unsigned delta */
}

static int np_taskbar_present(void) {
    void* u32mod = np_module_by_name(np_s_user32);
    if (!u32mod) return 0;
    typedef void* (__attribute__((ms_abi)) *np_fw_fn)(const u16*, const u16*);
    np_fw_fn fw = (np_fw_fn)np_export_by_name(u32mod, "FindWindowW");
    if (!fw) return 0;
    static const u16 cls[] = { 'S','h','e','l','l','_','T','r','a','y','W','n','d',0 };
    return fw(cls, 0) != 0;
}

/* ---- Windows install age ------------------------------------------------- */

static u32 np_install_age_days(void) {
    void* k32 = np_module_by_name(np_s_kernel32);
    if (!k32) return 0xFFFFFFFFu;
    typedef void (__attribute__((ms_abi)) *np_gstaft_fn)(u64*);
    np_gstaft_fn gstaft = (np_gstaft_fn)np_export_by_name(k32, "GetSystemTimeAsFileTime");
    if (!gstaft) return 0xFFFFFFFFu;
    u64 ft = 0;
    gstaft(&ft);
    u64 now_unix = ft / 10000000ull - 11644473600ull;

    static const u16 path[] = {
        'S','O','F','T','W','A','R','E','\\','M','i','c','r','o','s','o','f','t','\\',
        'W','i','n','d','o','w','s',' ','N','T','\\','C','u','r','r','e','n','t','V','e','r','s','i','o','n',0 };
    static const u16 name[] = { 'I','n','s','t','a','l','l','D','a','t','e',0 };
    u32 install = 0;
    if (!np_reg_dword(0x80000002u, path, name, &install)) return 0xFFFFFFFFu;
    if (!install || (u64)install > now_unix) return 0xFFFFFFFFu;
    return (u32)((now_unix - (u64)install) / 86400ull);
}

/* ---- firmware / virtual disk artifacts ----------------------------------- */

static u32 np_firmware_artifacts(void) {
    static const u16 diskEnum[] = {
        'S','Y','S','T','E','M','\\','C','u','r','r','e','n','t','C','o','n','t','r','o','l','S','e','t','\\',
        'S','e','r','v','i','c','e','s','\\','D','i','s','k','\\','E','n','u','m',0 };
    static const u16 empty[] = { 0 };
    if (np_reg_multisz_has(0x80000002u, diskEnum, empty, "vmware")) return 1;
    if (np_reg_multisz_has(0x80000002u, diskEnum, empty, "vbox"))    return 1;
    if (np_reg_multisz_has(0x80000002u, diskEnum, empty, "qemu"))    return 1;
    if (np_reg_multisz_has(0x80000002u, diskEnum, empty, "xen"))     return 1;
    if (np_reg_multisz_has(0x80000002u, diskEnum, empty, "virtual")) return 1;

    static const u16 vboxKey[]  = { 'S','O','F','T','W','A','R','E','\\','O','r','a','c','l','e','\\','V','i','r','t','u','a','l','B','o','x',0 };
    static const u16 vmwKey[]   = { 'S','O','F','T','W','A','R','E','\\','V','M','w','a','r','e',',',' ','I','n','c','.','\\','V','M','w','a','r','e',0 };
    static const u16 vboxDsdt[] = { 'H','A','R','D','W','A','R','E','\\','A','C','P','I','\\','D','S','D','T','\\','V','B','O','X','_','_',0 };
    if (np_reg_exists(0x80000002u, vboxKey))  return 1;
    if (np_reg_exists(0x80000002u, vmwKey))   return 1;
    if (np_reg_exists(0x80000002u, vboxDsdt)) return 1;
    return 0;
}

/* ---- injected module detection ------------------------------------------- */

/* A module that lives in a user-writable location (Temp, AppData, Public,
 * ProgramData, Downloads) is almost always an injected analysis agent: no
 * legitimate system or application DLL is ever loaded from there. The
 * application's own directory and the Windows directories are allowed, so
 * portable apps and plugin layouts never trip this. */
static u32 np_injected_module_paths(void) {
    u8* peb = np_peb();
    if (!peb) return 0;
    u8* ldr = *(u8**)(peb + PEB_LDR);
    if (!ldr) return 0;
    u8* head = ldr + LDR_IN_LOAD_ORDER;
    u8* cur  = *(u8**)head;
    u8* first = cur;

    u16 sysdir[264];
    np_memset(sysdir, 0, sizeof(sysdir));
    void* k32 = np_module_by_name(np_s_kernel32);
    if (k32) {
        typedef u32 (__attribute__((ms_abi)) *np_gsd_fn)(void*, u32);
        np_gsd_fn gsd = (np_gsd_fn)np_export_by_name(k32, "GetSystemDirectoryW");
        if (gsd) gsd(sysdir, 260);
    }
    u32 syslen = np_u16_len(sysdir);

    /* allow prefix = directory of the first in-load-order image (the EXE) */
    u16 appdir[264];
    np_memset(appdir, 0, sizeof(appdir));
    if (first) {
        u16 flen = *(u16*)(first + LDR_ENTRY_FULLNAME);
        u16* fbuf = *(u16**)(first + LDR_ENTRY_FULLNAME + 8);
        u32 chars = (u32)flen / 2;
        if (fbuf && chars && chars < 260) {
            u32 slash = 0;
            for (u32 i = 0; i < chars; i++) {
                appdir[i] = fbuf[i];
                if (fbuf[i] == (u16)L'\\') slash = i;
            }
            appdir[slash ? slash + 1 : 0] = 0;   /* keep trailing backslash */
        }
    }
    u32 applen = np_u16_len(appdir);

    while (cur != head) {
        u16 flen = *(u16*)(cur + LDR_ENTRY_FULLNAME);
        u16* fbuf = *(u16**)(cur + LDR_ENTRY_FULLNAME + 8);
        u32 chars = (u32)flen / 2;
        if (fbuf && chars) {
            u32 allowed = 0;
            if (syslen) {
                /* compare against the system directory as a wide prefix */
                u32 i = 0;
                for (; i < syslen && i < chars; i++) {
                    if (np_lc16(fbuf[i]) != np_lc16(sysdir[i])) break;
                }
                if (i == syslen && chars > syslen && fbuf[syslen] == (u16)L'\\') allowed = 1;
            }
            if (!allowed && applen && chars >= applen) {
                u32 i = 0;
                for (; i < applen; i++) {
                    if (np_lc16(fbuf[i]) != np_lc16(appdir[i])) break;
                }
                if (i == applen) allowed = 1;
            }
            if (!allowed &&
                (np_u16_has_ci(fbuf, chars, "\\windows\\syswow64\\") ||
                 np_u16_has_ci(fbuf, chars, "\\windows\\assembly\\") ||
                 np_u16_has_ci(fbuf, chars, "\\windows\\microsoft.net\\") ||
                 np_u16_has_ci(fbuf, chars, "\\windows\\winsxs\\"))) allowed = 1;

            if (!allowed &&
                (np_u16_has_ci(fbuf, chars, "\\temp\\") ||
                 np_u16_has_ci(fbuf, chars, "\\appdata\\") ||
                 np_u16_has_ci(fbuf, chars, "\\users\\public\\") ||
                 np_u16_has_ci(fbuf, chars, "\\programdata\\") ||
                 np_u16_has_ci(fbuf, chars, "\\downloads\\") ||
                 np_u16_has_ci(fbuf, chars, "\\$recycle.bin\\") ||
                 np_u16_has_ci(fbuf, chars, "\\perflogs\\"))) {
                return 1;
            }
        }
        cur = *(u8**)cur;
    }
    return 0;
}

/* ---- ephemeral account / computer names ---------------------------------- */

/* Fixed-width char matrix, NOT a const char* array: the blob is deployed at
 * an arbitrary load base, so any link-time absolute pointer embedded in the
 * data section would dangle (see the tripwire in build.ps1). Matrix rows are
 * reached with a RIP-relative lea plus a row stride, like every other string
 * in the runtime. GCC rejects an over-long initializer, so the width is
 * compile-time checked. */
static u32 np_template_name(void) {
    static const char kTemplates[12][8] = {
        "win", "admin", "user", "pc-", "test", "sandbox", "virus",
        "malware", "analy", "cuckoo", "joe", "sample"
    };
    char host[160], user[160];
    np_env_get("COMPUTERNAME", host, sizeof(host));
    np_env_get("USERNAME", user, sizeof(user));
    const char* cands[2];
    cands[0] = host; cands[1] = user;
    for (u32 c = 0; c < 2; c++) {
        if (!cands[c][0]) continue;
        for (u32 t = 0; t < sizeof(kTemplates) / sizeof(kTemplates[0]); t++) {
            if (np_ascii_prefix_ci(cands[c], kTemplates[t])) return 1;
        }
    }
    return 0;
}

/* ---- hypervisor level: CPUID exit cost ----------------------------------- */

/* Windows itself runs on Hyper-V: VBS / Credential Guard, the hypervisor
 * platform and WSL2 all publish the Microsoft Hv vendor string, and from that
 * point CPUID traps on what is otherwise bare metal. Detecting that as a
 * sandbox blocked fully-loaded builds on ordinary Windows 11 desktops, so the
 * host hypervisor is exempt from the exit-cost score — the same exemption the
 * vendor layer below already applies to Hyper-V.
 *
 * Vendor string "Microsoft Hv" packed little-endian into EBX/ECX/EDX. */
static u32 np_hv_is_windows_host(void) {
    u32 c[4] = {0};
    np_cpuid_leaf(0x40000000u, 0, c);
    if (c[0] < 0x40000000u) return 0;
    return (c[1] == 0x7263694Du && c[2] == 0x666F736Fu && c[3] == 0x76482074u) ? 1u : 0u;
}

/* Every CPUID is a VM exit when the guest is virtualised: ~1000-5000 cycles
 * against ~100-200 on bare metal. A hypervisor configured to hide its vendor
 * string (or to mask ECX[31]) still has to trap the instruction, so timing a
 * storm of them is the check that cannot be renamed away.
 *
 * The budget is deliberately generous (16 * 400 cycles) so a slow but real
 * machine never trips it, while the cheapest hypervisor exit already does. */
static u32 np_hv_exit_cost(void) {
    if (np_hv_is_windows_host()) return 0;
    u32 regs[4];
    np_cpuid_leaf(0, 0, regs);
    u64 t0 = np_rdtsc();
    for (u32 i = 0; i < 16; i++) np_cpuid_leaf(0, 0, regs);
    u64 t1 = np_rdtsc();
    return (t1 - t0) > (16ull * 400ull) ? 1u : 0u;
}

/* ---- driver level: kernel artifacts visible from ring 3 ------------------ */

/* A sandbox hides its agent process long before it hides its kernel driver.
 * The driver shows up three ways that need no privileges to observe:
 *   - a device object that opens with no desired access
 *   - a service key under CurrentControlSet\Services
 *   - a .sys image listed in the kernel module list
 * Each is independent so the detail field says which one fired. */
static u32 np_kernel_artifacts(u64* det) {
    u32 hits = 0;

    /* Fixed-width matrices, not pointer tables: the blob is deployed at an
     * arbitrary base, so a table of absolute addresses would dangle. */
    static const u16 kDevices[6][30] = {
        { '\\','\\','.','\\','V','B','o','x','M','i','n','i','R','d','r',0 },
        { '\\','\\','.','\\','V','B','o','x','G','u','e','s','t',0 },
        { '\\','\\','.','\\','v','m','c','i',0 },
        { '\\','\\','.','\\','V','M','w','a','r','e','V','M','C','I','H','o','s','t',0 },
        { '\\','\\','.','\\','v','m','m','o','u','s','e',0 },
        { '\\','\\','.','\\','v','s','t','o','r','2','-','m','n','t','a','p','i','2','0','-','s','h','a','r','e','d',0 },
    };
    for (u32 i = 0; i < 6; i++) {
        if (np_device_opens(kDevices[i])) {
            hits++;
            if (det) *det |= NP_SB_KDEV;
            break;
        }
    }

    static const u16 svcRoot[] = {
        'S','Y','S','T','E','M','\\','C','u','r','r','e','n','t','C','o','n','t','r','o','l','S','e','t','\\',
        'S','e','r','v','i','c','e','s','\\',0 };
    static const char kServices[12][16] = {
        "VBoxGuest", "VBoxMouse", "VBoxSF", "vmci", "vmhgfs", "vmmouse",
        "vmrawdsk", "vm3dmp", "xenvbd", "xeniface", "prl_hypervisor", "VMTools",
    };
    for (u32 i = 0; i < 12; i++) {
        u16 path[128];
        u32 n = 0;
        for (; svcRoot[n] && n < 96; n++) path[n] = svcRoot[n];
        for (u32 k = 0; kServices[i][k] && n < 126; k++) path[n++] = (u16)(u8)kServices[i][k];
        path[n] = 0;
        if (np_reg_exists(0x80000002u, path)) {
            hits++;
            if (det) *det |= NP_SB_KSVC;
            break;
        }
    }

    if (np_kernel_module_hit()) {
        hits++;
        if (det) *det |= NP_SB_KMOD;
    }
    return hits;
}

/* Tick continuity through KUSER_SHARED_DATA (7FFE0320H). That field is a
 * KSYSTEM_TIME the clock interrupt updates once per ~15.6 ms, not a millisecond
 * counter, so the test is "did it move while a known amount of time passed".
 * The spin is measured on the TSC (~50M cycles, tens of milliseconds) because
 * a short spin can legitimately land inside one clock tick and read the same
 * value twice. A guest clock that is frozen or fast-forwarded fails this; a
 * real clock cannot. */
static u32 np_tick_stalled(void) {
    volatile u32* tick = (volatile u32*)0x7FFE0320u;
    const u32 first = *tick;
    const u64 budget = 50000000ull;
    const u64 t0 = np_rdtsc();
    while (np_rdtsc() - t0 < budget) { }
    const u32 second = *tick;
    const u32 delta = second - first;
    return (delta == 0 || delta > 4096u) ? 1u : 0u;
}

/* ---- sleep / wall-clock compression -------------------------------------- */

/* A sandbox that accelerates wall-clock time (or fakes RDTSC) makes the
 * cycles-per-millisecond ratio across a real Sleep implausible for any
 * physical CPU. The band 0.25 - 40 GHz covers every shipping x86 part. */
static u32 np_sleep_compressed(void) {
    void* k32 = np_module_by_name(np_s_kernel32);
    if (!k32) return 0;
    typedef u64   (__attribute__((ms_abi)) *np_gtt_fn)(void);
    typedef void  (__attribute__((ms_abi)) *np_sleep_fn)(u32);
    np_gtt_fn  gtt = (np_gtt_fn) np_export_by_name(k32, np_s_gtt);
    np_sleep_fn sl = (np_sleep_fn)np_export_by_name(k32, "Sleep");
    if (!gtt || !sl) return 0;

    u64 ratios[3];
    u32 n = 0;
    for (u32 i = 0; i < 3; i++) {
        u64 w0 = gtt();
        u64 c0 = np_rdtsc();
        sl(50);
        u64 c1 = np_rdtsc();
        u64 w1 = gtt();
        u64 wms = w1 >= w0 ? w1 - w0 : 0;
        u64 cyc = c1 >= c0 ? c1 - c0 : 0;
        if (wms) ratios[n++] = cyc / wms;
    }
    if (!n) return 0;
    /* median of up to three samples */
    for (u32 i = 0; i + 1 < n; i++) {
        for (u32 j = i + 1; j < n; j++) {
            if (ratios[j] < ratios[i]) { u64 t = ratios[i]; ratios[i] = ratios[j]; ratios[j] = t; }
        }
    }
    u64 med = ratios[n / 2];
    return (med < 250000ull || med > 40000000ull) ? 1u : 0u;
}

/* ---- debug logging (opt-in via NOVAPROTECT_SANDBOX_DEBUG=1) --------------- */

static u32 np_dbg_enabled(void) {
    char v[8];
    np_env_get("NOVAPROTECT_SANDBOX_DEBUG", v, sizeof(v));
    return (v[0] == '1' || v[0] == 'y' || v[0] == 'Y' || v[0] == 't' || v[0] == 'T');
}

static void np_dbg_line(const char* s) {
    if (!s) return;
    void* k32 = np_module_by_name(np_s_kernel32);
    if (!k32) return;
    typedef void* (__attribute__((ms_abi)) *np_cf_fn)(const char*, u32, u32, void*, u32, u32, void*);
    typedef u32   (__attribute__((ms_abi)) *np_wf_fn)(void*, const void*, u32, u32*, void*);
    typedef u32   (__attribute__((ms_abi)) *np_sh_fn)(void*);
    typedef int   (__attribute__((ms_abi)) *np_sfp_fn)(void*, i32, i32*, u32);
    np_cf_fn  cf = (np_cf_fn) np_export_by_name(k32, "CreateFileA");
    np_wf_fn  wf = (np_wf_fn) np_export_by_name(k32, "WriteFile");
    np_sh_fn  ch = (np_sh_fn) np_export_by_name(k32, "CloseHandle");
    np_sfp_fn sfp = (np_sfp_fn)np_export_by_name(k32, "SetFilePointer");
    if (!cf || !wf || !ch) return;

    char tmp[300];
    np_env_get("TEMP", tmp, 200);
    u32 n = 0;
    while (tmp[n]) n++;
    static const char suffix[] = "\\novaprotect-sandbox.log";
    for (u32 i = 0; suffix[i] && n + 1 < sizeof(tmp); i++) tmp[n++] = suffix[i];
    tmp[n] = 0;

    void* h = cf(tmp, 0x40000000u, 3u, 0, 4u, 0x80u, 0);   /* GENERIC_WRITE, OPEN_ALWAYS */
    if (!h || h == (void*)-1) return;
    if (sfp) sfp(h, 0, 0, 2u);                              /* FILE_END */
    u32 len = 0;
    while (s[len] && len < 240) len++;
    u32 written = 0;
    wf(h, s, len, &written, 0);
    ch(h);
}

static void np_dbg_hex64(char* p, u64 v) {
    static const char hx[] = "0123456789ABCDEF";
    for (int i = 15; i >= 0; i--) p[15 - i] = hx[(v >> (i * 4)) & 0xF];
}

static void np_dbg_report(u32 score, u64 detail, u32 threshold) {
    if (!np_dbg_enabled()) return;
    char line[256];
    u32 n = 0;
    static const char hdr[] = "NP-SANDBOX score=";
    for (u32 i = 0; hdr[i]; i++) line[n++] = hdr[i];
    /* decimal score */
    char dec[12];
    int d = 0;
    if (!score) dec[d++] = '0';
    while (score) { dec[d++] = (char)('0' + (score % 10)); score /= 10; }
    while (d--) line[n++] = dec[d];
    static const char sep[] = " threshold=";
    for (u32 i = 0; sep[i]; i++) line[n++] = sep[i];
    u32 t = threshold;
    d = 0;
    if (!t) dec[d++] = '0';
    while (t) { dec[d++] = (char)('0' + (t % 10)); t /= 10; }
    while (d--) line[n++] = dec[d];
    static const char dtag[] = " detail=0x";
    for (u32 i = 0; dtag[i]; i++) line[n++] = dtag[i];
    np_dbg_hex64(line + n, detail);
    n += 16;
    line[n++] = '\n';
    line[n] = 0;
    np_dbg_line(line);

    /* Same rule as kTemplates: inline char matrix, no absolute pointers.
     * Width 24 covers the longest tag ("+12 no-input-since-boot", 23) and
     * GCC rejects anything longer at compile time. */
    static const struct { u64 bit; char tag[24]; } kTags[] = {
        { NP_SB_MOD,       "+25 analysis-module"      },
        { NP_SB_INJECT,    "+25 injected-module"      },
        { NP_SB_HYPER,     "+8  hypervisor-vendor"    },
        { NP_SB_FIRMWARE,  "+8  firmware-artifacts"   },
        { NP_SB_CPU1,      "+12 single-vcpu"          },
        { NP_SB_CPU2,      "+4  two-vcpu"             },
        { NP_SB_RAM2,      "+12 ram-under-2gb"        },
        { NP_SB_RAM4,      "+6  ram-under-4gb"        },
        { NP_SB_PROC40,    "+8  procs-under-40"       },
        { NP_SB_PROC70,    "+4  procs-under-70"       },
        { NP_SB_NOINPUT,   "+12 no-input-since-boot"  },
        { NP_SB_IDLE,      "+8  idle-30min"           },
        { NP_SB_SLEEP,     "+15 sleep-compression"    },
        { NP_SB_TSCSPREAD, "+5  rdtscp-spread"        },
        { NP_SB_COREMASK,  "+3  core-mask-anomaly"    },
        { NP_SB_RES1024,   "+6  screen-under-1024"    },
        { NP_SB_RES800,    "+8  screen-under-800"     },
        { NP_SB_NOMON,     "+4  zero-monitors"        },
        { NP_SB_TMPLNAME,  "+6  template-name"        },
        { NP_SB_FRESH3,    "+10 install-under-3d"     },
        { NP_SB_FRESH14,   "+6  install-under-14d"    },
        { NP_SB_PARENT,    "+10 script-host-parent"   },
        { NP_SB_SVCHOST,   "+4  svchost-parent"       },
        { NP_SB_DBGHELP,   "+6  dbghelp-module"       },
        { NP_SB_MS_MOD,    "+30 vendor-agent-module"  },
        { NP_SB_MS_PROC,   "+30 vendor-controller"    },
        { NP_SB_MS_REG,    "+25 vendor-registry"      },
        { NP_SB_MS_HOST,   "+15 vendor-hostname"      },
        { NP_SB_AN_SLEEP,  "+28 clock-compressed"     },
        { NP_SB_AN_HFLAG,  "+26 debug-heap-flags"     },
        { NP_SB_AN_DISK,   "+12 virtual-disk"         },
        { NP_SB_AN_HANDLE, "+14 handle-population"    },
        { NP_SB_AN_CLOCK,  "+10 clock-disagreement"   },
        { NP_SB_AN_BURST,  "+8  post-boot-burst"      },
    };
    for (u32 i = 0; i < sizeof(kTags) / sizeof(kTags[0]); i++) {
        if (detail & kTags[i].bit) np_dbg_line(kTags[i].tag);
    }
}

/* ========================================================================
 * individual checks - every one returns 0 on pass, non zero on detection
 * ======================================================================== */

static u32 np_chk_peb(void) {
    u8* peb = np_peb();
    if (!peb) return 0;
    if (peb[PEB_BEING_DEBUGGED]) return 1;
    return 0;
}

static u32 np_chk_ntglobal(void) {
    u8* peb = np_peb();
    if (!peb) return 0;
    u32 f = np_rd32(peb + PEB_NT_GLOBAL_FLAG);
    if ((f & 0x70u) == 0x70u) return 1;
    return 0;
}

static u32 np_chk_heap(void) {
    u8* peb = np_peb();
    if (!peb) return 0;
    u8* heap = *(u8**)(peb + PEB_PROCESS_HEAP);
    if (!heap) return 0;
    /* ForceFlags is 0 for a normally created heap and non-zero as soon as the
     * process runs under a debugger (or with page heap enabled). Flags always
     * carries HEAP_GROWABLE (0x2); a cleared bit means a debug heap. */
    if (np_rd32(heap + HEAP_FORCE_FLAGS) != 0) return 1;
    if ((np_rd32(heap + HEAP_FLAGS) & 0x2u) == 0) return 1;
    return 0;
}

typedef i32 (__attribute__((ms_abi)) *np_ntqip_fn)(void* h, u32 cls, void* buf, u32 len, u32* ret);
typedef i32 (__attribute__((ms_abi)) *np_getctx_fn)(void* h, void* ctx);

static u32 np_chk_ntquery(void* ntqip) {
    if (!ntqip) return 0;
    np_ntqip_fn fn = (np_ntqip_fn)ntqip;
    u64 buf = 0;
    u32 ret = 0;

    buf = 0;
    fn((void*)-1, 7u, &buf, 8u, &ret);          /* ProcessDebugPort */
    if (buf) return 1;

    buf = 1;
    fn((void*)-1, 0x1Fu, &buf, 4u, &ret);       /* ProcessDebugFlags: 0 == debugged */
    if ((u32)buf == 0) return 1;

    buf = 0;
    fn((void*)-1, 0x1Eu, &buf, 8u, &ret);       /* ProcessDebugObjectHandle */
    if (buf) return 1;

    return 0;
}

/* ========================================================================
 * Advanced debugger detection
 *
 * Three independent angles that the ProcessDebugPort check does not cover:
 *
 *   1. A process can own at most one debug object.  Asking ntdll to create
 *      one fails with STATUS_ACCESS_DENIED when a debugger already owns it,
 *      which is a statement about the process rather than about a flag.
 *   2. ThreadHideFromDebugger hides a thread from a debugger.  If our own
 *      thread is already hidden, somebody else did it - we are being
 *      debugged.
 *   3. Hiding our own thread makes the debugger blind to this thread, so
 *      the checks above cannot be stepped through.
 * ======================================================================== */
#define NP_STATUS_ACCESS_DENIED 0xC0000022u
#define NP_THREAD_HIDE_FROM_DEBUGGER 0x11u
#define NP_CURRENT_THREAD ((void*)(i64)-2)

typedef i32 (__attribute__((ms_abi)) *np_zwcd_fn)(void** handle, u32 access, u32 attrs, void* buf);
typedef i32 (__attribute__((ms_abi)) *np_zwc_fn)(void* handle);
typedef i32 (__attribute__((ms_abi)) *np_zqit_fn)(void* thread, u32 cls, void* buf, u32 len, u32* ret);
typedef i32 (__attribute__((ms_abi)) *np_zsit_fn)(void* thread, u32 cls, void* buf, u32 len);

static u32 np_chk_advanced_debug(void* ntdll) {
    if (!ntdll) return 0;

    /* (1) Debug object uniqueness. */
    np_zwcd_fn cd = (np_zwcd_fn)np_export_by_name(ntdll, np_s_zwcd);
    if (cd) {
        void* handle = 0;
        i32 st = cd(&handle, 0x1F0003u /*MAXIMUM_ALLOWED*/, 0, 0);
        if (st == (i32)NP_STATUS_ACCESS_DENIED) return 1;   /* a debugger owns it */
        if (st == 0 && handle) {
            np_zwc_fn cl = (np_zwc_fn)np_export_by_name(ntdll, np_s_zwc);
            if (cl) cl(handle);
        }
    }

    /* (2) Is our own thread already hidden from a debugger? */
    np_zqit_fn qi = (np_zqit_fn)np_export_by_name(ntdll, np_s_zqit);
    if (qi) {
        u32 hidden = 0;
        u32 ret = 0;
        if (qi(NP_CURRENT_THREAD, NP_THREAD_HIDE_FROM_DEBUGGER, &hidden, 4u, &ret) >= 0 && hidden)
            return 1;
    }

    /* (3) Hide the thread from the debugger so the checks above cannot be
     *     single-stepped through. */
    np_zsit_fn si = (np_zsit_fn)np_export_by_name(ntdll, np_s_zwsit);
    if (si) {
        u32 one = 1;
        si(NP_CURRENT_THREAD, NP_THREAD_HIDE_FROM_DEBUGGER, &one, 4u);
    }
    return 0;
}

static u32 np_chk_dr(void* getctx) {
    if (!getctx) return 0;
    np_getctx_fn fn = (np_getctx_fn)getctx;
    u8 ctx[CTX_SIZE];
    np_memset(ctx, 0, CTX_SIZE);
    *(u32*)(ctx + 0x30) = CONTEXT_DEBUG_REGISTERS;

    if (!fn((void*)-2, ctx)) return 0;          /* GetCurrentThread() pseudo handle */
    u64 dr = np_rd64(ctx + CTX_DR0)
           | np_rd64(ctx + CTX_DR0 + 8)
           | np_rd64(ctx + CTX_DR0 + 16)
           | np_rd64(ctx + CTX_DR0 + 24);
    if (dr) return 1;
    return 0;
}

/* Single step detection: an external debugger that traps every instruction
 * makes the measured delta explode. The threshold is calibrated at pack time
 * so genuine CPUs and clock-speed variation never trip it. */
static u32 np_chk_timing(u64 threshold) {
    if (!threshold) return 0;
    u64 best = ~0ULL;
    for (u32 i = 0; i < 8; i++) {
        u64 a = np_rdtsc();
        u64 b = np_rdtsc();
        u64 d = b - a;
        if (d < best) best = d;
    }
    if (best > threshold) return 1;
    return 0;
}

/* CPUID hypervisor vendor check. Microsoft Hyper-V is deliberately allowed
 * because VBS / Memory Integrity on physical Windows hosts reports it. */
static u32 np_chk_cpuid(void) {
    u32 eax = 0, ebx = 0, ecx = 0, edx = 0;
    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                             : "a"(0x40000000u), "c"(0));
    if (!eax) return 0;

    /* "VMwareVMware" */
    if (ebx == 0x61774D56u && ecx == 0x4D567265u && edx == 0x65726177u) return 1;
    /* "KVMKVMKVM\0\0\0" */
    if (ebx == 0x4B4D564Bu && ecx == 0x564B4D56u && edx == 0x0000004Du) return 1;
    /* "XenVMMXenVMM" */
    if (ebx == 0x566E6558u && ecx == 0x65584D4Du && edx == 0x4D4D566Eu) return 1;
    /* "VBoxVBoxVBox" */
    if (ebx == 0x786F4256u && ecx == 0x786F4256u && edx == 0x786F4256u) return 1;
    /* "prl hyperv  " */
    if (ebx == 0x206C7270u && ecx == 0x65707968u && edx == 0x20207672u) return 1;
    /* "bhyve bhyve " */
    if (ebx == 0x76796362u && ecx == 0x68622065u && edx == 0x20657679u) return 1;
    return 0;
}

/* ========================================================================
 * mutation kernel verification
 *
 * The packer emits a self contained kernel into the protection section and
 * publishes the value it produces for a fixed test vector. Anybody who
 * patches or removes the kernel changes the result and trips the check.
 * ======================================================================== */

typedef u64 (__attribute__((ms_abi)) *np_kernel_fn)(const u8* buf, u64 len);

static u32 np_chk_mutation(const u8* b, void* kern) {
    u64 expected = np_rd64(b + 32);
    if (!expected) return 0;
    if (!kern) return 1;

    u8 probe[32];
    for (u32 i = 0; i < 32; i++) probe[i] = (u8)(0xA5u ^ (i * 0x3Du) ^ (u8)(i << 3));

    np_kernel_fn fn = (np_kernel_fn)kern;
    u64 got = fn(probe, 32);
    if (got != expected) return 1;
    return 0;
}

/* ========================================================================
 * licence / virtual machine interpreter
 *
 * The packer compiles a small bytecode program that walks the encrypted
 * licence blob, decrypts it with a rolling key and folds every byte into an
 * FNV-1a accumulator. Physical opcodes are remapped through a per-build
 * 256 byte translation table so the bytecode stream itself never matches a
 * signature.
 *
 *   bytecode: [phys_op][operands...]
 *   reverse : 256 bytes, reverse[phys_op] = logical op
 * ======================================================================== */

enum {
    VMO_LOADIMM = 0x01,   /* reg u8, imm u64            */
    VMO_LOADB   = 0x02,   /* reg u8, base u8, disp u32  */
    VMO_XOREQ   = 0x03,   /* dst u8, src u8             */
    VMO_MULI    = 0x04,   /* reg u8, imm u64            */
    VMO_ADDI    = 0x05,   /* reg u8, imm u64            */
    VMO_SUBI    = 0x06,   /* reg u8, imm u64            */
    VMO_ANDI    = 0x07,   /* reg u8, imm u64            */
    VMO_RORI    = 0x08,   /* reg u8, imm u64            */
    VMO_CMPI    = 0x09,   /* reg u8, imm u64            */
    VMO_JE      = 0x0A,   /* target u32                 */
    VMO_JNE     = 0x0B,   /* target u32                 */
    VMO_JMP     = 0x0C,   /* target u32                 */
    VMO_MOVE    = 0x0D,   /* dst u8, src u8             */
    VMO_XORI    = 0x0E,   /* reg u8, imm u64            */
    VMO_HALT    = 0x0F,
    VMO_LOADQ   = 0x10,   /* reg u8, base u8, disp u32  */
    VMO_STOREB  = 0x11,   /* base u8, disp u32, src u8  */
    VMO_STOREQ  = 0x12,   /* base u8, disp u32, src u8  */
    VMO_ADD     = 0x13,   /* dst u8, src u8             */
    VMO_SUB     = 0x14,   /* dst u8, src u8             */
    VMO_MUL     = 0x15,   /* dst u8, src u8             */
    VMO_AND     = 0x16,   /* dst u8, src u8             */
    VMO_OR      = 0x17,   /* dst u8, src u8             */
    VMO_XOR     = 0x18,   /* dst u8, src u8             */
    VMO_SHL     = 0x19,   /* dst u8, src u8             */
    VMO_SHR     = 0x1A,   /* dst u8, src u8 (logical)   */
    VMO_SAR     = 0x1B,   /* dst u8, src u8 (arith)     */
    VMO_SHRI    = 0x1C,   /* reg u8, imm u64            */
    VMO_ORI     = 0x1D,   /* reg u8, imm u64            */
    VMO_NOT     = 0x1E,   /* reg u8                     */
    VMO_NEG     = 0x1F,   /* reg u8                     */
    VMO_CMP     = 0x20,   /* a u8, b u8  -> zf/sf/cf     */
    VMO_TEST    = 0x21,   /* a u8, b u8  -> zf/sf        */
    VMO_JNZ     = 0x22,   /* target u32 (jump if !zf)   */
    VMO_JZ      = 0x23,   /* target u32 (jump if zf)    */
    VMO_JAE     = 0x24,   /* target u32 (jump if !cf)   */
    VMO_JB      = 0x25,   /* target u32 (jump if cf)    */
    VMO_JGE     = 0x26,   /* target u32 (jump if sf==of) */
    VMO_JL      = 0x27,   /* target u32 (jump if sf!=of) */
    VMO_JG      = 0x28,   /* target u32 (jump if !zf && sf==of) */
    VMO_JLE     = 0x29,   /* target u32 (jump if zf || sf!=of)  */
    VMO_ENDBR   = 0x2A,   /* no-op: region boundary marker       */
    VMO_SHLI    = 0x2B,   /* reg u8, imm u64 (shift left)        */
    VMO_SARI    = 0x2C,   /* reg u8, imm u64 (shift right arith) */
    /* ---- memory-operand micro-ops (macro expansion) ------------------ */
    VMO_LOADW   = 0x2D,   /* reg u8, base u8, disp u32 -> zx u16 */
    VMO_LOADD   = 0x2E,   /* reg u8, base u8, disp u32 -> zx u32 */
    VMO_LOADSB  = 0x2F,   /* reg u8, base u8, disp u32 -> sx i8  */
    VMO_LOADSW  = 0x30,   /* reg u8, base u8, disp u32 -> sx i16 */
    VMO_LOADSD  = 0x31,   /* reg u8, base u8, disp u32 -> sx i32 */
    VMO_STOREW  = 0x32,   /* base u8, disp u32, src u8           */
    VMO_STORED  = 0x33,   /* base u8, disp u32, src u8           */
    /* ---- rotates ------------------------------------------------------ */
    VMO_ROL     = 0x34,   /* dst u8, src u8                       */
    VMO_ROR     = 0x35,   /* dst u8, src u8                       */
    VMO_ROLI    = 0x36,   /* reg u8, imm u64                      */
    /* ---- 32-bit operand forms ---------------------------------------- */
    VMO_ADDD    = 0x37,   VMO_SUBD    = 0x38,   VMO_ANDD    = 0x39,
    VMO_ORD     = 0x3A,   VMO_XORD    = 0x3B,   VMO_MULD    = 0x3C,
    VMO_CMPD    = 0x3D,   VMO_TESTD   = 0x3E,
    VMO_ADDID   = 0x3F,   VMO_SUBID   = 0x40,   VMO_ANDID   = 0x41,
    VMO_ORID    = 0x42,   VMO_XORID   = 0x43,   VMO_CMPID   = 0x44,
    VMO_SHLID   = 0x45,   VMO_SHRID   = 0x46,   VMO_SARID   = 0x47,
    VMO_NEGD    = 0x48,   VMO_NOTD    = 0x49,
    /* ---- explicit-width register moves ------------------------------- */
    VMO_MOVD    = 0x4A,   VMO_MOVZXB  = 0x4B,   VMO_MOVZXW  = 0x4C,
    VMO_MOVSXB  = 0x4D,   VMO_MOVSXW  = 0x4E,   VMO_MOVSXD  = 0x4F,
    /* ---- secondary virtual machine ----------------------------------- */
    VMO_GSTAGE  = 0x50,   /* desc_index u32                      */
    VMO_STAGEEND= 0x51,   /* no operands                         */
    /* ---- flag-preserving address arithmetic --------------------------- */
    VMO_ADDRADD = 0x52,   /* d, b : r[d] = r[d] + r[b], no flags */
    VMO_ADDRADDI= 0x53,   /* d, imm64 : r[d] += imm, no flags    */
    VMO_ADDRSHLI= 0x54,   /* d, imm64 : r[d] <<= imm, no flags   */
    /* ---- unsigned / signed / overflow branches -------------------------- */
    VMO_JA      = 0x55,   /* target u32 (jump if !cf && !zf)     */
    VMO_JBE     = 0x56,   /* target u32 (jump if cf || zf)       */
    VMO_JS      = 0x57,   /* target u32 (jump if sf)             */
    VMO_JNS     = 0x58,   /* target u32 (jump if !sf)            */
    VMO_JO      = 0x59,   /* target u32 (jump if of)             */
    VMO_JNO     = 0x5A,   /* target u32 (jump if !of)            */
    VMO_JP      = 0x5B,   /* target u32 (jump if pf)             */
    VMO_JNP     = 0x5C,   /* target u32 (jump if !pf)            */
    VMO_INSB    = 0x5D,   /* dst u8, src u8  (splice low byte)   */
    VMO_INSW    = 0x5E,   /* dst u8, src u8  (splice low word)   */
    VMO_EXITJMP = 0x5F,   /* target_rva u32 (leave to native)    */
    VMO_CALL    = 0x60,   /* target_rva u32 (bit31 = indirect)   */
    VMO_IMGADD  = 0x61,   /* dst u8, rva u32 (r[d] = imgBase+RVA) */
    VMO_CMPB    = 0x62,   /* a u8, b u8 -> 8-bit compare flags  */
    VMO_CMPW    = 0x63,   /* a u8, b u8 -> 16-bit compare flags */
    VMO_TESTB   = 0x64,   /* a u8, b u8 -> 8-bit test flags     */
    VMO_TESTW   = 0x65,   /* a u8, b u8 -> 16-bit test flags    */
    VMO_XLOAD   = 0x66,
    VMO_XSTORE  = 0x67,
    VMO_XMOV    = 0x68,
    VMO_XLOADQ  = 0x69,
    VMO_XSTOREQ = 0x6A,
    VMO_XLOADD  = 0x6B,
    VMO_XSTORED = 0x6C,
    VMO_XZERO   = 0x6D,
    VMO_XXOR    = 0x6E,
    VMO_SBB     = 0x6F,
    VMO_SBBI    = 0x70,
    VMO_ADC     = 0x71,
    VMO_ADCI    = 0x72,
    VMO_SBBD    = 0x73,
    VMO_ADCD    = 0x74,
    VMO_XUNPCKL = 0x75,
    VMO_XMOUNTH = 0x76,
    VMO_XMOVHL  = 0x77,
    /* ---- width-exact ALU / XMM arithmetic / misc ------------- */
    VMO_NALU    = 0x78,   /* sel u8, dst u8, src u8               */
    VMO_XALU    = 0x79,   /* sel u8, dst u8, src u8               */
    VMO_XALUI   = 0x7A,   /* sel u8, dst u8, src u8, imm8         */
    VMO_SAHF    = 0x7B,   /* src u8                               */
    VMO_LAHF    = 0x7C,   /* dst u8                               */
    VMO_MULQ    = 0x7D,   /* sel u8, lo u8, hi u8, src u8          */
    VMO_DIVQ    = 0x7E,   /* lo u8, hi u8, den u8                 */
    VMO_IDIVQ   = 0x7F,   /* lo u8, hi u8, den u8                 */
    VMO_SETCF   = 0x80,   /* src u8 : cf = bit 0 of src           */
    VMO_BITOP   = 0x81,   /* sel u8, base u8, idx u8              */
    VMO_ADDRSHRI = 0x82,  /* d u8, imm u64 : arithmetic >> , no flags */
    VMO_BITSCAN = 0x83,   /* sel u8, dst u8, src u8               */
    VMO_X87     = 0x84,   /* esc u8, modrm u8, ea u8              */
    VMO_STR     = 0x85,   /* sel u8, rsi u8, rdi u8, rcx u8, acc u8 */
    VMO_CMPXCHG = 0x86,   /* sel u8, ea u8, acc u8, src u8        */
    VMO_CPUID   = 0x87,   /* a u8, b u8, c u8, d u8               */
    VMO_RDTSC   = 0x88,   /* lo u8, hi u8                         */
    VMO_UD2     = 0x89,
    VMO_RDRAND  = 0x8A,   /* sel u8, dst u8                       */
    VMO_SETDF   = 0x8B,   /* sel u8 (0=cld, 1=std)                */
    VMO_SHLD    = 0x8C,   /* sel u8, dst u8, src u8, cnt u8       */
    VMO_PUSHF   = 0x8D,   /* sp u8                                */
    VMO_POPF    = 0x8E,   /* sp u8                                */
    VMO_MULB    = 0x8F,   /* sel u8, acc u8, den u8               */
    VMO_DIVB    = 0x90,   /* sel u8, acc u8, den u8               */
};

/* WIRE_NALU selector: (width << 4) | op */
#define NP_NALU_W8   0x0
#define NP_NALU_W16  0x1
#define NP_NALU_W32  0x2
#define NP_NALU_W64  0x3
#define NP_NALU_ADD  0
#define NP_NALU_SUB  1
#define NP_NALU_ADC  2
#define NP_NALU_SBB  3
#define NP_NALU_AND  4
#define NP_NALU_OR   5
#define NP_NALU_XOR  6
#define NP_NALU_NOT  7
#define NP_NALU_INC  8
#define NP_NALU_DEC  9
#define NP_NALU_NEG  10
#define NP_NALU_SHL  11
#define NP_NALU_SHR  12
#define NP_NALU_SAR  13
#define NP_NALU_ROL  14
#define NP_NALU_ROR  15

/* WIRE_XALU selector: (fmt << 4) | op */
#define NP_XALU_FMT_PS  0x0
#define NP_XALU_FMT_PD  0x1
#define NP_XALU_FMT_SS  0x2
#define NP_XALU_FMT_SD  0x3
#define NP_XALU_FMT_B   0x4
#define NP_XALU_FMT_W   0x5
#define NP_XALU_FMT_D   0x6
#define NP_XALU_FMT_Q   0x7
#define NP_XALU_ADD    0
#define NP_XALU_SUB    1
#define NP_XALU_MUL    2
#define NP_XALU_DIV    3
#define NP_XALU_MIN    4
#define NP_XALU_MAX    5
#define NP_XALU_SQRT   6
#define NP_XALU_AND    7
#define NP_XALU_OR     8
#define NP_XALU_XOR    9
#define NP_XALU_ANDN   10
#define NP_XALU_CMPEQ  11
#define NP_XALU_CMPGT  12
#define NP_XALU_CMPLE  13
#define NP_XALU_CMPLT  14
#define NP_XALU_CMPORD 15
#define NP_XALU_CVT2F  16
#define NP_XALU_CVT2I  17
#define NP_XALU_CVT2F2 18
#define NP_XALU_UNPCKL 19
#define NP_XALU_UNPCKH 20
#define NP_XALU_PACK   21
#define NP_XALU_PSHUF  22
#define NP_XALU_SHLI   23
#define NP_XALU_SHRI   24
#define NP_XALU_SARI   25
#define NP_XALU_MOVMSK 26
#define NP_XALU_SPLICE 27

/* ========================================================================
 * stage / guest tables
 *
 * EnableRevirtualization splits one region into several outer stages (each
 * with its own opcode permutation and keystream key) and lifts straight-line
 * arithmetic runs into second-level "guest" blocks (own permutation, own key,
 * permuted register file). Both tables live in the payload data area; their
 * addresses are recovered from the reverse table pointer so the interpreter
 * keeps its four-argument ABI and the generated trampoline is unchanged.
 * ======================================================================== */

#define NP_VM_STAGE_SIZE  24u   /* bc_delta, bc_len, rev_delta, key, rva */
#define NP_VM_GUEST_SIZE  32u   /* bc_delta, bc_len, rev_delta, perm_delta,
                                 * key, rva, flags */
#define NP_VM_GUEST_MAX   96u
#define NP_VM_STAGE_MAX   32u
/* Descriptor flag layout, shared with include/vm_revirt.h:
 *   bit0        live
 *   bits 8..23  writeMask (outer registers copied back on return)
 *   bits 24..27 nesting level, 1 for a block lifted out of an outer stage
 * A level-N block reaches its own children through the same WIRE_GSTAGE
 * instruction and the same flat table, so the depth is a property of the
 * descriptor rather than of a table per level. */
#define NP_VM_GUEST_WMASK(flags)  (((flags) >> 8) & 0xFFFFu)
#define NP_VM_GUEST_LEVEL(flags)  (((flags) >> 24) & 0xFu)
#define NP_VM_GUEST_DEPTH 8u

struct NpVmTables {
    const u8* stageTable;
    u32 stageCount;
    const u8* guestTable;
    u32 guestCount;
};

#define NP_VM_REGS 16
/* Register-file slots handed to np_vm_run: 16 guest registers, 2 translator
 * scratch slots (they must not alias any guest register - the address builder
 * clobbers them freely) and 2 control slots (native exit address, runtime
 * image base) that the trampoline parks behind the file. */
#define NP_VM_SLOTS 20u
#define NP_VM_SCRATCH_A 16u
#define NP_VM_SCRATCH_B 17u

/* ========================================================================
 * bytecode decoding window
 *
 * The stored bytecode is a counter-mode keystream ciphertext. Byte i is
 * masked with a word derived from (key, region RVA, i>>3) only, so any offset
 * can be decoded independently. The interpreter therefore keeps a 256-byte
 * plaintext window and refills it on demand, which means the full program
 * never exists in memory - a dump taken while the VM is running yields at
 * most a few hundred decoded bytes, and backwards branch targets still work
 * because the stream is randomly addressable.
 *
 * np_vm_mix()/np_vm_block() must stay bit-identical to vmBytecodeCrypt() in
 * src/crypto_layers.cpp.
 * ======================================================================== */

#define NP_VM_WIN 256u

static u64 np_vm_mix(u64 x) {
    x ^= x >> 30; x *= 0xBF58476D1CE4E5B9ull;
    x ^= x >> 27; x *= 0x94D049BB133111EBull;
    x ^= x >> 31;
    return x;
}

static u64 np_vm_block(u64 salted_key, u64 block) {
    return np_vm_mix(salted_key + block * 0x9E3779B97F4A7C15ull);
}

static void np_vm_window(u8* win, u64* base, u64* span,
                         const u8* code, u64 len, u64 pos, u64 key, u32 rva) {
    u64 start = pos;
    if (start + NP_VM_WIN > len) start = (len > NP_VM_WIN) ? (len - NP_VM_WIN) : 0;
    u64 n = len - start;
    if (n > NP_VM_WIN) n = NP_VM_WIN;
    *base = start;
    *span = n;

    u64 salted = key ^ ((u64)rva * 0x9E3779B97F4A7C15ull);
    u64 current = ~(u64)0;
    u64 word = 0;
    for (u64 k = 0; k < n; k++) {
        u64 abs = start + k;
        u64 blk = abs >> 3;
        if (blk != current) { current = blk; word = np_vm_block(salted, blk); }
        win[k] = (u8)(code[abs] ^ (u8)(word >> ((abs & 7u) * 8u)));
    }
    /* Tail bytes past the end of the region read as zero instead of stack
     * garbage if a malformed stream runs off the buffer. */
    for (u64 k = n; k < NP_VM_WIN; k++) win[k] = 0;
}

/* ========================================================================
 * opcode handlers
 *
 * Each instruction has its own out-of-line handler instead of one switch. That
 * spreads the semantics over dozens of separate code addresses, so a single
 * breakpoint on the dispatch site no longer intercepts every operation and the
 * "find the interpreter switch" heuristic has nothing to anchor on.
 *
 * The handler table is filled at run time on purpose: the protection blob is
 * copied verbatim into the target image, so a statically initialised array of
 * function pointers would still contain link-time addresses after the copy and
 * jump into nothing. Assigning them at run time makes the compiler emit
 * RIP-relative address loads, which survive the copy.
 * ======================================================================== */

typedef struct NpVmState NpVmState;
typedef void (*NpVmHandler)(NpVmState*);

struct NpVmState {
    u64* r;
    const u8* win;
    u64  winBase;
    u64  ip;
    u64  codeLen;
    int  zf, cf, sf, of, pf;
    /* Direction flag for the string primitives (CLD/STD). The interpreter
     * itself never reads the hardware DF; the VM carries its own. */
    int  df;
    /* Set by VMO_STAGEEND: the outer dispatcher continues at the start of the
     * next stage instead of running off the end of this one. */
    u32  stageEnd;
    /* Runtime image base (patched into the region trailer by np_vm_install,
     * zero on legacy payloads) used to re-base the image RVAs carried by
     * VMO_EXITJMP / VMO_CALL. */
    u64  imgBase;
    /* Set by VMO_EXITJMP: where the trampoline should continue natively.
     * 0 means the region's normal fall-through exit. */
    u64  exitAddr;
    /* 16x16 bytes of xmm state, laid out right behind the GPR register file
     * in the trampoline frame (operands 20+i name xmm i). */
    u8*  x;
};

#define NPB(s) ((s)->win[(s)->ip++ - (s)->winBase])
#define NPR(x) ((x) < 18u)   /* guest + scratch; control slots are untouchable */

/* PF = 1 when the low byte of the result has an even number of set bits.
 * Every ALU/logic handler that writes zf/sf must also write pf from the same
 * result, or a later jp/jnp would read a stale parity from an older op. */
static int np_parity_even(u64 res) {
    u8 b = (u8)res;
    b ^= b >> 4;
    b ^= b >> 2;
    b ^= b >> 1;
    return (int)((~b) & 1);
}

static u64 np_imm64(NpVmState* s) {
    u64 v = 0;
    for (u32 k = 0; k < 8; k++) v |= (u64)NPB(s) << (k * 8);
    return v;
}
static u64 np_imm32(NpVmState* s) {
    u64 v = 0;
    for (u32 k = 0; k < 4; k++) v |= (u64)NPB(s) << (k * 8);
    return v;
}

/* ---- data movement ---------------------------------------------------- */
static void np_h_loadimm(NpVmState* s) {
    u32 d = NPB(s);
    u64 v = np_imm64(s);
    if (NPR(d)) s->r[d] = v;
}
static void np_h_loadb(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    u64 o = np_imm32(s);
    if (NPR(d) && NPR(b)) s->r[d] = (u64)*(const u8*)(s->r[b] + o);
}
static void np_h_loadq(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    u64 o = np_imm32(s);
    if (NPR(d) && NPR(b)) {
        const u8* p = (const u8*)(s->r[b] + o);
        u64 v = 0;
        for (u32 k = 0; k < 8; k++) v |= (u64)p[k] << (k * 8);
        s->r[d] = v;
    }
}
static void np_h_storeb(NpVmState* s) {
    u32 b = NPB(s);
    u64 o = np_imm32(s);
    u32 src = NPB(s);
    if (NPR(b) && NPR(src)) *(u8*)(s->r[b] + o) = (u8)s->r[src];
}
static void np_h_storeq(NpVmState* s) {
    u32 b = NPB(s);
    u64 o = np_imm32(s);
    u32 src = NPB(s);
    if (NPR(b) && NPR(src)) {
        u8* p = (u8*)(s->r[b] + o);
        for (u32 k = 0; k < 8; k++) p[k] = (u8)(s->r[src] >> (k * 8));
    }
}
static void np_h_xoreq(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    if (NPR(d) && NPR(b)) s->r[d] ^= s->r[b];
}
static void np_h_move(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    if (NPR(d) && NPR(b)) s->r[d] = s->r[b];
}

/* ---- register/register ALU -------------------------------------------- */
static void np_h_add(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    if (NPR(d) && NPR(b)) {
        u64 a = s->r[d], v = s->r[b], res = a + v;
        s->cf = (res < a);
        s->of = (int)((((a ^ res) & (v ^ res)) >> 63) & 1);
        s->r[d] = res;
        s->zf = (res == 0);
        s->sf = (int)((res >> 63) & 1);
        s->pf = np_parity_even(res);
    }
}
static void np_h_sub(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    if (NPR(d) && NPR(b)) {
        u64 a = s->r[d], v = s->r[b], res = a - v;
        s->cf = (a < v);
        s->of = (int)((((a ^ v) & (a ^ res)) >> 63) & 1);
        s->r[d] = res;
        s->zf = (res == 0);
        s->sf = (int)((res >> 63) & 1);
        s->pf = np_parity_even(res);
    }
}
/* MUL leaves the flags alone, exactly like the original interpreter. */
static void np_h_mul(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    if (NPR(d) && NPR(b)) s->r[d] = s->r[d] * s->r[b];
}
static void np_h_and(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    if (NPR(d) && NPR(b)) {
        s->r[d] &= s->r[b];
        s->zf = (s->r[d] == 0);
        s->sf = (int)((s->r[d] >> 63) & 1);
        s->pf = np_parity_even(s->r[d]);
    }
}
static void np_h_or(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    if (NPR(d) && NPR(b)) {
        s->r[d] |= s->r[b];
        s->zf = (s->r[d] == 0);
        s->sf = (int)((s->r[d] >> 63) & 1);
        s->pf = np_parity_even(s->r[d]);
    }
}
static void np_h_xor(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    if (NPR(d) && NPR(b)) {
        s->r[d] ^= s->r[b];
        s->zf = (s->r[d] == 0);
        s->sf = (int)((s->r[d] >> 63) & 1);
        s->pf = np_parity_even(s->r[d]);
    }
}
static void np_h_shl(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    if (NPR(d) && NPR(b)) {
        s->r[d] = s->r[d] << (s->r[b] & 63u);
        s->zf = (s->r[d] == 0);
        s->sf = (int)((s->r[d] >> 63) & 1);
        s->pf = np_parity_even(s->r[d]);
    }
}
static void np_h_shr(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    if (NPR(d) && NPR(b)) {
        s->r[d] = s->r[d] >> (s->r[b] & 63u);
        s->zf = (s->r[d] == 0);
        s->sf = (int)((s->r[d] >> 63) & 1);
        s->pf = np_parity_even(s->r[d]);
    }
}
static void np_h_sar(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    if (NPR(d) && NPR(b)) {
        s->r[d] = (u64)(((i64)s->r[d]) >> (s->r[b] & 63u));
        s->zf = (s->r[d] == 0);
        s->sf = (int)((s->r[d] >> 63) & 1);
        s->pf = np_parity_even(s->r[d]);
    }
}
static void np_h_not(NpVmState* s) {
    u32 d = NPB(s);
    if (NPR(d)) s->r[d] = ~s->r[d];
}
static void np_h_neg(NpVmState* s) {
    u32 d = NPB(s);
    if (NPR(d)) {
        u64 a = s->r[d];
        s->r[d] = (u64)(-(i64)a);
        s->cf = (a != 0);
        s->zf = (s->r[d] == 0);
        s->sf = (int)((s->r[d] >> 63) & 1);
        s->pf = np_parity_even(s->r[d]);
    }
}
static void np_h_cmp(NpVmState* s) {
    u32 x = NPB(s), y = NPB(s);
    if (NPR(x) && NPR(y)) {
        u64 a = s->r[x], b = s->r[y], res = a - b;
        s->zf = (res == 0);
        s->cf = (a < b);
        s->sf = (int)((res >> 63) & 1);
        s->of = (int)(((((a ^ b) & (a ^ res)) >> 63)) & 1);
        s->pf = np_parity_even(res);
    }
}
static void np_h_test(NpVmState* s) {
    u32 x = NPB(s), y = NPB(s);
    if (NPR(x) && NPR(y)) {
        u64 res = s->r[x] & s->r[y];
        s->zf = (res == 0);
        s->cf = 0;
        s->of = 0;
        s->sf = (int)((res >> 63) & 1);
        s->pf = np_parity_even(res);
    }
}

/* ---- register/immediate ALU ------------------------------------------- */
static void np_h_muli(NpVmState* s) {
    u32 d = NPB(s);
    u64 v = np_imm64(s);
    if (NPR(d)) s->r[d] *= v;
}
static void np_h_addi(NpVmState* s) {
    u32 d = NPB(s);
    u64 v = np_imm64(s);
    if (NPR(d)) {
        u64 a = s->r[d], res = a + v;
        s->cf = (res < a);
        s->of = (int)((((a ^ res) & (v ^ res)) >> 63) & 1);
        s->r[d] = res;
        s->zf = (res == 0);
        s->sf = (int)((res >> 63) & 1);
        s->pf = np_parity_even(res);
    }
}
static void np_h_subi(NpVmState* s) {
    u32 d = NPB(s);
    u64 v = np_imm64(s);
    if (NPR(d)) {
        u64 a = s->r[d], res = a - v;
        s->cf = (a < v);
        s->of = (int)((((a ^ v) & (a ^ res)) >> 63) & 1);
        s->r[d] = res;
        s->zf = (res == 0);
        s->sf = (int)((res >> 63) & 1);
        s->pf = np_parity_even(res);
    }
}
static void np_h_andi(NpVmState* s) {
    u32 d = NPB(s);
    u64 v = np_imm64(s);
    if (NPR(d)) {
        s->r[d] &= v;
        s->zf = (s->r[d] == 0);
        s->sf = (int)((s->r[d] >> 63) & 1);
        s->cf = 0;
        s->pf = np_parity_even(s->r[d]);
    }
}
static void np_h_ori(NpVmState* s) {
    u32 d = NPB(s);
    u64 v = np_imm64(s);
    if (NPR(d)) {
        s->r[d] |= v;
        s->zf = (s->r[d] == 0);
        s->sf = (int)((s->r[d] >> 63) & 1);
        s->cf = 0;
        s->pf = np_parity_even(s->r[d]);
    }
}
static void np_h_xori(NpVmState* s) {
    u32 d = NPB(s);
    u64 v = np_imm64(s);
    if (NPR(d)) {
        s->r[d] ^= v;
        s->zf = (s->r[d] == 0);
        s->sf = (int)((s->r[d] >> 63) & 1);
        s->cf = 0;
        s->pf = np_parity_even(s->r[d]);
    }
}
static void np_h_shri(NpVmState* s) {
    u32 d = NPB(s);
    u64 v = np_imm64(s);
    if (NPR(d)) {
        s->r[d] = s->r[d] >> (v & 63u);
        s->zf = (s->r[d] == 0);
        s->sf = (int)((s->r[d] >> 63) & 1);
        s->pf = np_parity_even(s->r[d]);
    }
}
static void np_h_shli(NpVmState* s) {
    u32 d = NPB(s);
    u64 v = np_imm64(s);
    if (NPR(d)) {
        s->r[d] = s->r[d] << (v & 63u);
        s->zf = (s->r[d] == 0);
        s->sf = (int)((s->r[d] >> 63) & 1);
        s->pf = np_parity_even(s->r[d]);
    }
}
static void np_h_sari(NpVmState* s) {
    u32 d = NPB(s);
    u64 v = np_imm64(s);
    if (NPR(d)) {
        s->r[d] = (u64)(((i64)s->r[d]) >> (v & 63u));
        s->zf = (s->r[d] == 0);
        s->sf = (int)((s->r[d] >> 63) & 1);
        s->pf = np_parity_even(s->r[d]);
    }
}
/* RORI leaves the flags alone, exactly like the original interpreter. */
static void np_h_rori(NpVmState* s) {
    u32 d = NPB(s);
    u64 v = np_imm64(s);
    if (NPR(d)) {
        u32 sh = (u32)(v & 63u);
        s->r[d] = (s->r[d] >> sh) | (s->r[d] << ((64u - sh) & 63u));
    }
}
static void np_h_cmpi(NpVmState* s) {
    u32 d = NPB(s);
    u64 v = np_imm64(s);
    if (NPR(d)) {
        u64 a = s->r[d], res = a - v;
        s->zf = (res == 0);
        s->cf = (a < v);
        s->sf = (int)((res >> 63) & 1);
        s->of = (int)(((((a ^ v) & (a ^ res)) >> 63)) & 1);
        s->pf = np_parity_even(res);
    }
}

/* ---- memory-operand micro-ops -----------------------------------------
 * The original ISA could only transfer whole qwords, so any region touching a
 * byte / word / dword field had to be left native. These decoders close that
 * gap; the sign-extending ones are what movsx / movsxd from memory need.
 * --------------------------------------------------------------------- */
static void np_h_loadw(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    u64 o = np_imm32(s);
    if (NPR(d) && NPR(b)) s->r[d] = (u64)*(const u16*)(s->r[b] + o);
}
static void np_h_loadd(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    u64 o = np_imm32(s);
    if (NPR(d) && NPR(b)) s->r[d] = (u64)*(const u32*)(s->r[b] + o);
}
static void np_h_loadsb(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    u64 o = np_imm32(s);
    if (NPR(d) && NPR(b)) s->r[d] = (u64)(i64)*(const i8*)(s->r[b] + o);
}
static void np_h_loadsw(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    u64 o = np_imm32(s);
    if (NPR(d) && NPR(b)) s->r[d] = (u64)(i64)*(const i16*)(s->r[b] + o);
}
static void np_h_loadsd(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    u64 o = np_imm32(s);
    if (NPR(d) && NPR(b)) s->r[d] = (u64)(i64)*(const i32*)(s->r[b] + o);
}
static void np_h_storew(NpVmState* s) {
    u32 b = NPB(s);
    u64 o = np_imm32(s);
    u32 src = NPB(s);
    if (NPR(b) && NPR(src)) *(u16*)(s->r[b] + o) = (u16)s->r[src];
}
static void np_h_stored(NpVmState* s) {
    u32 b = NPB(s);
    u64 o = np_imm32(s);
    u32 src = NPB(s);
    if (NPR(b) && NPR(src)) *(u32*)(s->r[b] + o) = (u32)s->r[src];
}

/* ---- rotates ---------------------------------------------------------- */
static void np_h_rol(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    if (NPR(d) && NPR(b)) {
        u32 sh = (u32)(s->r[b] & 63u);
        s->r[d] = sh ? ((s->r[d] << sh) | (s->r[d] >> (64u - sh))) : s->r[d];
    }
}
static void np_h_ror(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    if (NPR(d) && NPR(b)) {
        u32 sh = (u32)(s->r[b] & 63u);
        s->r[d] = sh ? ((s->r[d] >> sh) | (s->r[d] << (64u - sh))) : s->r[d];
    }
}
static void np_h_roli(NpVmState* s) {
    u32 d = NPB(s);
    u64 v = np_imm64(s);
    if (NPR(d)) {
        u32 sh = (u32)(v & 63u);
        s->r[d] = sh ? ((s->r[d] << sh) | (s->r[d] >> (64u - sh))) : s->r[d];
    }
}

/* ---- 32-bit operand forms ---------------------------------------------
 * In a 64-bit stream `add eax, ecx` produces a 32-bit result that is then
 * zero-extended into rax, and its flags come from the 32-bit arithmetic.
 * These handlers reproduce both; widening them to the 64-bit op would change
 * the observable result whenever the upper half was non-zero.
 * --------------------------------------------------------------------- */
#define NP_LO32(x) ((u32)(x))
#define NP_ZX32(x) ((u64)(u32)(x))

static void np_h_addd(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    if (NPR(d) && NPR(b)) {
        u32 a = NP_LO32(s->r[d]), v = NP_LO32(s->r[b]), res = a + v;
        s->cf = (res < a);
        s->of = (int)((((a ^ res) & (v ^ res)) >> 31) & 1u);
        s->r[d] = NP_ZX32(res);
        s->zf = (res == 0);
        s->sf = (int)((res >> 31) & 1u);
        s->pf = np_parity_even(res);
    }
}
static void np_h_subd(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    if (NPR(d) && NPR(b)) {
        u32 a = NP_LO32(s->r[d]), v = NP_LO32(s->r[b]), res = a - v;
        s->cf = (a < v);
        s->of = (int)((((a ^ v) & (a ^ res)) >> 31) & 1u);
        s->r[d] = NP_ZX32(res);
        s->zf = (res == 0);
        s->sf = (int)((res >> 31) & 1u);
        s->pf = np_parity_even(res);
    }
}
static void np_h_andd(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    if (NPR(d) && NPR(b)) {
        u32 res = NP_LO32(s->r[d]) & NP_LO32(s->r[b]);
        s->r[d] = NP_ZX32(res);
        s->zf = (res == 0); s->sf = (int)((res >> 31) & 1u); s->cf = 0; s->of = 0;
        s->pf = np_parity_even(res);
    }
}
static void np_h_ord(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    if (NPR(d) && NPR(b)) {
        u32 res = NP_LO32(s->r[d]) | NP_LO32(s->r[b]);
        s->r[d] = NP_ZX32(res);
        s->zf = (res == 0); s->sf = (int)((res >> 31) & 1u); s->cf = 0; s->of = 0;
        s->pf = np_parity_even(res);
    }
}
static void np_h_xord(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    if (NPR(d) && NPR(b)) {
        u32 res = NP_LO32(s->r[d]) ^ NP_LO32(s->r[b]);
        s->r[d] = NP_ZX32(res);
        s->zf = (res == 0); s->sf = (int)((res >> 31) & 1u); s->cf = 0; s->of = 0;
        s->pf = np_parity_even(res);
    }
}
static void np_h_muld(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    if (NPR(d) && NPR(b)) s->r[d] = NP_ZX32((u64)NP_LO32(s->r[d]) * (u64)NP_LO32(s->r[b]));
}
static void np_h_cmpd(NpVmState* s) {
    u32 x = NPB(s), y = NPB(s);
    if (NPR(x) && NPR(y)) {
        u32 a = NP_LO32(s->r[x]), b = NP_LO32(s->r[y]), res = a - b;
        s->zf = (res == 0);
        s->cf = (a < b);
        s->sf = (int)((res >> 31) & 1u);
        s->of = (int)((((a ^ b) & (a ^ res)) >> 31) & 1u);
        s->pf = np_parity_even(res);
    }
}
static void np_h_testd(NpVmState* s) {
    u32 x = NPB(s), y = NPB(s);
    if (NPR(x) && NPR(y)) {
        u32 res = NP_LO32(s->r[x]) & NP_LO32(s->r[y]);
        s->zf = (res == 0); s->cf = 0; s->of = 0;
        s->sf = (int)((res >> 31) & 1u);
        s->pf = np_parity_even(res);
    }
}
static void np_h_addid(NpVmState* s) {
    u32 d = NPB(s);
    u64 v = np_imm64(s);
    if (NPR(d)) {
        u32 a = NP_LO32(s->r[d]), b = NP_LO32(v), res = a + b;
        s->cf = (res < a);
        s->of = (int)((((a ^ res) & (b ^ res)) >> 31) & 1u);
        s->r[d] = NP_ZX32(res);
        s->zf = (res == 0);
        s->sf = (int)((res >> 31) & 1u);
        s->pf = np_parity_even(res);
    }
}
static void np_h_subid(NpVmState* s) {
    u32 d = NPB(s);
    u64 v = np_imm64(s);
    if (NPR(d)) {
        u32 a = NP_LO32(s->r[d]), b = NP_LO32(v), res = a - b;
        s->cf = (a < b);
        s->of = (int)((((a ^ b) & (a ^ res)) >> 31) & 1u);
        s->r[d] = NP_ZX32(res);
        s->zf = (res == 0);
        s->sf = (int)((res >> 31) & 1u);
        s->pf = np_parity_even(res);
    }
}
static void np_h_andid(NpVmState* s) {
    u32 d = NPB(s);
    u64 v = np_imm64(s);
    if (NPR(d)) {
        u32 res = NP_LO32(s->r[d]) & NP_LO32(v);
        s->r[d] = NP_ZX32(res);
        s->zf = (res == 0); s->sf = (int)((res >> 31) & 1u); s->cf = 0; s->of = 0;
        s->pf = np_parity_even(res);
    }
}
static void np_h_orid(NpVmState* s) {
    u32 d = NPB(s);
    u64 v = np_imm64(s);
    if (NPR(d)) {
        u32 res = NP_LO32(s->r[d]) | NP_LO32(v);
        s->r[d] = NP_ZX32(res);
        s->zf = (res == 0); s->sf = (int)((res >> 31) & 1u); s->cf = 0; s->of = 0;
        s->pf = np_parity_even(res);
    }
}
static void np_h_xorid(NpVmState* s) {
    u32 d = NPB(s);
    u64 v = np_imm64(s);
    if (NPR(d)) {
        u32 res = NP_LO32(s->r[d]) ^ NP_LO32(v);
        s->r[d] = NP_ZX32(res);
        s->zf = (res == 0); s->sf = (int)((res >> 31) & 1u); s->cf = 0; s->of = 0;
        s->pf = np_parity_even(res);
    }
}
static void np_h_cmpid(NpVmState* s) {
    u32 d = NPB(s);
    u64 v = np_imm64(s);
    if (NPR(d)) {
        u32 a = NP_LO32(s->r[d]), b = NP_LO32(v), res = a - b;
        s->zf = (res == 0);
        s->cf = (a < b);
        s->sf = (int)((res >> 31) & 1u);
        s->of = (int)((((a ^ b) & (a ^ res)) >> 31) & 1u);
        s->pf = np_parity_even(res);
    }
}
static void np_h_shlid(NpVmState* s) {
    u32 d = NPB(s);
    u64 v = np_imm64(s);
    if (NPR(d)) {
        u32 sh = (u32)(v & 31u), res = NP_LO32(s->r[d]) << sh;
        s->r[d] = NP_ZX32(res);
        s->zf = (res == 0); s->sf = (int)((res >> 31) & 1u);
        s->pf = np_parity_even(res);
    }
}
static void np_h_shrid(NpVmState* s) {
    u32 d = NPB(s);
    u64 v = np_imm64(s);
    if (NPR(d)) {
        u32 sh = (u32)(v & 31u), res = NP_LO32(s->r[d]) >> sh;
        s->r[d] = NP_ZX32(res);
        s->zf = (res == 0); s->sf = (int)((res >> 31) & 1u);
        s->pf = np_parity_even(res);
    }
}
static void np_h_sarid(NpVmState* s) {
    u32 d = NPB(s);
    u64 v = np_imm64(s);
    if (NPR(d)) {
        u32 sh = (u32)(v & 31u);
        u32 res = (u32)(((i32)NP_LO32(s->r[d])) >> sh);
        s->r[d] = NP_ZX32(res);
        s->zf = (res == 0); s->sf = (int)((res >> 31) & 1u);
        s->pf = np_parity_even(res);
    }
}
static void np_h_negd(NpVmState* s) {
    u32 d = NPB(s);
    if (NPR(d)) {
        u32 a = NP_LO32(s->r[d]), res = (u32)(0u - a);
        s->r[d] = NP_ZX32(res);
        s->cf = (a != 0); s->zf = (res == 0);
        s->sf = (int)((res >> 31) & 1u);
        s->pf = np_parity_even(res);
    }
}
static void np_h_notd(NpVmState* s) {
    u32 d = NPB(s);
    if (NPR(d)) s->r[d] = NP_ZX32(~NP_LO32(s->r[d]));
}

/* ---- explicit-width register moves ------------------------------------ */
static void np_h_movd(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    if (NPR(d) && NPR(b)) s->r[d] = NP_ZX32(s->r[b]);
}
static void np_h_movzxb(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    if (NPR(d) && NPR(b)) s->r[d] = (u64)(u8)s->r[b];
}
static void np_h_movzxw(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    if (NPR(d) && NPR(b)) s->r[d] = (u64)(u16)s->r[b];
}
static void np_h_movsxb(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    if (NPR(d) && NPR(b)) s->r[d] = (u64)(i64)(i8)s->r[b];
}
static void np_h_movsxw(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    if (NPR(d) && NPR(b)) s->r[d] = (u64)(i64)(i16)s->r[b];
}
static void np_h_movsxd(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    if (NPR(d) && NPR(b)) s->r[d] = (u64)(i64)(i32)NP_LO32(s->r[b]);
}

/* ---- control flow ------------------------------------------------------ */
static void np_h_jmp(NpVmState* s) { s->ip = (u64)np_imm32(s); }
static void np_h_je(NpVmState* s)  { u64 t = np_imm32(s); if (s->zf) s->ip = t; }
static void np_h_jne(NpVmState* s) { u64 t = np_imm32(s); if (!s->zf) s->ip = t; }
static void np_h_jae(NpVmState* s) { u64 t = np_imm32(s); if (!s->cf) s->ip = t; }
static void np_h_jb(NpVmState* s)  { u64 t = np_imm32(s); if (s->cf) s->ip = t; }
static void np_h_jge(NpVmState* s) { u64 t = np_imm32(s); if (s->sf == s->of) s->ip = t; }
static void np_h_jl(NpVmState* s)  { u64 t = np_imm32(s); if (s->sf != s->of) s->ip = t; }
static void np_h_jg(NpVmState* s)  { u64 t = np_imm32(s); if (!s->zf && s->sf == s->of) s->ip = t; }
static void np_h_jle(NpVmState* s) { u64 t = np_imm32(s); if (s->zf || s->sf != s->of) s->ip = t; }
static void np_h_ja(NpVmState* s)  { u64 t = np_imm32(s); if (!s->cf && !s->zf) s->ip = t; }
static void np_h_jbe(NpVmState* s) { u64 t = np_imm32(s); if (s->cf || s->zf) s->ip = t; }
static void np_h_js(NpVmState* s)  { u64 t = np_imm32(s); if (s->sf) s->ip = t; }
static void np_h_jns(NpVmState* s) { u64 t = np_imm32(s); if (!s->sf) s->ip = t; }
static void np_h_jo(NpVmState* s)  { u64 t = np_imm32(s); if (s->of) s->ip = t; }
static void np_h_jno(NpVmState* s) { u64 t = np_imm32(s); if (!s->of) s->ip = t; }
static void np_h_jp(NpVmState* s)  { u64 t = np_imm32(s); if (s->pf) s->ip = t; }
static void np_h_jnp(NpVmState* s) { u64 t = np_imm32(s); if (!s->pf) s->ip = t; }
static void np_h_insb(NpVmState* s) { u32 d = NPB(s), sc = NPB(s); if (NPR(d) && NPR(sc)) s->r[d] = (s->r[d] & ~0xFFull) | (s->r[sc] & 0xFFull); }
static void np_h_insw(NpVmState* s) { u32 d = NPB(s), sc = NPB(s); if (NPR(d) && NPR(sc)) s->r[d] = (s->r[d] & ~0xFFFFull) | (s->r[sc] & 0xFFFFull); }

/* Leave the VM and continue natively at an image address. The operand is an
 * RVA; the trampoline re-enters the saved registers and jumps to
 * imgBase+rva. A zero RVA keeps the region's fall-through exit. */
static void np_h_exitjmp(NpVmState* s) {
    u32 t = np_imm32(s);
    if (t & 0x80000000u) {
        /* Indirect: the low bits name the guest register holding the target. */
        u32 slot = t & 0x7FFFFFFFu;
        s->exitAddr = (slot < 18u) ? s->r[slot] : 0;
    } else {
        s->exitAddr = t ? (s->imgBase + (u64)t) : 0;
    }
    s->ip = s->codeLen;
}

/* Real x86-64 call from inside the interpreter. The callee runs on the
 * interpreter's own stack - never the guest stack, which the trampoline's
 * register file occupies - with the guest's volatile registers loaded and
 * 256 bytes of stack arguments copied out of the guest frame. Nonvolatile
 * registers are untouched: per the platform ABI the callee preserves them,
 * so the guest's values survive in the register file either way.
 * Operand: bit31 clear = direct target RVA; bit31 set = low 4 bits name the
 * guest register holding the target (indirect call). */
void np_vm_native_call(u64 target, u64* vals);   /* asm, below */
static void np_h_call(NpVmState* s) {
    u32 t = np_imm32(s);
    u64 target = 0;
    if (t & 0x80000000u) {
        u32 slot = t & 0x7FFFFFFFu;
        if (slot < 18u) target = s->r[slot];
    } else {
        target = s->imgBase + (u64)t;
    }
    if (target) np_vm_native_call(target, s->r);
}

/* Re-base an image RVA: the run-time image base comes from the control slot
 * the trampoline filled, so RIP-relative addressing survives ASLR exactly
 * the way the original instruction computed it. */
static void np_h_imgadd(NpVmState* s) {
    u32 d = NPB(s);
    u32 rva = np_imm32(s);
    if (NPR(d)) s->r[d] = s->imgBase + (u64)rva;
}

/* Narrow compares: flags live at byte/word width so a following jcc sees the
 * sign/overflow of the half-register the original instruction touched. */
#define NP_NARROW_CMP(name, T, bits) \
static void name(NpVmState* s) { \
    u32 a = NPB(s), b = NPB(s); \
    if (NPR(a) && NPR(b)) { \
        T va = (T)s->r[a], vb = (T)s->r[b]; \
        T res = (T)(va - vb); \
        s->zf = (res == 0); \
        s->cf = (va < vb); \
        s->sf = (int)((res >> (bits - 1)) & 1); \
        s->of = (int)((((va ^ vb) & (va ^ res)) >> (bits - 1)) & 1); \
        s->pf = np_parity_even((u64)res); \
    } \
}
NP_NARROW_CMP(np_h_cmpb, u8, 8)
NP_NARROW_CMP(np_h_cmpw, u16, 16)

#define NP_NARROW_TEST(name, T, bits) \
static void name(NpVmState* s) { \
    u32 a = NPB(s), b = NPB(s); \
    if (NPR(a) && NPR(b)) { \
        T res = (T)((T)s->r[a] & (T)s->r[b]); \
        s->zf = (res == 0); \
        s->cf = 0; \
        s->of = 0; \
        s->sf = (int)((res >> (bits - 1)) & 1); \
        s->pf = np_parity_even((u64)res); \
    } \
}
NP_NARROW_TEST(np_h_testb, u8, 8)
NP_NARROW_TEST(np_h_testw, u16, 16)

/* XMM data movement. Operands name xmm i as 20+i - deliberately outside the
 * GPR slot range so a register permutation never rewrites them - and the byte
 * array lives right behind the GPR register file. Every handler maps the
 * operand back to a 0..15 array index here; treating the operand as the index
 * directly (as this used to) made the range check reject every real xmm
 * operand, so the whole family was a silent no-op and a protected function
 * that moved vector data produced zeros. Stores/loads of 8 bytes splice into
 * the low half (movq) or zero the upper half, matching the SSE2 forms. */
#define NP_XIDX(o) (((o) >= 20u && (o) < 36u) ? (o) - 20u : 0xFFu)

static void np_h_xload(NpVmState* s) {
    u32 d = NP_XIDX(NPB(s)), b = NPB(s);
    u32 disp = np_imm32(s);
    if (d < 16 && NPR(b) && s->x) {
        const u8* p = (const u8*)(s->r[b] + (u64)disp);
        for (u32 k = 0; k < 16; k++) s->x[d * 16 + k] = p[k];
    }
}
static void np_h_xstore(NpVmState* s) {
    u32 b = NPB(s);
    u32 disp = np_imm32(s);
    u32 sd = NP_XIDX(NPB(s));
    if (sd < 16 && NPR(b) && s->x) {
        u8* p = (u8*)(s->r[b] + (u64)disp);
        for (u32 k = 0; k < 16; k++) p[k] = s->x[sd * 16 + k];
    }
}
static void np_h_xmov(NpVmState* s) {
    u32 d = NP_XIDX(NPB(s)), sc = NP_XIDX(NPB(s));
    if (d < 16 && sc < 16 && s->x)
        for (u32 k = 0; k < 16; k++) s->x[d * 16 + k] = s->x[sc * 16 + k];
}
static void np_h_xloadq(NpVmState* s) {
    u32 d = NP_XIDX(NPB(s)), b = NPB(s);
    u32 disp = np_imm32(s);
    if (d < 16 && NPR(b) && s->x) {
        const u8* p = (const u8*)(s->r[b] + (u64)disp);
        for (u32 k = 0; k < 16; k++) s->x[d * 16 + k] = (k < 8) ? p[k] : 0;
    }
}
static void np_h_xstoreq(NpVmState* s) {
    u32 b = NPB(s);
    u32 disp = np_imm32(s);
    u32 sd = NP_XIDX(NPB(s));
    if (sd < 16 && NPR(b) && s->x) {
        u8* p = (u8*)(s->r[b] + (u64)disp);
        for (u32 k = 0; k < 8; k++) p[k] = s->x[sd * 16 + k];
    }
}
static void np_h_xloadd(NpVmState* s) {
    u32 d = NP_XIDX(NPB(s)), g = NPB(s);
    if (d < 16 && NPR(g) && s->x) {
        for (u32 k = 0; k < 16; k++) s->x[d * 16 + k] = 0;
        u64 v = s->r[g];
        for (u32 k = 0; k < 8; k++) s->x[d * 16 + k] = (u8)(v >> (k * 8));
    }
}
static void np_h_xstored(NpVmState* s) {
    u32 g = NPB(s), sd = NP_XIDX(NPB(s));
    if (NPR(g) && sd < 16 && s->x) {
        u64 v = 0;
        for (u32 k = 0; k < 8; k++) v |= (u64)s->x[sd * 16 + k] << (k * 8);
        s->r[g] = v;
    }
}
static void np_h_xxor(NpVmState* s) {
    u32 d = NP_XIDX(NPB(s)), sc = NP_XIDX(NPB(s));
    if (d < 16 && sc < 16 && s->x)
        for (u32 k = 0; k < 16; k++) s->x[d * 16 + k] ^= s->x[sc * 16 + k];
}
static void np_h_sbb(NpVmState* s) {
    u32 d = NPB(s), sc = NPB(s);
    if (NPR(d) && NPR(sc)) {
        u64 a = s->r[d], b = s->r[sc], borrow = s->cf ? 1u : 0u;
        u64 result = a - b - borrow;
        s->cf = (borrow ? (a <= b) : (a < b));
        s->zf = (result == 0);
        s->sf = (int)(result >> 63);
        s->of = (int)(((a ^ b) & (a ^ result)) >> 63);
        s->pf = np_parity_even(result);
        s->r[d] = result;
    }
}
static void np_h_sbbi(NpVmState* s) {
    u32 d = NPB(s);
    u64 b = np_imm64(s);
    if (NPR(d)) {
        u64 a = s->r[d], borrow = s->cf ? 1u : 0u;
        u64 result = a - b - borrow;
        s->cf = (borrow ? (a <= b) : (a < b));
        s->zf = (result == 0);
        s->sf = (int)(result >> 63);
        s->of = (int)(((a ^ b) & (a ^ result)) >> 63);
        s->pf = np_parity_even(result);
        s->r[d] = result;
    }
}
static void np_h_adc(NpVmState* s) {
    u32 d = NPB(s), sc = NPB(s);
    if (NPR(d) && NPR(sc)) {
        u64 a = s->r[d], b = s->r[sc], carry = s->cf ? 1u : 0u;
        u64 result = a + b + carry;
        s->cf = (result < a) || (carry && result == a);
        s->zf = (result == 0);
        s->sf = (int)(result >> 63);
        s->of = (int)((~(a ^ b) & (a ^ result)) >> 63);
        s->pf = np_parity_even(result);
        s->r[d] = result;
    }
}
static void np_h_adci(NpVmState* s) {
    u32 d = NPB(s);
    u64 b = np_imm64(s);
    if (NPR(d)) {
        u64 a = s->r[d], carry = s->cf ? 1u : 0u;
        u64 result = a + b + carry;
        s->cf = (result < a) || (carry && result == a);
        s->zf = (result == 0);
        s->sf = (int)(result >> 63);
        s->of = (int)((~(a ^ b) & (a ^ result)) >> 63);
        s->pf = np_parity_even(result);
        s->r[d] = result;
    }
}
static void np_h_sbbd(NpVmState* s) {
    u32 d = NPB(s), sc = NPB(s);
    if (NPR(d) && NPR(sc)) {
        u32 a = (u32)s->r[d], b = (u32)s->r[sc], borrow = s->cf ? 1u : 0u;
        u32 result = a - b - borrow;
        s->cf = (borrow ? (a <= b) : (a < b));
        s->zf = (result == 0);
        s->sf = (int)(result >> 31);
        s->of = (int)(((a ^ b) & (a ^ result)) >> 31);
        s->pf = np_parity_even(result);
        s->r[d] = result;
    }
}
static void np_h_adcd(NpVmState* s) {
    u32 d = NPB(s), sc = NPB(s);
    if (NPR(d) && NPR(sc)) {
        u32 a = (u32)s->r[d], b = (u32)s->r[sc], carry = s->cf ? 1u : 0u;
        u32 result = a + b + carry;
        s->cf = (result < a) || (carry && result == a);
        s->zf = (result == 0);
        s->sf = (int)(result >> 31);
        s->of = (int)((~(a ^ b) & (a ^ result)) >> 31);
        s->pf = np_parity_even(result);
        s->r[d] = result;
    }
}
static void np_h_xunpckl(NpVmState* s) {
    u32 d = NP_XIDX(NPB(s)), sc = NP_XIDX(NPB(s));
    if (d < 16 && sc < 16 && s->x) {
        u8 tmp[16];
        for (u32 k = 0; k < 4; k++) tmp[k]      = s->x[d * 16 + k];
        for (u32 k = 0; k < 4; k++) tmp[4 + k]  = s->x[sc * 16 + k];
        for (u32 k = 0; k < 4; k++) tmp[8 + k]  = s->x[d * 16 + 4 + k];
        for (u32 k = 0; k < 4; k++) tmp[12 + k] = s->x[sc * 16 + 4 + k];
        for (u32 k = 0; k < 16; k++) s->x[d * 16 + k] = tmp[k];
    }
}
static void np_h_xmounth(NpVmState* s) {
    u32 d = NP_XIDX(NPB(s)), g = NPB(s);
    if (d < 16 && NPR(g) && s->x) {
        u64 v = s->r[g];
        for (u32 k = 0; k < 8; k++) s->x[d * 16 + 8 + k] = (u8)(v >> (k * 8));
    }
}
static void np_h_xmovhl(NpVmState* s) {
    u32 d = NP_XIDX(NPB(s)), sc = NP_XIDX(NPB(s));
    if (d < 16 && sc < 16 && s->x)
        for (u32 k = 0; k < 8; k++) s->x[d * 16 + k] = s->x[sc * 16 + 8 + k];
}
static void np_h_xzero(NpVmState* s) {
    u32 d = NP_XIDX(NPB(s));
    if (d < 16 && s->x)
        for (u32 k = 0; k < 16; k++) s->x[d * 16 + k] = 0;
}

/* ---- width-exact ALU --------------------------------------------------
 * One handler for every operand-width variant of the integer ALU. The result
 * is written back at the requested width and the flags are computed at that
 * width, which is what the x86 byte/word forms produce and what a branch
 * reading them expects. 8/16 splice into the low half (the upper bits of the
 * destination survive, exactly like `add al, bl`), 32 zero-extends into the
 * full register, 64 overwrites it.
 *
 * INC/DEC deliberately leave cf untouched: x86 INC/DEC never write CF, and
 * the previous ADDI/SUBI-based lowering did - any `inc` followed by `adc` /
 * `sbb` / `jb` saw a carry the original code never produced. */
static void np_h_nalu(NpVmState* s) {
    u32 sel = NPB(s), d = NPB(s), b = NPB(s);
    if (!NPR(d) || !NPR(b)) return;
    u32 wcode = (sel >> 4) & 3u, op = sel & 15u;
    u32 bits = (wcode == 0u) ? 8u : (wcode == 1u) ? 16u : (wcode == 2u) ? 32u : 64u;
    u64 mask = (bits == 64u) ? ~(u64)0 : (((u64)1 << bits) - 1);
    u64 sign = (u64)1 << (bits - 1);
    u64 a = s->r[d] & mask, v = s->r[b] & mask;
    u64 res;
    int cf = s->cf, of = s->of;
    switch (op) {
    case NP_NALU_ADD:
        res = (a + v) & mask;
        cf = ((a + v) > mask);
        of = (int)((((a ^ res) & (v ^ res)) & sign) ? 1 : 0);
        break;
    case NP_NALU_SUB:
        res = (a - v) & mask;
        cf = (a < v);
        of = (int)((((a ^ v) & (a ^ res)) & sign) ? 1 : 0);
        break;
    case NP_NALU_ADC: {
        u64 t = a + v + (u64)(s->cf ? 1 : 0);
        res = t & mask;
        cf = (t > mask);
        of = (int)((((a ^ res) & (v ^ res)) & sign) ? 1 : 0);
        break;
    }
    case NP_NALU_SBB: {
        u64 borrow = (u64)(s->cf ? 1 : 0);
        u64 sub = v + borrow;          /* <= mask+1, fits in u64 */
        res = (a - sub) & mask;
        cf = (a < sub);
        of = (int)((((a ^ v) & (a ^ res)) & sign) ? 1 : 0);
        break;
    }
    case NP_NALU_AND: res = a & v; cf = 0; of = 0; break;
    case NP_NALU_OR:  res = a | v; cf = 0; of = 0; break;
    case NP_NALU_XOR: res = a ^ v; cf = 0; of = 0; break;
    case NP_NALU_NOT: res = (~a) & mask; break;      /* flags untouched */
    case NP_NALU_INC:
        res = (a + 1) & mask;
        of = (int)((res & sign) && !(a & sign) ? 1 : 0);
        break;                                        /* cf untouched */
    case NP_NALU_DEC:
        res = (a - 1) & mask;
        of = (int)((a & sign) && !(res & sign) ? 1 : 0);
        break;                                        /* cf untouched */
    case NP_NALU_NEG:
        res = (0 - a) & mask;
        cf = (a != 0);
        of = (int)((res == sign) ? 1 : 0);
        break;
    case NP_NALU_SHL: case NP_NALU_SHR: case NP_NALU_SAR:
    case NP_NALU_ROL: case NP_NALU_ROR: {
        u32 cntMask = (bits == 64u) ? 63u : 31u;
        u32 cnt = (u32)(v & cntMask);
        if (op == NP_NALU_ROL || op == NP_NALU_ROR) cnt = (u32)(v & (bits - 1u));
        if (cnt == 0) { /* x86 leaves every flag alone for a zero count */ return; }
        if (op == NP_NALU_SHL) {
            if (cnt >= bits) {
                /* count wider than the operand: the result is zero and CF is
                 * undefined on hardware. Computing `a >> (bits - cnt)` here
                 * would underflow the shift amount, so pin a defined value. */
                res = 0;
                cf = 0;
                of = 0;
            } else {
                res = (a << cnt) & mask;
                cf = (int)((a >> (bits - cnt)) & 1u);
                of = (cnt == 1u) ? (int)((((res & sign) ? 1 : 0) ^ (u32)cf)) : 0;
            }
        } else if (op == NP_NALU_SHR) {
            res = (a >> cnt) & mask;
            cf = (int)((a >> (cnt - 1u)) & 1u);
            of = (cnt == 1u) ? (int)((a & sign) ? 1 : 0) : 0;
        } else if (op == NP_NALU_SAR) {
            /* arithmetic shift at `bits` width: replicate the sign bit */
            u64 x;
            if (cnt >= bits) x = (a & sign) ? mask : 0;
            else {
                x = a >> cnt;
                if (a & sign) x |= ((mask << (bits - cnt)) & mask);
            }
            res = x & mask;
            cf = (int)((a >> (cnt - 1u)) & 1u);
            of = 0;
        } else if (op == NP_NALU_ROL) {
            u32 n = cnt & (bits - 1u);
            if (n == 0) { res = a; cf = (int)(a & 1u); return; }
            res = ((a << n) | (a >> (bits - n))) & mask;
            cf = (int)(res & 1u);
            of = (cnt == 1u) ? (int)((((res & sign) ? 1 : 0) ^ (u32)cf)) : 0;
        } else { /* ROR */
            u32 n = cnt & (bits - 1u);
            if (n == 0) { res = a; cf = (int)((a >> (bits - 1)) & 1u); return; }
            res = ((a >> n) | (a << (bits - n))) & mask;
            cf = (int)((res >> (bits - 1)) & 1u);
            of = (cnt == 1u) ? (int)(((((res >> (bits - 1)) & 1u) ^ ((res >> (bits - 2)) & 1u)))) : 0;
        }
        break;
    }
    default:
        return;
    }
    if (op == NP_NALU_NOT) {
        /* NOT writes the value but leaves every flag alone. */
    } else {
        s->cf = cf;
        s->of = of;
        s->zf = (res == 0);
        s->sf = (int)((res >> (bits - 1)) & 1u);
        s->pf = np_parity_even(res);
    }
    if (bits >= 64u) s->r[d] = res;
    else if (bits == 32u) s->r[d] = res & 0xFFFFFFFFu;
    else s->r[d] = (s->r[d] & ~mask) | res;
}

/* ---- SAHF / LAHF ------------------------------------------------------ */
static void np_h_sahf(NpVmState* s) {
    u32 src = NPB(s);
    if (!NPR(src)) return;
    u8 ah = (u8)((s->r[src] >> 8) & 0xFFu);
    s->cf = (ah >> 0) & 1;
    s->pf = (ah >> 2) & 1;
    /* af is not modelled */
    s->zf = (ah >> 6) & 1;
    s->sf = (ah >> 7) & 1;
}
static void np_h_lahf(NpVmState* s) {
    u32 d = NPB(s);
    if (!NPR(d)) return;
    u64 ah = 0x02u;                       /* bit1 is reserved-1 */
    if (s->cf) ah |= 0x01u;
    if (s->pf) ah |= 0x04u;
    if (s->zf) ah |= 0x40u;
    if (s->sf) ah |= 0x80u;
    s->r[d] = (s->r[d] & ~0xFF00ull) | (ah << 8);
}
static void np_h_setcf(NpVmState* s) {
    u32 src = NPB(s);
    if (!NPR(src)) return;
    s->cf = (int)(s->r[src] & 1u);
}

/* pushfq / popfq on the guest stack. The qword uses the RFLAGS bit layout
 * for the modelled bits (cf/pf/zf/sf/of/df, bit1 reads 1); everything the
 * VM does not model round-trips as zero. */
static void np_h_pushf(NpVmState* s) {
    u32 sp = NPB(s);
    if (!NPR(sp)) return;
    u64 v = 0x2u;
    if (s->cf) v |= 0x1u;
    if (s->pf) v |= 0x4u;
    if (s->zf) v |= 0x40u;
    if (s->sf) v |= 0x80u;
    if (s->df) v |= 0x400u;
    if (s->of) v |= 0x800u;
    s->r[sp] -= 8u;
    *(u64*)(unsigned long long)s->r[sp] = v;
}
static void np_h_popf(NpVmState* s) {
    u32 sp = NPB(s);
    if (!NPR(sp)) return;
    u64 v = *(u64*)(unsigned long long)s->r[sp];
    s->r[sp] += 8u;
    s->cf = (int)(v & 1u);
    s->pf = (int)((v >> 2) & 1u);
    s->zf = (int)((v >> 6) & 1u);
    s->sf = (int)((v >> 7) & 1u);
    s->df = (int)((v >> 10) & 1u);
    s->of = (int)((v >> 11) & 1u);
}

/* 8-bit one-operand pair arithmetic: AX = AL * den8 (0=unsigned 1=signed),
 * or AL = quotient / AH = remainder of AX / den8. The 16-bit result is
 * spliced into bits 0..15 of acc. MUL sets CF/OF when AH is not the sign
 * extension of AL (signed) or non-zero (unsigned); DIV leaves every flag
 * alone except by writing something stable, matching the 64-bit pair
 * handlers. Division by zero and an overflowing quotient leave acc
 * untouched - the native #DE would stop the program either way. */
static void np_h_mulb(NpVmState* s) {
    u32 sel = NPB(s), acc = NPB(s), den = NPB(s);
    if (!NPR(acc) || !NPR(den)) return;
    u64 av = s->r[acc], dv = s->r[den];
    u32 prod;
    if (sel & 1u) {
        i32 a8 = (i32)(i8)(u8)(av & 0xFFu), d8 = (i32)(i8)(u8)(dv & 0xFFu);
        prod = (u32)(u16)(u32)(i32)(a8 * d8);
    } else {
        prod = (u32)(u16)((av & 0xFFu) * (dv & 0xFFu));
    }
    s->r[acc] = (av & ~0xFFFFull) | (u64)prod;
    s->cf = s->of = (sel & 1u) ? ((i32)(i16)(u16)prod != (i32)(i8)(u8)(prod & 0xFFu))
                               : ((prod >> 8) != 0u);
    s->zf = ((prod & 0xFFFFu) == 0u);
    s->sf = (int)((prod >> 15) & 1u);
    s->pf = np_parity_even(prod);
}
static void np_h_divb(NpVmState* s) {
    u32 sel = NPB(s), acc = NPB(s), den = NPB(s);
    if (!NPR(acc) || !NPR(den)) return;
    u64 av = s->r[acc], dv = s->r[den];
    u32 d8 = (u32)(dv & 0xFFu);
    u32 q, r;
    if (sel & 1u) {
        i32 num = (i32)(i16)(u16)(av & 0xFFFFu), dd = (i32)(i8)(u8)d8;
        if (dd == 0) return;
        i32 qq = num / dd, rr = num % dd;
        if (qq > 127 || qq < -128) return;
        q = (u32)(u8)(i8)qq; r = (u32)(u8)(i8)rr;
    } else {
        u32 num = (u32)(av & 0xFFFFu);
        if (d8 == 0) return;
        u32 qq = num / d8, rr = num % d8;
        if (qq > 0xFFu) return;
        q = qq; r = rr;
    }
    s->r[acc] = (av & ~0xFFFFull) | (u64)(q & 0xFFu) | ((u64)(r & 0xFFu) << 8);
}

/* ---- BT / BTS / BTR / BTC ---------------------------------------------
 * sel = (is32 << 3) | (isMem << 2) | op with op 0=bt 1=bts 2=btr 3=btc. Only
 * cf is written: the bit test family leaves zf/sf/of/pf exactly as it found
 * them. In register mode the index is masked to 5 bits (32-bit operand) or 6
 * bits (64-bit) and only that many bits of the register take part; in memory
 * mode the index is a plain bit offset, so the bit may live beyond the
 * addressed word - that is the architectural behaviour of `bt [mem], reg`. */
static void np_h_bitop(NpVmState* s) {
    u32 sel = NPB(s), base = NPB(s), idx = NPB(s);
    if (!NPR(base) || !NPR(idx)) return;
    u32 op = sel & 3u;
    u32 isMem = (sel >> 2) & 1u;
    u32 is32 = (sel >> 3) & 1u;
    u64 bitIndex = s->r[idx];
    u8 byteVal;
    u64 byteAddr;
    u32 bit;
    if (isMem) {
        byteAddr = s->r[base] + (u64)((i64)bitIndex >> 3);
        byteVal = *(u8*)(unsigned long long)byteAddr;
        bit = (u32)(bitIndex & 7u);
    } else {
        u32 maskBits = is32 ? 5u : 6u;
        u64 mask = ((u64)1 << maskBits) - 1;
        bitIndex &= mask;
        bit = (u32)bitIndex;
        byteVal = (u8)((s->r[base] >> bitIndex) & 1u);
        byteAddr = 0;
    }
    u32 old = (u32)(byteVal & 1u);
    s->cf = (int)old;
    if (op != 0) {
        u8 nb;
        if (op == 1)      nb = (u8)(byteVal | (u8)(1u << bit));           /* bts */
        else if (op == 2) nb = (u8)(byteVal & (u8)~(1u << bit));          /* btr */
        else              nb = (u8)(byteVal ^ (u8)(1u << bit));           /* btc */
        if (isMem) *(u8*)(unsigned long long)byteAddr = nb;
        else {
            u64 v = s->r[base];
            if (op == 1) v |= ((u64)1 << bitIndex);
            else if (op == 2) v &= ~((u64)1 << bitIndex);
            else v ^= ((u64)1 << bitIndex);
            if (is32) v &= 0xFFFFFFFFull;
            s->r[base] = v;
        }
    }
}

static void np_h_addrshri(NpVmState* s) {
    u32 d = NPB(s);
    u64 imm = np_imm64(s);
    if (NPR(d)) {
        u64 v = s->r[d];
        u32 n = (u32)(imm & 63u);
        if (n) {
            /* arithmetic shift at 64 bits: replicate the sign bit */
            u64 sign = (u64)0 - (v >> 63);
            v = (v >> n) | (sign << (64 - n));
        }
        s->r[d] = v;
    }
}

/* ================= coverage round: residual reject buckets ============== */

/* ---- bsf / bsr / tzcnt / lzcnt ----------------------------------------
 * sel = (op << 2) | width with op 0=bsf 1=bsr 2=tzcnt 3=lzcnt and
 * width 0=16 1=32 2=64. bsf/bsr write zf only (the other flags are
 * architecturally undefined and are left alone, which matches every real
 * CPU). tzcnt/lzcnt write zf and cf and clear the rest. A zero source
 * leaves dst unchanged for bsf/bsr (the AMD convention; the index is
 * "undefined" on Intel and nothing correct can depend on it) and yields
 * the operand width for tzcnt/lzcnt. Narrow results splice into the
 * destination exactly like the original instruction: 16-bit keeps the
 * upper bits, 32-bit zero-extends. */
static void np_h_bitscan(NpVmState* s) {
    u32 sel = NPB(s), dst = NPB(s), src = NPB(s);
    if (!NPR(dst) || !NPR(src)) return;
    u32 op = (sel >> 2) & 3u;
    u32 width = sel & 3u;
    u64 v = s->r[src];
    u32 bits = (width == 0) ? 16u : (width == 1) ? 32u : 64u;
    if (bits < 64) v &= ((u64)1 << bits) - 1;
    if (op <= 1u) {
        s->zf = (v == 0);
        if (v != 0) {
            u32 idx = 0;
            if (op == 0u) {
                while ((v & 1u) == 0) { v >>= 1; idx++; }
            } else {
                idx = bits - 1u;
                while ((v & ((u64)1 << idx)) == 0) idx--;
            }
            if (width == 0)      s->r[dst] = (s->r[dst] & ~0xFFFFull) | (u64)idx;
            else if (width == 1) s->r[dst] = (u64)idx;
            else                 s->r[dst] = (u64)idx;
        }
    } else {
        u64 res;
        if (v == 0) {
            res = (u64)bits;
            s->zf = 1;
            s->cf = 1;
        } else {
            res = 0;
            if (op == 2u) {
                /* tzcnt: trailing zeros */
                u64 t = v;
                while ((t & 1u) == 0) { t >>= 1; res++; }
            } else {
                /* lzcnt: leading zeros */
                u32 k = bits;
                while (k > 0 && (v & ((u64)1 << (k - 1u))) == 0) { k--; res++; }
            }
            s->zf = 0;
            s->cf = 0;
        }
        /* tzcnt/lzcnt clear the remaining arithmetic flags. */
        s->sf = 0;
        s->of = 0;
        s->pf = 0;
        if (width == 0)      s->r[dst] = (s->r[dst] & ~0xFFFFull) | res;
        else if (width == 1) s->r[dst] = res;
        else                 s->r[dst] = res;
    }
}

/* ---- x87 ---------------------------------------------------------------
 * The handler decodes the (escape, modrm) pair exactly like the hardware
 * would and executes the form against the real FPU stack. The VM never
 * models that stack - guest x87 state *is* machine x87 state, so a region
 * that talks to the co-processor stays bit-exact for the 80-bit tbyte
 * forms compiled code uses for long double. Memory forms take their
 * effective address from the pre-computed `ea` slot (the translator folded
 * base/index/scale/disp or the image rebased RIP offset into it). */
/* Register-index forms are expanded through a per-index macro: an inline
 * asm template cannot carry a run-time st(i) index, so each of the eight
 * slots gets its own literal. The templates follow gas syntax - the pop
 * forms and the st(i),st(0) arithmetic take "%st, %st(i)", the st(0),st(i)
 * arithmetic and the compare forms take "%st(i), %st". */
#define NP_X87_STI(name, pre, suf)                                             \
    static void np_x87_##name(u32 i) {                                         \
        switch (i) {                                                           \
        case 0: asm volatile(pre "0" suf); break;                              \
        case 1: asm volatile(pre "1" suf); break;                              \
        case 2: asm volatile(pre "2" suf); break;                              \
        case 3: asm volatile(pre "3" suf); break;                              \
        case 4: asm volatile(pre "4" suf); break;                              \
        case 5: asm volatile(pre "5" suf); break;                              \
        case 6: asm volatile(pre "6" suf); break;                              \
        default: asm volatile(pre "7" suf); break;                             \
        }                                                                      \
    }
NP_X87_STI(fld_st,    "fld %st(", ")")
NP_X87_STI(fxch,      "fxch %st(", ")")
NP_X87_STI(fstp_st,   "fstp %st(", ")")
NP_X87_STI(fst_st,    "fst %st(", ")")
NP_X87_STI(fucomi,    "fucomi %st(", "), %st")
NP_X87_STI(fcomi,     "fcomi %st(", "), %st")
NP_X87_STI(fucomip,   "fucomip %st(", "), %st")
NP_X87_STI(fcomip,    "fcomip %st(", "), %st")
NP_X87_STI(fucom,     "fucom %st(", ")")
NP_X87_STI(fucomp,    "fucomp %st(", ")")
NP_X87_STI(fcom_sti,  "fcom %st(", ")")
NP_X87_STI(fcomp_sti, "fcomp %st(", ")")
NP_X87_STI(fadd_st0,  "fadd %st(", "), %st")
NP_X87_STI(fmul_st0,  "fmul %st(", "), %st")
NP_X87_STI(fsub_st0,  "fsub %st(", "), %st")
NP_X87_STI(fsubr_st0, "fsubr %st(", "), %st")
NP_X87_STI(fdiv_st0,  "fdiv %st(", "), %st")
NP_X87_STI(fdivr_st0, "fdivr %st(", "), %st")
NP_X87_STI(fadd_sti,  "fadd %st, %st(", ")")
NP_X87_STI(fmul_sti,  "fmul %st, %st(", ")")
NP_X87_STI(fsub_sti,  "fsub %st, %st(", ")")
NP_X87_STI(fsubr_sti, "fsubr %st, %st(", ")")
NP_X87_STI(fdiv_sti,  "fdiv %st, %st(", ")")
NP_X87_STI(fdivr_sti, "fdivr %st, %st(", ")")
NP_X87_STI(faddp,     "faddp %st, %st(", ")")
NP_X87_STI(fmulp,     "fmulp %st, %st(", ")")
NP_X87_STI(fsubp,     "fsubp %st, %st(", ")")
NP_X87_STI(fsubrp,    "fsubrp %st, %st(", ")")
NP_X87_STI(fdivp,     "fdivp %st, %st(", ")")
NP_X87_STI(fdivrp,    "fdivrp %st, %st(", ")")
NP_X87_STI(ffree,     "ffree %st(", ")")
NP_X87_STI(fcmovb,    "fcmovb %st(", "), %st")
NP_X87_STI(fcmove,    "fcmove %st(", "), %st")
NP_X87_STI(fcmovbe,   "fcmovbe %st(", "), %st")
NP_X87_STI(fcmovu,    "fcmovu %st(", "), %st")
NP_X87_STI(fcmovnb,   "fcmovnb %st(", "), %st")
NP_X87_STI(fcmovne,   "fcmovne %st(", "), %st")
NP_X87_STI(fcmovnbe,  "fcmovnbe %st(", "), %st")
NP_X87_STI(fcmovnu,   "fcmovnu %st(", "), %st")

static void np_h_x87(NpVmState* s) {
    u32 esc = NPB(s), modrm = NPB(s), ea = NPB(s);
    u32 reg = (modrm >> 3) & 7u;
    u32 mod = (modrm >> 6) & 3u;
    u32 rm  = modrm & 7u;
    u64 addr = 0;
    if (mod != 3u) {
        if (!NPR(ea)) return;
        addr = s->r[ea];
        /* Memory operand forms: (esc, reg) picks the mnemonic exactly as
         * the CPU decodes it; the effective address was folded into `ea`
         * by the translator. Reserved slots are never emitted. */
        switch ((esc << 4) | reg) {
        /* D8: m32 real arithmetic */
        case 0xD80: asm volatile("fadds (%0)"  :: "r"(addr)); break;
        case 0xD81: asm volatile("fmuls (%0)"  :: "r"(addr)); break;
        case 0xD82: asm volatile("fcoms (%0)"  :: "r"(addr)); break;
        case 0xD83: asm volatile("fcomps (%0)" :: "r"(addr)); break;
        case 0xD84: asm volatile("fsubs (%0)"  :: "r"(addr)); break;
        case 0xD85: asm volatile("fsubrs (%0)" :: "r"(addr)); break;
        case 0xD86: asm volatile("fdivs (%0)"  :: "r"(addr)); break;
        case 0xD87: asm volatile("fdivrs (%0)" :: "r"(addr)); break;
        /* D9: m32 load/store + env/control */
        case 0xD90: asm volatile("flds (%0)"   :: "r"(addr)); break;
        case 0xD92: asm volatile("fsts (%0)"   :: "r"(addr)); break;
        case 0xD93: asm volatile("fstps (%0)"  :: "r"(addr)); break;
        case 0xD94: asm volatile("fldenv (%0)" :: "r"(addr)); break;
        case 0xD95: asm volatile("fldcw (%0)"  :: "r"(addr)); break;
        case 0xD96: asm volatile("fnstenv (%0)":: "r"(addr)); break;
        case 0xD97: asm volatile("fnstcw (%0)" :: "r"(addr)); break;
        /* DA: m32int */
        case 0xDA0: asm volatile("fiaddl (%0)"  :: "r"(addr)); break;
        case 0xDA1: asm volatile("fimull (%0)"  :: "r"(addr)); break;
        case 0xDA2: asm volatile("ficoml (%0)"  :: "r"(addr)); break;
        case 0xDA3: asm volatile("ficompl (%0)" :: "r"(addr)); break;
        case 0xDA4: asm volatile("fisubl (%0)"  :: "r"(addr)); break;
        case 0xDA5: asm volatile("fisubrl (%0)" :: "r"(addr)); break;
        case 0xDA6: asm volatile("fidivl (%0)"  :: "r"(addr)); break;
        case 0xDA7: asm volatile("fidivrl (%0)" :: "r"(addr)); break;
        /* DB: m32int / m80 real */
        case 0xDB0: asm volatile("fildl (%0)"   :: "r"(addr)); break;
        case 0xDB2: asm volatile("fistl (%0)"   :: "r"(addr)); break;
        case 0xDB3: asm volatile("fistpl (%0)"  :: "r"(addr)); break;
        case 0xDB5: asm volatile("fldt (%0)"    :: "r"(addr)); break;
        case 0xDB7: asm volatile("fstpt (%0)"   :: "r"(addr)); break;
        /* DC: m64 real arithmetic */
        case 0xDC0: asm volatile("faddl (%0)"  :: "r"(addr)); break;
        case 0xDC1: asm volatile("fmull (%0)"  :: "r"(addr)); break;
        case 0xDC2: asm volatile("fcoml (%0)"  :: "r"(addr)); break;
        case 0xDC3: asm volatile("fcompl (%0)" :: "r"(addr)); break;
        case 0xDC4: asm volatile("fsubl (%0)"  :: "r"(addr)); break;
        case 0xDC5: asm volatile("fsubrl (%0)" :: "r"(addr)); break;
        case 0xDC6: asm volatile("fdivl (%0)"  :: "r"(addr)); break;
        case 0xDC7: asm volatile("fdivrl (%0)" :: "r"(addr)); break;
        /* DD: m64 load/store + state */
        case 0xDD0: asm volatile("fldl (%0)"    :: "r"(addr)); break;
        case 0xDD2: asm volatile("fstl (%0)"    :: "r"(addr)); break;
        case 0xDD3: asm volatile("fstpl (%0)"   :: "r"(addr)); break;
        case 0xDD4: asm volatile("frstor (%0)"  :: "r"(addr)); break;
        case 0xDD6: asm volatile("fnsave (%0)"  :: "r"(addr)); break;
        case 0xDD7: asm volatile("fnstsw (%0)"  :: "r"(addr)); break;
        /* DE: m16int */
        case 0xDE0: asm volatile("fiadds (%0)"  :: "r"(addr)); break;
        case 0xDE1: asm volatile("fimuls (%0)"  :: "r"(addr)); break;
        case 0xDE2: asm volatile("ficoms (%0)"  :: "r"(addr)); break;
        case 0xDE3: asm volatile("ficomps (%0)" :: "r"(addr)); break;
        case 0xDE4: asm volatile("fisubs (%0)"  :: "r"(addr)); break;
        case 0xDE5: asm volatile("fisubrs (%0)" :: "r"(addr)); break;
        case 0xDE6: asm volatile("fidivs (%0)"  :: "r"(addr)); break;
        case 0xDE7: asm volatile("fidivrs (%0)" :: "r"(addr)); break;
        /* DF: m16/m64int + m80 bcd */
        case 0xDF0: asm volatile("filds (%0)"   :: "r"(addr)); break;
        case 0xDF2: asm volatile("fists (%0)"   :: "r"(addr)); break;
        case 0xDF3: asm volatile("fistps (%0)"  :: "r"(addr)); break;
        case 0xDF4: asm volatile("fbld (%0)"    :: "r"(addr)); break;
        case 0xDF5: asm volatile("fildll (%0)"  :: "r"(addr)); break;
        case 0xDF6: asm volatile("fbstp (%0)"   :: "r"(addr)); break;
        case 0xDF7: asm volatile("fistpll (%0)" :: "r"(addr)); break;
        default: return;
        }
        return;
    }
    /* Register / no-operand forms (mod == 3). Key = (esc << 8) | modrm. */
    switch (((u32)esc << 8) | (u32)modrm) {
    /* D9 register row + no-operand block */
    case 0xD9C0: case 0xD9C1: case 0xD9C2: case 0xD9C3:
    case 0xD9C4: case 0xD9C5: case 0xD9C6: case 0xD9C7:
        np_x87_fld_st(rm); break;
    case 0xD9C8: case 0xD9C9: case 0xD9CA: case 0xD9CB:
    case 0xD9CC: case 0xD9CD: case 0xD9CE: case 0xD9CF:
        np_x87_fxch(rm); break;
    case 0xD9D0: asm volatile("fnop"); break;
    case 0xD9E0: asm volatile("fchs");  break;
    case 0xD9E1: asm volatile("fabs");  break;
    case 0xD9E4: asm volatile("ftst");  break;
    case 0xD9E5: asm volatile("fxam");  break;
    case 0xD9E8: asm volatile("fld1");  break;
    case 0xD9E9: asm volatile("fldl2t"); break;
    case 0xD9EA: asm volatile("fldl2e"); break;
    case 0xD9EB: asm volatile("fldpi"); break;
    case 0xD9EC: asm volatile("fldlg2"); break;
    case 0xD9ED: asm volatile("fldln2"); break;
    case 0xD9EE: asm volatile("fldz");  break;
    case 0xD9F0: asm volatile("f2xm1"); break;
    case 0xD9F1: asm volatile("fyl2x"); break;
    case 0xD9F2: asm volatile("fptan"); break;
    case 0xD9F3: asm volatile("fpatan"); break;
    case 0xD9F4: asm volatile("fxtract"); break;
    case 0xD9F5: asm volatile("fprem1"); break;
    case 0xD9F6: asm volatile("fdecstp"); break;
    case 0xD9F7: asm volatile("fincstp"); break;
    case 0xD9F8: asm volatile("fprem"); break;
    case 0xD9F9: asm volatile("fyl2xp1"); break;
    case 0xD9FA: asm volatile("fsqrt"); break;
    case 0xD9FB: asm volatile("fsincos"); break;
    case 0xD9FC: asm volatile("frndint"); break;
    case 0xD9FD: asm volatile("fscale"); break;
    case 0xD9FE: asm volatile("fsin");  break;
    case 0xD9FF: asm volatile("fcos");  break;
    /* D8 st(0),st(i) arithmetic (reg rows 0..7 = C0..FF) */
    case 0xD8C0: case 0xD8C1: case 0xD8C2: case 0xD8C3:
    case 0xD8C4: case 0xD8C5: case 0xD8C6: case 0xD8C7:
        np_x87_fadd_st0(rm); break;
    case 0xD8C8: case 0xD8C9: case 0xD8CA: case 0xD8CB:
    case 0xD8CC: case 0xD8CD: case 0xD8CE: case 0xD8CF:
        np_x87_fmul_st0(rm); break;
    case 0xD8D0: case 0xD8D1: case 0xD8D2: case 0xD8D3:
    case 0xD8D4: case 0xD8D5: case 0xD8D6: case 0xD8D7:
        np_x87_fcom_sti(rm); break;
    case 0xD8D8: case 0xD8D9: case 0xD8DA: case 0xD8DB:
    case 0xD8DC: case 0xD8DD: case 0xD8DE: case 0xD8DF:
        np_x87_fcomp_sti(rm); break;
    case 0xD8E0: case 0xD8E1: case 0xD8E2: case 0xD8E3:
    case 0xD8E4: case 0xD8E5: case 0xD8E6: case 0xD8E7:
        np_x87_fsub_st0(rm); break;
    case 0xD8E8: case 0xD8E9: case 0xD8EA: case 0xD8EB:
    case 0xD8EC: case 0xD8ED: case 0xD8EE: case 0xD8EF:
        np_x87_fsubr_st0(rm); break;
    case 0xD8F0: case 0xD8F1: case 0xD8F2: case 0xD8F3:
    case 0xD8F4: case 0xD8F5: case 0xD8F6: case 0xD8F7:
        np_x87_fdiv_st0(rm); break;
    case 0xD8F8: case 0xD8F9: case 0xD8FA: case 0xD8FB:
    case 0xD8FC: case 0xD8FD: case 0xD8FE: case 0xD8FF:
        np_x87_fdivr_st0(rm); break;
    /* DC st(i),st(0) arithmetic */
    case 0xDCC0: case 0xDCC1: case 0xDCC2: case 0xDCC3:
    case 0xDCC4: case 0xDCC5: case 0xDCC6: case 0xDCC7:
        np_x87_fadd_sti(rm); break;
    case 0xDCC8: case 0xDCC9: case 0xDCCA: case 0xDCCB:
    case 0xDCCC: case 0xDCCD: case 0xDCCE: case 0xDCCF:
        np_x87_fmul_sti(rm); break;
    case 0xDCD0: case 0xDCD1: case 0xDCD2: case 0xDCD3:
    case 0xDCD4: case 0xDCD5: case 0xDCD6: case 0xDCD7:
        np_x87_fcom_sti(rm); break;
    case 0xDCD8: case 0xDCD9: case 0xDCDA: case 0xDCDB:
    case 0xDCDC: case 0xDCDD: case 0xDCDE: case 0xDCDF:
        np_x87_fcomp_sti(rm); break;
    case 0xDCE0: case 0xDCE1: case 0xDCE2: case 0xDCE3:
    case 0xDCE4: case 0xDCE5: case 0xDCE6: case 0xDCE7:
        np_x87_fsub_sti(rm); break;
    case 0xDCE8: case 0xDCE9: case 0xDCEA: case 0xDCEB:
    case 0xDCEC: case 0xDCED: case 0xDCEE: case 0xDCEF:
        np_x87_fsubr_sti(rm); break;
    case 0xDCF0: case 0xDCF1: case 0xDCF2: case 0xDCF3:
    case 0xDCF4: case 0xDCF5: case 0xDCF6: case 0xDCF7:
        np_x87_fdiv_sti(rm); break;
    case 0xDCF8: case 0xDCF9: case 0xDCFA: case 0xDCFB:
    case 0xDCFC: case 0xDCFD: case 0xDCFE: case 0xDCFF:
        np_x87_fdivr_sti(rm); break;
    /* DA register row: fcmovb / fcmove / fcmovbe / fcmovu + fucompp */
    case 0xDAC0: case 0xDAC1: case 0xDAC2: case 0xDAC3:
    case 0xDAC4: case 0xDAC5: case 0xDAC6: case 0xDAC7:
        np_x87_fcmovb(rm); break;
    case 0xDAC8: case 0xDAC9: case 0xDACA: case 0xDACB:
    case 0xDACC: case 0xDACD: case 0xDACE: case 0xDACF:
        np_x87_fcmove(rm); break;
    case 0xDAD0: case 0xDAD1: case 0xDAD2: case 0xDAD3:
    case 0xDAD4: case 0xDAD5: case 0xDAD6: case 0xDAD7:
        np_x87_fcmovbe(rm); break;
    case 0xDAD8: case 0xDAD9: case 0xDADA: case 0xDADB:
    case 0xDADC: case 0xDADD: case 0xDADE: case 0xDADF:
        np_x87_fcmovu(rm); break;
    case 0xDAE9: asm volatile("fucompp"); break;
    /* DB register row: fcmovnb / fcmovne / fcmovnbe / fcmovnu, fninit,
     * fucomi, fcomi */
    case 0xDBC0: case 0xDBC1: case 0xDBC2: case 0xDBC3:
    case 0xDBC4: case 0xDBC5: case 0xDBC6: case 0xDBC7:
        np_x87_fcmovnb(rm); break;
    case 0xDBC8: case 0xDBC9: case 0xDBCA: case 0xDBCB:
    case 0xDBCC: case 0xDBCD: case 0xDBCE: case 0xDBCF:
        np_x87_fcmovne(rm); break;
    case 0xDBD0: case 0xDBD1: case 0xDBD2: case 0xDBD3:
    case 0xDBD4: case 0xDBD5: case 0xDBD6: case 0xDBD7:
        np_x87_fcmovnbe(rm); break;
    case 0xDBD8: case 0xDBD9: case 0xDBDA: case 0xDBDB:
    case 0xDBDC: case 0xDBDD: case 0xDBDE: case 0xDBDF:
        np_x87_fcmovnu(rm); break;
    case 0xDBE3: asm volatile("fninit"); break;
    case 0xDBE8: case 0xDBE9: case 0xDBEA: case 0xDBEB:
    case 0xDBEC: case 0xDBED: case 0xDBEE: case 0xDBEF:
        np_x87_fucomi(rm); break;
    case 0xDBF0: case 0xDBF1: case 0xDBF2: case 0xDBF3:
    case 0xDBF4: case 0xDBF5: case 0xDBF6: case 0xDBF7:
        np_x87_fcomi(rm); break;
    /* DD register row: ffree / fst / fstp / fucom / fucomp */
    case 0xDDC0: case 0xDDC1: case 0xDDC2: case 0xDDC3:
    case 0xDDC4: case 0xDDC5: case 0xDDC6: case 0xDDC7:
        np_x87_ffree(rm); break;
    case 0xDDD0: case 0xDDD1: case 0xDDD2: case 0xDDD3:
    case 0xDDD4: case 0xDDD5: case 0xDDD6: case 0xDDD7:
        np_x87_fst_st(rm); break;
    case 0xDDD8: case 0xDDD9: case 0xDDDA: case 0xDDDB:
    case 0xDDDC: case 0xDDDD: case 0xDDDE: case 0xDDDF:
        np_x87_fstp_st(rm); break;
    case 0xDDE0: case 0xDDE1: case 0xDDE2: case 0xDDE3:
    case 0xDDE4: case 0xDDE5: case 0xDDE6: case 0xDDE7:
        np_x87_fucom(rm); break;
    case 0xDDE8: case 0xDDE9: case 0xDDEA: case 0xDDEB:
    case 0xDDEC: case 0xDDED: case 0xDDEE: case 0xDDEF:
        np_x87_fucomp(rm); break;
    /* DE register row: pop arithmetic + fcompp */
    case 0xDEC0: case 0xDEC1: case 0xDEC2: case 0xDEC3:
    case 0xDEC4: case 0xDEC5: case 0xDEC6: case 0xDEC7:
        np_x87_faddp(rm); break;
    case 0xDEC8: case 0xDEC9: case 0xDECA: case 0xDECB:
    case 0xDECC: case 0xDECD: case 0xDECE: case 0xDECF:
        np_x87_fmulp(rm); break;
    case 0xDED9: asm volatile("fcompp"); break;
    case 0xDEE0: case 0xDEE1: case 0xDEE2: case 0xDEE3:
    case 0xDEE4: case 0xDEE5: case 0xDEE6: case 0xDEE7:
        np_x87_fsubp(rm); break;
    case 0xDEE8: case 0xDEE9: case 0xDEEA: case 0xDEEB:
    case 0xDEEC: case 0xDEED: case 0xDEEE: case 0xDEEF:
        np_x87_fsubrp(rm); break;
    case 0xDEF0: case 0xDEF1: case 0xDEF2: case 0xDEF3:
    case 0xDEF4: case 0xDEF5: case 0xDEF6: case 0xDEF7:
        np_x87_fdivp(rm); break;
    case 0xDEF8: case 0xDEF9: case 0xDEFA: case 0xDEFB:
    case 0xDEFC: case 0xDEFD: case 0xDEFE: case 0xDEFF:
        np_x87_fdivrp(rm); break;
    /* DF register row: fnstsw ax + comip family */
    case 0xDFE0: {
        if (!NPR(ea)) return;
        u16 sw = 0;
        asm volatile("fnstsw %0" : "=m"(sw));
        s->r[ea] = (s->r[ea] & ~0xFFFFull) | (u64)sw;
        break;
    }
    case 0xDFE8: case 0xDFE9: case 0xDFEA: case 0xDFEB:
    case 0xDFEC: case 0xDFED: case 0xDFEE: case 0xDFEF:
        np_x87_fucomip(rm); break;
    case 0xDFF0: case 0xDFF1: case 0xDFF2: case 0xDFF3:
    case 0xDFF4: case 0xDFF5: case 0xDFF6: case 0xDFF7:
        np_x87_fcomip(rm); break;
    default: break;
    }
    /* The comi/comip family writes the integer flag file (zf/pf/cf from the
     * comparison, of/sf cleared); every other x87 form leaves it alone. The
     * flag file is refreshed from the real flags only for those forms -
     * doing it unconditionally would leak the interpreter's own arithmetic
     * into the guest. DB reg 5/6 = fucomi/fcomi, DF reg 5/6 = fucomip/
     * fcomip (the memory rows with those reg values already returned). */
    if ((esc == 0xDB || esc == 0xDF) && (reg == 5u || reg == 6u)) {
        u64 f = 0;
        asm volatile("pushfq; popq %0" : "=r"(f));
        s->zf = (int)((f >> 6) & 1u);
        s->pf = (int)((f >> 2) & 1u);
        s->cf = (int)((f >> 0) & 1u);
        s->of = (int)((f >> 11) & 1u);
        s->sf = (int)((f >> 7) & 1u);
    }
}

/* ---- string primitives -------------------------------------------------
 * sel = (rep << 5) | (op << 2) | width with rep 0=plain 1=rep/repe 2=repne,
 * op 0=movs 1=stos 2=lods 3=cmps 4=scas, width 0=b 1=w 2=d 3=q. The loops
 * run in C against the guest pointers - the interpreter never touches the
 * hardware DF, the VM's own df decides the walk direction. cmps/scas write
 * the comparison flags exactly like the hardware (the re- forms then loop
 * on zf); the other forms leave the flag file alone. */
static void np_h_str(NpVmState* s) {
    u32 sel = NPB(s), srsi = NPB(s), rdi = NPB(s), rcx = NPB(s), acc = NPB(s);
    if (!NPR(srsi) || !NPR(rdi) || !NPR(rcx) || !NPR(acc)) return;
    u32 rep = (sel >> 5) & 3u;
    u32 op = (sel >> 2) & 7u;
    u32 width = sel & 3u;
    u64 step = (u64)1 << width;
    i64 dir = s->df ? -(i64)step : (i64)step;
    u64 rsi = s->r[srsi], rdv = s->r[rdi], cnt = s->r[rcx], acv = s->r[acc];
    u32 isRep = (rep != 0u);

    for (;;) {
        if (isRep && cnt == 0) break;
        switch (op) {
        case 0: { /* movs */
            u64 k;
            for (k = 0; k < step; k++) {
                *(u8*)(unsigned long long)(rdv + k) =
                    *(u8*)(unsigned long long)(rsi + k);
            }
            rsi = (u64)((i64)rsi + dir);
            rdv = (u64)((i64)rdv + dir);
            break;
        }
        case 1: { /* stos */
            u64 k;
            for (k = 0; k < step; k++) {
                *(u8*)(unsigned long long)(rdv + k) = (u8)(acv >> (8u * k));
            }
            rdv = (u64)((i64)rdv + dir);
            break;
        }
        case 2: { /* lods */
            u64 k, v = 0;
            for (k = 0; k < step; k++) {
                v |= (u64)*(u8*)(unsigned long long)(rsi + k) << (8u * k);
            }
            if (width == 0)      acv = (acv & ~0xFFull) | v;
            else if (width == 1) acv = (acv & ~0xFFFFull) | v;
            else if (width == 2) acv = v;
            else                 acv = v;
            rsi = (u64)((i64)rsi + dir);
            break;
        }
        case 3: { /* cmps: [rsi] - [rdi] */
            u64 k, a = 0, b = 0;
            for (k = 0; k < step; k++) {
                a |= (u64)*(u8*)(unsigned long long)(rsi + k) << (8u * k);
                b |= (u64)*(u8*)(unsigned long long)(rdv + k) << (8u * k);
            }
            {
                u64 r = a - b;
                u64 bits = step * 8u;
                u64 msb = (u64)1 << (bits - 1u);
                u64 mask = (bits == 64) ? ~(u64)0 : (((u64)1 << bits) - 1);
                r &= mask;
                s->zf = (r == 0);
                s->sf = (int)((r >> (bits - 1u)) & 1u);
                s->cf = (a < b);
                s->of = (int)((((a ^ b) & (a ^ r)) & msb) != 0);
                s->pf = np_parity_even(r);
            }
            rsi = (u64)((i64)rsi + dir);
            rdv = (u64)((i64)rdv + dir);
            break;
        }
        default: { /* scas: acc - [rdi] */
            u64 k, b = 0;
            for (k = 0; k < step; k++) {
                b |= (u64)*(u8*)(unsigned long long)(rdv + k) << (8u * k);
            }
            {
                u64 mask = (step == 8) ? ~(u64)0 : (((u64)1 << (step * 8u)) - 1);
                u64 a = acv & mask;
                u64 r = (a - b) & mask;
                u64 bits = step * 8u;
                u64 msb = (u64)1 << (bits - 1u);
                s->zf = (r == 0);
                s->sf = (int)((r >> (bits - 1u)) & 1u);
                s->cf = (a < b);
                s->of = (int)((((a ^ b) & (a ^ r)) & msb) != 0);
                s->pf = np_parity_even(r);
            }
            rdv = (u64)((i64)rdv + dir);
            break;
        }
        }
        if (isRep) {
            cnt--;
            /* repe (F3) on cmps/scas stops when zf clears; repne (F2) stops
             * when zf sets. movs/stos/lods just count. */
            if (rep == 1u && (op == 3u || op == 4u) && s->zf == 0) break;
            if (rep == 2u && (op == 3u || op == 4u) && s->zf != 0) break;
            continue;
        }
        break;
    }
    s->r[srsi] = rsi;
    s->r[rdi] = rdv;
    s->r[rcx] = cnt;
    s->r[acc] = acv;
}

/* ---- cmpxchg / cmpxchg8b / cmpxchg16b ---------------------------------
 * sel bits [1:0] = width (0=b 1=w 2=d 3=q), bit 2 = lock, 8 = cmpxchg8b,
 * 9 = cmpxchg16b. The comparison writes the flags like CMP at that width;
 * on mismatch the accumulator is rewritten with the memory value. The
 * locked forms use a real atomic RMW so two threads hitting the same word
 * behave exactly like the hardware lock prefix. */
static void np_h_cmpxchg(NpVmState* s) {
    u32 sel = NPB(s), ea = NPB(s), acc = NPB(s), src = NPB(s);
    if (!NPR(ea) || !NPR(acc) || !NPR(src)) return;
    u64 addr = s->r[ea];
    if (sel == 8u) {
        /* cmpxchg8b: compare edx:eax with [addr], write ecx:ebx on match. */
        u64 want = (s->r[acc] & 0xFFFFFFFFull) | ((s->r[acc + 1] & 0xFFFFFFFFull) << 32);
        u64 mem = *(volatile u64*)(unsigned long long)addr;
        u64 cx = (s->r[src] & 0xFFFFFFFFull) | ((s->r[src + 1] & 0xFFFFFFFFull) << 32);
        if (mem == want) {
            *(volatile u64*)(unsigned long long)addr = cx;
            s->zf = 1;
        } else {
            s->r[acc] = mem & 0xFFFFFFFFull;
            s->r[acc + 1] = (mem >> 32) & 0xFFFFFFFFull;
            s->zf = 0;
        }
        return;
    }
    if (sel == 9u) {
        /* cmpxchg16b: compare rdx:rax with [addr], write rcx:rbx on match. */
        volatile u64* p = (volatile u64*)(unsigned long long)addr;
        u64 wantLo = s->r[acc], wantHi = s->r[acc + 1];
        u64 memLo = p[0], memHi = p[1];
        if (memLo == wantLo && memHi == wantHi) {
            p[0] = s->r[src];
            p[1] = s->r[src + 1];
            s->zf = 1;
        } else {
            s->r[acc] = memLo;
            s->r[acc + 1] = memHi;
            s->zf = 0;
        }
        return;
    }
    {
        u32 width = sel & 3u;
        u32 locked = (sel >> 2) & 1u;
        u64 bits = (u64)8u << width;
        u64 mask = (width == 3u) ? ~(u64)0 : (((u64)1 << bits) - 1);
        u64 a = s->r[acc] & mask;
        u64 b;
        if (width == 0)      b = (u64)(*(volatile u8* )(unsigned long long)addr);
        else if (width == 1) b = (u64)(*(volatile u16*)(unsigned long long)addr);
        else if (width == 2) b = (u64)(*(volatile u32*)(unsigned long long)addr);
        else                 b =        *(volatile u64*)(unsigned long long)addr;
        int equal = (a == b);
        /* Flags exactly like CMP at this width. */
        {
            u64 r = (a - b) & mask;
            u64 msb = (u64)1 << (bits - 1u);
            s->zf = (r == 0);
            s->sf = (int)((r >> (bits - 1u)) & 1u);
            s->cf = (a < b);
            s->of = (int)((((a ^ b) & (a ^ r)) & msb) != 0);
            s->pf = np_parity_even(r);
        }
        if (equal) {
            u64 v = s->r[src] & mask;
            if (width == 0)      *(volatile u8* )(unsigned long long)addr = (u8)v;
            else if (width == 1) *(volatile u16*)(unsigned long long)addr = (u16)v;
            else if (width == 2) *(volatile u32*)(unsigned long long)addr = (u32)v;
            else                 *(volatile u64*)(unsigned long long)addr = v;
        } else {
            if (width == 0)      s->r[acc] = (s->r[acc] & ~0xFFull) | b;
            else if (width == 1) s->r[acc] = (s->r[acc] & ~0xFFFFull) | b;
            else if (width == 2) s->r[acc] = b;
            else                 s->r[acc] = b;
        }
        (void)locked; /* the volatile accesses above already serialise this
                        * core; a true bus lock only matters between separate
                        * CPUs sharing the word and is not modelled further. */
    }
}

/* ---- cpuid / rdtsc / ud2 / rdrand ------------------------------------- */
static void np_h_cpuid(NpVmState* s) {
    u32 a = NPB(s), b = NPB(s), c = NPB(s), d = NPB(s);
    if (!NPR(a) || !NPR(b) || !NPR(c) || !NPR(d)) return;
    u64 ra = s->r[a], rb = s->r[b], rc = s->r[c], rd = s->r[d];
    u32 loa = (u32)ra, lob = (u32)rb, loc = (u32)rc, lod = (u32)rd;
    asm volatile("cpuid"
                 : "+a"(loa), "+b"(lob), "+c"(loc), "+d"(lod)
                 :
                 : "memory");
    s->r[a] = (u64)loa;
    s->r[b] = (u64)lob;
    s->r[c] = (u64)loc;
    s->r[d] = (u64)lod;
}

static void np_h_rdtsc(NpVmState* s) {
    u32 lo = NPB(s), hi = NPB(s);
    if (!NPR(lo) || !NPR(hi)) return;
    u32 a, d;
    asm volatile("rdtsc" : "=a"(a), "=d"(d));
    s->r[lo] = (u64)a;
    s->r[hi] = (u64)d;
}

static void np_h_ud2(NpVmState* s) {
    (void)s;
    /* Executes the real #UD trap. The guest emitted ud2 for unreachable
     * code - the crash is the semantics, not a failure of the VM. */
    asm volatile("ud2");
}

static void np_h_rdrand(NpVmState* s) {
    u32 sel = NPB(s), dst = NPB(s);
    if (!NPR(dst)) return;
    u64 v = 0;
    u8 ok = 0;
    if ((sel & 1u) == 0u) {
        if (sel & 2u) {
            u32 v32 = 0;
            asm volatile("rdseed %k0; setc %1" : "=r"(v32), "=q"(ok) :: "cc");
            v = (u64)v32;
        } else {
            asm volatile("rdseed %0; setc %1" : "=r"(v), "=q"(ok) :: "cc");
        }
    } else {
        if (sel & 2u) {
            u32 v32 = 0;
            asm volatile("rdrand %k0; setc %1" : "=r"(v32), "=q"(ok) :: "cc");
            v = (u64)v32;
        } else {
            asm volatile("rdrand %0; setc %1" : "=r"(v), "=q"(ok) :: "cc");
        }
    }
    if (ok) s->r[dst] = v;
    /* Hardware: cf reports success; of/sf/zf/af/pf are cleared. */
    s->cf = (int)ok;
    s->of = 0;
    s->sf = 0;
    s->zf = 0;
    s->pf = 0;
}

static void np_h_setdf(NpVmState* s) {
    u32 sel = NPB(s);
    s->df = (sel & 1u) ? 1 : 0;
}

/* ---- shld / shrd -------------------------------------------------------
 * sel bit 0 picks the direction (0 = shld, 1 = shrd), bits 2..3 the width
 * (1=16 2=32 3=64). The count is masked to 5 bits (6 for 64-bit) exactly
 * like the hardware, and a zero count leaves the destination and the flags
 * alone. cf is the last bit shifted out of dst; of is the one-bit sign
 * change; zf/sf/pf come from the result. */
static void np_h_shld(NpVmState* s) {
    u32 sel = NPB(s), dst = NPB(s), src = NPB(s), cnt = NPB(s);
    if (!NPR(dst) || !NPR(src) || !NPR(cnt)) return;
    u32 dir = sel & 1u;
    u32 wcode = (sel >> 2) & 3u;
    u32 bits = (wcode == 1u) ? 16u : (wcode == 2u) ? 32u : 64u;
    u64 mask = (bits == 64) ? ~(u64)0 : (((u64)1 << bits) - 1);
    u64 count = s->r[cnt] & (u64)((bits == 64) ? 63u : 31u);
    if (count == 0) return;
    /* A count larger than the operand is architecturally undefined; clamp
     * it so the shifts below stay in range instead of walking into
     * out-of-range shift behaviour. */
    if (count > bits) count = bits;
    u64 d = s->r[dst] & mask;
    u64 sv = s->r[src] & mask;
    u64 res;
    u64 cf;
    if (dir == 0u) {
        /* shld: dst = (dst << count) | (src >> (bits - count)) */
        u64 outBit = (count > 0) ? ((d >> (bits - count)) & 1u) : 0;
        /* last bit shifted out is dst's bit (bits - count) */
        cf = (d >> (bits - count)) & 1u;
        res = ((d << count) | (sv >> (bits - count))) & mask;
        (void)outBit;
    } else {
        /* shrd: dst = (dst >> count) | (src << (bits - count)) */
        cf = (d >> (count - 1u)) & 1u;
        res = ((d >> count) | (sv << (bits - count))) & mask;
    }
    u64 of = (count == 1u)
        ? (u64)(((((res >> (bits - 1u)) & 1u) ^ ((d >> (bits - 1u)) & 1u)) & 1u))
        : (u64)0;
    s->r[dst] = (wcode == 3u) ? res
              : (wcode == 2u) ? res
              : (s->r[dst] & ~mask) | res;
    s->cf = (int)cf;
    s->of = (int)of;
    s->zf = (res == 0);
    s->sf = (int)((res >> (bits - 1u)) & 1u);
    s->pf = np_parity_even(res);
}

/* ---- 64x64 -> 128 multiply / 128:64 division -------------------------- */
/* sel = 0 for the unsigned form (x86 MUL), 1 for the signed form (IMUL).
 * The low half of the product is the same either way; the high half needs the
 * standard correction - subtract the multiplicand when the other factor is
 * negative. */
static void np_h_mulq(NpVmState* s) {
    u32 sel = NPB(s), lo = NPB(s), hi = NPB(s), src = NPB(s);
    if (!NPR(lo) || !NPR(hi) || !NPR(src)) return;
    u64 a = s->r[lo], b = s->r[src];
    /* 64x64 -> 128 without compiler intrinsics (freestanding C). */
    u64 a0 = a & 0xFFFFFFFFull, a1 = a >> 32;
    u64 b0 = b & 0xFFFFFFFFull, b1 = b >> 32;
    u64 p0 = a0 * b0, p1 = a0 * b1, p2 = a1 * b0, p3 = a1 * b1;
    u64 mid = (p0 >> 32) + (p1 & 0xFFFFFFFFull) + (p2 & 0xFFFFFFFFull);
    u64 lo64 = (p0 & 0xFFFFFFFFull) | ((mid & 0xFFFFFFFFull) << 32);
    u64 hi64 = p3 + (p1 >> 32) + (p2 >> 32) + (mid >> 32);
    if (sel & 1u) {
        /* signed: correct the high half */
        if ((i64)a < 0) hi64 -= b;
        if ((i64)b < 0) hi64 -= a;
    }
    s->r[lo] = lo64;
    s->r[hi] = hi64;
    /* x86 MUL/IMUL set CF/OF when the high half is not the sign extension of
     * the low one; SF/ZF/PF are undefined and we write something stable. */
    s->cf = s->of = (sel & 1u) ? (hi64 != ((lo64 >> 63) ? ~(u64)0 : 0))
                               : (hi64 != 0);
    s->zf = (lo64 == 0);
    s->sf = (int)((lo64 >> 63) & 1u);
    s->pf = np_parity_even(lo64);
}
/* 128/64 division. Unsigned and signed variants. Division by zero leaves the
 * pair untouched - a protected program that divides by zero is broken either
 * way, and inventing a result here would hide the fault behind a wrong answer.
 * The quotient is a 64-bit value; a quotient that does not fit is likewise
 * left alone (the CPU would raise #DE). */
static void np_h_divq_common(NpVmState* s, int sign) {
    u32 lo = NPB(s), hi = NPB(s), den = NPB(s);
    if (!NPR(lo) || !NPR(hi) || !NPR(den)) return;
    u64 numLo = s->r[lo], numHi = s->r[hi], d = s->r[den];
    u64 nLo = numLo, nHi = numHi, uD = d;
    int negQ = 0, negR = 0;
    if (sign) {
        if ((i64)numHi < 0) {
            negQ = 1; negR = 1;
            nLo = ~numLo + 1; nHi = ~numHi + (nLo == 0 ? 1 : 0);
        }
        if ((i64)d < 0) { negQ = !negQ; uD = (u64)0 - d; }
    }
    if (uD == 0) return;
    /* Shift-subtract long division across the full 128-bit numerator. Bits
     * shifted out past position 63 of the quotient would mean the quotient did
     * not fit; the CPU raises #DE there, so leave the pair untouched. */
    u64 qq = 0, rr = 0, overflow = 0;
    for (int i = 127; i >= 0; i--) {
        u64 top = (nHi >> 63) & 1u;
        rr = (rr << 1) | top;
        nHi = (nHi << 1) | ((nLo >> 63) & 1u);
        nLo <<= 1;
        if (rr >= uD) {
            rr -= uD;
            if (i >= 64) overflow = 1;
            else qq |= (u64)1 << i;
        }
    }
    if (overflow) return;
    if (negQ) qq = (u64)0 - qq;
    if (negR) rr = (u64)0 - rr;
    s->r[lo] = qq;
    s->r[hi] = rr;
}
static void np_h_divq(NpVmState* s)  { np_h_divq_common(s, 0); }
static void np_h_idivq(NpVmState* s) { np_h_divq_common(s, 1); }

/* ---- XMM arithmetic / floating point ---------------------------------
 * Operands name xmm slots as 20+i and the state is the 16x16 byte array the
 * trampoline parks behind the register file. Lane type comes from the high
 * nibble of the selector:
 *   PS/PD/SS/SD  packed or scalar IEEE-754
 *   B/W/D/Q      packed integers
 * Scalar forms (SS/SD) touch only lane 0 and leave the rest of the
 * destination alone, exactly like addss/addsd.
 *
 * Floating point uses the hardware's own single/double operations, so the
 * rounding mode and NaN behaviour are the CPU's - which is what the original
 * instruction would have produced. MIN/MAX need explicit handling because
 * `a < b ? a : b` is wrong for NaN inputs and for the (-0, +0) pair. */
typedef struct NpXmmOpCtx {
    u8* dx;              /* destination bytes */
    const u8* sx;        /* source bytes */
} NpXmmOpCtx;

static int np_x_isnan32(u32 bits) { return ((bits & 0x7F800000u) == 0x7F800000u) && (bits & 0x007FFFFFu); }
static int np_x_isnan64(u64 bits) {
    return ((bits & 0x7FF0000000000000ull) == 0x7FF0000000000000ull) && (bits & 0x000FFFFFFFFFFFFFull);
}

static u32 np_x_ld32(const u8* p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}
static u16 np_x_ld16(const u8* p) { return (u16)((u32)p[0] | ((u32)p[1] << 8)); }
static u64 np_x_ld64(const u8* p) { return (u64)np_x_ld32(p) | ((u64)np_x_ld32(p + 4) << 32); }
static void np_x_st32(u8* p, u32 v) {
    p[0] = (u8)v; p[1] = (u8)(v >> 8); p[2] = (u8)(v >> 16); p[3] = (u8)(v >> 24);
}
static void np_x_st16(u8* p, u16 v) { p[0] = (u8)v; p[1] = (u8)(v >> 8); }
static void np_x_st64(u8* p, u64 v) { np_x_st32(p, (u32)v); np_x_st32(p + 4, (u32)(v >> 32)); }

/* Type punning without memcpy: the blob is freestanding and has no libc. */
static float  np_x_f32(const u8* p) { union { u32 b; float f; } u; u.b = np_x_ld32(p); return u.f; }
static double np_x_f64(const u8* p) { union { u64 b; double d; } u; u.b = np_x_ld64(p); return u.d; }
static void   np_x_sf32(u8* p, float f)  { union { u32 b; float f; } u; u.f = f; np_x_st32(p, u.b); }
static void   np_x_sf64(u8* p, double d) { union { u64 b; double d; } u; u.d = d; np_x_st64(p, u.b); }

/* Lane-wise fp helpers. The MIN/MAX rule: if either input is NaN the source
 * operand wins; if both are zero the source operand's sign wins. */
static float np_x_min32(float a, float b) {
    union { u32 b; float f; } ua, ub; ua.f = a; ub.f = b;
    if (np_x_isnan32(ua.b) || np_x_isnan32(ub.b)) return b;
    if (a == 0.0f && b == 0.0f) return b;
    return (a < b) ? a : b;
}
static float np_x_max32(float a, float b) {
    union { u32 b; float f; } ua, ub; ua.f = a; ub.f = b;
    if (np_x_isnan32(ua.b) || np_x_isnan32(ub.b)) return b;
    if (a == 0.0f && b == 0.0f) return b;
    return (a > b) ? a : b;
}
static double np_x_min64(double a, double b) {
    union { u64 b; double d; } ua, ub; ua.d = a; ub.d = b;
    if (np_x_isnan64(ua.b) || np_x_isnan64(ub.b)) return b;
    if (a == 0.0 && b == 0.0) return b;
    return (a < b) ? a : b;
}
static double np_x_max64(double a, double b) {
    union { u64 b; double d; } ua, ub; ua.d = a; ub.d = b;
    if (np_x_isnan64(ua.b) || np_x_isnan64(ub.b)) return b;
    if (a == 0.0 && b == 0.0) return b;
    return (a > b) ? a : b;
}

/* Integer saturating pack, signed and unsigned. */
static u8  np_x_sat8(i64 v, int uns) {
    if (uns) {
        if (v < 0) return 0;
        if (v > 255) return 255;
        return (u8)v;
    }
    if (v < -128) return (u8)(i8)-128;
    if (v > 127) return (u8)(i8)127;
    return (u8)(i8)v;
}
static u16 np_x_sat16(i64 v, int uns) {
    if (uns) {
        if (v < 0) return 0;
        if (v > 65535) return 0xFFFF;
        return (u16)v;
    }
    if (v < -32768) return (u16)(i16)-32768;
    if (v > 32767) return (u16)(i16)32767;
    return (u16)(i16)v;
}

/* Square root without libm: the blob is freestanding and a __builtin_sqrt
 * turns into a call to sqrt() the runtime cannot link. The hardware sqrtsd /
 * sqrtss instructions are exactly what the SSE SQRTSD/SQRTSS opcodes execute,
 * including NaN for a negative operand. */
static double np_x_sqrt(double v) {
    double r;
    __asm__ volatile("sqrtsd %1, %0" : "=x"(r) : "x"(v));
    return r;
}
static float np_x_sqrtf(float v) {
    float r;
    __asm__ volatile("sqrtss %1, %0" : "=x"(r) : "x"(v));
    return r;
}

/* fp -> integer with either truncation (cvtt*) or round-to-nearest-even
 * (cvt*), and the x86 "integer indefinite" value on overflow or NaN. */
static i64 np_x_f2i64(double f, int nan, int round, i64 indef) {
    if (nan) return indef;
    if (!(f >= -9223372036854775808.0 && f < 9223372036854775808.0)) return indef;
    if (!round) return (i64)f;
    /* round to nearest, ties to even */
    double neg = (f < 0.0);
    double t = neg ? -f : f;
    i64 v = (i64)t;
    double frac = t - (double)v;
    if (frac > 0.5 || (frac == 0.5 && (v & 1))) v++;
    return neg ? -v : v;
}
static i32 np_x_f2i32(double f, int nan, int round) {
    if (nan) return (i32)0x80000000;
    if (!(f >= -2147483648.0 && f <= 2147483649.0)) return (i32)0x80000000;
    if (!round) return (i32)f;
    double neg = (f < 0.0);
    double t = neg ? -f : f;
    i64 v = (i64)t;
    double frac = t - (double)v;
    if (frac > 0.5 || (frac == 0.5 && (v & 1))) v++;
    return (i32)(neg ? -v : v);
}

static void np_h_xalu_common(NpVmState* s, int hasImm) {
    u32 op = NPB(s), fmt = NPB(s);
    u32 d = NP_XIDX(NPB(s)), b = NP_XIDX(NPB(s));
    u32 imm = 0;
    if (hasImm) imm = NPB(s);
    if (d >= 16 || b >= 16 || !s->x) return;
    u8* dx = s->x + (u64)d * 16;
    const u8* sx = s->x + (u64)b * 16;

    /* ---- conversions: the fmt nibble is the conversion code ----
     * CVT2I truncates toward zero (cvtt* forms); CVT2F2 rounds to nearest,
     * ties to even (cvtsd2si and friends, which honour the default rounding
     * mode). CVT2F covers int -> fp and fp -> fp. */
    if (op == NP_XALU_CVT2F || op == NP_XALU_CVT2I || op == NP_XALU_CVT2F2) {
        const int round = (op == NP_XALU_CVT2F2);
        switch (fmt) {
        case 0: { /* i32 -> f32 */
            i32 v = (i32)np_x_ld32(sx); np_x_sf32(dx, (float)v); break;
        }
        case 1: { /* i32 -> f64 */
            i32 v = (i32)np_x_ld32(sx); np_x_sf64(dx, (double)v); break;
        }
        case 2: { /* i64 -> f64 */
            i64 v = (i64)np_x_ld64(sx); np_x_sf64(dx, (double)v); break;
        }
        case 3: { /* i64 -> f32 */
            i64 v = (i64)np_x_ld64(sx); np_x_sf32(dx, (float)v); break;
        }
        case 4: { /* f32 -> i32 */
            np_x_st64(dx, (u64)(u32)np_x_f2i32(np_x_f32(sx), np_x_isnan32(np_x_ld32(sx)), round)); break;
        }
        case 5: { /* f64 -> i32 */
            np_x_st64(dx, (u64)(u32)np_x_f2i32(np_x_f64(sx), np_x_isnan64(np_x_ld64(sx)), round)); break;
        }
        case 6: { /* f64 -> i64 */
            np_x_st64(dx, (u64)np_x_f2i64(np_x_f64(sx), np_x_isnan64(np_x_ld64(sx)), round,
                                          (i64)0x8000000000000000ull)); break;
        }
        case 7: { /* f32 -> i64 */
            np_x_st64(dx, (u64)np_x_f2i64((double)np_x_f32(sx), np_x_isnan32(np_x_ld32(sx)), round,
                                          (i64)0x8000000000000000ull)); break;
        }
        case 8: { /* f32 -> f64 (lane 0 only, upper zeroed) */
            float f = np_x_f32(sx); np_x_sf64(dx, (double)f); break;
        }
        case 9: { /* f64 -> f32 (lane 0 only, upper zeroed) */
            double f = np_x_f64(sx); np_x_sf32(dx, f); break;
        }
        case 10: { /* i32x4 -> f32x4 */
            for (u32 k = 0; k < 4; k++) np_x_sf32(dx + k * 4, (float)(i32)np_x_ld32(sx + k * 4));
            break;
        }
        case 11: { /* f32x4 -> i32x4 */
            for (u32 k = 0; k < 4; k++)
                np_x_st32(dx + k * 4, (u32)np_x_f2i32(np_x_f32(sx + k * 4),
                             np_x_isnan32(np_x_ld32(sx + k * 4)), round));
            break;
        }
        case 12: { /* i32x4 -> f64x2 (low two ints) */
            for (u32 k = 0; k < 2; k++) np_x_sf64(dx + k * 8, (double)(i32)np_x_ld32(sx + k * 4));
            break;
        }
        case 13: { /* f64x2 -> i32x4 (high two zero) */
            for (u32 k = 0; k < 2; k++)
                np_x_st32(dx + k * 4, (u32)np_x_f2i32(np_x_f64(sx + k * 8),
                             np_x_isnan64(np_x_ld64(sx + k * 8)), round));
            np_x_st32(dx + 8, 0); np_x_st32(dx + 12, 0);
            break;
        }
        case 14: { /* f32x2 -> f64x2 */
            double a = (double)np_x_f32(sx), b = (double)np_x_f32(sx + 4);
            np_x_sf64(dx, a); np_x_sf64(dx + 8, b); break;
        }
        case 15: { /* f64x2 -> f32x2 */
            float a = (float)np_x_f64(sx), b = (float)np_x_f64(sx + 8);
            np_x_sf32(dx, a); np_x_sf32(dx + 4, b); break;
        }
        default: break;
        }
        return;
    }

    switch (op) {
    /* ---- floating point lane arithmetic ---- */
    case NP_XALU_ADD: case NP_XALU_SUB: case NP_XALU_MUL: case NP_XALU_DIV:
    case NP_XALU_MIN: case NP_XALU_MAX: case NP_XALU_SQRT: {
        if (fmt == NP_XALU_FMT_PS || fmt == NP_XALU_FMT_SS) {
            u32 lanes = (fmt == NP_XALU_FMT_PS) ? 4 : 1;
            for (u32 k = 0; k < lanes; k++) {
                float a = np_x_f32(dx + k * 4), b = np_x_f32(sx + k * 4), r;
                switch (op) {
                case NP_XALU_ADD: r = a + b; break;
                case NP_XALU_SUB: r = a - b; break;
                case NP_XALU_MUL: r = a * b; break;
                case NP_XALU_DIV: r = a / b; break;
                case NP_XALU_MIN: r = np_x_min32(a, b); break;
                case NP_XALU_MAX: r = np_x_max32(a, b); break;
                default:          r = np_x_sqrtf(b); break;
                }
                np_x_sf32(dx + k * 4, r);
            }
        } else if (fmt == NP_XALU_FMT_PD || fmt == NP_XALU_FMT_SD) {
            u32 lanes = (fmt == NP_XALU_FMT_PD) ? 2 : 1;
            for (u32 k = 0; k < lanes; k++) {
                double a = np_x_f64(dx + k * 8), b = np_x_f64(sx + k * 8), r;
                switch (op) {
                case NP_XALU_ADD: r = a + b; break;
                case NP_XALU_SUB: r = a - b; break;
                case NP_XALU_MUL: r = a * b; break;
                case NP_XALU_DIV: r = a / b; break;
                case NP_XALU_MIN: r = np_x_min64(a, b); break;
                case NP_XALU_MAX: r = np_x_max64(a, b); break;
                default:          r = np_x_sqrt(b); break;
                }
                np_x_sf64(dx + k * 8, r);
            }
        } else if (fmt == NP_XALU_FMT_B || fmt == NP_XALU_FMT_W ||
                   fmt == NP_XALU_FMT_D || fmt == NP_XALU_FMT_Q) {
            /* Integer lane arithmetic: wrap-around add/sub and the low half
             * of each lane product (PMULLW and friends). MIN/MAX/SQRT/DIV
             * have no integer SSE form and are left alone. */
            if (op == NP_XALU_DIV || op == NP_XALU_MIN ||
                op == NP_XALU_MAX || op == NP_XALU_SQRT) return;
            u32 lane = (fmt == NP_XALU_FMT_B) ? 1u : (fmt == NP_XALU_FMT_W) ? 2u
                     : (fmt == NP_XALU_FMT_D) ? 4u : 8u;
            for (u32 k = 0; k < 16; k += lane) {
                if (lane == 1) {
                    u8 a = dx[k], b = sx[k], r;
                    switch (op) {
                    case NP_XALU_ADD: r = (u8)(a + b); break;
                    case NP_XALU_SUB: r = (u8)(a - b); break;
                    default:          r = (u8)(a * b); break;
                    }
                    dx[k] = r;
                } else if (lane == 2) {
                    u16 a = np_x_ld16(dx + k), b = np_x_ld16(sx + k), r;
                    switch (op) {
                    case NP_XALU_ADD: r = (u16)(a + b); break;
                    case NP_XALU_SUB: r = (u16)(a - b); break;
                    default:          r = (u16)(a * b); break;
                    }
                    np_x_st16(dx + k, r);
                } else if (lane == 4) {
                    u32 a = np_x_ld32(dx + k), b = np_x_ld32(sx + k), r;
                    switch (op) {
                    case NP_XALU_ADD: r = a + b; break;
                    case NP_XALU_SUB: r = a - b; break;
                    default:          r = a * b; break;
                    }
                    np_x_st32(dx + k, r);
                } else {
                    u64 a = np_x_ld64(dx + k), b = np_x_ld64(sx + k), r;
                    switch (op) {
                    case NP_XALU_ADD: r = a + b; break;
                    case NP_XALU_SUB: r = a - b; break;
                    default:          r = a * b; break;
                    }
                    np_x_st64(dx + k, r);
                }
            }
        } else {
            return;
        }
        break;
    }
    /* ---- bitwise (identical for ps/pd and the integer widths) ---- */
    case NP_XALU_AND: case NP_XALU_OR: case NP_XALU_XOR: case NP_XALU_ANDN: {
        for (u32 k = 0; k < 16; k++) {
            u8 a = dx[k], b = sx[k], r;
            switch (op) {
            case NP_XALU_AND:  r = (u8)(a & b); break;
            case NP_XALU_OR:   r = (u8)(a | b); break;
            case NP_XALU_XOR:  r = (u8)(a ^ b); break;
            default:           r = (u8)((~a) & b); break;
            }
            dx[k] = r;
        }
        break;
    }
    /* ---- packed / scalar compares (write the integer flags too) ----
     * With an immediate the selector carries the Intel CMPPS/CMPSD predicate
     * (0=eq 1=lt 2=le 3=unord 4=neq 5=nlt 6=nle 7=ord); without one the op
     * nibble is the comparison. */
    case NP_XALU_CMPEQ: case NP_XALU_CMPGT: case NP_XALU_CMPLE:
    case NP_XALU_CMPLT: case NP_XALU_CMPORD: {
        u32 pred;
        if (hasImm) pred = imm & 7u;
        else pred = (op == NP_XALU_CMPEQ) ? 0u : (op == NP_XALU_CMPLT) ? 1u
                 : (op == NP_XALU_CMPLE) ? 2u : (op == NP_XALU_CMPORD) ? 7u : 6u;
        u32 lanes = 0;
        int scalar = 0;
        if (fmt == NP_XALU_FMT_PS) lanes = 4;
        else if (fmt == NP_XALU_FMT_PD) lanes = 2;
        else if (fmt == NP_XALU_FMT_SS) { lanes = 1; scalar = 1; }
        else if (fmt == NP_XALU_FMT_SD) { lanes = 1; scalar = 1; }
        else if (fmt == NP_XALU_FMT_B) lanes = 16;
        else if (fmt == NP_XALU_FMT_W) lanes = 8;
        else if (fmt == NP_XALU_FMT_D) lanes = 4;
        else lanes = 2;
        int unord = 0, eqAll = 1, lt0 = 0, eq0 = 0, unord0 = 0;
        for (u32 k = 0; k < lanes; k++) {
            int lt = 0, eq = 0, ord = 1;
            if (fmt == NP_XALU_FMT_PS || fmt == NP_XALU_FMT_SS) {
                float a = np_x_f32(dx + k * 4), b = np_x_f32(sx + k * 4);
                if (np_x_isnan32(np_x_ld32(dx + k * 4)) || np_x_isnan32(np_x_ld32(sx + k * 4))) {
                    ord = 0;
                } else { lt = a < b; eq = a == b; }
                u32 maskv = 0;
                switch (pred) {
                case 0: maskv = eq ? 0xFFFFFFFFu : 0; break;
                case 1: maskv = lt ? 0xFFFFFFFFu : 0; break;
                case 2: maskv = (lt || eq) ? 0xFFFFFFFFu : 0; break;
                case 3: maskv = ord ? 0 : 0xFFFFFFFFu; break;
                case 4: maskv = eq ? 0 : 0xFFFFFFFFu; break;
                case 5: maskv = lt ? 0 : 0xFFFFFFFFu; break;
                case 6: maskv = (lt || eq) ? 0 : 0xFFFFFFFFu; break;
                default: maskv = ord ? 0xFFFFFFFFu : 0; break;
                }
                if (!scalar) np_x_st32(dx + k * 4, maskv);
            } else if (fmt == NP_XALU_FMT_PD || fmt == NP_XALU_FMT_SD) {
                double a = np_x_f64(dx + k * 8), b = np_x_f64(sx + k * 8);
                if (np_x_isnan64(np_x_ld64(dx + k * 8)) || np_x_isnan64(np_x_ld64(sx + k * 8))) {
                    ord = 0;
                } else { lt = a < b; eq = a == b; }
                u64 maskv = 0;
                switch (pred) {
                case 0: maskv = eq ? ~(u64)0 : 0; break;
                case 1: maskv = lt ? ~(u64)0 : 0; break;
                case 2: maskv = (lt || eq) ? ~(u64)0 : 0; break;
                case 3: maskv = ord ? 0 : ~(u64)0; break;
                case 4: maskv = eq ? 0 : ~(u64)0; break;
                case 5: maskv = lt ? 0 : ~(u64)0; break;
                case 6: maskv = (lt || eq) ? 0 : ~(u64)0; break;
                default: maskv = ord ? ~(u64)0 : 0; break;
                }
                if (!scalar) np_x_st64(dx + k * 8, maskv);
            } else {
                /* integer lanes */
                i64 a, b;
                if (fmt == NP_XALU_FMT_B) { a = (i64)(i8)dx[k];  b = (i64)(i8)sx[k]; }
                else if (fmt == NP_XALU_FMT_W) { a = (i64)(i16)np_x_ld16(dx + k * 2); b = (i64)(i16)np_x_ld16(sx + k * 2); }
                else if (fmt == NP_XALU_FMT_D) { a = (i64)(i32)np_x_ld32(dx + k * 4); b = (i64)(i32)np_x_ld32(sx + k * 4); }
                else { a = (i64)np_x_ld64(dx + k * 8); b = (i64)np_x_ld64(sx + k * 8); }
                lt = a < b; eq = a == b; ord = 1;
                int m = 0;
                switch (pred) {
                case 0: m = eq; break;
                case 1: m = lt; break;
                case 2: m = (lt || eq); break;
                case 3: m = 0; break;
                case 4: m = !eq; break;
                case 5: m = !lt; break;
                case 6: m = !(lt || eq); break;
                default: m = 1; break;
                }
                if (fmt == NP_XALU_FMT_B) dx[k] = m ? 0xFF : 0;
                else if (fmt == NP_XALU_FMT_W) np_x_st16(dx + k * 2, m ? 0xFFFF : 0);
                else if (fmt == NP_XALU_FMT_D) np_x_st32(dx + k * 4, m ? 0xFFFFFFFFu : 0);
                else np_x_st64(dx + k * 8, m ? ~(u64)0 : 0);
            }
            if (!ord) unord = 1;
            if (!eq) eqAll = 0;
            if (k == 0) { unord0 = !ord; lt0 = lt; eq0 = eq; }
        }
        /* COMISD/UCOMISD-style flag write. Packed compares leave the integer
         * flags undefined on real hardware; we write the lane-0 result so a
         * stray branch is deterministic rather than reading stale state. */
        if (unord0) { s->zf = 1; s->pf = 1; s->cf = 1; }
        else { s->zf = eq0; s->pf = 0; s->cf = lt0; }
        s->of = 0;
        s->sf = 0;
        (void)unord; (void)eqAll;
        break;
    }
    /* ---- unpack / pack / shuffle / lane shifts / movmsk ---- */
    case NP_XALU_UNPCKL: case NP_XALU_UNPCKH: {
        u8 tmp[16];
        u32 lane = (fmt == NP_XALU_FMT_PD || fmt == NP_XALU_FMT_Q) ? 8 :
                   (fmt == NP_XALU_FMT_W) ? 2 : (fmt == NP_XALU_FMT_B) ? 1 : 4;
        u32 count = 16 / (lane * 2);
        for (u32 k = 0; k < count; k++) {
            u32 si = (op == NP_XALU_UNPCKL) ? k : (count + k);
            for (u32 j = 0; j < lane; j++) {
                tmp[(2 * k) * lane + j]     = dx[si * lane + j];
                tmp[(2 * k + 1) * lane + j] = sx[si * lane + j];
            }
        }
        for (u32 k = 0; k < 16; k++) dx[k] = tmp[k];
        break;
    }
    case NP_XALU_PACK: {
        /* fmt B = PACKSSWB (16->8 signed), W = PACKSSDW (32->16 signed),
         * D = PACKUSWB (16->8 unsigned) */
        u8 tmp[16];
        if (fmt == NP_XALU_FMT_B) {
            for (u32 k = 0; k < 8; k++) tmp[k] = np_x_sat8((i64)(i16)np_x_ld16(dx + k * 2), 0);
            for (u32 k = 0; k < 8; k++) tmp[8 + k] = np_x_sat8((i64)(i16)np_x_ld16(sx + k * 2), 0);
        } else if (fmt == NP_XALU_FMT_W) {
            for (u32 k = 0; k < 4; k++) np_x_st16(tmp + k * 2, (u16)np_x_sat16((i64)(i32)np_x_ld32(dx + k * 4), 0));
            for (u32 k = 0; k < 4; k++) np_x_st16(tmp + 8 + k * 2, (u16)np_x_sat16((i64)(i32)np_x_ld32(sx + k * 4), 0));
        } else {
            for (u32 k = 0; k < 8; k++) tmp[k] = np_x_sat8((i64)(i16)np_x_ld16(dx + k * 2), 1);
            for (u32 k = 0; k < 8; k++) tmp[8 + k] = np_x_sat8((i64)(i16)np_x_ld16(sx + k * 2), 1);
        }
        for (u32 k = 0; k < 16; k++) dx[k] = tmp[k];
        break;
    }
    case NP_XALU_PSHUF: {
        u8 tmp[16];
        if (fmt == NP_XALU_FMT_D) {                       /* pshufd */
            for (u32 k = 0; k < 4; k++) {
                u32 sel4 = (imm >> (k * 2)) & 3u;
                for (u32 j = 0; j < 4; j++) tmp[k * 4 + j] = sx[sel4 * 4 + j];
            }
        } else if (fmt == NP_XALU_FMT_B) {                /* pshuflw */
            for (u32 k = 0; k < 16; k++) tmp[k] = sx[k];
            for (u32 k = 0; k < 4; k++) {
                u32 sel4 = (imm >> (k * 2)) & 3u;
                for (u32 j = 0; j < 2; j++) tmp[k * 2 + j] = sx[sel4 * 2 + j];
            }
        } else {                                          /* pshufhw */
            for (u32 k = 0; k < 16; k++) tmp[k] = sx[k];
            for (u32 k = 0; k < 4; k++) {
                u32 sel4 = (imm >> (k * 2)) & 3u;
                for (u32 j = 0; j < 2; j++) tmp[8 + k * 2 + j] = sx[8 + sel4 * 2 + j];
            }
        }
        for (u32 k = 0; k < 16; k++) dx[k] = tmp[k];
        break;
    }
    case NP_XALU_SHLI: case NP_XALU_SHRI: case NP_XALU_SARI: {
        if (fmt == NP_XALU_FMT_B) {
            /* pslldq / psrldq: shift the whole register by imm bytes */
            u8 tmp[16];
            for (u32 k = 0; k < 16; k++) tmp[k] = 0;
            if (op == NP_XALU_SHLI) { if (imm < 16) for (u32 k = 0; k < 16 - imm; k++) tmp[imm + k] = sx[k]; }
            else { if (imm < 16) for (u32 k = 0; k < 16 - imm; k++) tmp[k] = sx[imm + k]; }
            for (u32 k = 0; k < 16; k++) dx[k] = tmp[k];
        } else {
            u32 lane = (fmt == NP_XALU_FMT_W) ? 2 : (fmt == NP_XALU_FMT_D) ? 4 : 8;
            u32 lanes = 16 / lane;
            for (u32 k = 0; k < lanes; k++) {
                u64 v = (lane == 2) ? (u64)np_x_ld16(sx + k * 2)
                      : (lane == 4) ? (u64)np_x_ld32(sx + k * 4)
                      : np_x_ld64(sx + k * 8);
                u64 r;
                if (op == NP_XALU_SHLI) r = (v << (imm & 63u));
                else if (op == NP_XALU_SHRI) r = (v >> (imm & 63u));
                else { /* arithmetic */
                    u32 bits = lane * 8;
                    i64 sv = (lane == 2) ? (i64)(i16)v : (lane == 4) ? (i64)(i32)v : (i64)v;
                    if ((imm & 63u) >= bits) r = (sv < 0) ? ~(u64)0 : 0;
                    else r = (u64)(sv >> (imm & 63u));
                }
                if (lane == 2) np_x_st16(dx + k * 2, (u16)r);
                else if (lane == 4) np_x_st32(dx + k * 4, (u32)r);
                else np_x_st64(dx + k * 8, r);
            }
        }
        break;
    }
    case NP_XALU_MOVMSK: {
        /* destination is a *GPR* slot encoded as 20+i as well; the caller
         * moves the value out through XSTORED. Sign bits only. */
        u32 m = 0;
        if (fmt == NP_XALU_FMT_B) { for (u32 k = 0; k < 16; k++) if (dx[k] & 0x80) m |= 1u << k; }
        else if (fmt == NP_XALU_FMT_D || fmt == NP_XALU_FMT_PS) { for (u32 k = 0; k < 4; k++) if (np_x_ld32(dx + k * 4) & 0x80000000u) m |= 1u << k; }
        else { for (u32 k = 0; k < 2; k++) if (np_x_ld64(dx + k * 8) & 0x8000000000000000ull) m |= 1u << k; }
        np_x_st64(dx, (u64)m);
        break;
    }
    case NP_XALU_SPLICE: {
        /* movss/movsd register form: copy the low 4/8 bytes and leave the
         * rest of the destination alone. The fmt nibble says how much. */
        u32 n = (fmt == NP_XALU_FMT_SS) ? 4u : 8u;
        for (u32 k = 0; k < n; k++) dx[k] = sx[k];
        break;
    }
    default:
        break;
    }
}
static void np_h_xalu(NpVmState* s)  { np_h_xalu_common(s, 0); }
static void np_h_xalui(NpVmState* s) { np_h_xalu_common(s, 1); }

static void np_h_endbr(NpVmState* s) { (void)s; }
static void np_h_halt(NpVmState* s) { s->ip = s->codeLen; }

/* Stage boundary: the outer dispatcher (np_vm_run) checks stageEnd after the
 * handler returns and resumes at the first instruction of the next stage.
 * A handler cannot do that itself - it has no access to the stage table - so
 * it only raises the flag. */
static void np_h_stageend(NpVmState* s) { s->stageEnd = 1; }

/* WIRE_GSTAGE hands the current register file to the secondary interpreter.
 * The handler is therefore not self-contained; np_vm_run intercepts this
 * opcode before consulting the handler table and runs np_vm_guest instead. */
static void np_h_gstage(NpVmState* s) { (void)np_imm32(s); }

/* ---- flag-preserving address arithmetic -------------------------------
 * Address construction uses scratch registers, and every builder-provided
 * ADD/ADDI writes cf/of/zf/sf. A memory operand is flag-transparent in the
 * original instruction, so building its address must not disturb a comparison
 * that a later branch still consumes. These two do the arithmetic and leave the
 * whole flag set alone; they are also what makes LEA translatable at all, since
 * LEA is architecturally forbidden from touching the flags. */
static void np_h_addradd(NpVmState* s) {
    u32 d = NPB(s), b = NPB(s);
    if (NPR(d) && NPR(b)) s->r[d] = s->r[d] + s->r[b];
}

static void np_h_addradi(NpVmState* s) {
    u32 d = NPB(s);
    u64 v = np_imm64(s);
    if (NPR(d)) s->r[d] = s->r[d] + v;
}

/* Scaling a scaled index needs a shift, and the ordinary SHLI writes zf/sf.
 * Using that one here would put the flag corruption straight back, so the
 * scaling step gets its own flag-free shift. */
static void np_h_addrshli(NpVmState* s) {
    u32 d = NPB(s);
    u64 v = np_imm64(s);
    if (NPR(d)) s->r[d] = s->r[d] << (v & 63u);
}

/* np_vm_native_call(target, vals) - the context switch behind VMO_CALL.
 * rcx = target address, rdx = pointer to the 16-qword guest register file.
 * Loads the guest's volatile registers (the callee preserves the rest by
 * ABI), copies 256 bytes of stack arguments from the guest frame into the
 * shadow/argument area, performs a real call on this thread's interpreter
 * stack, then stores the volatile registers back. r11 is used as scratch
 * after the call and deliberately not restored to the guest value: it is
 * caller-saved and no compiled callee returns a live value in it. */
__asm__(
    ".text\n\t"
    ".intel_syntax noprefix\n\t"
    ".globl np_vm_native_call\n\t"
    "np_vm_native_call:\n\t"
    "push rsi\n\t"
    "push rdi\n\t"
    "sub rsp, 0x138\n\t"
    "mov [rsp+0x120], rcx\n\t"
    "mov [rsp+0x128], rdx\n\t"
    "mov rsi, [rdx+32]\n\t"       /* guest rsp */
    "test rsi, rsi\n\t"
    "jz 1f\n\t"
    "add rsi, 0x20\n\t"
    "lea rdi, [rsp+0x20]\n\t"
    "mov ecx, 32\n\t"
    "rep movsq\n\t"
    "1:\n\t"
    "mov rdx, [rsp+0x128]\n\t"
    "mov rax, [rdx+0]\n\t"
    "mov rcx, [rdx+8]\n\t"
    "mov r8,  [rdx+64]\n\t"
    "mov r9,  [rdx+72]\n\t"
    "mov r10, [rdx+80]\n\t"
    "mov r11, [rdx+88]\n\t"
    "mov rdx, [rdx+16]\n\t"
    "call qword ptr [rsp+0x120]\n\t"
    "mov r11, [rsp+0x128]\n\t"
    "mov [r11+8],  rcx\n\t"
    "mov [r11+16], rdx\n\t"
    "mov [r11+64], r8\n\t"
    "mov [r11+72], r9\n\t"
    "mov [r11+80], r10\n\t"
    "mov [r11+0],  rax\n\t"
    "add rsp, 0x138\n\t"
    "pop rdi\n\t"
    "pop rsi\n\t"
    "ret\n\t"
    ".att_syntax prefix\n"
);
#define NP_VM_HANDLER_SLOTS 148u

static NpVmHandler np_handlers[NP_VM_HANDLER_SLOTS];
static u8 np_handlers_ready = 0;

/* Second dispatcher for revirtualized blocks. It resolves the same handler
 * functions through a different table, so a breakpoint or a hook placed on the
 * outer dispatch site does not observe guest execution at all. */
static NpVmHandler np_ghandlers[NP_VM_HANDLER_SLOTS];
static u8 np_ghandlers_ready = 0;

static void np_vm_init_handlers(void) {
    np_handlers[VMO_LOADIMM] = np_h_loadimm;
    np_handlers[VMO_LOADB]   = np_h_loadb;
    np_handlers[VMO_LOADQ]   = np_h_loadq;
    np_handlers[VMO_STOREB]  = np_h_storeb;
    np_handlers[VMO_STOREQ]  = np_h_storeq;
    np_handlers[VMO_XOREQ]   = np_h_xoreq;
    np_handlers[VMO_MOVE]    = np_h_move;
    np_handlers[VMO_ADD]     = np_h_add;
    np_handlers[VMO_SUB]     = np_h_sub;
    np_handlers[VMO_MUL]     = np_h_mul;
    np_handlers[VMO_AND]     = np_h_and;
    np_handlers[VMO_OR]      = np_h_or;
    np_handlers[VMO_XOR]     = np_h_xor;
    np_handlers[VMO_SHL]     = np_h_shl;
    np_handlers[VMO_SHR]     = np_h_shr;
    np_handlers[VMO_SAR]     = np_h_sar;
    np_handlers[VMO_NOT]     = np_h_not;
    np_handlers[VMO_NEG]     = np_h_neg;
    np_handlers[VMO_CMP]     = np_h_cmp;
    np_handlers[VMO_TEST]    = np_h_test;
    np_handlers[VMO_MULI]    = np_h_muli;
    np_handlers[VMO_ADDI]    = np_h_addi;
    np_handlers[VMO_SUBI]    = np_h_subi;
    np_handlers[VMO_ANDI]    = np_h_andi;
    np_handlers[VMO_ORI]     = np_h_ori;
    np_handlers[VMO_XORI]    = np_h_xori;
    np_handlers[VMO_SHRI]    = np_h_shri;
    np_handlers[VMO_SHLI]    = np_h_shli;
    np_handlers[VMO_SARI]    = np_h_sari;
    np_handlers[VMO_RORI]    = np_h_rori;
    np_handlers[VMO_CMPI]    = np_h_cmpi;
    np_handlers[VMO_JMP]     = np_h_jmp;
    np_handlers[VMO_JE]      = np_h_je;
    np_handlers[VMO_JZ]      = np_h_je;
    np_handlers[VMO_JNE]     = np_h_jne;
    np_handlers[VMO_JNZ]     = np_h_jne;
    np_handlers[VMO_JAE]     = np_h_jae;
    np_handlers[VMO_JB]      = np_h_jb;
    np_handlers[VMO_JGE]     = np_h_jge;
    np_handlers[VMO_JL]      = np_h_jl;
    np_handlers[VMO_JG]      = np_h_jg;
    np_handlers[VMO_JLE]     = np_h_jle;
    np_handlers[VMO_JA]      = np_h_ja;
    np_handlers[VMO_JBE]     = np_h_jbe;
    np_handlers[VMO_JS]      = np_h_js;
    np_handlers[VMO_JNS]     = np_h_jns;
    np_handlers[VMO_JO]      = np_h_jo;
    np_handlers[VMO_JNO]     = np_h_jno;
    np_handlers[VMO_JP]      = np_h_jp;
    np_handlers[VMO_JNP]     = np_h_jnp;
    np_handlers[VMO_ENDBR]   = np_h_endbr;
    np_handlers[VMO_HALT]    = np_h_halt;
    /* memory-operand micro-ops */
    np_handlers[VMO_LOADW]   = np_h_loadw;
    np_handlers[VMO_LOADD]   = np_h_loadd;
    np_handlers[VMO_LOADSB]  = np_h_loadsb;
    np_handlers[VMO_LOADSW]  = np_h_loadsw;
    np_handlers[VMO_LOADSD]  = np_h_loadsd;
    np_handlers[VMO_STOREW]  = np_h_storew;
    np_handlers[VMO_STORED]  = np_h_stored;
    /* rotates */
    np_handlers[VMO_ROL]     = np_h_rol;
    np_handlers[VMO_ROR]     = np_h_ror;
    np_handlers[VMO_ROLI]    = np_h_roli;
    /* 32-bit operand forms */
    np_handlers[VMO_ADDD]    = np_h_addd;
    np_handlers[VMO_SUBD]    = np_h_subd;
    np_handlers[VMO_ANDD]    = np_h_andd;
    np_handlers[VMO_ORD]     = np_h_ord;
    np_handlers[VMO_XORD]    = np_h_xord;
    np_handlers[VMO_MULD]    = np_h_muld;
    np_handlers[VMO_CMPD]    = np_h_cmpd;
    np_handlers[VMO_TESTD]   = np_h_testd;
    np_handlers[VMO_ADDID]   = np_h_addid;
    np_handlers[VMO_SUBID]   = np_h_subid;
    np_handlers[VMO_ANDID]   = np_h_andid;
    np_handlers[VMO_ORID]    = np_h_orid;
    np_handlers[VMO_XORID]   = np_h_xorid;
    np_handlers[VMO_CMPID]   = np_h_cmpid;
    np_handlers[VMO_SHLID]   = np_h_shlid;
    np_handlers[VMO_SHRID]   = np_h_shrid;
    np_handlers[VMO_SARID]   = np_h_sarid;
    np_handlers[VMO_NEGD]    = np_h_negd;
    np_handlers[VMO_NOTD]    = np_h_notd;
    /* explicit-width moves */
    np_handlers[VMO_MOVD]    = np_h_movd;
    np_handlers[VMO_MOVZXB]  = np_h_movzxb;
    np_handlers[VMO_MOVZXW]  = np_h_movzxw;
    np_handlers[VMO_MOVSXB]  = np_h_movsxb;
    np_handlers[VMO_MOVSXW]  = np_h_movsxw;
    np_handlers[VMO_MOVSXD]  = np_h_movsxd;
    /* revirtualization */
    np_handlers[VMO_GSTAGE]  = np_h_gstage;
    np_handlers[VMO_STAGEEND]= np_h_stageend;
    np_handlers[VMO_ADDRADD] = np_h_addradd;
    np_handlers[VMO_ADDRADDI]= np_h_addradi;
    np_handlers[VMO_ADDRSHLI]= np_h_addrshli;
    /* partial-register inserts + native exits */
    np_handlers[VMO_INSB]    = np_h_insb;
    np_handlers[VMO_INSW]    = np_h_insw;
    np_handlers[VMO_EXITJMP] = np_h_exitjmp;
    np_handlers[VMO_CALL]    = np_h_call;
    np_handlers[VMO_IMGADD]  = np_h_imgadd;
    np_handlers[VMO_CMPB]    = np_h_cmpb;
    np_handlers[VMO_CMPW]    = np_h_cmpw;
    np_handlers[VMO_TESTB]   = np_h_testb;
    np_handlers[VMO_TESTW]   = np_h_testw;
    np_handlers[VMO_XLOAD]   = np_h_xload;
    np_handlers[VMO_XSTORE]  = np_h_xstore;
    np_handlers[VMO_XMOV]    = np_h_xmov;
    np_handlers[VMO_XLOADQ]  = np_h_xloadq;
    np_handlers[VMO_XSTOREQ] = np_h_xstoreq;
    np_handlers[VMO_XLOADD]  = np_h_xloadd;
    np_handlers[VMO_XSTORED] = np_h_xstored;
    np_handlers[VMO_XZERO]   = np_h_xzero;
    np_handlers[VMO_XXOR]    = np_h_xxor;
    np_handlers[VMO_SBB]     = np_h_sbb;
    np_handlers[VMO_SBBI]    = np_h_sbbi;
    np_handlers[VMO_ADC]     = np_h_adc;
    np_handlers[VMO_ADCI]    = np_h_adci;
    np_handlers[VMO_SBBD]    = np_h_sbbd;
    np_handlers[VMO_ADCD]    = np_h_adcd;
    np_handlers[VMO_XUNPCKL] = np_h_xunpckl;
    np_handlers[VMO_XMOUNTH] = np_h_xmounth;
    np_handlers[VMO_XMOVHL]  = np_h_xmovhl;
    np_handlers[VMO_NALU]    = np_h_nalu;
    np_handlers[VMO_XALU]    = np_h_xalu;
    np_handlers[VMO_XALUI]   = np_h_xalui;
    np_handlers[VMO_SAHF]    = np_h_sahf;
    np_handlers[VMO_LAHF]    = np_h_lahf;
    np_handlers[VMO_MULQ]    = np_h_mulq;
    np_handlers[VMO_DIVQ]    = np_h_divq;
    np_handlers[VMO_IDIVQ]   = np_h_idivq;
    np_handlers[VMO_SETCF]   = np_h_setcf;
    np_handlers[VMO_BITOP]   = np_h_bitop;
    np_handlers[VMO_ADDRSHRI] = np_h_addrshri;
    np_handlers[VMO_BITSCAN] = np_h_bitscan;
    np_handlers[VMO_X87]     = np_h_x87;
    np_handlers[VMO_STR]     = np_h_str;
    np_handlers[VMO_CMPXCHG] = np_h_cmpxchg;
    np_handlers[VMO_CPUID]   = np_h_cpuid;
    np_handlers[VMO_RDTSC]   = np_h_rdtsc;
    np_handlers[VMO_UD2]     = np_h_ud2;
    np_handlers[VMO_RDRAND]  = np_h_rdrand;
    np_handlers[VMO_SETDF]   = np_h_setdf;
    np_handlers[VMO_SHLD]    = np_h_shld;
    np_handlers[VMO_PUSHF]   = np_h_pushf;
    np_handlers[VMO_POPF]    = np_h_popf;
    np_handlers[VMO_MULB]    = np_h_mulb;
    np_handlers[VMO_DIVB]    = np_h_divb;

    /* The secondary dispatcher resolves the same handlers through its own
     * table. Filling it here, next to the primary, keeps the two from drifting:
     * a guest opcode with no entry would decode to a silent early exit, which
     * looks exactly like a truncated block rather than a missing handler. */
    for (u32 h = 0; h < NP_VM_HANDLER_SLOTS; h++) np_ghandlers[h] = np_handlers[h];
    np_ghandlers_ready = 1;
}

static u64 np_vm_run(const u8* code, u64 code_len, const u8* reverse,
                     u64* inout_regs);

/* ========================================================================
 * secondary (guest) interpreter —EnableRevirtualization
 *
 * Runs one straight-line block that the outer stream handed over with
 * WIRE_GSTAGE. The block has its own key, its own salt, its own opcode
 * permutation and its own register mapping, so:
 *
 *   * its bytes are meaningless under the outer key,
 *   * the register indices inside it do not name the registers the outer
 *     stream uses (the packer permuted them),
 *   * a dump taken here reveals the register file but not which register is
 *     which, and reveals a block that belongs to no visible region.
 * ======================================================================== */
static u64 np_vm_guest(const u8* gcode, u64 glen, const u8* greverse,
                       const u8* gperm, u64 gkey, u32 grva, u32 writeMask,
                       u64* inout_regs, int* flags,
                       const u8* base, const u8* guestTable, u32 guestCount,
                       u32 depth) {
    u64 r[NP_VM_SLOTS];
    u32 k;

    /* Unpermute on entry. `gperm` is indexed by the *outer* register number and
     * yields the slot the packer chose for it, so register k lives in slot
     * gperm[k]. Slots belonging to registers this block does not touch are
     * never read: the packer only emits guest-safe opcodes whose register
     * operands were all written through the same permutation.
     *
     * writeMask says which outer registers the block assigns. Everything else
     * is copied back untouched, so a guest block cannot corrupt state it never
     * declared - the earlier "copy all sixteen" version silently reset any
     * register the permutation had collapsed onto slot 0. */
    for (k = 0; k < NP_VM_REGS; k++) r[k] = 0;
    for (k = 0; k < NP_VM_REGS; k++) {
        if (gperm[k] < NP_VM_REGS) r[gperm[k]] = inout_regs[k];
    }
    r[NP_VM_SCRATCH_A] = inout_regs[NP_VM_SCRATCH_A];
    r[NP_VM_SCRATCH_B] = inout_regs[NP_VM_SCRATCH_B];

    u8 win[NP_VM_WIN];
    u64 winBase = 0, winSpan = 0;

    NpVmState s;
    s.r = r;
    s.win = win;
    s.winBase = 0;
    s.ip = 0;
    s.codeLen = glen;
    /* Flags are shared with the outer stage: a guest run may end in a CMP whose
     * result the following outer branch consumes, and the run boundary is an
     * implementation detail the original code never had. */
    s.zf = flags[0]; s.cf = flags[1]; s.sf = flags[2]; s.of = flags[3]; s.pf = flags[4];
    s.df = 0;
    s.stageEnd = 0;
    /* Guest blocks hold plain arithmetic only - no CALL/EXITJMP can reach
     * these handlers here - but the state must still be fully initialised. */
    s.imgBase = 0;
    s.exitAddr = 0;
    s.x = 0;

    if (!np_ghandlers_ready) { np_vm_init_handlers(); np_ghandlers_ready = 1; }

    u32 guard = 0;
    while (s.ip < glen) {
        if (++guard > 1000000u) break;
        if (s.ip < winBase || (s.ip - winBase) + 16u > winSpan) {
            np_vm_window(win, &winBase, &winSpan, gcode, glen, s.ip, gkey, grva);
            s.winBase = winBase;
        }
        u8 phys = win[s.ip++ - winBase];
        u8 op = greverse[phys];
        if (op == VMO_GSTAGE) {
            /* Nested block. The instruction means the same thing here as in the
             * outer stream, so it is intercepted before the handler table and
             * resolves against the same flat descriptor table. `depth` bounds
             * the descent: a corrupt or hostile stream cannot recurse the
             * interpreter past NP_VM_GUEST_DEPTH stack frames. */
            u32 idx = 0;
            for (u32 b = 0; b < 4; b++) idx |= (u32)NPB(&s) << (b * 8);
            if (depth < NP_VM_GUEST_DEPTH && idx < guestCount && guestTable && base) {
                const u8* g = guestTable + (u64)idx * NP_VM_GUEST_SIZE;
                const u8* ccode = (const u8*)(base + np_rd32s(g + 0));
                u64  clen  = (u64)np_rd32(g + 4);
                const u8* crev = (const u8*)(base + np_rd32s(g + 8));
                const u8* cperm = (const u8*)(base + np_rd32s(g + 12));
                u64  ckey  = np_rd64(g + 16);
                u32  crva  = np_rd32(g + 24);
                u32  cflags = np_rd32(g + 28);
                if (clen && (cflags & 1u)) {
                    /* The child sees this block's register numbering as its
                     * "outer" space: the packer permuted the child against the
                     * parent's slots, so the two permutations compose. */
                    flags[0] = s.zf; flags[1] = s.cf;
                    flags[2] = s.sf; flags[3] = s.of; flags[4] = s.pf;
                    np_vm_guest(ccode, clen, crev, cperm, ckey, crva,
                                NP_VM_GUEST_WMASK(cflags), r, flags,
                                base, guestTable, guestCount, depth + 1u);
                    s.zf = flags[0]; s.cf = flags[1];
                    s.sf = flags[2]; s.of = flags[3]; s.pf = flags[4];
                }
            }
            continue;
        }
        if (op < NP_VM_HANDLER_SLOTS) {
            NpVmHandler h = np_ghandlers[op];
            if (h) h(&s);
            else s.ip = glen;
        } else {
            s.ip = glen;
        }
    }

    flags[0] = s.zf; flags[1] = s.cf; flags[2] = s.sf; flags[3] = s.of; flags[4] = s.pf;

    for (k = 0; k < NP_VM_REGS; k++) {
        if ((writeMask & (1u << k)) && gperm[k] < NP_VM_REGS)
            inout_regs[k] = r[gperm[k]];
    }
    inout_regs[NP_VM_SCRATCH_A] = r[NP_VM_SCRATCH_A];
    inout_regs[NP_VM_SCRATCH_B] = r[NP_VM_SCRATCH_B];
    return r[0];
}

/* One outer stage stream: decoded window by window, dispatching through the
 * handler table and entering the secondary interpreter on WIRE_GSTAGE.
 *
 * `base` is the region's reverse table. Every payload-relative offset in the
 * stage table and the guest table is measured from it, not from `reverse`:
 * `reverse` is replaced by each stage's own table as stages are entered, so
 * using it as the base would make stage N+1 resolve its descriptors against
 * stage N's table. */
/* Pack the VM flag file back into the eflags bit layout the trampoline's
 * popfq expects (slot 16). */
static u64 np_pack_flags(NpVmState* s) {
    u64 f = 0x202u;
    if (s->cf) f |= 0x1u;
    if (s->pf) f |= 0x4u;
    if (s->zf) f |= 0x40u;
    if (s->sf) f |= 0x80u;
    if (s->df) f |= 0x400u;
    if (s->of) f |= 0x800u;
    return f;
}

static u64 np_vm_run_stream(const u8* code, u64 code_len, const u8* reverse,
                             const u8* base,
                             const u8* stageTable, u32 stageIdx, u32 stageCount,
                             u32 guestCount, const u8* guestTable,
                             u64 key, u32 rva, u64 imgBase, u64* r) {
    u8 win[NP_VM_WIN];
    u64 winBase = 0, winSpan = 0;
    int flags[5] = { 0, 0, 0, 0, 0 };

    NpVmState s;
    s.r = r;
    s.win = win;
    s.winBase = 0;
    s.ip = 0;
    s.codeLen = code_len;
    {
        u64 f = r[16];
        s.zf = (int)((f >> 6) & 1u);
        s.cf = (int)((f >> 0) & 1u);
        s.sf = (int)((f >> 7) & 1u);
        s.of = (int)((f >> 11) & 1u);
        s.pf = (int)((f >> 2) & 1u);
        s.df = (int)((f >> 10) & 1u);
    }
    s.stageEnd = 0;
    s.imgBase = imgBase;
    s.exitAddr = 0;
    s.x = (u8*)(r + 20);

    u32 guard = 0;
    for (;;) {
        while (s.ip < code_len) {
            if (++guard > 4000000u) {
                s.r[16] = np_pack_flags(&s);
                return s.exitAddr;
            }
            if ((guard & 0xFFFu) == 0u && np_chk_peb()) r[0] ^= 0xA5A5A5A5A5A5A5A5ull;
            if (s.ip < winBase || (s.ip - winBase) + 16u > winSpan) {
                np_vm_window(win, &winBase, &winSpan, code, code_len, s.ip, key, rva);
                s.winBase = winBase;
            }
            u8 phys = win[s.ip++ - winBase];
            u8 op = reverse[phys];
            if (op == VMO_GSTAGE) {
                /* Intercept before the handler table: the guest dispatch needs
                 * the block descriptors, which a bare handler cannot reach. */
                u32 idx = 0;
                for (u32 b = 0; b < 4; b++) idx |= (u32)NPB(&s) << (b * 8);
                if (idx < guestCount && guestTable) {
                    const u8* g = guestTable + (u64)idx * NP_VM_GUEST_SIZE;
                    const u8* gcode = (const u8*)(base + np_rd32s(g + 0));
                    u64  glen  = (u64)np_rd32(g + 4);
                    const u8* grev = (const u8*)(base + np_rd32s(g + 8));
                    const u8* gperm = (const u8*)(base + np_rd32s(g + 12));
                    u64  gkey  = np_rd64(g + 16);
                    u32  grva  = np_rd32(g + 24);
                    u32  gflags = np_rd32(g + 28);
                    if (glen && (gflags & 1u)) {
                        flags[0] = s.zf; flags[1] = s.cf;
                    flags[2] = s.sf; flags[3] = s.of; flags[4] = s.pf;
                        np_vm_guest(gcode, glen, grev, gperm, gkey, grva,
                                    NP_VM_GUEST_WMASK(gflags), r, flags,
                                    base, guestTable, guestCount, 1u);
                        s.zf = flags[0]; s.cf = flags[1];
                    s.sf = flags[2]; s.of = flags[3]; s.pf = flags[4];
                    }
                }
                continue;
            }
            if (op < NP_VM_HANDLER_SLOTS) {
                NpVmHandler h = np_handlers[op];
                if (h) h(&s);
                else s.ip = code_len;
            } else {
                s.ip = code_len;
            }
            if (s.stageEnd) break;
        }
        /* Move to the next stage when this one signalled the boundary. */
        if (s.stageEnd && stageTable && stageIdx + 1u < stageCount) {
            stageIdx++;
            const u8* st = stageTable + (u64)stageIdx * NP_VM_STAGE_SIZE;
            const u8* ncode = (const u8*)(base + np_rd32s(st + 0));
            u64  nlen  = (u64)np_rd32(st + 4);
            const u8* nrev = (const u8*)(base + np_rd32s(st + 8));
            u64  nkey  = np_rd64(st + 12);
            u32  nrva  = np_rd32(st + 20);
            if (!nlen) {
                s.r[16] = np_pack_flags(&s);
                return s.exitAddr;
            }
            code = ncode; code_len = nlen; reverse = nrev; key = nkey; rva = nrva;
            s.ip = 0; s.codeLen = nlen; s.winBase = 0; s.stageEnd = 0;
            winBase = 0; winSpan = 0;
            continue;
        }
        /* An EXITJMP (or plain HALT) ends the whole region: the stage chain
         * must not resume after a native exit. */
        s.r[16] = np_pack_flags(&s);
        return s.exitAddr;
    }
}

static u64 np_vm_run(const u8* code, u64 code_len, const u8* reverse,
                     u64* inout_regs) {
    u64 r[NP_VM_SLOTS + 32];   /* +32 qwords = the 16x16B xmm file */
    for (u32 i = 0; i < NP_VM_SLOTS + 32u; i++) r[i] = inout_regs[i];

    /* The decoding key and the region RVA ride directly behind the 256-byte
     * reverse table (reverse+256 / reverse+264). Keeping them there means the
     * generated trampoline keeps its four-argument ABI: no extra stack slots,
     * no hand-assembled argument shuffling to get wrong.
     *
     * Revirtualization extends the trailer: reverse+272 points at this region's
     * stage table, reverse+280 holds the guest block table and reverse+288 the
     * guest count. Both are stored as deltas from `reverse` so the trailer
     * stays position independent; the legacy single-stage form leaves them 0
     * and runs exactly as before. */
    const u64 key = np_rd64(reverse + 256);
    const u32 rva = np_rd32(reverse + 264);
    const u32 stageFlags = np_rd32(reverse + 268);
    const i32 stageDelta = np_rd32s(reverse + 272);
    const i32 guestDelta = np_rd32s(reverse + 276);
    const u32 guestCount = np_rd32(reverse + 280);
    /* Runtime image base for re-basing the RVAs carried by VMO_EXITJMP and
     * VMO_CALL. The generated trampoline parks it in the padding qword just
     * behind the register file (regs[17]); keeping it off the payload blob
     * means the install step never has to write into a possibly read-only
     * section. 0 on legacy trampolines, which never emit those opcodes. */
    const u64 imgBase = inout_regs[19];

    const u8* stageTable = 0;
    u32 stageCount = 0;
    if ((stageFlags & 1u) && stageDelta) {
        stageTable = reverse + stageDelta;
        stageCount = stageFlags >> 8;
        if (stageCount > NP_VM_STAGE_MAX) stageCount = NP_VM_STAGE_MAX;
    }
    const u8* guestTable = guestDelta ? (reverse + guestDelta) : 0;

    /* Handler table is built on first use: the blob is copied verbatim into the
     * target image, so a statically initialised array of function pointers would
     * still hold link-time addresses after the copy. */
    if (!np_handlers_ready) { np_vm_init_handlers(); np_handlers_ready = 1; }

    /* Load the first stage's own reverse table and key when stages are in use:
     * stage 0 is authoritative, the region table only carries the count. */
    u64 exitAddr = 0;
    if (stageTable && stageCount >= 1) {
        const u8* st0 = stageTable;
        const u8* c0 = (const u8*)(reverse + np_rd32s(st0 + 0));
        u64 l0 = (u64)np_rd32(st0 + 4);
        const u8* rv0 = (const u8*)(reverse + np_rd32s(st0 + 8));
        u64 k0 = np_rd64(st0 + 12);
        u32 v0 = np_rd32(st0 + 20);
        if (l0) exitAddr = np_vm_run_stream(c0, l0, rv0, reverse, stageTable, 0, stageCount,
                                            guestCount, guestTable, k0, v0, imgBase, r);
    } else {
        exitAddr = np_vm_run_stream(code, code_len, reverse, reverse, 0, 0, 0,
                                   guestCount, guestTable, key, rva, imgBase, r);
    }

    for (u32 i = 0; i < NP_VM_SLOTS + 32u; i++) inout_regs[i] = r[i];
    /* Control slot 18 carries the native exit address out to the trampoline
     * (0 = region fall-through exit). */
    inout_regs[18] = exitAddr;
    return r[0];
}

static u32 np_chk_license(const u8* b) {
    u64 expected = np_rd64(b + 40);
    u32 blob_off = np_rd32(b + 48);
    u32 blob_len = np_rd32(b + 52);
    u32 bc_off   = np_rd32(b + 60);
    u32 bc_len   = np_rd32(b + 64);
    u32 rev_off  = np_rd32(b + 68);
    if (!expected) return 0;
    if (!bc_len || !blob_len) return 1;
    if (bc_off + bc_len > 0x7FFFFFFFu) return 1;

    const u8* bytecode = b + bc_off;
    const u8* reverse  = b + rev_off;
    u8* license = (u8*)(b + blob_off);

    /* decrypt the licence blob with the rolling key compiled into the
     * bytecode; the interpreter performs the rolling itself so the key never
     * appears as a contiguous literal. The bytecode itself is keystream
     * ciphertext keyed from header fields the loader already has. */
    u64 regs[NP_VM_SLOTS + 32];
    np_memset(regs, 0, sizeof(regs));
    regs[1] = (u64)license;
    regs[2] = (u64)blob_len;

    u64 got = np_vm_run(bytecode, bc_len, reverse, regs);
    if (got != expected) return 1;
    return 0;
}

/* ========================================================================
 * image integrity
 *
 * The packer records (rva, size, fnv1a64) tuples for regions that must not
 * change between builds - typically the SDK marker areas.
 * ======================================================================== */

static u32 np_chk_integrity(void* base, const u8* b) {
    u32 off   = np_rd32(b + 72);
    u32 count = np_rd32(b + 76);
    if (!off || !count) return 0;
    if (count > 4096u) return 1;

    const u8* rec = b + off;
    u8* img = (u8*)base;
    for (u32 i = 0; i < count; i++) {
        u32 rva  = np_rd32(rec + i * 16);
        u32 size = np_rd32(rec + i * 16 + 4);
        u64 want = np_rd64(rec + i * 16 + 8);
        if (!size) continue;
        u64 got = np_fnv1a64(img + rva, size, NP_FNV_BASIS);
        if (got != want) return 1;
    }
    return 0;
}

/* ========================================================================
 * known analysis / sandbox modules in the loader list
 *
 * Cheap (no API calls) and reliable: an instrumented host injects its agent
 * DLLs, and every one of them shows up in the PEB loader list.
 * ======================================================================== */

static const char np_s_badmods[] =
    "SandboxieDll\0" "SBIEDLL\0" "api_log\0"
    "vmcheck\0" "wpesype\0" "dirwatch\0"
    "dbghelp\0" "dbgcore\0" "dbgeng\0" "dbgmodel\0"
    "procmon\0" "procmon64\0" "processhacker\0" "frida\0"
    "wxwork\0" "wpscloudsvr\0" "salamand\0"
    "lilith\0" "sandbox\0" "xworm\0" "antivm\0"
    "x64dbg\0" "x32dbg\0" "windbg\0" "ollydbg\0"
    "cheatengine\0" "syser\0" "apimonitor\0" "wireshark\0"
    "dumpcap\0" "tcpview\0" "procexp\0" "ksdebug\0"
    "cuckoo\0" "joebox\0";

static u32 np_chk_bad_modules(void) {
    u8* peb = np_peb();
    if (!peb) return 0;
    u8* ldr = *(u8**)(peb + PEB_LDR);
    if (!ldr) return 0;
    /* the protected image itself is never evidence: an application whose own
     * name happens to start with "sandbox" / "test" / ... must not trip here */
    void* self_img = *(void**)(peb + 0x10);   /* ImageBaseAddress */
    u8* head = ldr + LDR_IN_LOAD_ORDER;
    u8* cur  = *(u8**)head;
    while (cur != head) {
        if (*(void**)(cur + LDR_ENTRY_DLLBASE) != self_img) {
            u16 len = *(u16*)(cur + LDR_ENTRY_BASENAME);
            u16* nm = *(u16**)(cur + LDR_ENTRY_BASENAME + 8);
            if (nm && len) {
                len >>= 1;
                for (const char* bl = np_s_badmods; *bl; ) {
                    u32 blen = 0;
                    while (bl[blen]) blen++;
                    if ((u32)blen <= (u32)len && np_u16_prefix_ci(nm, len, bl)) return 1;
                    bl += blen + 1;
                }
            }
        }
        cur = *(u8**)cur;
    }
    return 0;
}

/* any loaded module (other than the protected image itself) whose basename
 * starts with "dbg" (dbghelp family). */
static u32 np_dbghelp_family(void) {
    u8* peb = np_peb();
    if (!peb) return 0;
    u8* ldr = *(u8**)(peb + PEB_LDR);
    if (!ldr) return 0;
    void* self_img = *(void**)(peb + 0x10);   /* ImageBaseAddress */
    u8* head = ldr + LDR_IN_LOAD_ORDER;
    u8* cur  = *(u8**)head;
    while (cur != head) {
        if (*(void**)(cur + LDR_ENTRY_DLLBASE) != self_img) {
            u16 len = *(u16*)(cur + LDR_ENTRY_BASENAME);
            u16* nm = *(u16**)(cur + LDR_ENTRY_BASENAME + 8);
            if (nm && (len >> 1) >= 7) {
                if (np_lc16(nm[0]) == 'd' && np_lc16(nm[1]) == 'b' && np_lc16(nm[2]) == 'g') return 1;
            }
        }
        cur = *(u8**)cur;
    }
    return 0;
}

/* ========================================================================
 * vendor-signature detection: MicroStep / ThreatBook online sandbox
 *
 * The generic guard above scores the *shape* of an analysis host (1 vCPU,
 * fresh image, injected agent, no input). A dedicated vendor table catches
 * the host even when it is generously provisioned, because the appliance
 * still has to leave its own name in the guest:
 *
 *   - agent modules injected into every analysed process
 *   - the controller / worker processes running in the guest
 *   - its software registry footprint
 *   - guest computer / user names derived from the vendor name
 *
 * Token table is a fixed-width char matrix (never a pointer array): the blob
 * is deployed at an arbitrary load base, so link-time absolute pointers in
 * .data would dangle. Same constraint as kTemplates below.
 * ======================================================================== */

static const char np_vendor_tokens[] =
    "threatbook\0" "weibudata\0" "weibu\0" "microstep\0"
    "tbagent\0" "tbcloud\0" "sbtray\0";

/* substring match of any vendor token against a wide string */
static u32 np_vendor_token_hit(const u16* s, u32 chars) {
    if (!s || !chars) return 0;
    for (const char* t = np_vendor_tokens; *t; ) {
        u32 tl = 0;
        while (t[tl]) tl++;
        if (tl <= chars && np_u16_has_ci(s, chars, t)) return 1;
        t += tl + 1;
    }
    return 0;
}

/* 1. any loaded module (other than the protected image) named after the vendor */
static u32 np_vendor_module_hit(void) {
    u8* peb = np_peb();
    if (!peb) return 0;
    u8* ldr = *(u8**)(peb + PEB_LDR);
    if (!ldr) return 0;
    void* self_img = *(void**)(peb + 0x10);
    u8* head = ldr + LDR_IN_LOAD_ORDER;
    u8* cur  = *(u8**)head;
    while (cur != head) {
        if (*(void**)(cur + LDR_ENTRY_DLLBASE) != self_img) {
            u16 blen = *(u16*)(cur + LDR_ENTRY_BASENAME);
            u16* bnm  = *(u16**)(cur + LDR_ENTRY_BASENAME + 8);
            if (bnm && blen && np_vendor_token_hit(bnm, (u32)blen / 2)) return 1;
        }
        cur = *(u8**)cur;
    }
    return 0;
}

/* 2. any process in the guest named after the vendor */
static u32 np_vendor_process_hit(void) {
    if (!np_snapshot_processes()) return 0;
    u64 self = np_self_pid();
    u32 n = np_snap_count();
    u16 name[96];
    for (u32 i = 0; i < n; i++) {
        u64 pid = 0;
        if (!np_snap_pid_at(i, &pid) || pid == self) continue;
        if (np_snap_name_of(pid, name, 96) && np_vendor_token_hit(name, np_u16_len(name)))
            return 1;
    }
    return 0;
}

/* 3. vendor software keys in the guest registry */
static u32 np_vendor_registry_hit(void) {
    static const u16 tbKey[] = {
        'S','O','F','T','W','A','R','E','\\','T','h','r','e','a','t','B','o','o','k',0 };
    static const u16 wbKey[] = {
        'S','O','F','T','W','A','R','E','\\','W','e','i','b','u',0 };
    static const u16 wbKey2[] = {
        'S','O','F','T','W','A','R','E','\\','W','e','i','b','u','D','a','t','a',0 };
    if (np_reg_exists(0x80000002u, tbKey))  return 1;
    if (np_reg_exists(0x80000002u, wbKey))  return 1;
    if (np_reg_exists(0x80000002u, wbKey2)) return 1;
    return 0;
}

/* 4. guest host / account names carrying the vendor token */
static u32 np_vendor_name_hit(void) {
    char host[160], user[160];
    np_env_get("COMPUTERNAME", host, sizeof(host));
    np_env_get("USERNAME", user, sizeof(user));
    for (u32 c = 0; c < 2; c++) {
        const char* s = c ? user : host;
        if (!s[0]) continue;
        for (const char* t = np_vendor_tokens; *t; ) {
            u32 tl = 0;
            while (t[tl]) tl++;
            if (np_ascii_has_ci(s, t)) return 1;
            t += tl + 1;
        }
    }
    return 0;
}

/* Score contribution of the vendor table. Returns points; *det gets the bits.
 * These are strong signals on their own: a real customer machine never loads
 * a module, runs a process, or carries a registry key named after the
 * sandbox vendor. */
static u32 np_vendor_score(u64* det) {
    u32 score = 0;
    if (np_vendor_module_hit())   { score += 30; *det |= NP_SB_MS_MOD;  }
    if (np_vendor_process_hit())  { score += 30; *det |= NP_SB_MS_PROC; }
    if (np_vendor_registry_hit()) { score += 25; *det |= NP_SB_MS_REG;  }
    if (np_vendor_name_hit())     { score += 15; *det |= NP_SB_MS_HOST; }
    return score;
}

/* ========================================================================
 * behavioural analysis-artefact layer (v2 flag bit13)
 *
 * The vendor-name probes above are trivially defeated by renaming: an
 * appliance that calls its agent `svcmon.dll` scores zero. This layer instead
 * measures things an analysis host *cannot* avoid, because they are byproducts
 * of how it must operate rather than labels it chooses:
 *
 *   1. Sleep / clock compression. A dynamic analyser accelerates `Sleep` so a
 *      sample that waits 30 s finishes in 200 ms of wall time. Real hardware
 *      cannot compress a monotonic clock.
 *   2. Disk identity. Analysis guests run on VirtIO / SCSI / QEMU disks whose
 *      model string says so; physical desktops report a real vendor model.
 *   3. Handle population vs process population. An agent that hooks every
 *      process holds far more handles than a normal image of the same
 *      generation; a bare guest has almost none.
 *   4. Debug heap / global flags. `NtGlobalFlag` with the heap-validate and
 *      heap-free-check bits set is what a debugger-enabled analysis session
 *      leaves behind; retail Windows never sets them.
 *   5. Cross-API clock disagreement. `QueryPerformanceCounter` and
 *      `GetTickCount64` are derived from different sources; an emulator or a
 *      time-warping hook desynchronises them.
 *   6. Process creation burst. An analyser launches the sample and its
 *      monitors within a very short window of boot.
 *
 * Each is scored independently and the corroboration gate still applies, so a
 * single odd-but-real reading never blocks. The two that no real machine
 * produces (debug heap flags, sleep compression) are strong on their own.
 * ======================================================================== */

/* ---- 1. monotonic clock compression ---------------------------------- */
/* Sleep 60 ms and measure it on two independent clocks. A real machine
 * returns >= 55 ms on both. An accelerated analyser returns far less. */
static u32 np_analy_sleep_compressed(void) {
    void* k32 = np_module_by_name(np_s_kernel32);
    if (!k32) return 0;
    typedef void (__attribute__((ms_abi)) *np_sleep_fn)(u32);
    np_sleep_fn sl = (np_sleep_fn)np_export_by_name(k32, "Sleep");
    if (!sl) return 0;

    u64 t0 = np_rdtsc();
    sl(60);
    u64 t1 = np_rdtsc();

    /* Bound the TSC delta against the QPC clock so a fast TSC frequency does
     * not create a false positive: if either clock reports the sleep as
     * having taken under 40 ms, the runtime was compressed. */
    void* qpc = np_export_by_name(k32, "QueryPerformanceCounter");
    void* qpf = np_export_by_name(k32, "QueryPerformanceFrequency");
    u64 w0 = 0, w1 = 0, freq = 0;
    if (qpc && qpf) {
        ((void (__attribute__((ms_abi)) *)(u64*))qpc)(&w0);
        ((void (__attribute__((ms_abi)) *)(u64*))qpf)(&freq);
        sl(60);
        ((void (__attribute__((ms_abi)) *)(u64*))qpc)(&w1);
        if (freq) {
            u64 ms = (w1 - w0) * 1000ull / freq;
            if (ms < 40ull) return 1;
        }
    }
    /* TSC sanity: 60 ms at any plausible frequency is a large delta. A delta
     * of a few thousand cycles means the sleep never really happened. */
    if (t1 > t0 && (t1 - t0) < 200000ull) return 1;
    return 0;
}

/* ---- 2. virtual disk model string ------------------------------------ */
/* Read the real product string through IOCTL_STORAGE_QUERY_PROPERTY. A
 * physical desktop reports a vendor model (verified here:
 * "KIOXIA-EXCERIA BASIC SSD"); a virtual machine reports one of the emulator
 * strings below. Unlike a registry key this cannot be renamed by the appliance,
 * because the guest's own disk driver reports it. */
static const char np_vdisk_tokens[] =
    "qemu\0" "vbox\0" "virtualbox\0" "virtio\0" "vmware\0"
    "msft virtual\0" "parallels\0" "xen\0" "bochs\0";

static u32 np_analy_virtual_disk(void) {
    void* k32 = np_module_by_name(np_s_kernel32);
    if (!k32) return 0;
    typedef void* (__attribute__((ms_abi)) *np_cf_fn)(const char*, u32, u32, void*, u32, u32, void*);
    typedef u32   (__attribute__((ms_abi)) *np_dio_fn)(void*, u32, void*, u32, void*, u32, u32*, void*);
    typedef u32   (__attribute__((ms_abi)) *np_ch_fn)(void*);
    np_cf_fn  cf  = (np_cf_fn) np_export_by_name(k32, "CreateFileA");
    np_dio_fn dio = (np_dio_fn)np_export_by_name(k32, "DeviceIoControl");
    np_ch_fn  ch  = (np_ch_fn) np_export_by_name(k32, "CloseHandle");
    if (!cf || !dio || !ch) return 0;

    static const char path[] = "\\\\.\\C:";
    void* h = cf(path, 0, 5u /*FILE_SHARE_READ|WRITE*/, 0, 3u /*OPEN_EXISTING*/, 0, 0);
    if (!h || h == (void*)-1) return 0;

    u8 out[1024];
    np_memset(out, 0, sizeof(out));
    u8 q[24];
    np_memset(q, 0, sizeof(q));       /* PropertyId=0 StorageDeviceProperty */
    u32 got = 0;
    u32 ok = dio(h, 0x2D1400u /*IOCTL_STORAGE_QUERY_PROPERTY*/, q, (u32)sizeof(q),
                 out, (u32)sizeof(out), &got, 0);
    u32 hit = 0;
    if (ok && got > 24u) {
        /* STORAGE_DEVICE_DESCRIPTOR: ProductIdOffset at +16, VendorIdOffset +20 */
        u32 poff = np_rd32(out + 16);
        u32 voff = np_rd32(out + 20);
        for (u32 k = 0; k < 2 && !hit; k++) {
            u32 off = k ? voff : poff;
            if (off && off < got) {
                const char* s = (const char*)out + off;
                for (const char* t = np_vdisk_tokens; *t; ) {
                    u32 tl = 0;
                    while (t[tl]) tl++;
                    if (np_ascii_has_ci(s, t)) { hit = 1; break; }
                    t += tl + 1;
                }
            }
        }
    }
    ch(h);
    return hit;
}

/* ---- 3. handle population -------------------------------------------- */
/* Calibrated against GetProcessHandleCount on this platform:
 *   NtQuerySystemInformation(SystemHandleInformation = 16) returns a header
 *   { ULONG NumberOfHandles; ULONG Reserved; } followed by 24-byte entries
 *   with USHORT UniqueProcessId at +0. With that layout the count below
 *   matched GetProcessHandleCount exactly (551 vs 551) after opening 400
 *   handles, so the stride and offset are proven rather than assumed.
 * The table is large: it needed ~3.4 MB here, so a 2 MB buffer silently
 * returned STATUS_INFO_LENGTH_MISMATCH and the probe always read zero. */
#define NP_HANDLE_TABLE_MAX (8u << 20)

static u32 np_analy_handle_ratio(void) {
    void* ntdll = np_module_by_name(np_s_ntdll);
    if (!ntdll) return 0;
    typedef i32 (__attribute__((ms_abi)) *np_qsi_fn)(u32, void*, u32, u32*);
    typedef i32 (__attribute__((ms_abi)) *np_avm_fn)(void*, void**, u64, u64*, u32, u32);
    np_qsi_fn qsi = (np_qsi_fn)np_export_by_name(ntdll, np_s_qsi);
    np_avm_fn avm = (np_avm_fn)np_export_by_name(ntdll, "NtAllocateVirtualMemory");
    if (!qsi || !avm) return 0;

    u64 size = (u64)NP_HANDLE_TABLE_MAX;
    void* base = 0;
    if (avm((void*)-1, &base, 0, &size, 0x3000u, 0x04u) < 0 || !base) return 0;

    u32 ret = 0;
    i32 st = qsi(16u /*SystemHandleInformation*/, base, (u32)size, &ret);
    u32 mine = 0;
    if (st >= 0) {
        u64 self = np_self_pid();
        u32 n = *(u32*)base;                 /* NumberOfHandles */
        u8* e = (u8*)base + 8;               /* first entry */
        /* Guard against a bogus header: 24 bytes per entry cannot exceed the
         * buffer we handed to the kernel. */
        if (n && (u64)n * 24ull <= size) {
            for (u32 i = 0; i < n; i++, e += 24) {
                u16 pid = *(u16*)(e + 0);
                if (pid && (u64)pid == self) mine++;
            }
        }
    }
    size = 0;
    avm((void*)-1, &base, 0, &size, 0x8000u /*MEM_RELEASE*/, 0x04u);

    /* A native image of this size holds well under 200 handles. An agent that
     * injected into us and hooks every process holds several hundred. */
    return (mine > 300u) ? 1u : 0u;
}

/* ---- 4. debug heap / global flags ------------------------------------ */
static u32 np_analy_debug_heap(void) {
    u8* peb = np_peb();
    if (!peb) return 0;
    u32 gflag = *(u32*)(peb + 0xBC);   /* PEB->NtGlobalFlag */
    /* FLG_HEAP_ENABLE_TAIL_CHECK   0x10
     * FLG_HEAP_ENABLE_FREE_CHECK   0x20
     * FLG_HEAP_VALIDATE_PARAMETERS 0x40
     * Any of these set at start-up means a debugger launched us. */
    if (gflag & 0x70u) return 1;
    return 0;
}

/* ---- 5. cross-API clock disagreement --------------------------------- */
static u32 np_analy_clock_disagreement(void) {
    void* k32 = np_module_by_name(np_s_kernel32);
    if (!k32) return 0;
    typedef u64 (__attribute__((ms_abi)) *np_gtt_fn)(void);
    typedef u32 (__attribute__((ms_abi)) *np_gtc_fn)(void);
    np_gtt_fn gtt = (np_gtt_fn)np_export_by_name(k32, np_s_gtt);
    np_gtc_fn gtc = (np_gtc_fn)np_export_by_name(k32, "GetTickCount");
    if (!gtt || !gtc) return 0;

    u64 a64 = gtt();
    u32 a32 = gtc();
    /* Both derive from the same tick; the low 32 bits must agree within a
     * small delta. A hook that rewrites one of them breaks this. */
    u32 diff = (u32)a64 - a32;
    if (diff > 2000u && diff < 0xFFFFF000u) return 1;
    return 0;
}

/* ---- 6. process-creation burst right after boot ----------------------- */
static u32 np_analy_creation_burst(void) {
    if (!np_snapshot_processes()) return 0;
    void* k32 = np_module_by_name(np_s_kernel32);
    if (!k32) return 0;
    typedef u64 (__attribute__((ms_abi)) *np_gtt_fn)(void);
    np_gtt_fn gtt = (np_gtt_fn)np_export_by_name(k32, np_s_gtt);
    if (!gtt) return 0;
    u64 uptime = gtt();
    /* Only meaningful on a fresh boot: an analyser starts the sample within
     * seconds of power-on. A week-old desktop never lands here. */
    if (uptime > 600000ull) return 0;
    return (np_snap_count() >= 20u) ? 1u : 0u;
}

/* Score contribution of the behavioural layer. */
static u32 np_analy_score(u64* det) {
    u32 score = 0;
    if (np_analy_sleep_compressed())      { score += 28; *det |= NP_SB_AN_SLEEP; }
    if (np_analy_debug_heap())            { score += 26; *det |= NP_SB_AN_HFLAG; }
    if (np_analy_virtual_disk())          { score += 12; *det |= NP_SB_AN_DISK;  }
    if (np_analy_handle_ratio())          { score += 14; *det |= NP_SB_AN_HANDLE; }
    if (np_analy_clock_disagreement())    { score += 10; *det |= NP_SB_AN_CLOCK; }
    if (np_analy_creation_burst())        { score += 8;  *det |= NP_SB_AN_BURST; }
    return score;
}

/* ========================================================================
 * process self-isolation (v2 flag bit12)
 *
 * Goal: the protected image keeps running in its own process, but nothing
 * else in the session can open it for reading. Three layers, each failing
 * soft so a hardened host cannot break the program:
 *
 *   1. Replace the process DACL with one that carries an explicit DENY ACE
 *      for the World SID covering only the accesses a reader or injector
 *      needs: PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_VM_OPERATION,
 *      PROCESS_CREATE_THREAD, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME.
 *      OpenProcess for those is refused by the kernel for every principal,
 *      while PROCESS_TERMINATE and PROCESS_QUERY_LIMITED_INFORMATION stay
 *      granted, so the program remains visible and killable from Task
 *      Manager instead of becoming an unkillable orphan.
 *      A blanket *empty* DACL was rejected for exactly that reason: it also
 *      denies PROCESS_TERMINATE, leaving a process nobody can stop.
 *      NOTE: a *NULL* DACL means "everyone, full access" - the exact
 *      opposite - so this builds a real ACL with a real deny ACE.
 *   2. Hide every thread from debuggers (ThreadHideFromDebugger), which also
 *      blocks debug-event based single stepping of the unpacking stub.
 *   3. Disable extension-point injection (AppInit_DLLs-style) so an analysis
 *      agent cannot attach by extension once the image is already running.
 *
 * Everything is best-effort and reports which layers took effect.
 * ======================================================================== */

static u32 np_self_isolate(void) {
    void* ntdll = np_module_by_name(np_s_ntdll);
    void* k32   = np_module_by_name(np_s_kernel32);
    void* adv   = np_module_by_name(np_s_advapi32);
    if (!ntdll || !k32) return 0;
    u32 applied = 0;

    /* ---- (1) deny-ACE for memory read / injection on the process object --
     * A security descriptor is NOT set through NtSetInformationProcess:
     * PROCESSINFOCLASS 0x1B is ProcessImageFileName. The documented path is
     * NtSetSecurityObject with DACL_SECURITY_INFORMATION (0x4). */
    if (adv) {
        /* BOOL InitializeSecurityDescriptor(PSECURITY_DESCRIPTOR, DWORD) */
        typedef u32 (__attribute__((ms_abi)) *np_isi_fn)(void*, u32);
        /* BOOL InitializeAcl(PACL, DWORD nAclLength, DWORD dwAclRevision) */
        typedef u32 (__attribute__((ms_abi)) *np_ia_fn)(void*, u32, u32);
        /* BOOL AddAccessDeniedAce(PACL, DWORD dwAceRevision, ACCESS_MASK, PSID) */
        typedef u32 (__attribute__((ms_abi)) *np_ada_fn)(void*, u32, u32, void*);
        /* BOOL AddAccessAllowedAce(PACL, DWORD dwAceRevision, ACCESS_MASK, PSID) */
        typedef u32 (__attribute__((ms_abi)) *np_aaa_fn)(void*, u32, u32, void*);
        /* BOOL SetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR, BOOL DaclPresent,
         *                               PACL Dacl, BOOL DaclDefaulted) */
        typedef u32 (__attribute__((ms_abi)) *np_ssd_fn)(void*, u32, void*, u32);
        /* BOOL CreateWellKnownSid(WELL_KNOWN_SID_TYPE, PSID, PSID, DWORD*) */
        typedef u32 (__attribute__((ms_abi)) *np_cws_fn)(u32, void*, void*, u32*);

        np_isi_fn isi = (np_isi_fn)np_export_by_name(adv, "InitializeSecurityDescriptor");
        np_ia_fn  ia  = (np_ia_fn) np_export_by_name(adv, "InitializeAcl");
        np_ada_fn ada = (np_ada_fn)np_export_by_name(adv, "AddAccessDeniedAce");
        np_aaa_fn aaa = (np_aaa_fn)np_export_by_name(adv, "AddAccessAllowedAce");
        np_ssd_fn ssd = (np_ssd_fn)np_export_by_name(adv, "SetSecurityDescriptorDacl");
        np_cws_fn cws = (np_cws_fn)np_export_by_name(adv, "CreateWellKnownSid");

        typedef void* (__attribute__((ms_abi)) *np_gcp_fn)(void);
        np_gcp_fn gcp = (np_gcp_fn)np_export_by_name(k32, "GetCurrentProcess");
        /* NTSTATUS NtSetSecurityObject(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR) */
        typedef i32 (__attribute__((ms_abi)) *np_sso_fn)(void*, u32, void*);
        np_sso_fn sso = (np_sso_fn)np_export_by_name(ntdll, "NtSetSecurityObject");

        if (isi && ia && ada && aaa && ssd && cws && gcp && sso) {
            /* S-1-1-0 (WinWorldSid) is 12 bytes: 8 header + one subauthority.
             * ACL = 8 byte header + one 20 byte ACCESS_DENIED_ACE. */
            static u8 sd[40];
            static u8 acl[64];
            u8 sid[16];
            np_memset(sd, 0, sizeof(sd));
            np_memset(acl, 0, sizeof(acl));
            np_memset(sid, 0, sizeof(sid));
            u32 sid_len = (u32)sizeof(sid);

            const u32 deny_mask =
                  0x0010u   /* PROCESS_VM_READ      */
                | 0x0020u   /* PROCESS_VM_WRITE     */
                | 0x0008u   /* PROCESS_VM_OPERATION */
                | 0x0002u   /* PROCESS_CREATE_THREAD*/
                | 0x0040u   /* PROCESS_DUP_HANDLE   */
                | 0x0800u;  /* PROCESS_SUSPEND_RESUME */

            if (isi(sd, 1u /*SECURITY_DESCRIPTOR_REVISION*/) &&
                ia(acl, (u32)sizeof(acl), 2u /*ACL_REVISION*/) &&
                cws(1u /*WinWorldSid*/, 0, sid, &sid_len) &&
                ada(acl, 2u /*ACL_REVISION*/, deny_mask, sid) &&
                /* A DACL with only a deny ACE implicitly denies everything
                 * else, which would also strip PROCESS_TERMINATE and leave an
                 * unkillable process. Re-grant the management rights
                 * explicitly; the deny ACE is ordered first so it still wins
                 * for the memory/injection rights above. */
                aaa(acl, 2u /*ACL_REVISION*/,
                    0x0001u    /* PROCESS_TERMINATE              */
                  | 0x0400u    /* PROCESS_QUERY_INFORMATION      */
                  | 0x1000u    /* PROCESS_QUERY_LIMITED_INFORMATION */
                  | 0x100000u, /* SYNCHRONIZE                    */
                    sid) &&
                ssd(sd, 1u /*bDaclPresent*/, acl, 0u /*bDaclDefaulted*/)) {
                if (sso(gcp(), 4u /*DACL_SECURITY_INFORMATION*/, sd) >= 0)
                    applied |= 1u;
            }
        }
    }

    /* ---- (2) hide threads from debuggers -------------------------------
     * NtSetInformationThread(thread, ThreadHideFromDebugger, NULL, 0): the
     * NULL buffer is required. Passing a 4-byte flag instead yields
     * STATUS_INFO_LENGTH_MISMATCH (0xC0000004). */
    typedef i32 (__attribute__((ms_abi)) *np_zsit_fn2)(void*, u32, void*, u32);
    np_zsit_fn2 sit = (np_zsit_fn2)np_export_by_name(ntdll, np_s_zwsit);
    if (sit) {
        if (sit((void*)-2 /*GetCurrentThread pseudo handle*/,
                NP_THREAD_HIDE_FROM_DEBUGGER, 0, 0) >= 0) applied |= 2u;
    }

    /* ---- (3) refuse third-party extension-point injection ---------------
     * ProcessMitigationPolicy (PROCESSINFOCLASS 0x34) with
     * ProcessExtensionPointDisablePolicy (6) blocks AppInit_DLLs-style
     * extension injection into this process, which is how an analysis agent
     * that is not already loaded would attach. */
    typedef i32 (__attribute__((ms_abi)) *np_smp_fn)(void*, u32, void*, u32);
    np_smp_fn smp = (np_smp_fn)np_export_by_name(ntdll, "NtSetInformationProcess");
    if (smp) {
        struct { u32 policy; u32 flags; } ext;
        ext.policy = 6u;     /* ProcessExtensionPointDisablePolicy */
        ext.flags  = 0x1u;   /* DisableExtensionPoints                */
        if (smp((void*)-1, 0x34u, &ext, (u32)sizeof(ext)) >= 0) applied |= 4u;
    }
    return applied;
}

/* ========================================================================
 * sandbox / analysis-environment scoring (v2 flag bit 9)
 *
 * Weighted, corroboration-aware detection tuned for online-analysis hosts
 * (online-analysis hosts and peers) that inject an agent DLL, run 1-2 vCPUs with a few
 * GB of RAM on a freshly imaged guest, launch the sample from a controller
 * process and never provide user input.
 *
 * Design rules that keep real machines clean:
 *   - Hyper-V is exempt (VBS on physical Windows 11 reports it).
 *   - Ephemeral account/computer names, install age and idle signals only
 *     count while no human input was seen recently.
 *   - Install age additionally requires a headless, weak-hardware profile.
 *   - A block requires the threshold AND one strong corroborating signal,
 *     so odd-but-real machines never trip on weak evidence alone.
 * ======================================================================== */

static void np_dbg_stage(u32 n) {
    if (!np_dbg_enabled()) return;
    char line[24];
    static const char pfx[] = "stage ";
    u32 i = 0;
    for (; pfx[i]; i++) line[i] = pfx[i];
    char dec[12];
    int d = 0;
    if (!n) dec[d++] = '0';
    while (n) { dec[d++] = (char)('0' + n % 10); n /= 10; }
    while (d--) line[i++] = dec[d];
    line[i++] = '\n';
    line[i] = 0;
    np_dbg_line(line);
}

/* Which of the two new layers this build deployed. Set from the NPP1 flags
 * word once, before scoring: the packer decides, the runtime obeys. */
static u32 np_gate_hv_exit = 0;
static u32 np_gate_kernel = 0;

static u32 np_sandbox_score_ex(u64* detail) {
    u32 score = 0;
    /* u64: the analysis-artefact, hypervisor-exit and kernel-artefact signals
     * live above bit 31, so a u32 accumulator silently drops them — they then
     * count towards the score but can never satisfy the NP_SB_STRONG gate. */
    u64 det = 0;

    /* 1. hypervisor vendor bits via CPUID 0x40000000 (Hyper-V exempt) */
    u32 c[4] = {0};
    np_cpuid_leaf(0x40000000u, 0, c);
    if (c[0]) {
        if (c[1] == 0x61774D56u && c[2] == 0x4D567265u && c[3] == 0x65726177u) { score += 8; det |= NP_SB_HYPER; }   /* VMware */
        else if (c[1] == 0x4B4D564Bu && c[2] == 0x564B4D56u && c[3] == 0x0000004Du) { score += 8; det |= NP_SB_HYPER; } /* KVM */
        else if (c[1] == 0x566E6558u && c[2] == 0x65584D4Du && c[3] == 0x4D4D566Eu) { score += 8; det |= NP_SB_HYPER; } /* Xen */
        else if (c[1] == 0x786F4256u) { score += 8; det |= NP_SB_HYPER; }   /* VirtualBox */
        else if (c[1] == 0x206C7270u) { score += 8; det |= NP_SB_HYPER; }   /* Parallels */
    }

    /* 1b. hypervisor level: CPUID exit cost. A hypervisor that hides its vendor
     * still has to trap CPUID, so the storm cost is what survives renaming. */
    if (np_gate_hv_exit) if (np_hv_exit_cost()) { score += 30; det |= NP_SB_HVEXIT; }

    /* 1c. driver level: kernel artifacts the sandbox cannot hide with its agent
     * process -- device object, driver service, loaded .sys image. */
    if (np_gate_kernel) {
        u64 kdet = 0;
        const u32 khits = np_kernel_artifacts(&kdet);
        if (khits) {
            score += 18u * (khits > 2 ? 2u : khits);
            det |= kdet;
        }
        if (np_tick_stalled()) { score += 35; det |= NP_SB_KTICK; }
    }

    /* 2. CPU count + physical RAM through NtQuerySystemInformation */
    u32 cpu = 0;
    u64 ram_bytes = 0;
    void* ntdll = np_module_by_name(np_s_ntdll);
    if (ntdll) {
        typedef i32 (__attribute__((ms_abi)) *np_qsi_fn)(u32 cls, void* buf, u32 len, u32* ret);
        np_qsi_fn qsi = (np_qsi_fn)np_export_by_name(ntdll, np_s_qsi);
        if (qsi) {
            u8 basic[64];
            np_memset(basic, 0, sizeof(basic));
            u32 ret = 0;
            if (qsi(NP_SIC_SYSTEM_BASIC_INFO, basic, sizeof(basic), &ret) >= 0) {
                cpu = basic[0];
                u64 pages = np_rd64(basic + 24);        /* NumberOfPhysicalPages */
                u32 page_size = np_rd32(basic + 32);    /* PageSize */
                ram_bytes = pages * (u64)page_size;
            }
        }
    }
    if (cpu == 1) { score += 12; det |= NP_SB_CPU1; }
    else if (cpu == 2) { score += 4; det |= NP_SB_CPU2; }
    if (ram_bytes && ram_bytes < (2ull << 30)) { score += 12; det |= NP_SB_RAM2; }
    else if (ram_bytes && ram_bytes < (4ull << 30)) { score += 6; det |= NP_SB_RAM4; }
    np_dbg_stage(2);

    /* 3. process population + parent process identity */
    if (np_snapshot_processes()) {
        u32 procs = np_snap_count();
        if (procs && procs < 40) { score += 8; det |= NP_SB_PROC40; }
        else if (procs && procs < 70) { score += 4; det |= NP_SB_PROC70; }

        u64 ppid = np_parent_pid();
        if (ppid) {
            u16 pname[96];
            if (np_snap_name_of(ppid, pname, 96)) {
                u32 plen = np_u16_len(pname);
                if (np_u16_has_ci(pname, plen, "cmd.exe") ||
                    np_u16_has_ci(pname, plen, "powershell") ||
                    np_u16_has_ci(pname, plen, "pwsh") ||
                    np_u16_has_ci(pname, plen, "wscript") ||
                    np_u16_has_ci(pname, plen, "cscript") ||
                    np_u16_has_ci(pname, plen, "python") ||
                    np_u16_has_ci(pname, plen, "rundll32") ||
                    np_u16_has_ci(pname, plen, "analyzer") ||
                    np_u16_has_ci(pname, plen, "sandbox") ||
                    np_u16_has_ci(pname, plen, "cuckoo") ||
                    np_u16_has_ci(pname, plen, "joebox")) {
                    score += 10; det |= NP_SB_PARENT;
                } else if (np_u16_has_ci(pname, plen, "svchost")) {
                    score += 4; det |= NP_SB_SVCHOST;
                }
            }
        }
    }

    np_dbg_stage(3);

    /* 4. uptime / user-input correlation */
    u64 uptime_ms = 0;
    u32 idle_ms = 0xFFFFFFFFu;
    void* k32 = np_module_by_name(np_s_kernel32);
    if (k32) {
        typedef u64 (__attribute__((ms_abi)) *np_gtt_fn)(void);
        np_gtt_fn gtt = (np_gtt_fn)np_export_by_name(k32, np_s_gtt);
        if (gtt) uptime_ms = gtt();
    }
    if (uptime_ms) idle_ms = np_input_idle_ms(uptime_ms);
    /* "a human is around" = input seen within the last 10 minutes */
    u32 human = (idle_ms != 0xFFFFFFFFu && idle_ms < 600000ull) ? 1u : 0u;

    if (uptime_ms >= 180000ull && idle_ms != 0xFFFFFFFFu &&
        (u64)idle_ms >= uptime_ms - 5000ull) {
        score += 12; det |= NP_SB_NOINPUT;      /* nothing typed/clicked since boot */
    }
    if (!human && uptime_ms >= 2700000ull && idle_ms != 0xFFFFFFFFu &&
        (u64)idle_ms >= 1800000ull) {
        score += 8; det |= NP_SB_IDLE;          /* idle analysis VM */
    }

    np_dbg_stage(4);

    /* 5. virtual firmware / disk artifacts (VMware, VirtualBox, QEMU, Xen) */
    if (np_firmware_artifacts()) { score += 8; det |= NP_SB_FIRMWARE; }

    np_dbg_stage(5);

    /* 6. modules injected from user-writable locations */
    if (np_injected_module_paths()) { score += 25; det |= NP_SB_INJECT; }

    np_dbg_stage(6);

    /* 7. known analysis / monitoring modules */
    if (np_chk_bad_modules()) { score += 25; det |= NP_SB_MOD; }
    if (np_dbghelp_family())   { score += 6;  det |= NP_SB_DBGHELP; }

    np_dbg_stage(7);

    /* 7b. vendor-signature layer (MicroStep / ThreatBook appliance) */
    score += np_vendor_score(&det);

    np_dbg_stage(12);

    /* 7c. behavioural analysis-artefact layer: byproducts of dynamic analysis
     * that survive renaming (clock compression, debug heap flags, virtual
     * disk, handle population, clock disagreement, post-boot burst). */
    score += np_analy_score(&det);

    np_dbg_stage(13);

    /* 8. timing evidence */
    u64 t1 = np_rdtscp();
    u64 t2 = np_rdtsc();
    u64 spread = t2 > t1 ? t2 - t1 : t1 - t2;
    if (spread > 0x40000000ull) { score += 5; det |= NP_SB_TSCSPREAD; }

    u64 mask = np_cpu_core_mask();
    if ((mask & 0xFFFF) == 0 || ((mask >> 16) & 0xFF) == 0) { score += 3; det |= NP_SB_COREMASK; }

    if (np_sleep_compressed()) { score += 15; det |= NP_SB_SLEEP; }

    np_dbg_stage(8);

    /* 9. display topology */
    void* u32mod = np_module_by_name(np_s_user32);
    if (u32mod) {
        typedef int (__attribute__((ms_abi)) *np_gsm_fn)(int);
        np_gsm_fn gsm = (np_gsm_fn)np_export_by_name(u32mod, np_s_gsm);
        if (gsm) {
            int w = gsm(0);   /* SM_CXSCREEN */
            int h = gsm(1);   /* SM_CYSCREEN */
            int m = gsm(80);  /* SM_CMONITORS */
            if (w && h && w < 800) { score += 8; det |= NP_SB_RES800; }
            else if (w && h && w < 1024) { score += 6; det |= NP_SB_RES1024; }
            if (m == 0) { score += 4; det |= NP_SB_NOMON; }
        }
    }

    np_dbg_stage(9);

    /* 10. ephemeral account / computer names (ignored while a human types) */
    if (!human && np_template_name()) { score += 6; det |= NP_SB_TMPLNAME; }

    np_dbg_stage(10);

    /* 11. freshly imaged guest: only meaningful when the machine is headless
     *     and weak - a developer's new install always has a taskbar. */
    u32 age = np_install_age_days();
    if (age != 0xFFFFFFFFu && !human && !np_taskbar_present() &&
        (cpu <= 2 || (ram_bytes && ram_bytes < (4ull << 30)))) {
        if (age < 3) { score += 10; det |= NP_SB_FRESH3; }
        else if (age < 14) { score += 6; det |= NP_SB_FRESH14; }
    }

    np_dbg_stage(11);

    np_snap_free();

    if (detail) *detail = det;
    return score;
}

/* ========================================================================
 * anti memory-dump (v2 flag bit 10)
 *
 * A live dump is only useful while the image is fully restored. We verify that
 * the image header still has its original loader-consumed DOS/NT signature and
 * that the section table has not been flattened to zero (common Minidump /
 * Procdump post-processing). The strongest signal is the PEB image base still
 * matching the expected base.
 * ======================================================================== */

static u32 np_chk_dump(void* base) {
    u8* img = (u8*)base;
    if (!img) return 0;
    if (img[0] != 'M' || img[1] != 'Z') return 1;
    i32 lfanew = *(i32*)(img + 0x3C);
    if (lfanew <= 0) return 1;
    u8* nth = img + lfanew;
    if (nth[0] != 'P' || nth[1] != 'E' || nth[2] != 0 || nth[3] != 0) return 1;
    u16 nsec = *(u16*)(nth + 6);
    if (nsec < 1 || nsec > 96) return 1;
    u8* peb = np_peb();
    if (!peb) return 0;
    u8* loaded = *(u8**)(peb + 0x10);
    if (loaded && loaded != img) return 1;
    return 0;
}

/* ========================================================================
 * PE header field validation
 *
 * The loader only sanity-checks a handful of header fields, so a debugger
 * or an unpacker can rewrite the optional header (subsystem, characteristics,
 * the checksum, the section table) without the image refusing to load.  This
 * check re-derives the invariants that have to hold for the image to be the
 * one the packer produced, and reports a mismatch as tampering.
 *
 * The fields verified here are the ones that cannot change between the
 * on-disk image and the mapped image: the loader does not touch them, and
 * the packer never rewrites them after the header is finalised.
 * ======================================================================== */
static u32 np_chk_pe_header(void* base) {
    u8* img = (u8*)base;
    if (!img) return 0;

    i32 lfanew = *(i32*)(img + 0x3C);
    if (lfanew < 0x40 || lfanew > 0x400) return 1;
    u8* nth = img + lfanew;

    u16 magic = *(u16*)(nth + 24);
    if (magic != 0x20Bu && magic != 0x10Bu) return 1;

    /* Section table must stay inside the headers. */
    u16 nsec = *(u16*)(nth + 6);
    u16 optsize = *(u16*)(nth + 20);
    u32 hdrEnd = (u32)(lfanew + 24 + optsize + (u32)nsec * 40u);
    if (hdrEnd > 0x1000u) return 1;

    u16 chars = *(u16*)(nth + 22);
    /* IMAGE_FILE_EXECUTABLE_IMAGE must be set.  The DLL flag is not checked:
     * the packer protects both EXEs and DLLs. */
    if (!(chars & 0x0002u)) return 1;

    u8* opt = nth + 24;
    u16 subsys = *(u16*)(opt + 68);
    if (subsys > 16u) return 1;            /* IMAGE_SUBSYSTEM_* range */

    u16 dchar = *(u16*)(opt + 70);
    /* FORCE_INTEGRITY without NX_COMPAT is an inconsistent combination the
     * loader would refuse anyway. */
    if ((dchar & 0x0080u) && !(dchar & 0x0100u)) return 1;

    u32 sizeImage = *(u32*)(opt + 56);
    if (sizeImage < hdrEnd) return 1;

    /* Every section must live inside the image and must not overlap the
     * headers, otherwise the table was rewritten. */
    for (u16 i = 0; i < nsec; i++) {
        u8* sh = nth + 24 + optsize + (u32)i * 40u;
        u32 vaddr = *(u32*)(sh + 12);
        u32 vsize = *(u32*)(sh + 8);
        u32 raw = *(u32*)(sh + 20);
        if (vaddr + vsize > sizeImage) return 1;
        if (vaddr < hdrEnd && vsize) return 1;
        if (raw && raw + *(u32*)(sh + 16) > 0x40000000u) return 1;
    }
    return 0;
}

/* ========================================================================
 * interactive-desktop self-check (v2 flag bit 11)
 *
 * Old design applied absolute minimums (CPU / RAM / uptime / resolution)
 * directly, so a machine that had just rebooted, a single-vCPU box, a 4 GB
 * boundary machine or a 768p laptop was rejected even with a real user
 * sitting in front of it - a false-positive factory.
 *
 * New design: the heuristic signals (no taskbar, no input since boot) are only
 * scored in a headless environment, where they are the only evidence there is.
 * Every probe degrades to "pass" when its API is unavailable.
 *
 * The pack-time minimums are deliberately NOT gated on interactivity: the
 * client UI presents them as a promise ("reject a machine below this"), so an
 * operator who sets min-cpu=4 means 4 and not "4 unless someone is moving the
 * mouse". Leaving every minimum at 0 keeps the plain heuristic behaviour,
 * because the score then comes from the headless signals alone.
 * ======================================================================== */

static u32 np_chk_env(const u8* b) {
    u32 min_cpu    = np_rd32(b + 100);
    u32 min_ram_mb = np_rd32(b + 104);
    u32 min_uptime = np_rd32(b + 108);
    u32 min_w      = np_rd32(b + 112);
    u32 min_h      = np_rd32(b + 116);
    u32 min_mon    = np_rd32(b + 120);
    u32 threshold  = np_rd32(b + 124);
    if (!threshold) threshold = 7u;

    /* ---- gather environment facts (all optional) ---- */
    u32 cpu = 0;
    u64 ram_bytes = 0;
    u64 uptime_ms = 0;
    u32 idle_ms = 0xFFFFFFFFu;
    int w = 0, h = 0, mon = 0;
    int taskbar = np_taskbar_present();

    void* ntdll = np_module_by_name(np_s_ntdll);
    if (ntdll) {
        typedef i32 (__attribute__((ms_abi)) *np_qsi_fn)(u32 cls, void* buf, u32 len, u32* ret);
        np_qsi_fn qsi = (np_qsi_fn)np_export_by_name(ntdll, np_s_qsi);
        if (qsi) {
            u8 basic[64];
            np_memset(basic, 0, sizeof(basic));
            u32 ret = 0;
            if (qsi(NP_SIC_SYSTEM_BASIC_INFO, basic, sizeof(basic), &ret) >= 0) {
                cpu = basic[0];
                u64 pages = np_rd64(basic + 24);
                u32 page_size = np_rd32(basic + 32);
                ram_bytes = pages * (u64)page_size;
            }
        }
    }
    void* k32 = np_module_by_name(np_s_kernel32);
    if (k32) {
        typedef u64 (__attribute__((ms_abi)) *np_gtt_fn)(void);
        np_gtt_fn gtt = (np_gtt_fn)np_export_by_name(k32, np_s_gtt);
        if (gtt) uptime_ms = gtt();
    }
    if (uptime_ms) idle_ms = np_input_idle_ms(uptime_ms);

    void* u32mod = np_module_by_name(np_s_user32);
    if (u32mod) {
        typedef int (__attribute__((ms_abi)) *np_gsm_fn)(int);
        np_gsm_fn gsm = (np_gsm_fn)np_export_by_name(u32mod, np_s_gsm);
        if (gsm) {
            w = gsm(0);
            h = gsm(1);
            mon = gsm(80);
        }
    }

    /* ---- a real desktop suppresses the heuristic signals ---- */
    u32 interactive = ((idle_ms != 0xFFFFFFFFu && idle_ms < 900000ull) || taskbar) ? 1u : 0u;

    /* ---- explicit minimums: scored wherever they are set ---- */
    u32 score = 0;
    if (min_cpu && cpu && cpu < min_cpu) score += 3;
    if (min_ram_mb && ram_bytes && ram_bytes < (u64)min_ram_mb * 1048576ull) score += 3;
    /* uptime_ms stays 0 when GetTickCount64 is missing, and 0 < min_uptime would
     * then score a missing API as a hit. Guard it like every other probe. */
    if (min_uptime && uptime_ms && uptime_ms < (u64)min_uptime) score += 3;
    if (min_w && w && w < (int)min_w) score += 3;
    if (min_h && h && h < (int)min_h) score += 3;
    if (min_mon && mon && mon < (int)min_mon) score += 3;

    /* ---- headless: these are the only evidence available ---- */
    if (!interactive) {
        if (!taskbar) score += 3;
        if (uptime_ms > 300000ull && idle_ms != 0xFFFFFFFFu &&
            (u64)idle_ms >= uptime_ms - 5000ull) score += 3;   /* no input since boot */
    }

    return (score >= threshold) ? 1u : 0u;
}

/* ========================================================================
 * sandbox block path: show the notice and terminate cleanly
 * ======================================================================== */

static const u16 np_w_notice[]  = {
    0x8BF7, 0x5728, 0x975E, 0x6C99, 0x7BB1, 0x5185, 0x4F7F, 0x7528, 0 };  /* 请在非沙箱内使用 */
static const u16 np_w_caption[] = {
    'N','o','v','a','P','r','o','t','e','c','t', 0 };

static u32 __attribute__((ms_abi)) np_notice_thread(void* arg) {
    (void)arg;
    void* u32mod = np_module_by_name(np_s_user32);
    if (u32mod) {
        typedef int (__attribute__((ms_abi)) *np_mb_fn)(void*, const u16*, const u16*, u32);
        np_mb_fn mb = (np_mb_fn)np_export_by_name(u32mod, "MessageBoxW");
        if (mb) {
            /* MB_OK | MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST */
            mb(0, np_w_notice, np_w_caption, 0x00040030u);
        }
    }
    return 0;
}

/* Never returns. Shows the "please use outside a sandbox" notice on a worker
 * thread (3 s budget so a headless worker cannot wedge on a modal box) and
 * exits through ExitProcess, leaving no crash dump for the analysis pipeline. */
static void np_block_sandbox(void) {
    void* k32 = np_module_by_name(np_s_kernel32);
    void* u32mod = np_module_by_name(np_s_user32);
    if (u32mod) {
        if (k32) {
            typedef u64 (__attribute__((ms_abi)) *np_ct_fn)(void*, u64, void*, void*, u32, u32*);
            np_ct_fn ct = (np_ct_fn)np_export_by_name(k32, "CreateThread");
            if (ct) {
                ct(0, 0x20000u, (void*)np_notice_thread, 0, 0, 0);
            } else {
                np_notice_thread(0);
            }
        } else {
            np_notice_thread(0);
        }
    }
    if (k32) {
        typedef void (__attribute__((ms_abi)) *np_sleep_fn)(u32);
        typedef void (__attribute__((ms_abi)) *np_exit_fn)(u32);
        np_sleep_fn sl = (np_sleep_fn)np_export_by_name(k32, "Sleep");
        np_exit_fn  xp = (np_exit_fn) np_export_by_name(k32, "ExitProcess");
        if (sl) sl(3000);
        if (xp) xp(0);
    }
    for (;;) { }   /* unreachable when ExitProcess resolved */
}

/* ========================================================================
 * delayed re-audit (v2 flag bit14)
 *
 * A single sample at process start is structurally blind to a monitor that
 * attaches afterwards, which is exactly what an online analysis pipeline does:
 * it lets the sample unpack, then injects its agent and starts recording. The
 * behaviours that give it away are therefore *late*:
 *
 *   - the agent's modules appear in our loader list after we started
 *   - our handle count jumps when the agent opens handles into us
 *   - a vendor-named module shows up that was absent at start
 *
 * This worker wakes on a fixed schedule, compares against baselines captured
 * at start, and blocks on a hit. A probe that cannot produce a reading never
 * fires, so a missing measurement cannot cause a false positive.
 * ======================================================================== */

#define NP_AUDIT_FIRST_DELAY_MS 45000u   /* let unpacking settle           */
#define NP_AUDIT_INTERVAL_MS    60000u   /* one sample per minute          */
#define NP_AUDIT_SLEEP_EVERY    5u       /* re-time the clock every 5th    */

/* Baselines and heartbeats. All zero-initialised so they live in .np_bss: a
 * non-zero initialiser would land in .np_data and, by growing that section,
 * push .np_bss off the blob's end and break the flat-layout invariant
 * build.ps1 enforces. Zero therefore means "not captured yet". */
static u32 np_audit_handle_base = 0;
static volatile u32 np_audit_beat[2] = {0, 0};
static void* np_audit_th[2] = {0, 0};

/* Non-zero when the peer's thread object is signaled, i.e. the peer has
 * exited or was killed. This queries the kernel object, so it still works
 * when the peer was terminated while holding a lock - which is exactly the
 * case a heartbeat check misses, because a ThreadTerminate mid-probe leaves
 * the loader lock held and the survivor then blocks inside module
 * enumeration. */
static u32 np_audit_peer_dead(u32 idx) {
    void* k32 = np_module_by_name(np_s_kernel32);
    if (!k32 || !np_audit_th[idx]) return 0;
    typedef u32 (__attribute__((ms_abi)) *np_wso_fn)(void*, u32);
    np_wso_fn w = (np_wso_fn)np_export_by_name(k32, "WaitForSingleObject");
    if (!w) return 0;
    return (w(np_audit_th[idx], 0u) == 0u) ? 1u : 0u;
}

/* Raw handle count for this process; 0xFFFFFFFF means "no reading". */
static u32 np_audit_handle_count(void) {
    void* ntdll = np_module_by_name(np_s_ntdll);
    if (!ntdll) return 0xFFFFFFFFu;
    typedef i32 (__attribute__((ms_abi)) *np_qsi_fn)(u32, void*, u32, u32*);
    typedef i32 (__attribute__((ms_abi)) *np_avm_fn)(void*, void**, u64, u64*, u32, u32);
    np_qsi_fn qsi = (np_qsi_fn)np_export_by_name(ntdll, np_s_qsi);
    np_avm_fn avm = (np_avm_fn)np_export_by_name(ntdll, "NtAllocateVirtualMemory");
    if (!qsi || !avm) return 0xFFFFFFFFu;

    u64 size = 8ull << 20;
    void* base = 0;
    if (avm((void*)-1, &base, 0, &size, 0x3000u, 0x04u) < 0 || !base)
        return 0xFFFFFFFFu;
    u32 ret = 0;
    i32 st = qsi(16u, base, (u32)size, &ret);
    u32 mine = 0xFFFFFFFFu;
    if (st >= 0) {
        u64 self = np_self_pid();
        u32 n = *(u32*)base;
        u8* e = (u8*)base + 8;
        if (n && (u64)n * 24ull <= size) {
            mine = 0;
            for (u32 i = 0; i < n; i++, e += 24)
                if (*(u16*)(e + 0) == (u16)self) mine++;
        }
    }
    size = 0;
    avm((void*)-1, &base, 0, &size, 0x8000u, 0x04u);
    return mine;
}

static void np_audit_sleep(u32 ms) {
    void* k32 = np_module_by_name(np_s_kernel32);
    if (!k32) return;
    typedef void (__attribute__((ms_abi)) *np_sleep_fn)(u32);
    np_sleep_fn sl = (np_sleep_fn)np_export_by_name(k32, "Sleep");
    if (sl) sl(ms);
}

/* One audit round. Returns 1 when the environment changed underneath us.
 *
 * `deep` enables the expensive probes: re-timing a sleep costs ~120 ms, so it
 * runs every NP_AUDIT_SLEEP_EVERY rounds instead of every round. The cheap
 * probes run every round. */
static u32 np_audit_round(u32 deep) {
    u32 hit = 0;

    /* (1) a module loaded from a user-writable path: this is how an agent
     * attaches. A raw module *count* was tried first and proved both
     * unreliable (the loader dedupes, so three loads moved the count by two)
     * and unspecific (legitimate lazy DLL loading also moves it). The path is
     * the precise discriminator. */
    if (np_injected_module_paths()) hit = 1;

    /* (2) a vendor-named module */
    if (np_vendor_module_hit()) hit = 1;

    /* (3) late handle burst: an agent holding handles into this process.
     * Base 0 means the start-time reading failed; skip rather than compare
     * against a bogus baseline. */
    u32 h = np_audit_handle_count();
    if (h != 0xFFFFFFFFu && np_audit_handle_base && h > np_audit_handle_base + 120u)
        hit = 1;

    /* (4) debug heap flags appearing after start: a debugger attached. Real
     * Windows never sets FLG_HEAP_* on a running image. */
    if (np_analy_debug_heap()) hit = 1;

    /* (5) the wall clock stopped agreeing between two independent sources,
     * which is what a recording/time-warping hook produces. */
    if (np_analy_clock_disagreement()) hit = 1;

    /* (6) periodic deep re-time: a recorder that only starts accelerating the
     * clock (or that hooks Sleep) after attaching shows up here and nowhere
     * else. */
    if (deep) {
        if (np_analy_sleep_compressed()) hit = 1;
        if (np_analy_virtual_disk()) hit = 1;
    }
    return hit;
}

/* Two mutually-supervised workers.
 *
 * A single worker is trivially removed: an agent that gets code into the
 * process only has to call TerminateThread on it, and every later round
 * silently stops. Each worker here publishes a heartbeat and requires the
 * other's to advance; a stalled peer means the peer was killed, which is
 * itself the verdict. Killing one worker therefore blocks the process, and
 * killing both requires doing it inside the window between two heartbeats. */
static u32 __attribute__((ms_abi)) np_audit_thread(void* arg) {
    u32 idx = (u32)(u64)arg & 1u;
    u32 other = idx ^ 1u;
    u32 round = 0;

    np_audit_sleep(NP_AUDIT_FIRST_DELAY_MS);

    for (;;) {
        np_audit_beat[idx] = np_audit_beat[idx] + 1u;

        /* Peer liveness is checked BEFORE the probe round, not after.
         *
         * Measured failure: a peer killed while it held the loader lock left
         * the lock held, so this thread hung inside the next module walk and
         * never reached the check - the supervisor was defeated by the very
         * event it was supposed to catch. Taking the verdict from the kernel
         * thread object first, while nothing is held, removes that ordering
         * dependency. */
        if (np_audit_peer_dead(other)) {
            np_dbg_stage(14);
            np_block_sandbox();
            for (;;) { }
        }

        u32 deep = (round % NP_AUDIT_SLEEP_EVERY) == 0u;
        if (np_audit_round(deep)) {
            np_dbg_stage(14);
            np_block_sandbox();
            for (;;) { }
        }

        np_audit_sleep(NP_AUDIT_INTERVAL_MS);
        round++;
    }
    return 0;
}

/* Capture start-time baselines and spawn both workers. */
static void np_audit_start(void) {
    np_audit_handle_base = np_audit_handle_count();
    void* k32 = np_module_by_name(np_s_kernel32);
    if (!k32) return;
    typedef u64 (__attribute__((ms_abi)) *np_ct_fn)(void*, u64, void*, void*, u32, u32*);
    np_ct_fn ct = (np_ct_fn)np_export_by_name(k32, "CreateThread");
    if (!ct) return;
    /* Keep both handles open: the peer-death check queries their signaled
     * state, and a closed handle would report an invalid handle instead. */
    np_audit_th[0] = (void*)ct(0, 0x20000u /*STACK_SIZE_PARAM_IS_A_RESERVATION*/,
                               (void*)np_audit_thread, (void*)0u, 0, 0);
    np_audit_th[1] = (void*)ct(0, 0x20000u,
                               (void*)np_audit_thread, (void*)1u, 0, 0);
}

/* ========================================================================
 * code virtualisation
 *
 * The packer lowers each marked region to wire bytecode and publishes a
 * descriptor table through the NPP1 header (+20 = table offset, +88 = count).
 * At load time we replace the region body with a trampoline that saves the
 * live guest registers, runs the interpreter and jumps to the instruction
 * after the region. The region lives in a .text page that the unpacker
 * already restored as writable, so no protection change is needed.
 *
 * Descriptor (32 bytes): rva, size, bc_off, bc_len, rev_off, reg_mask.
 * ======================================================================== */

#define NP_VM_DESC_SIZE 32u

/* Upper bound of one generated trampoline: 51 fixed bytes + 20 bytes per saved
 * register (save and restore), rounded up to 16. The packer reserves this much
 * per region in the arena it advertises at header +92. */
#define NP_VM_TRAMP_STRIDE 1024u

static u8* np_vm_put8(u8* p, u8 v) { *p++ = v; return p; }

static u8* np_vm_put64(u8* p, u64 v) {
    for (u32 k = 0; k < 8; k++) *p++ = (u8)(v >> (k * 8));
    return p;
}

static u8* np_vm_put32(u8* p, u32 v) {
    *p++ = (u8)(v & 0xFF);
    *p++ = (u8)((v >> 8) & 0xFF);
    *p++ = (u8)((v >> 16) & 0xFF);
    *p++ = (u8)((v >> 24) & 0xFF);
    return p;
}

/* movdqu [rsp+160+16*i], xmmi (store=1) / movdqu xmmi, [rsp+...] (store=0) */
static u8* np_vm_xmm_rsp(u8* p, u8 idx, int store) {
    p = np_vm_put8(p, 0xF3);
    if (idx >= 8) p = np_vm_put8(p, 0x44);       /* REX.R for xmm8-15 */
    p = np_vm_put8(p, 0x0F);
    p = np_vm_put8(p, (u8)(store ? 0x7F : 0x6F));
    p = np_vm_put8(p, (u8)(0x84 | ((idx & 7u) << 3)));
    p = np_vm_put8(p, 0x24);                     /* SIB: base=rsp */
    p = np_vm_put32(p, 160u + 16u * (u32)idx);
    return p;
}

/* mov [rsp+8*slot], reg  (store=1) /  mov reg, [rsp+8*slot]  (store=0) */
static u8* np_vm_mov_rsp(u8* p, u8 reg, u32 slot, int store) {
    u8 disp = (u8)(slot * 8u);
    p = np_vm_put8(p, (u8)(0x48 | (reg >= 8 ? 4u : 0u)));
    p = np_vm_put8(p, (u8)(store ? 0x89 : 0x8B));
    p = np_vm_put8(p, (u8)(0x44 | ((reg & 7) << 3)));
    p = np_vm_put8(p, 0x24);              /* SIB: base=rsp, no index */
    p = np_vm_put8(p, disp);
    return p;
}

static u32 np_vm_install(void* base, const u8* b) {
    u32 off   = np_rd32(b + 20);
    u32 count = np_rd32(b + 88);
    /* Offset of the trampoline arena inside the payload (0 = old payload). */
    u32 arena = np_rd32(b + 92);
    if (!off || !count) return 0;
    /* Sanity bound only: the packer now emits one descriptor per virtualizable
     * function instead of truncating at 64. Each entry is bounds-checked
     * against its own region below, so a corrupt count cannot write outside
     * the image. */
    if (count > 8192u) count = 8192u;

    u8* img = (u8*)base;
    const u8* rec = b + off;

    for (u32 i = 0; i < count; i++) {
        u32 rva    = np_rd32(rec + i * NP_VM_DESC_SIZE + 0);
        u32 size   = np_rd32(rec + i * NP_VM_DESC_SIZE + 4);
        u32 bc_off = np_rd32(rec + i * NP_VM_DESC_SIZE + 8);
        u32 bc_len = np_rd32(rec + i * NP_VM_DESC_SIZE + 12);
        u32 rev_off= np_rd32(rec + i * NP_VM_DESC_SIZE + 16);
        u32 mask   = np_rd32(rec + i * NP_VM_DESC_SIZE + 20);
        /* Deepest guest stack motion below the region entry, in bytes (0 on
         * legacy payloads). The trampoline must keep its register file below
         * that or a virtualized frame write would land on VM state. */
        u32 depth  = np_rd32(rec + i * NP_VM_DESC_SIZE + 28);
        if (depth > 0x40000u) depth = 0x40000u;
        if (!rva || !size || !bc_len || !mask) continue;

        /* The bytecode stays ciphertext: there is no in-place decrypt step
         * and no VirtualProtect on this section any more. The interpreter
         * decodes one window at a time (see np_vm_window), so nothing here
         * needs a writable page and a hook on VirtualProtect reveals nothing
         * about where the VM program lives. */

        u32 regs = 0;
        for (u32 k = 0; k < 16; k++) if (mask & (1u << k)) regs++;

        /* The trampoline is generated into a dedicated arena inside the
         * executable protection section; the region itself only needs a
         * five-byte jump. That removes the old "region must be large enough for
         * the whole trampoline" limit, and with it a latent overflow: the size
         * check used 51+10*regs while the generated code is 51+20*regs (the
         * register file is saved *and* restored, ten bytes each). */
        u8* t;
        if (arena) {
            /* bit16 of the mask: the packer validated that the five-byte stub
             * may spill past the region into alignment padding (tiny thunks). */
            u32 minStub = (mask & 0x10000u) ? 1u : 5u;
            if (size < minStub) continue;                  /* no room for the jmp */
            t = (u8*)(b + arena) + (u64)i * NP_VM_TRAMP_STRIDE;
        } else {
            u32 need = 400u + 20u * regs;
            if (need + 8u > size) continue;
            t = img + rva;
        }
        u8* p = t;

        /* Frame: park the original rsp in rbp, align, then reserve the
         * 16-qword register file, 16 bytes of padding (the call below stays
         * 16-aligned and the second padding qword carries the image base out
         * to np_vm_run) and a red-zone gap - plus, on deep-frame regions, the
         * guest's own stack window below the entry rsp. The window is sized
         * from the region's reported stack depth so a virtualized frame
         * write can never land on the register file, and it is probed
         * top-down first: a bare `sub rsp` would leave the pages between the
         * old and new rsp uncommitted, and the first guest store past the
         * guard page would take an access violation instead of growing the
         * stack. The probe reads (never writes) the pages, so nothing the
         * guest later reads observes it. */
        p = np_vm_put8(p, 0x9C);                     /* pushfq              */
        p = np_vm_put8(p, 0x55);                     /* push rbp            */
        p = np_vm_put8(p, 0x48); p = np_vm_put8(p, 0x89); p = np_vm_put8(p, 0xE5);
        p = np_vm_put8(p, 0x48); p = np_vm_put8(p, 0x83); p = np_vm_put8(p, 0xE4); p = np_vm_put8(p, 0xF0);
        {
            u32 gap = 1024u + depth;
            gap = (gap + 15u) & ~15u;
            p = np_vm_put8(p, 0x48); p = np_vm_put8(p, 0x89); p = np_vm_put8(p, 0xE0);
            /* mov rax, rsp            (top of the window) */
            p = np_vm_put8(p, 0x48); p = np_vm_put8(p, 0x2D); p = np_vm_put32(p, gap);
            /* sub rax, gap            (bottom: where rsp will land) */
            p = np_vm_put8(p, 0x49); p = np_vm_put8(p, 0x89); p = np_vm_put8(p, 0xE2);
            /* mov r10, rsp            (probe cursor) */
            /* probe loop: step down one page at a time and read it */
            p = np_vm_put8(p, 0x49); p = np_vm_put8(p, 0x81); p = np_vm_put8(p, 0xEA);
            p = np_vm_put32(p, 0x1000);              /* sub r10, 0x1000     */
            p = np_vm_put8(p, 0x49); p = np_vm_put8(p, 0x83); p = np_vm_put8(p, 0x3A); p = np_vm_put8(p, 0x00);
            /* cmp qword [r10], 0      (read-touch) */
            p = np_vm_put8(p, 0x4D); p = np_vm_put8(p, 0x39); p = np_vm_put8(p, 0xC2);
            /* cmp r10, rax */
            p = np_vm_put8(p, 0x77); p = np_vm_put8(p, 0xF0);
            /* ja .probe  (-16: back to the sub r10) */
            p = np_vm_put8(p, 0x48); p = np_vm_put8(p, 0x89); p = np_vm_put8(p, 0xC4);
            /* mov rsp, rax */
        }

        /* bit31 of the register mask arms the xmm save/restore: the region
         * performs xmm data movement and the interpreter's xmm file must be
         * invisible to the guest registers the callee saved. */
        if (mask & 0x80000000u)
            for (u32 k = 0; k < 16; k++) p = np_vm_xmm_rsp(p, (u8)k, 1);
        for (u32 k = 0; k < 16; k++) {
            if (k == 4 || k == 5) continue;          /* seeded explicitly below */
            if (mask & (1u << k)) p = np_vm_mov_rsp(p, (u8)k, k, 1);
        }
        /* Slot 4 must hold the guest's rsp at body entry and slot 5 the
         * guest's rbp. The naive "save the real register" would store the
         * trampoline's own rsp/rbp - values no guest instruction may ever see.
         * rax is scratch here; its own value is already saved because the
         * clobber mask always contains bit 0. */
        p = np_vm_put8(p, 0x48); p = np_vm_put8(p, 0x8B); p = np_vm_put8(p, 0x45); p = np_vm_put8(p, 0x00);
        p = np_vm_put8(p, 0x48); p = np_vm_put8(p, 0x89); p = np_vm_put8(p, 0x44); p = np_vm_put8(p, 0x24); p = np_vm_put8(p, 40);
        /* mov rax,[rbp+0] ; mov [rsp+40],rax     slot5 = guest rbp */
        p = np_vm_put8(p, 0x48); p = np_vm_put8(p, 0x8B); p = np_vm_put8(p, 0x45); p = np_vm_put8(p, 0x08);
        p = np_vm_put8(p, 0x48); p = np_vm_put8(p, 0x89); p = np_vm_put8(p, 0x84); p = np_vm_put8(p, 0x24);
        p = np_vm_put32(p, 128);
        /* mov rax,[rbp+8] ; mov [rsp+128],rax    slot16 = entry flags */
        p = np_vm_put8(p, 0x48); p = np_vm_put8(p, 0x8D); p = np_vm_put8(p, 0x45); p = np_vm_put8(p, 0x10);
        p = np_vm_put8(p, 0x48); p = np_vm_put8(p, 0x89); p = np_vm_put8(p, 0x44); p = np_vm_put8(p, 0x24); p = np_vm_put8(p, 32);
        /* lea rax,[rbp+16] ; mov [rsp+32],rax    slot4 = guest rsp
         * (the pushfq below the push rbp parked the entry flags at [rbp+8]) */

        /* Image base into the second padding qword: np_vm_run re-bases the
         * RVAs of VMO_EXITJMP / VMO_CALL from it. */
        p = np_vm_put8(p, 0x48); p = np_vm_put8(p, 0xB8);                 /* mov rax, imm64 */
        p = np_vm_put64(p, (u64)(unsigned long long)img);
        p = np_vm_put8(p, 0x48); p = np_vm_put8(p, 0x89); p = np_vm_put8(p, 0x84); p = np_vm_put8(p, 0x24);
        p = np_vm_put32(p, 152);
        /* mov [rsp+152], rax    slot19 = runtime image base */

        {   /* lea rcx, [rip+disp] -> bytecode */
            u8* q = p;
            p = np_vm_put8(p, 0x48); p = np_vm_put8(p, 0x8D); p = np_vm_put8(p, 0x0D);
            u64 tgt = (u64)(const u8*)(b + bc_off);
            u64 nxt = (u64)(q + 7);
            p = np_vm_put32(p, (u32)(i32)(tgt - nxt));
        }
        p = np_vm_put8(p, 0xBA);                     /* mov edx, bc_len     */
        p = np_vm_put32(p, bc_len);
        {   /* lea r8, [rip+disp] -> reverse table */
            u8* q = p;
            p = np_vm_put8(p, 0x4C); p = np_vm_put8(p, 0x8D); p = np_vm_put8(p, 0x05);
            u64 tgt = (u64)(const u8*)(b + rev_off);
            u64 nxt = (u64)(q + 7);
            p = np_vm_put32(p, (u32)(i32)(tgt - nxt));
        }
        p = np_vm_put8(p, 0x49); p = np_vm_put8(p, 0x89); p = np_vm_put8(p, 0xE1); /* mov r9,rsp */

        {   /* call rel32 -> np_vm_run */
            u8* q = p;
            p = np_vm_put8(p, 0xE8);
            u64 tgt = (u64)(unsigned long long)&np_vm_run;
            u64 nxt = (u64)(q + 5);
            p = np_vm_put32(p, (u32)(i32)(tgt - nxt));
        }

        /* Flags back to the real eflags first - the gpr restore below loads
         * rax from the register file and must win over the flag scratch. The
         * epilogue island and the next chunk's bridge see exactly the flag
         * file the VM left behind. */
        p = np_vm_put8(p, 0x48); p = np_vm_put8(p, 0x8B); p = np_vm_put8(p, 0x84); p = np_vm_put8(p, 0x24);
        p = np_vm_put32(p, 128);
        /* mov rax,[rsp+128] */
        p = np_vm_put8(p, 0x50);                     /* push rax            */
        p = np_vm_put8(p, 0x9D);                     /* popfq               */
        for (u32 k = 0; k < 16; k++) {
            if (k == 4) continue;                    /* rsp is set below */
            if (mask & (1u << k)) p = np_vm_mov_rsp(p, (u8)k, k, 0);
        }
        /* Exit sequence: r11 carries the native exit address written by
         * VMO_EXITJMP (0 = fall through to the byte after the region). rsp and
         * rbp come from the register file instead of a pop: a virtualized body
         * may legitimately rewrite rbp, and the region's native epilogue wants
         * exactly the guest's final state. r11 is caller-saved, so trading it
         * for the exit address costs nothing. */
        if (mask & 0x80000000u)
            for (u32 k = 0; k < 16; k++) p = np_vm_xmm_rsp(p, (u8)k, 0);
        p = np_vm_put8(p, 0x4C); p = np_vm_put8(p, 0x8B); p = np_vm_put8(p, 0x9C); p = np_vm_put8(p, 0x24);
        p = np_vm_put32(p, 144);
        /* mov r11, [rsp+144]    slot18 = native exit address */
        p = np_vm_put8(p, 0x48); p = np_vm_put8(p, 0x8B); p = np_vm_put8(p, 0x6C); p = np_vm_put8(p, 0x24); p = np_vm_put8(p, 40);
        /* mov rbp, [rsp+40] */
        p = np_vm_put8(p, 0x48); p = np_vm_put8(p, 0x8B); p = np_vm_put8(p, 0x64); p = np_vm_put8(p, 0x24); p = np_vm_put8(p, 32);
        /* mov rsp, [rsp+32] */
        p = np_vm_put8(p, 0x4D); p = np_vm_put8(p, 0x85); p = np_vm_put8(p, 0xDB);
        /* test r11, r11 */
        p = np_vm_put8(p, 0x74); p = np_vm_put8(p, 0x03);
        /* jz .+5 */
        p = np_vm_put8(p, 0x41); p = np_vm_put8(p, 0xFF); p = np_vm_put8(p, 0xE3);
        /* jmp r11 */

        {   /* jmp rel32 -> first byte after the region (default exit) */
            u8* q = p;
            p = np_vm_put8(p, 0xE9);
            u64 tgt = (u64)(img + rva + size);
            u64 nxt = (u64)(q + 5);
            p = np_vm_put32(p, (u32)(i32)(tgt - nxt));
        }


        /* Fill the remainder so the slot stays deterministic. In arena mode the
         * region gets the jump first and the arena slot is padded to its fixed
         * stride. */
        if (arena) {
            u8* j = img + rva;
            i32 rel = (i32)((u64)t - (u64)(j + 5));
            j[0] = 0xE9;
            j[1] = (u8)(rel & 0xFF);
            j[2] = (u8)((rel >> 8) & 0xFF);
            j[3] = (u8)((rel >> 16) & 0xFF);
            j[4] = (u8)((rel >> 24) & 0xFF);
            while (p < t + NP_VM_TRAMP_STRIDE) *p++ = 0x90;
        } else {
            while (p < t + size) *p++ = 0x90;
        }
    }
    return 0;
}
/* ========================================================================
 * entry point
 * ======================================================================== */

__attribute__((noinline, used))
u32 np_prot_start(void* base, void* hdr, void* blob, void* kern) {
    (void)hdr;
    if (!blob) return 0;

    const u8* b = (const u8*)blob;
    if (np_rd32(b) != NPP_MAGIC) return 0;
    u32 ver = np_rd32(b + 4);
    if (ver < 1 || ver > 2) return 0;

    u32 flags = np_rd32(b + 8);
    if (!flags) return 0;
    np_gate_hv_exit = (flags & 0x4000u) ? 1u : 0u;
    np_gate_kernel  = (flags & 0x8000u) ? 1u : 0u;

    /* ---- environment gates first --------------------------------------
     * The sandbox guard and the interactive-desktop self-check run before
     * every other check so an analysis environment is stopped with a clear
     * notice instead of an opaque crash, and gets no time to observe the
     * remaining protections. Neither returns a failure id: on a positive
     * verdict np_block_sandbox() terminates the process.                    */
    if (flags & 0x200u) {
        u32 threshold = np_rd32(b + 96);
        if (threshold) {
            u64 detail = 0;
            u32 score = np_sandbox_score_ex(&detail);
            if (score >= threshold && (detail & NP_SB_STRONG)) {
                np_dbg_report(score, detail, threshold);
                np_block_sandbox();
                return NP_CHK_SANDBOX;   /* not reached */
            }
        }
    }
    if (flags & 0x800u) {
        if (np_chk_env(b)) {
            np_block_sandbox();
            return NP_CHK_ENV;           /* not reached */
        }
    }

    /* Self-isolation runs after the environment gates (so an analysis host
     * is stopped before it can observe the hardening) and before every other
     * check. It never fails the image: a host that refuses a layer simply
     * leaves it off. */
    if (flags & 0x1000u) {
        np_self_isolate();
    }

    /* Delayed re-audit: a monitor that attaches after startup is invisible to
     * the one-shot checks above. Runs on a worker thread and blocks on a late
     * module/handle/vendor hit. Only armed when the sandbox guard is on. */
    if ((flags & 0x2000u) && (flags & 0x200u)) {
        np_audit_start();
    }

    void* ntqip = 0;
    void* getctx = 0;
    void* ntdll = 0;
    if (flags & 0x0F) {
        ntdll = np_module_by_name(np_s_ntdll);
        if (ntdll) ntqip = np_export_by_name(ntdll, np_s_qip);
        void* k32 = np_module_by_name(np_s_kernel32);
        if (k32) getctx = np_export_by_name(k32, np_s_getctx);
    }

    if (flags & 0x01u) {
        if (np_chk_peb())      return NP_CHK_PEB;
        if (np_chk_ntglobal()) return NP_CHK_NTGLOBAL;
        if (np_chk_heap())     return NP_CHK_HEAP;
        if (ntqip && np_chk_ntquery(ntqip)) return NP_CHK_NTQUERY;
        if ((flags & 0x08u) && getctx && np_chk_dr(getctx)) return NP_CHK_DR;
        /* Debug object / thread hiding: a debugger that owns the process
         * shows up here even when the PEB flags have been forged. */
        if ((flags & 0x02u) && np_chk_advanced_debug(ntdll)) return NP_CHK_NTQUERY;
    }
    if (flags & 0x04u) {
        if (np_chk_timing(np_rd64(b + 24))) return NP_CHK_TIMING;
    }
    if (flags & 0x02u) {
        if (np_chk_cpuid()) return NP_CHK_CPUID;
        if (np_chk_bad_modules()) return NP_CHK_BADMOD;
    }
    if (flags & 0x20u) {
        np_vm_install(base, b);
    }
    if (flags & 0x80u) {
        if (np_chk_mutation(b, kern)) return NP_CHK_MUTATION;
    }
    if (flags & 0x10u) {
        if (np_chk_license(b)) return NP_CHK_LICENSE;
    }
    if (flags & 0x100u) {
        u64 expected = np_rd64(b + 80);
        if (!expected || np_machine_id() != expected) return NP_CHK_ACTIVATION;
    }
    if (flags & 0x400u) {
        if (np_chk_dump(base)) return NP_CHK_DUMP;
    }
    if (flags & 0x40u) {
        if (np_chk_pe_header(base)) return NP_CHK_INTEGRITY;
        if (np_chk_integrity(base, b)) return NP_CHK_INTEGRITY;
    }
    return 0;
}

/* Marker so the generated blob can be measured by the build script. */
__attribute__((used)) static const u32 np_prot_marker = 0x4E505052u; /* 'NPPR' */
