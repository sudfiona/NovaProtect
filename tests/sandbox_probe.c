/* tests/sandbox_probe.c - local harness for the sandbox / env self-check probes.
 *
 * Build (MinGW-W64):
 *   gcc -O2 -Wall -Wextra -o tests/sandbox_probe.exe tests/sandbox_probe.c
 *
 * Run:
 *   sandbox_probe.exe            baseline on this machine (expect: pass)
 *   sandbox_probe.exe 1          + DLL loaded from %TEMP% (injected agent)
 *   sandbox_probe.exe 2          + ephemeral account/computer names
 *   sandbox_probe.exe 3          + both of the above
 *   cmd /c sandbox_probe.exe 0   + script-host (cmd.exe) parent process
 *   sandbox_probe.exe 4          end-to-end block path (notice + ExitProcess(0))
 *
 * The harness calls the runtime probes directly (never np_prot_start), so a
 * positive verdict prints numbers instead of terminating the process.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

/* prot64.c carries its own freestanding copies of the winnt.h macros */
#undef CONTEXT_DEBUG_REGISTERS
#include "../runtime/prot64.c"

static u8 blob[256];

static void make_blob(void) {
    memset(blob, 0, sizeof(blob));
    *(u32*)(blob + 0)   = 0x3150504Eu;   /* NPP1 */
    *(u32*)(blob + 4)   = 2u;            /* version 2 */
    *(u32*)(blob + 8)   = 0xEA9u;        /* every protection bit */
    *(u32*)(blob + 96)  = 40u;           /* sandbox_score_threshold  */
    *(u32*)(blob + 100) = 2u;            /* min_cpu_count            */
    *(u32*)(blob + 104) = 4096u;         /* min_ram_mb               */
    *(u32*)(blob + 108) = 3000u;         /* min_uptime_ms            */
    *(u32*)(blob + 112) = 1024u;         /* min_screen_width         */
    *(u32*)(blob + 116) = 768u;          /* min_screen_height        */
    *(u32*)(blob + 120) = 1u;            /* min_monitor_count        */
    *(u32*)(blob + 124) = 7u;            /* env_score_threshold      */
}

static const struct { u64 bit; const char* name; } kBits[] = {
    { NP_SB_MOD,      "MOD"      }, { NP_SB_INJECT,   "INJECT"   },
    { NP_SB_HYPER,    "HYPER"    }, { NP_SB_FIRMWARE, "FIRMWARE" },
    { NP_SB_CPU1,     "CPU1"     }, { NP_SB_CPU2,     "CPU2"     },
    { NP_SB_RAM2,     "RAM2"     }, { NP_SB_RAM4,     "RAM4"     },
    { NP_SB_PROC40,   "PROC40"   }, { NP_SB_PROC70,   "PROC70"   },
    { NP_SB_NOINPUT,  "NOINPUT"  }, { NP_SB_IDLE,     "IDLE"     },
    { NP_SB_SLEEP,    "SLEEP"    }, { NP_SB_TSCSPREAD,"TSCSPREAD"},
    { NP_SB_COREMASK, "COREMASK" }, { NP_SB_RES1024,  "RES1024"  },
    { NP_SB_RES800,   "RES800"   }, { NP_SB_NOMON,    "NOMON"    },
    { NP_SB_TMPLNAME, "TMPLNAME" }, { NP_SB_FRESH3,   "FRESH3"   },
    { NP_SB_FRESH14,  "FRESH14"  }, { NP_SB_PARENT,   "PARENT"   },
    { NP_SB_SVCHOST,  "SVCHOST"  }, { NP_SB_DBGHELP,  "DBGHELP"  },
    { NP_SB_MS_MOD,   "MS-MOD"   }, { NP_SB_MS_PROC,  "MS-PROC"  },
    { NP_SB_MS_REG,   "MS-REG"   }, { NP_SB_MS_HOST,  "MS-HOST"  },
    { NP_SB_AN_SLEEP, "AN-SLEEP" }, { NP_SB_AN_HFLAG, "AN-HFLAG" },
    { NP_SB_AN_DISK,  "AN-DISK"  }, { NP_SB_AN_HANDLE,"AN-HANDLE"},
    { NP_SB_AN_CLOCK, "AN-CLOCK" }, { NP_SB_AN_BURST, "AN-BURST" },
};

int main(int argc, char** argv) {
    make_blob();
    int mode = (argc > 1) ? atoi(argv[1]) : 0;

    if (mode == 1 || mode == 3 || mode == 4) {
        /* simulate an analysis agent injected from a user-writable path */
        char tmp[MAX_PATH], dst[MAX_PATH];
        GetTempPathA(sizeof(tmp), tmp);
        _snprintf(dst, sizeof(dst), "%s\\np_probe_inject.dll", tmp);
        BOOL ok = CopyFileA("C:\\Windows\\System32\\version.dll", dst, FALSE);
        HMODULE m = ok ? LoadLibraryA(dst) : NULL;
        printf("[setup] injected module copy=%d load=%p (%s)\n", ok, (void*)m, dst);
    }
    if (mode == 2 || mode == 3) {
        /* simulate a freshly imaged sandbox guest with template names */
        SetEnvironmentVariableA("COMPUTERNAME", "WIN-TESTBOX");
        SetEnvironmentVariableA("USERNAME", "sandboxuser");
        printf("[setup] COMPUTERNAME=WIN-TESTBOX USERNAME=sandboxuser\n");
    }
    if (mode == 7) {
        /* vendor-signature layer: the appliance leaves its own name in the
         * guest. Simulate the hostname half (the module / process / registry
         * halves need a real appliance to be present). */
        SetEnvironmentVariableA("COMPUTERNAME", "WIN-THREATBOOK-01");
        printf("[setup] COMPUTERNAME=WIN-THREATBOOK-01 (vendor hostname)\n");
    }
    if (mode == 8) {
        /* full end-to-end: vendor hostname alone must reach the threshold
         * with a strong bit and block through np_prot_start. */
        SetEnvironmentVariableA("COMPUTERNAME", "WIN-THREATBOOK-01");
        *(u32*)(blob + 8)  = 0x200u;   /* sandbox guard only */
        *(u32*)(blob + 96) = 15u;      /* vendor name scores 15 */
        printf("[setup] np_prot_start(sandbox-only, threshold=15, vendor hostname)\n");
        fflush(stdout);
        u32 r = np_prot_start((void*)GetModuleHandleA(NULL), 0, blob, 0);
        printf("np_prot_start returned %u - block path NOT taken\n", r);
        return 0;
    }

    if (mode == 4) {
        /* end-to-end block path: sandbox flag alone, threshold below the
         * injected-module score (25) so the guard must fire. Expect a
         * "请在非沙箱内使用" notice and ExitProcess(0) within ~3 s. */
        *(u32*)(blob + 8)  = 0x200u;   /* sandbox guard only */
        *(u32*)(blob + 96) = 20u;      /* low threshold       */
        printf("[setup] invoking np_prot_start(sandbox-only, threshold=20)...\n");
        fflush(stdout);
        u32 r = np_prot_start((void*)GetModuleHandleA(NULL), 0, blob, 0);
        printf("np_prot_start returned %u - block path NOT taken\n", r);
        return 0;
    }

    if (mode == 9) {
        /* self-isolation: apply the layers and report which took effect.
         * The process must keep running (no crash, no exit). */
        u32 ap = np_self_isolate();
        printf("self_isolate applied=0x%X (1=dacl 2=thread-hide 4=ext-points)\n", ap);
        /* prove we still run: touch the heap and print */
        void* p = malloc(64);
        printf("still running: malloc=%p mode9=OK\n", p);
        free(p);
        return 0;
    }

    if (mode == 5 || mode == 6) {
        /* unit dump of every sub-probe (no scoring, no human suppression) */
        printf("template_name      = %u\n", np_template_name());
        printf("injected_module    = %u\n", np_injected_module_paths());
        printf("bad_modules        = %u\n", np_chk_bad_modules());
        printf("dbghelp_family     = %u\n", np_dbghelp_family());
        printf("firmware_artifacts = %u\n", np_firmware_artifacts());
        printf("sleep_compressed   = %u\n", np_sleep_compressed());
        printf("install_age_days   = %u\n", np_install_age_days());
        printf("taskbar_present    = %u\n", np_taskbar_present());
        /* behavioural analysis-artefact layer: all must read 0 on a real box */
        printf("analy_sleep        = %u\n", np_analy_sleep_compressed());
        printf("analy_debug_heap   = %u\n", np_analy_debug_heap());
        printf("analy_virtual_disk = %u\n", np_analy_virtual_disk());
        printf("analy_handle_ratio = %u\n", np_analy_handle_ratio());
        printf("analy_clock_disag  = %u\n", np_analy_clock_disagreement());
        printf("analy_creation_burst= %u\n", np_analy_creation_burst());
        u64 up = 0;
        void* k32 = np_module_by_name(np_s_kernel32);
        if (k32) {
            typedef u64 (__attribute__((ms_abi)) *np_gtt_fn)(void);
            np_gtt_fn gtt = (np_gtt_fn)np_export_by_name(k32, np_s_gtt);
            if (gtt) up = gtt();
        }
        printf("uptime_ms          = %llu\n", (unsigned long long)up);
        printf("input_idle_ms      = %u\n", np_input_idle_ms(up));
        printf("self_pid           = %llu\n", (unsigned long long)np_self_pid());
        printf("parent_pid         = %llu\n", (unsigned long long)np_parent_pid());
        return 0;
    }

    u64 detail = 0;
    u32 score = np_sandbox_score_ex(&detail);
    u32 thr = *(u32*)(blob + 96);
    printf("sandbox: score=%u threshold=%u strong=0x%016llX -> %s\n",
           score, thr, (unsigned long long)(detail & NP_SB_STRONG),
           (score >= thr && (detail & NP_SB_STRONG)) ? "BLOCK" : "pass");
    printf("detail = 0x%016llX :", (unsigned long long)detail);
    for (size_t i = 0; i < sizeof(kBits) / sizeof(kBits[0]); i++)
        if (detail & kBits[i].bit) printf(" %s", kBits[i].name);
    printf("\n");

    u32 env = np_chk_env(blob);
    printf("env    : verdict=%u threshold=7 -> %s\n", env, env ? "BLOCK" : "pass");

    /* process-table sanity: self pid must resolve to our own image name
     * (validates the UniqueProcessId offset used by np_snap_name_of). */
    if (np_snapshot_processes()) {
        u64 self = np_self_pid();
        u16 name[96];
        if (np_snap_name_of(self, name, 96)) {
            char narrow[96];
            for (int i = 0; i < 95 && name[i]; i++) narrow[i] = (char)name[i];
            narrow[95] = 0;
            printf("proc   : self_pid=%llu name=%s count=%u\n",
                   (unsigned long long)self, narrow, np_snap_count());
        } else {
            printf("proc   : self_pid=%llu name=<unresolved> count=%u\n",
                   (unsigned long long)self, np_snap_count());
        }
        np_snap_free();
    } else {
        printf("proc   : snapshot unavailable\n");
    }
    return 0;
}
