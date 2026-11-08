#pragma once
// Build-time dependency only. Protected output removes these SDK imports;
// no signing/activation secret is embedded in marker labels.
//
// The commercial VMProtect SDK is optional at build time:
//   - default build links the real VMProtectSDK64.a and calls into the SDK;
//   - NOVAPROTECT_VMP_STUB builds without the SDK (open-source clones) and
//     compiles the same marker call sites to no-ops.
// The marker call sites in src/client_gate.cpp and runtime/managed_host.cpp
// are identical in both modes; only this header switches.
#ifdef NOVAPROTECT_VMP_STUB
extern "C" {
inline void __stdcall VMProtectBeginUltra(const char* name) { (void)name; }
inline void __stdcall VMProtectEnd() {}
}
#else
extern "C" {
__declspec(dllimport) void __stdcall VMProtectBeginUltra(const char* name);
__declspec(dllimport) void __stdcall VMProtectEnd();
}
#endif
