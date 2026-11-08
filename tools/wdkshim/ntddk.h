/* ntddk.h stand-in for the syntax check only.
 *
 * tools/test-driver-emit.ps1 compiles the emitted driver with
 * `-I tools/wdkshim`, so the generated #include <ntddk.h> resolves here and the
 * source is compiled exactly as emitted -- no rewriting, no marker removal.
 * This is a parse check, not a driver build: no WDK is installed. */
#ifndef NP_NTDDK_STANDIN_H
#define NP_NTDDK_STANDIN_H
#include "../wdk_shim.h"
#endif
