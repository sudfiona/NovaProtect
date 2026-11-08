/* Test-only shim that lets MinGW's C front end parse the emitted driver.
 *
 * The real build needs the WDK (ntddk.h, the /kernel MSVC switches and the
 * intrinsic set). No WDK is installed on this machine, so this shim proves the
 * emitted source is syntactically valid C with consistently declared
 * identifiers -- NOT that it links or loads as a driver. Do not ship it. */
#ifndef NP_WDK_SHIM_H
#define NP_WDK_SHIM_H

typedef unsigned char      UCHAR;
typedef unsigned short     USHORT;
typedef unsigned long      ULONG;
typedef unsigned int       UINT32;
typedef int                INT32;
typedef long               NTSTATUS;
typedef long long          LONGLONG;
typedef unsigned long long ULONGLONG;
typedef unsigned long long ULONG64;
typedef void*              PVOID;
typedef void*              HANDLE;
typedef UCHAR*             PUCHAR;
typedef char               CHAR;
typedef char*              PCHAR;
typedef unsigned long long ULONG_PTR;
typedef USHORT*            PUSHORT;
typedef ULONG*             PULONG;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    unsigned short* Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY* Flink;
    struct _LIST_ENTRY* Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef union _LARGE_INTEGER {
    struct { ULONG LowPart; long HighPart; } u;
    LONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

typedef struct _IO_STATUS_BLOCK {
    NTSTATUS Status;
    ULONG_PTR Information;
} IO_STATUS_BLOCK;

typedef struct _IRP {
    IO_STATUS_BLOCK IoStatus;
    struct { PVOID SystemBuffer; } AssociatedIrp;
} IRP, *PIRP;

typedef struct _IO_STACK_LOCATION {
    struct {
        struct {
            ULONG IoControlCode;
            ULONG OutputBufferLength;
            ULONG InputBufferLength;
        } DeviceIoControl;
    } Parameters;
} IO_STACK_LOCATION, *PIO_STACK_LOCATION;

typedef struct _DEVICE_OBJECT {
    struct _DEVICE_OBJECT* DeviceObject;
    struct _DRIVER_OBJECT* DriverObject;
} DEVICE_OBJECT, *PDEVICE_OBJECT;

typedef struct _DRIVER_OBJECT {
    PDEVICE_OBJECT DeviceObject;
    PVOID DriverSection;
    NTSTATUS (*MajorFunction[28])(PDEVICE_OBJECT, PIRP);
    void (*DriverUnload)(struct _DRIVER_OBJECT*);
} DRIVER_OBJECT, *PDRIVER_OBJECT;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    PVOID DllBase;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

extern LIST_ENTRY PsLoadedModuleList;

#define CONTAINING_RECORD(address, type, field) \
    ((type*)((PCHAR)(address) - (ULONG_PTR)(&((type*)0)->field)))

#define UNREFERENCED_PARAMETER(x) ((void)(x))
#define STATUS_SUCCESS            ((NTSTATUS)0x00000000L)
#define STATUS_INVALID_DEVICE_REQUEST ((NTSTATUS)0xC0000010L)
#define NT_SUCCESS(s)             (((NTSTATUS)(s)) >= 0)
#define FILE_DEVICE_UNKNOWN       0x00000022
#define METHOD_BUFFERED           0
#define FILE_ANY_ACCESS           0
#define CTL_CODE(dev, fn, method, access) \
    (((dev) << 16) | ((access) << 14) | ((fn) << 2) | (method))
#define IRP_MJ_CREATE             0x00
#define IRP_MJ_CLOSE              0x02
#define IRP_MJ_DEVICE_CONTROL     0x0e
#define IO_NO_INCREMENT           0
#define FALSE                     0
#define TRUE                      1

void RtlInitUnicodeString(PUNICODE_STRING, const unsigned short*);
void RtlCopyMemory(void*, const void*, unsigned long);
NTSTATUS IoCreateDevice(PDRIVER_OBJECT, ULONG, PUNICODE_STRING, ULONG, ULONG, int, PDEVICE_OBJECT*);
NTSTATUS IoCreateSymbolicLink(PUNICODE_STRING, PUNICODE_STRING);
void IoDeleteDevice(PDEVICE_OBJECT);
NTSTATUS IoDeleteSymbolicLink(PUNICODE_STRING);
void IoCompleteRequest(PIRP, int);
PIO_STACK_LOCATION IoGetCurrentIrpStackLocation(PIRP);
LARGE_INTEGER KeQueryPerformanceCounter(void*);

/* MSVC intrinsics, provided here so the parse succeeds. */
static inline unsigned long long __readmsr(unsigned long) { return 0; }
static inline void __cpuidex(int out[4], int leaf, int sub) {
    out[0] = leaf; out[1] = sub; out[2] = 0; out[3] = 0;
}
static inline unsigned long long __rdtsc(void) { return 0; }
static inline void _mm_lfence(void) { }

#endif
