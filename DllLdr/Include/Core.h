
#include <windows.h>
#include <Macro.h>

#define NTDLL_HASH                      0xbc66d887
#define KERNEL32_HASH                   0xb344c2a4

#define SYS_LDRLOADDLL                  0xe9c62b77
#define SYS_NTALLOCATEVIRTUALMEMORY     0x6781cea0
#define SYS_NTPROTECTEDVIRTUALMEMORY    0xa1e157bc
#define SYS_NTFLUSHINSTRUCTIONCACHE     0xd267ce33
#define SYS_AttachConsole               0x451091c1
#define SYS_vsnprintf                   0xf110e402
#define SYS_GetStdHandle                0xc96e3950
#define SYS_WriteConsoleA               0x2c8f4918
#define SYS_LocalAlloc                  0xbd87fc8f


#define DLLEXPORT                       __declspec( dllexport )
#define NAKED                           __declspec( naked )
#define FORCE_INLINE                    __forceinline
#define WIN32_FUNC( x )                 __typeof__( x ) * x;

#define U_PTR( x )                      ( ( UINT_PTR ) x )
#define C_PTR( x )                      ( ( LPVOID ) x )
#define RVA2VA(type, base, rva) (type)((ULONG_PTR) base + rva)

#define DLL_QUERY_HMODULE   6

#ifdef _WIN64
#define IMAGE_REL_TYPE IMAGE_REL_BASED_DIR64
#else
#define IMAGE_REL_TYPE IMAGE_REL_BASED_HIGHLOW
#endif

typedef struct
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} U_STRING, *PU_STRING;

typedef struct
{
    struct
    {
        UINT_PTR Ntdll;
        UINT_PTR Kernel32;
    } Modules;

    struct {
        NTSTATUS ( NTAPI *LdrLoadDll )(
                PWSTR           DllPath,
                PULONG          DllCharacteristics,
                PU_STRING       DllName,
                PVOID           *DllHandle
        );

        NTSTATUS ( NTAPI *NtAllocateVirtualMemory ) (
                HANDLE      ProcessHandle,
                PVOID       *BaseAddress,
                ULONG_PTR   ZeroBits,
                PSIZE_T     RegionSize,
                ULONG       AllocationType,
                ULONG       Protect
        );

        NTSTATUS ( NTAPI *NtProtectVirtualMemory ) (
                HANDLE  ProcessHandle,
                PVOID   *BaseAddress,
                PSIZE_T RegionSize,
                ULONG   NewProtect,
                PULONG  OldProtect
        );

        NTSTATUS ( NTAPI *NtFlushInstructionCache ) (
                HANDLE  ProcessHandle,
                PVOID   BaseAddress,
                ULONG   NumberOfBytesToFlush
        );
        BOOL (NTAPI *AttachConsole)(DWORD dwProcessId);
        BOOL (NTAPI *WriteConsole)(HANDLE  hConsoleOutput,const VOID    *lpBuffer,DWORD   nNumberOfCharsToWrite,LPDWORD lpNumberOfCharsWritten,LPVOID  lpReserved);
        HANDLE (NTAPI* GetStdHandle)(DWORD nStdHandle);
        HLOCAL (NTAPI *LocalAlloc)(UINT   uFlags,SIZE_T uBytes);
        INT ( *vsnprintf ) ( PCHAR, SIZE_T, CONST PCHAR, va_list );
    } Win32;
        HANDLE hConsoleOutput;

} INSTANCE, *PINSTANCE;

typedef struct {
    WORD offset :12;
    WORD type   :4;
} *PIMAGE_RELOC;

LPVOID  KaynCaller( PVOID StartAddress );

VOID    Memcpy( PVOID Destination, PVOID source, SIZE_T Size );
VOID    Memset(PVOID Destination,int v,SIZE_T Size);

PVOID   KGetModuleByHash( DWORD hash );
PVOID   KGetProcAddressByHash( PINSTANCE Instance, PVOID DllModuleBase, DWORD FunctionHash, DWORD Ordinal );
PVOID   KLoadLibrary( PINSTANCE Instance, LPSTR Module );

VOID    KResolveIAT( PINSTANCE Instance, PVOID KaynImage, PVOID IatDir );
VOID    KReAllocSections( PVOID KaynImage, PVOID ImageBase, PVOID Dir );

DWORD   KHashString( LPVOID String, SIZE_T Size );
SIZE_T  KStringLengthA( LPCSTR String );
SIZE_T  KStringLengthW( LPCWSTR String );
VOID    KMemSet( PVOID Destination, INT Value, SIZE_T Size );
VOID    LogToConsole(IN LPCSTR fmt,...);
SIZE_T  KCharStringToWCharString( PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed );
