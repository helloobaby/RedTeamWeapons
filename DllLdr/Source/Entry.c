#include <Core.h>
#include <Native.h>
#include <ntdef.h>


// 不行，这个字符串gcc编译的时候会在.text的最前面，无法直接调用了
//const char log1[] __attribute__((section(".text"))) = "KaynLoader trace";

// 
DLLEXPORT VOID KaynLoader( LPVOID lpParameter )
{
    
#ifndef __clang__
    INSTANCE                Instance        = { 0 };
#else
    INSTANCE                Instance        ;
    Memset(&Instance,0,sizeof(INSTANCE));
#endif

    HMODULE                 KaynLibraryLdr  = NULL;
    PIMAGE_NT_HEADERS       NtHeaders       = NULL;
    PIMAGE_SECTION_HEADER   SecHeader       = NULL;
    LPVOID                  KVirtualMemory  = NULL;
    SIZE_T                  KMemSize        = 0;
    PVOID                   SecMemory       = NULL;
    SIZE_T                  SecMemorySize   = 0;
    ULONG                   Protection      = 0;
    ULONG                   OldProtection   = 0;
    PIMAGE_DATA_DIRECTORY   ImageDir        = NULL;
    PVOID                   StartAddress    = NULL;
    DWORD                   rva             = 0;
    PIMAGE_TLS_DIRECTORY    tls             = 0;
    PIMAGE_TLS_CALLBACK     *callbacks      = NULL;

    // 0. First we need to get the DLL base
    // KCharStringToWCharString函数的大小是0x71个字节
    StartAddress   = RVA2VA( PVOID, KCharStringToWCharString, 0x70 );

    KaynLibraryLdr = KaynCaller( StartAddress );

    // ------------------------
    // 1. Load needed Functions
    // ------------------------
    Instance.Modules.Ntdll                 = KGetModuleByHash( NTDLL_HASH );

    Instance.Win32.LdrLoadDll              = KGetProcAddressByHash( &Instance, Instance.Modules.Ntdll, SYS_LDRLOADDLL, 0  );
    Instance.Win32.NtAllocateVirtualMemory = KGetProcAddressByHash( &Instance, Instance.Modules.Ntdll, SYS_NTALLOCATEVIRTUALMEMORY, 0 );
    Instance.Win32.NtProtectVirtualMemory  = KGetProcAddressByHash( &Instance, Instance.Modules.Ntdll, SYS_NTPROTECTEDVIRTUALMEMORY, 0 );
    Instance.Win32.NtFlushInstructionCache = KGetProcAddressByHash( &Instance, Instance.Modules.Ntdll, SYS_NTFLUSHINSTRUCTIONCACHE, 0 );

// clang这样写字符串也是到rdata里面的,
#ifndef __clang__
    char KaynCaller_trace[]={'K','a','y','n','C','a','l','l','e','r',' ','t','r','a','c','e','\n','\0'};
    //LogToConsole(KaynCaller_trace);
    
    char ntdll_trace[]={'n','t','d','l','l',' ','%','p','\n','\0'};
    //LogToConsole(ntdll_trace,Instance.Modules.Ntdll);
#endif
    // ---------------------------------------------------------------------------
    // 2. Allocate virtual memory and copy headers and section into the new memory
    // ---------------------------------------------------------------------------
    NtHeaders = RVA2VA( PIMAGE_NT_HEADERS, KaynLibraryLdr, ( ( PIMAGE_DOS_HEADER ) KaynLibraryLdr )->e_lfanew );
    KMemSize  = NtHeaders->OptionalHeader.SizeOfImage;
#ifndef __clang__
    char SizeOfImageValue[]={'S','i','z','e','O','f','I','m','a','g','e',' ','%','x','\n','\0'};
    //LogToConsole(SizeOfImageValue,KMemSize);
#endif
    if ( NT_SUCCESS( Instance.Win32.NtAllocateVirtualMemory( NtCurrentProcess(), &KVirtualMemory, 0, &KMemSize, MEM_COMMIT, PAGE_READWRITE ) ) )
    {
        // ---- Copy Headers into new allocated memory ----
        Memcpy(KVirtualMemory, KaynLibraryLdr, NtHeaders->OptionalHeader.SizeOfHeaders);
        ( ( PIMAGE_NT_HEADERS ) KVirtualMemory )->OptionalHeader.ImageBase = KVirtualMemory;

        // ---- Copy Sections into new allocated memory ----
        SecHeader = IMAGE_FIRST_SECTION( NtHeaders );
        for ( DWORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
        {
            #ifndef __clang__
            char copydata[]={'C','o','p','y',' ','S','e','c','t','i','o','n',' ','V','i','r','t','u','a','l','A','d','d','r','e','s','s',' ','%','%p',' ','R','a','w','D','a','t','a',' ','%','x','\n','\0'};
            //LogToConsole(copydata,SecHeader[ i ].VirtualAddress,SecHeader[ i ].PointerToRawData );
            #endif
            Memcpy(
                RVA2VA( PVOID, KVirtualMemory, SecHeader[ i ].VirtualAddress ),      // Section New Memory
                RVA2VA( PVOID, KaynLibraryLdr, SecHeader[ i ].PointerToRawData ),    // Section Raw Data
                SecHeader[ i ].SizeOfRawData                                      // Section Size
            );
        }

        // ----------------------------------
        // 3. Process our images import table
        // ----------------------------------
        ImageDir = & NtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
        if ( ImageDir->VirtualAddress )
            KResolveIAT( &Instance, KVirtualMemory, RVA2VA( PVOID, KVirtualMemory, ImageDir->VirtualAddress ) );

        // ----------------------------
        // 4. Process image relocations
        // ----------------------------
        ImageDir = & NtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];
        if ( ImageDir->VirtualAddress )
            KReAllocSections( KVirtualMemory, NtHeaders->OptionalHeader.ImageBase, RVA2VA( PVOID, KVirtualMemory, ImageDir->VirtualAddress ) );

        // ----------------------------------
        // 5. Set protection for each section
        // ----------------------------------
        SecMemory     = KVirtualMemory;
        SecMemorySize = NtHeaders->OptionalHeader.SizeOfHeaders;
        Protection    = PAGE_READONLY;
        OldProtection = 0;
        Instance.Win32.NtProtectVirtualMemory( NtCurrentProcess(), &SecMemory, &SecMemorySize, Protection, &OldProtection );

        for ( DWORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
        {
            SecMemory       = RVA2VA( PVOID, KVirtualMemory, SecHeader[ i ].VirtualAddress );
            SecMemorySize   = SecHeader[ i ].SizeOfRawData;
            Protection      = 0;
            OldProtection   = 0;

            if ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE )
                Protection = PAGE_WRITECOPY;

            if ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_READ )
                Protection = PAGE_READONLY;

            if ( ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_READ ) )
                Protection = PAGE_READWRITE;

            if ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE )
                Protection = PAGE_EXECUTE;

            if ( ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE ) )
                Protection = PAGE_EXECUTE_WRITECOPY;

            if ( ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_READ ) )
                Protection = PAGE_EXECUTE_READ;

            if ( ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_READ ) )
                Protection = PAGE_EXECUTE_READWRITE;

            Instance.Win32.NtProtectVirtualMemory( NtCurrentProcess(), &SecMemory, &SecMemorySize, Protection, &OldProtection );
        }

        Instance.Win32.NtFlushInstructionCache( NtCurrentProcess(), NULL, 0 );

        // ----------------------------------
        // 6. Execute TLS callbacks
        // ----------------------------------
        rva = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
        if ( rva != 0 )
        {
            tls = RVA2VA(PIMAGE_TLS_DIRECTORY, KVirtualMemory, rva);
            callbacks = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;

            if ( callbacks )
            {
                while( *callbacks != NULL )
                {
                    // call function
                    (*callbacks)((LPVOID)KVirtualMemory, DLL_PROCESS_ATTACH, NULL);
                    callbacks++;
                }
            }
        }

        // --------------------------------
        // 7. Finally executing our DllMain
        // --------------------------------
        BOOL ( WINAPI *KaynDllMain ) ( PVOID, DWORD, PVOID ) = RVA2VA( PVOID, KVirtualMemory, NtHeaders->OptionalHeader.AddressOfEntryPoint );
        KaynDllMain( KVirtualMemory, DLL_PROCESS_ATTACH, lpParameter );
    }
}

// find entrypoint loop
// 向下面找pe文件，这个DllLdr就是附加到
#ifndef __clang__
NAKED LPVOID KaynCaller( PVOID StartAddress )
#else
// __attribute((noinline, bare)) 一开始加了这个声明，编译出来的代码有问题
LPVOID KaynCaller( PVOID StartAddress )
#endif
{
    #ifndef __clang__
    asm(
        "start: \n"
        "xor rbx, rbx \n"
        "mov ebx, 0x5A4D \n"
        "loop: \n"
        "inc rcx \n"
        "cmp bx,  [ rcx ] \n"
        "jne loop \n"
        "xor rax, rax \n"
        "mov ax,  [ rcx + 0x3C ] \n"
        "add rax, rcx \n"
        "xor rbx, rbx \n"
        "add bx,  0x4550 \n"
        "cmp bx,  [ rax ] \n"
        "jne start \n"
        "mov rax, rcx \n"
        "ret \n"
    );
    #else
    for (int i = 0;i<0x1000000;i++){  // 1M
        unsigned char* cur = (unsigned char*)StartAddress+i;
        if (cur[0]== 0x4D&&cur[1] == 0x5A){
            unsigned int offset = *(int*)(cur+0x3c);

            if (offset >=1000 || offset == 0 )
                continue;

            if( *(cur+offset) == 0x50){
            return cur;
        }
        }

    }
    return NULL;
    #endif
}
#ifndef __clang__
NAKED VOID Memcpy( PVOID Destination, PVOID source, SIZE_T Size )
#else
VOID Memcpy( PVOID Destination, PVOID source, SIZE_T Size )
#endif
{
    #ifndef __clang__
    asm(
        "xor r10, r10 \n"
        "test r8, r8 \n"
        "jne copy1 \n"
        "ret \n"
        "copy1: \n"
        "dec r8 \n"
        "mov r10b, [rdx] \n"
        "mov [rcx], r10b \n"
        "inc rdx \n"
        "inc rcx \n"
        "test r8, r8 \n"
        "jne copy1 \n"
        "ret \n"
    );
    #else

        /*
         * copy from lower addresses to higher addresses
         */
        while (Size--) {
                *(char *)Destination = *(char *)source;
                Destination = (char *)Destination + 1;
                source = (char *)source + 1;
        }

        return;
    #endif
}

VOID Memset(PVOID Destination,int v,SIZE_T Size){

    char *t = (char*)Destination;
    while(Size--)
    {
        t[Size] = (char)v;
    }

}

PVOID KGetModuleByHash( DWORD ModuleHash )
{
    PLDR_DATA_TABLE_ENTRY   LoaderEntry = NULL;
    PLIST_ENTRY             ModuleList  = NULL;
    PLIST_ENTRY             NextList    = NULL;

    /* Get pointer to list */
    ModuleList = & ( ( PPEB ) PPEB_PTR )->Ldr->InLoadOrderModuleList;
    NextList   = ModuleList->Flink;

    for ( ; ModuleList != NextList ; NextList = NextList->Flink )
    {
        LoaderEntry = NextList;

        if ( KHashString( LoaderEntry->BaseDllName.Buffer, LoaderEntry->BaseDllName.Length ) == ModuleHash )
            return LoaderEntry->DllBase;
    }

    return NULL;
}

FORCE_INLINE UINT32 CopyDotStr( PCHAR String )
{
    for ( UINT32 i = 0; i < KStringLengthA( String ); i++ )
    {
        if ( String[ i ] == '.' )
            return i;
    }
}

PVOID KGetProcAddressByHash( PINSTANCE Instance, PVOID DllModuleBase, DWORD FunctionHash, DWORD Ordinal )
{
    PIMAGE_NT_HEADERS       ModuleNtHeader          = NULL;
    PIMAGE_EXPORT_DIRECTORY ModuleExportedDirectory = NULL;
    SIZE_T                  ExportedDirectorySize   = 0;
    PDWORD                  AddressOfFunctions      = NULL;
    PDWORD                  AddressOfNames          = NULL;
    PWORD                   AddressOfNameOrdinals   = NULL;
    PVOID                   FunctionAddr            = NULL;
    UINT32                  Index                   = 0;

    ModuleNtHeader          = RVA2VA( PIMAGE_NT_HEADERS,       DllModuleBase, ( ( PIMAGE_DOS_HEADER ) DllModuleBase )->e_lfanew );
    ModuleExportedDirectory = RVA2VA( PIMAGE_EXPORT_DIRECTORY, DllModuleBase, ModuleNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
    ExportedDirectorySize   = ModuleNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size;

    AddressOfNames          = RVA2VA( PVOID, DllModuleBase, ModuleExportedDirectory->AddressOfNames );
    AddressOfFunctions      = RVA2VA( PVOID, DllModuleBase, ModuleExportedDirectory->AddressOfFunctions );
    AddressOfNameOrdinals   = RVA2VA( PVOID, DllModuleBase, ModuleExportedDirectory->AddressOfNameOrdinals );

    if (FunctionHash != NULL){
    for ( DWORD i = 0; i < ModuleExportedDirectory->NumberOfNames; i++ )
    {
        if ( KHashString( RVA2VA( PCHAR, DllModuleBase, AddressOfNames[ i ] ), 0 ) == FunctionHash )
        {
            FunctionAddr = RVA2VA( PVOID, DllModuleBase, AddressOfFunctions[ AddressOfNameOrdinals[ i ] ] );
            if ( ( ULONG_PTR ) FunctionAddr >= ( ULONG_PTR ) ModuleExportedDirectory &&
                 ( ULONG_PTR ) FunctionAddr <  RVA2VA( ULONG_PTR, ModuleExportedDirectory, ExportedDirectorySize ) )
            {
                #ifndef __clang__
                CHAR    Library [ MAX_PATH ] = { 0 };
                CHAR    Function[ MAX_PATH ] = { 0 };
                #else
                CHAR    Library [ MAX_PATH ];
                CHAR    Function[ MAX_PATH ];
                Memset(Library,0,MAX_PATH);
                Memset(Function,0,MAX_PATH);

                #endif
                // where is the dot
                Index = CopyDotStr( FunctionAddr );

                // Copy the library from our string
                Memcpy( Library,  FunctionAddr, Index );

                // Copy the function from our string
                Memcpy( Function, RVA2VA( PVOID, FunctionAddr, Index + 1 ), KStringLengthA( RVA2VA( PCHAR, FunctionAddr, Index + 1 ) ) );

                DllModuleBase = KLoadLibrary( Instance, Library );
                FunctionAddr  = KGetProcAddressByHash( Instance, DllModuleBase, KHashString( Function, 0 ), 0 );
            }

            return FunctionAddr;
        }
    }}else if (FunctionHash == NULL && Ordinal != NULL){
        //https://blog.csdn.net/weixin_43742894/article/details/105252653
        // 序号查找
        //char expnum[]={'e','x','p','n','u','m',' ','%','d','\n','\0'};
        char testd[]={'%','d','\n','\0'};
        char tests[]={'%','s','\n','\0'};
        int start_index = ModuleExportedDirectory->Base;
        int delta = Ordinal - start_index;
        if (delta > ModuleExportedDirectory->NumberOfFunctions)
            return NULL;
        return AddressOfFunctions[delta]+DllModuleBase;

    }else{
        #ifndef __clang__
        char error []={'e','r','r','o','r','1','\n','\0'};
        //LogToConsole(error);
        #endif
    }

    return NULL;
}

VOID KResolveIAT( PINSTANCE Instance, LPVOID KaynImage, LPVOID IatDir )
{
    PIMAGE_THUNK_DATA        OriginalTD        = NULL;
    PIMAGE_THUNK_DATA        FirstTD           = NULL;

    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = NULL;
    PIMAGE_IMPORT_BY_NAME    pImportByName     = NULL;

    PCHAR                    ImportModuleName  = NULL;
    HMODULE                  ImportModule      = NULL;

    for ( pImportDescriptor = IatDir; pImportDescriptor->Name != 0; ++pImportDescriptor )
    {
        ImportModuleName = RVA2VA( PCHAR, KaynImage, pImportDescriptor->Name );
        ImportModule     = KLoadLibrary( Instance, ImportModuleName );

#ifndef __clang__
        char loadtrace[]={'L','o','a','d',' ','%','s','\n','\0'};
        //LogToConsole(loadtrace,ImportModuleName);
#endif
        OriginalTD       = RVA2VA( PIMAGE_THUNK_DATA, KaynImage, pImportDescriptor->OriginalFirstThunk );
        FirstTD          = RVA2VA( PIMAGE_THUNK_DATA, KaynImage, pImportDescriptor->FirstThunk );

        for ( ; OriginalTD->u1.AddressOfData != 0 ; ++OriginalTD, ++FirstTD )
        {
            if ( IMAGE_SNAP_BY_ORDINAL( OriginalTD->u1.Ordinal ) )
            {
                // TODO: get function by ordinal
                PVOID Function = KGetProcAddressByHash( Instance, ImportModule, NULL, IMAGE_ORDINAL( OriginalTD->u1.Ordinal ) );
                if ( Function != NULL )
                    FirstTD->u1.Function = Function;
            }
            else
            {
                pImportByName       = RVA2VA( PIMAGE_IMPORT_BY_NAME, KaynImage, OriginalTD->u1.AddressOfData );
                DWORD  FunctionHash = KHashString( pImportByName->Name, KStringLengthA( pImportByName->Name ) );
                LPVOID Function     = KGetProcAddressByHash( Instance, ImportModule, FunctionHash, 0 );

                if ( Function != NULL )
                    FirstTD->u1.Function = Function;
            }
        }
    }
}

VOID KReAllocSections( PVOID KaynImage, PVOID ImageBase, PVOID BaseRelocDir )
{
    PIMAGE_BASE_RELOCATION  pImageBR = (PIMAGE_BASE_RELOCATION)BaseRelocDir;
    LPVOID                  OffsetIB = C_PTR( U_PTR( KaynImage ) - U_PTR( ImageBase ) );
    PIMAGE_RELOC            Reloc    = NULL;

    while( pImageBR->VirtualAddress != 0 )
    {
        Reloc = ( PIMAGE_RELOC ) ( pImageBR + 1 );

        while ( ( PBYTE ) Reloc != ( PBYTE ) pImageBR + pImageBR->SizeOfBlock )
        {
            if ( Reloc->type == IMAGE_REL_TYPE )
                *( ULONG_PTR* ) ( U_PTR( KaynImage ) + pImageBR->VirtualAddress + Reloc->offset ) += ( ULONG_PTR ) OffsetIB;

            else if ( Reloc->type != IMAGE_REL_BASED_ABSOLUTE )
                __debugbreak(); // TODO: handle this error

            Reloc++;
        }

        pImageBR = ( PIMAGE_BASE_RELOCATION ) Reloc;
    }
}

PVOID KLoadLibrary( PINSTANCE Instance, LPSTR ModuleName )
{
    if ( ! ModuleName )
        return NULL;

    #ifndef __clang__
    UNICODE_STRING  UnicodeString           = { 0 };
    WCHAR           ModuleNameW[ MAX_PATH ] = { 0 };
    #else
    UNICODE_STRING  UnicodeString;
    WCHAR           ModuleNameW[ MAX_PATH ];
    Memset(&UnicodeString,0,sizeof(UnicodeString));
    Memset(ModuleNameW,0,sizeof(ModuleNameW));
    #endif
    DWORD           dwModuleNameSize        = KStringLengthA( ModuleName );
    HMODULE         Module                  = NULL;

    KCharStringToWCharString( ModuleNameW, ModuleName, dwModuleNameSize );

    if ( ModuleNameW )
    {
        USHORT DestSize             = KStringLengthW( ModuleNameW ) * sizeof( WCHAR );
        UnicodeString.Length        = DestSize;
        UnicodeString.MaximumLength = DestSize + sizeof( WCHAR );
    }

    UnicodeString.Buffer = ModuleNameW;

    if ( NT_SUCCESS( Instance->Win32.LdrLoadDll( NULL, 0, &UnicodeString, &Module ) ) )
        return Module;
    else
        return NULL;
}

/*
 ---------------------------------
 ---- String & Data functions ----
 ---------------------------------
*/

DWORD KHashString( PVOID String, SIZE_T Length )
{
    ULONG   Hash = HASH_KEY;
    PUCHAR  Ptr  = String;

    do
    {
        UCHAR character = *Ptr;

        if ( ! Length )
        {
            if ( !*Ptr ) break;
        }
        else
        {
            if ( (ULONG) ( Ptr - (PUCHAR)String ) >= Length ) break;
            if ( !*Ptr ) ++Ptr;
        }

        if ( character >= 'a' )
            character -= 0x20;

        Hash = ( ( Hash << 5 ) + Hash ) + character;
        ++Ptr;
    } while ( TRUE );

    return Hash;
}

SIZE_T KStringLengthA( LPCSTR String )
{
    LPCSTR String2 = String;
    for (String2 = String; *String2; ++String2);
    return (String2 - String);
}

SIZE_T KStringLengthW(LPCWSTR String)
{
    LPCWSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

VOID LogToConsole(
    IN LPCSTR fmt,
    ...)
{
    INT     OutputSize   = 0;
    LPSTR   OutputString = NULL;
    va_list VaListArg    = 0;

    #ifndef __clang__
    INSTANCE                Instance        = { 0 };
#else
    INSTANCE                Instance        ;
    Memset(&Instance,0,sizeof(INSTANCE));
#endif

    Instance.Modules.Kernel32 = KGetModuleByHash( KERNEL32_HASH );
    Instance.Modules.Ntdll= KGetModuleByHash( NTDLL_HASH );
    Instance.Win32.AttachConsole = KGetProcAddressByHash(&Instance,Instance.Modules.Kernel32,SYS_AttachConsole,0);
    Instance.Win32.vsnprintf = KGetProcAddressByHash(&Instance,Instance.Modules.Ntdll,SYS_vsnprintf,0);
    Instance.Win32.WriteConsole = KGetProcAddressByHash(&Instance,Instance.Modules.Kernel32,SYS_WriteConsoleA,0);
    Instance.Win32.GetStdHandle = KGetProcAddressByHash(&Instance,Instance.Modules.Kernel32,SYS_GetStdHandle,0);
    Instance.Win32.LocalAlloc = KGetProcAddressByHash(&Instance,Instance.Modules.Kernel32,SYS_LocalAlloc,0);

    // have we initialized all the function addresses?
    if ( Instance.Win32.AttachConsole == NULL ||
         Instance.Win32.vsnprintf     == NULL ||
         Instance.Win32.GetStdHandle  == NULL ||
         Instance.Win32.WriteConsoleA == NULL ||
         Instance.Win32.LocalAlloc    == NULL )
        return;

    // get the handle to the output console
    if ( Instance.hConsoleOutput == NULL )
    {
        Instance.Win32.AttachConsole( ATTACH_PARENT_PROCESS );
        Instance.hConsoleOutput = Instance.Win32.GetStdHandle( STD_OUTPUT_HANDLE );
        if ( ! Instance.hConsoleOutput  )
            return;
    }

    va_start( VaListArg, fmt );

    // allocate space for the final string
    OutputSize   = Instance.Win32.vsnprintf( NULL, 0, fmt, VaListArg ) + 1;
    OutputString = Instance.Win32.LocalAlloc( LPTR, OutputSize );

    // write the final string
    Instance.Win32.vsnprintf( OutputString, OutputSize, fmt, VaListArg );

    // write it to the console
    Instance.Win32.WriteConsoleA( Instance.hConsoleOutput, OutputString, OutputSize, NULL, NULL );

    //DATA_FREE( OutputString, OutputSize );

    va_end( VaListArg );
}

SIZE_T KCharStringToWCharString( PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed )
{
    INT Length = MaximumAllowed;

    while (--Length >= 0)
    {
        if (!(*Destination++ = *Source++))
            return MaximumAllowed - Length - 1;
    }

    return MaximumAllowed - Length;
}
