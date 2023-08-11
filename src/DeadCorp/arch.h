#pragma once
#include "defines.h"
#include <ntifs.h>
#include <ntddk.h>
#include <classpnp.h>
#include <windef.h>
#include <ntimage.h>


 

namespace arch { 
typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemNextEventIdInformation,
	SystemEventIdsInformation,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

#define GDI_HANDLE_BUFFER_SIZE      34

//
// Process Information Classes
//

    typedef enum _PROCESSINFOCLASS {
        ProcessBasicInformation,
        ProcessQuotaLimits,
        ProcessIoCounters,
        ProcessVmCounters,
        ProcessTimes,
        ProcessBasePriority,
        ProcessRaisePriority,
        ProcessDebugPort,
        ProcessExceptionPort,
        ProcessAccessToken,
        ProcessLdtInformation,
        ProcessLdtSize,
        ProcessDefaultHardErrorMode,
        ProcessIoPortHandlers,          // Note: this is kernel mode only
        ProcessPooledUsageAndLimits,
        ProcessWorkingSetWatch,
        ProcessUserModeIOPL,
        ProcessEnableAlignmentFaultFixup,
        ProcessPriorityClass,
        ProcessWx86Information,
        ProcessHandleCount,
        ProcessAffinityMask,
        ProcessPriorityBoost,
        ProcessDeviceMap,
        ProcessSessionInformation,
        ProcessForegroundInformation,
        ProcessWow64Information,
        ProcessImageFileName,
        ProcessLUIDDeviceMapsEnabled,
        ProcessBreakOnTermination,
        ProcessDebugObjectHandle,
        ProcessDebugFlags,
        ProcessHandleTracing,
        MaxProcessInfoClass                             // MaxProcessInfoClass should always be the last enum
    } PROCESSINFOCLASS;

    //
    // Thread Information Classes
    //

    typedef enum _THREADINFOCLASS {
        ThreadBasicInformation,                            // ??
        ThreadTimes,
        ThreadPriority,                                    // ??
        ThreadBasePriority,                                // ??
        ThreadAffinityMask,                                // ??
        ThreadImpersonationToken,                        // HANDLE
        ThreadDescriptorTableEntry,                        // ULONG Selector + LDT_ENTRY
        ThreadEnableAlignmentFaultFixup,                // ??
        ThreadEventPair,                                // ??
        ThreadQuerySetWin32StartAddress,                // ??
        ThreadZeroTlsCell,                                // ??
        ThreadPerformanceCount,                            // ??
        ThreadAmILastThread,                            // ??
        ThreadIdealProcessor,                            // ??
        ThreadPriorityBoost,                            // ??
        ThreadSetTlsArrayAddress,                        // ??
        MaxThreadInfoClass
    } THREADINFOCLASS;


    typedef struct _RTL_DRIVE_LETTER_CURDIR
    {
        USHORT Flags;
        USHORT Length;
        ULONG  TimeStamp;
        STRING DosPath;

    } RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;


    typedef struct _RTL_USER_PROCESS_PARAMETERS
    {
        ULONG MaximumLength;                            // Should be set before call RtlCreateProcessParameters
        ULONG Length;                                   // Length of valid structure
        ULONG Flags;                                    // Currently only PPF_NORMALIZED (1) is known:
                                                        //  - Means that structure is normalized by call RtlNormalizeProcessParameters
        ULONG DebugFlags;

        PVOID ConsoleHandle;                            // HWND to console window associated with process (if any).
        ULONG ConsoleFlags;
        HANDLE StandardInput;
        HANDLE StandardOutput;
        HANDLE StandardError;

                               // Specified in DOS-like symbolic link path, ex: "C:/WinNT/SYSTEM32"
        UNICODE_STRING DllPath;                         // DOS-like paths separated by ';' where system should search for DLL files.
        UNICODE_STRING ImagePathName;                   // Full path in DOS-like format to process'es file image.
        UNICODE_STRING CommandLine;                     // Command line
        PVOID Environment;                              // Pointer to environment block (see RtlCreateEnvironment)
        ULONG StartingX;
        ULONG StartingY;
        ULONG CountX;
        ULONG CountY;
        ULONG CountCharsX;
        ULONG CountCharsY;
        ULONG FillAttribute;                            // Fill attribute for console window
        ULONG WindowFlags;
        ULONG ShowWindowFlags;
        UNICODE_STRING WindowTitle;
        UNICODE_STRING DesktopInfo;                     // Name of WindowStation and Desktop objects, where process is assigned
        UNICODE_STRING ShellInfo;
        UNICODE_STRING RuntimeData;
        RTL_DRIVE_LETTER_CURDIR CurrentDirectores[0x20];

    } RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

    //
    // Process Environment Block
    //

    typedef struct _PEB_FREE_BLOCK
    {
        struct _PEB_FREE_BLOCK *Next;
        ULONG Size;

    } PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;


    typedef struct _PEB_LDR_DATA
    {
        ULONG Length;
        BOOLEAN Initialized;
        HANDLE SsHandle;
        LIST_ENTRY InLoadOrderModuleList;               // Points to the loaded modules (main EXE usually)
        LIST_ENTRY InMemoryOrderModuleList;             // Points to all modules (EXE and all DLLs)
        LIST_ENTRY InInitializationOrderModuleList;
        PVOID      EntryInProgress;

    } PEB_LDR_DATA, *PPEB_LDR_DATA;

   typedef struct _LDR_DATA_TABLE_ENTRY
    {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        LIST_ENTRY InInitializationOrderLinks;
        PVOID DllBase;                             // Base address of the module
        PVOID EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
        ULONG  Flags;
        USHORT LoadCount;
        USHORT TlsIndex;
        LIST_ENTRY HashLinks;
        PVOID SectionPointer;
        ULONG CheckSum;
        ULONG TimeDateStamp;
        PVOID LoadedImports;
        PVOID EntryPointActivationContext;
        PVOID PatchInformation;
        PVOID Unknown1;
        PVOID Unknown2;
        PVOID Unknown3;

    } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;


typedef struct _PEB
    {
        BOOLEAN InheritedAddressSpace;      // These four fields cannot change unless the
        BOOLEAN ReadImageFileExecOptions;   //
        BOOLEAN BeingDebugged;              //
        BOOLEAN BitField;                  // reserved for bitfields with system-specific flags

        HANDLE Mutant;                      // INITIAL_PEB structure is also updated.

        PVOID ImageBaseAddress;
        PPEB_LDR_DATA Ldr;
        PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
        PVOID SubSystemData;
        PVOID ProcessHeap;
        

        PSLIST_HEADER AtlThunkSListPtr;
        PVOID IFEOKey;
        ULONG CrossProcessFlags;
        union {
            PVOID KernelCallbackTable;
            PVOID UserSharedInfoPtr;
        };

        DWORD SystemReserved;
        DWORD  AtlThunkSListPtr32;
        PVOID ApiSetMap;

        PVOID TlsExpansionCounter;
        PVOID TlsBitmap;
        DWORD  TlsBitmapBits[2];         // relates to TLS_MINIMUM_AVAILABLE

        PVOID ReadOnlySharedMemoryBase;
        PVOID SharedData;
        PVOID *ReadOnlyStaticServerData;
        PVOID AnsiCodePageData;
        PVOID OemCodePageData;
        PVOID UnicodeCaseTableData;

        //
        // Useful information for LdrpInitialize

        ULONG NumberOfProcessors;
        ULONG NtGlobalFlag;

        //
        // Passed up from MmCreatePeb from Session Manager registry key
        //

        LARGE_INTEGER CriticalSectionTimeout;
        PVOID HeapSegmentReserve;
        PVOID HeapSegmentCommit;
        PVOID HeapDeCommitTotalFreeThreshold;
        PVOID HeapDeCommitFreeBlockThreshold;

        //
        // Where heap manager keeps track of all heaps created for a process
        // Fields initialized by MmCreatePeb.  ProcessHeaps is initialized
        // to point to the first free byte after the PEB and MaximumNumberOfHeaps
        // is computed from the page size used to hold the PEB, less the fixed
        // size of this data structure.
        //

        DWORD NumberOfHeaps;
        DWORD MaximumNumberOfHeaps;
        PVOID *ProcessHeaps;

        //
        //
        PVOID GdiSharedHandleTable;
        PVOID ProcessStarterHelper;
        PVOID GdiDCAttributeList;
        

        //
        // Following fields filled in by MmCreatePeb from system values and/or
        // image header. These fields have changed since Windows NT 4.0,
        // so use with caution
        //

        DWORD OSMajorVersion;
        DWORD OSMinorVersion;
        USHORT OSBuildNumber;
        USHORT OSCSDVersion;
        DWORD OSPlatformId;
        DWORD ImageSubsystem;
        DWORD ImageSubsystemMajorVersion;

        PVOID ImageSubsystemMinorVersion;
        PVOID ImageProcessAffinityMask;
        PVOID GdiHandleBuffer[GDI_HANDLE_BUFFER_SIZE];

        // [...] - more fields are there: this is just a fragment of the PEB structure
} PEB, *PPEB;
typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
}SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;
 
typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION , *PSYSTEM_PROCESS_INFORMATION;

typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER Reserved1[3];
    ULONG Reserved2;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG Reserved3;
    ULONG ThreadState;
    ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_SPECULATION_CONTROL_INFORMATION {
    struct {
        ULONG BpbEnabled : 1;
        ULONG BpbDisabledSystemPolicy : 1;
        ULONG BpbDisabledNoHardwareSupport : 1;
        ULONG SpecCtrlEnumerated : 1;
        ULONG SpecCmdEnumerated : 1;
        ULONG IbrsPresent : 1;
        ULONG StibpPresent : 1;
        ULONG SmepPresent : 1;
        ULONG SpeculativeStoreBypassDisableAvailable : 1;
        ULONG SpeculativeStoreBypassDisableSupported : 1;
        ULONG SpeculativeStoreBypassDisabledSystemWide : 1;
        ULONG SpeculativeStoreBypassDisabledKernel : 1;
        ULONG SpeculativeStoreBypassDisableRequired : 1;
        ULONG BpbDisabledKernelToUser : 1;
        ULONG SpecCtrlRetpolineEnabled : 1;
        ULONG SpecCtrlImportOptimizationEnabled : 1;
        ULONG Reserved : 16;
    } SpeculationControlFlags;
} SYSTEM_SPECULATION_CONTROL_INFORMATION, * PSYSTEM_SPECULATION_CONTROL_INFORMATION;

typedef struct _SYSTEM_KERNEL_VA_SHADOW_INFORMATION {
    struct {
        ULONG KvaShadowEnabled:1;
        ULONG KvaShadowUserGlobal:1;
        ULONG KvaShadowPcid:1;
        ULONG KvaShadowInvpcid:1;
        ULONG KvaShadowRequired:1;
        ULONG KvaShadowRequiredAvailable:1;
        ULONG InvalidPteBit:6;
        ULONG L1DataCacheFlushSupported:1;
        ULONG L1TerminalFaultMitigationPresent:1;
        ULONG Reserved:18;
    } KvaShadowFlags;
} SYSTEM_KERNEL_VA_SHADOW_INFORMATION, * PSYSTEM_KERNEL_VA_SHADOW_INFORMATION;
typedef struct _SYSTEM_PERFORMANCE_INFORMATION {
    BYTE Reserved1[312];
} SYSTEM_PERFORMANCE_INFORMATION;
typedef struct _SYSTEM_INTERRUPT_INFORMATION {
    BYTE Reserved1[24];
} SYSTEM_INTERRUPT_INFORMATION;

typedef struct _SYSTEM_TIMEOFDAY_INFORMATION {
    BYTE Reserved1[48];
} SYSTEM_TIMEOFDAY_INFORMATION;

 typedef struct _SYSTEM_PROC_LITE {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    PVOID Reserved2[3];
    HANDLE UniqueProcessId;
    PVOID Reserved3;
    ULONG HandleCount;
    BYTE Reserved4[4];
    PVOID Reserved5[11];
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved6[6];
} SYSTEM_PROCESS_LITE;
 
}; using namespace arch;
extern "C" NTSTATUS WINAPI ZwQuerySystemInformation(
  _In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
  _Inout_   PVOID                    SystemInformation,
  _In_      ULONG                    SystemInformationLength,
  _Out_opt_ PULONG                   ReturnLength
);
EXTERN_C NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(__in PEPROCESS Process);
 



