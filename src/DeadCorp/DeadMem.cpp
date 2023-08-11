#include "defines.h" 
#include "DeadCorp.h"
#include "utils.h"
#include "deathcrypt.h"



typedef unsigned char * pbyte;
typedef unsigned long * plong;
typedef unsigned long long * pqword;
typedef unsigned short * pword;

/*?!
typedef int _KSTACK_COUNT;
typedef struct _KPROCESS
{
//?   struct _DISPATCHER_HEADER Header;                                       //0x0
//?   struct _LIST_ENTRY ProfileListHead;                                     //0x18
//?   ULONGLONG DirectoryTableBase;                                           //0x28
//?   struct _LIST_ENTRY ThreadListHead;                                      //0x30
//?   ULONG ProcessLock;                                                      //0x40
//?   ULONG ProcessTimerDelay;                                                //0x44
//?   ULONGLONG DeepFreezeStartTime;                                          //0x48
//?   typedef struct _KAFFINITY_EX Affinity;                                          //0x50
//?   struct _LIST_ENTRY ReadyListHead;                                       //0x158
//?   struct _SINGLE_LIST_ENTRY SwapListEntry;                                //0x168
//?   typedef volatile struct _KAFFINITY_EX ActiveProcessors;                         //0x170
//?   ULONG PROCESS_FLAGS;
//?   ULONG ActiveGroupsMask;                                                 //0x27c
//?   CHAR BasePriority;                                                      //0x280
//?   CHAR QuantumReset;                                                      //0x281
//?   CHAR Visited;                                                           //0x282
//?   typedef union _KEXECUTE_OPTIONS Flags;                                          //0x283
//?   USHORT ThreadSeed[32];                                                  //0x284
//?   USHORT IdealProcessor[32];                                              //0x2c4
//?   USHORT IdealNode[32];                                                   //0x304
//?   USHORT IdealGlobalNode;                                                 //0x344
//?   USHORT Spare1;                                                          //0x346
//?    _KSTACK_COUNT StackCount;                                 //0x348
//?   struct _LIST_ENTRY ProcessListEntry;                                    //0x350
//?   ULONGLONG CycleTime;                                                    //0x360
//?   ULONGLONG ContextSwitches;                                              //0x368
//?   struct _KSCHEDULING_GROUP* SchedulingGroup;                             //0x370
//?   ULONG FreezeCount;                                                      //0x378
//?   ULONG KernelTime;                                                       //0x37c
//?   ULONG UserTime;                                                         //0x380
//?   ULONG ReadyTime;                                                        //0x384
//?   ULONGLONG UserDirectoryTableBase;                                       //0x388
//?   UCHAR AddressPolicy;                                                    //0x390
//?   UCHAR Spare2[71];                                                       //0x391
//?   VOID* InstrumentationCallback;                                          //0x3d8
//?   union
//?   {
//?       ULONGLONG SecureHandle;                                             //0x3e0
//?       struct
//?       {
//?           ULONGLONG SecureProcess:1;                                      //0x3e0
//?           ULONGLONG Unused:1;                                             //0x3e0
//?       } Flags;                                                            //0x3e0
//?   } SecureState;                                                          //0x3e0
//?   ULONGLONG KernelWaitTime;                                               //0x3e8
//?   ULONGLONG UserWaitTime;                                                 //0x3f0
//?   ULONGLONG LastRebalanceQpc;                                             //0x3f8
//?   VOID* PerProcessorCycleTimes;                                           //0x400
//?   ULONGLONG ExtendedFeatureDisableMask;                                   //0x408
//?   USHORT PrimaryGroup;                                                    //0x410
//?   USHORT Spare3[3];                                                       //0x412
//?   VOID* UserCetLogging;                                                   //0x418
//?   struct _LIST_ENTRY CpuPartitionList;                                    //0x420
//?   ULONGLONG EndPadding[1];                                                //0x430
//? *qprocess; 
//? */

 

 


uint64 inline getcr3(PEPROCESS process)
{
    return *(qword_ptr)(recast<byte_ptr>(process) + 0x28);
}
uint64 inline getUserdir(PEPROCESS process)
{
    return *(qword_ptr) recast<byte_ptr>(process) + 0x388;
}

/*
 * Generic macros that allow you to quickly determine whether
 *  or not a page table entry is present or may forward to a
 *  large page of data, rather than another page table (applies
 *  only to PDPTEs and PDEs)
 */
#define IS_LARGE_PAGE(x)    ( (BOOLEAN)((x >> 7) & 1) )
#define IS_PAGE_PRESENT(x)  ( (BOOLEAN)(x & 1) )
 
/*
 * Macros allowing us to more easily deal with page offsets.
 *
 * The *_SHIFT values will allow us to correctly format physical
 *  addresses obtained using the bitfield structures below.
 *
 * The *_OFFSET macro functions will pull out physical page
 *  offsets from virtual addresses. This is only really to make handling
 *  1GB huge pages and 2MB large pages easier.
 * An example: 2MB large pages will require a 21-bit offset to index
 *  page data at one-byte granularity. So if we have the physical base address
 *  of a 2MB large page, in order to get the right physical address for our
 *  target data, we need to add the bottom 21-bits of a virtual address to this
*   base address. MAXUINT64 is simply a 64-bit value with every possible bit
*   set (0xFFFFFFFF`FFFFFFFF). In the case of a 2MB large page, we need the
*   bottom 21-bits from a virtual address to index, so we apply a function which
*   shifts this MAXUINT64 value by 21-bits, and then inverts all of the bits to
 *  create a mask that can pull out the bottom 21-bits of a target virtual
 *  address. The resulting mask is a value with only the bottom 21-bits of a 64-bit
 *  value set (0x1FFFFF). The below macro functions just make use of previous
 *  macros to make calculating this value easier, which sticks to theory and
 *  avoids magic values that have not yet been explained.
 */
 
#define PAGE_1GB_SHIFT      30
#define PAGE_1GB_OFFSET(x)  ( x & (~(MAXUINT64 << PAGE_1GB_SHIFT)) )
 
#define PAGE_2MB_SHIFT      21
#define PAGE_2MB_OFFSET(x)  ( x & (~(MAXUINT64 << PAGE_2MB_SHIFT)) )
 
#define PAGE_4KB_SHIFT      12
#define PAGE_4KB_OFFSET(x)  ( x & (~(MAXUINT64 << PAGE_4KB_SHIFT)) )
 
#pragma warning(push)
#pragma warning(disable:4214) // warning C4214: nonstandard extension used: bit field types other than int
 
/*
 * This is the format of a virtual address which would map a 4KB underlying
 *  chunk of physical memory
 */
typedef union _VIRTUAL_MEMORY_ADDRESS
{
    struct
    {
        UINT64 PageIndex : 12;  /* 0:11  */
        UINT64 PtIndex   : 9;   /* 12:20 */
        UINT64 PdIndex   : 9;   /* 21:29 */
        UINT64 PdptIndex : 9;   /* 30:38 */
        UINT64 Pml4Index : 9;   /* 39:47 */
        UINT64 Unused    : 16;  /* 48:63 */
    } Bits;
    UINT64 All;
} VIRTUAL_ADDRESS, *PVIRTUAL_ADDRESS;
 
/*
 * [Intel Software Development Manual, Volume 3A: Table 4-12]
 *  "Use of CR3 with 4-Level Paging and 5-level Paging and CR4.PCIDE = 0"
 */
typedef union _DIRECTORY_TABLE_BASE
{
    struct
    {
        UINT64 Ignored0         : 3;    /* 2:0   */
        UINT64 PageWriteThrough : 1;    /* 3     */
        UINT64 PageCacheDisable : 1;    /* 4     */
        UINT64 _Ignored1        : 7;    /* 11:5  */
        UINT64 PhysicalAddress  : 36;   /* 47:12 */
        UINT64 _Reserved0       : 16;   /* 63:48 */
    } Bits;
    UINT64 All;
} CR3, DIR_TABLE_BASE;
 
/*
 * [Intel Software Development Manual, Volume 3A: Table 4-15]
 *  "Format of a PML4 Entry (PML4E) that References a Page-Directory-Pointer Table"
 */
typedef union _PML4_ENTRY
{
    struct
    {
        UINT64 Present          : 1;    /* 0     */
        UINT64 ReadWrite        : 1;    /* 1     */
        UINT64 UserSupervisor   : 1;    /* 2     */
        UINT64 PageWriteThrough : 1;    /* 3     */
        UINT64 PageCacheDisable : 1;    /* 4     */
        UINT64 Accessed         : 1;    /* 5     */
        UINT64 _Ignored0        : 1;    /* 6     */
        UINT64 _Reserved0       : 1;    /* 7     */
        UINT64 _Ignored1        : 4;    /* 11:8  */
        UINT64 PhysicalAddress  : 40;   /* 51:12 */
        UINT64 _Ignored2        : 11;   /* 62:52 */
        UINT64 ExecuteDisable   : 1;    /* 63    */
    } Bits;
    UINT64 All;
} PML4E;
 
/*
 * [Intel Software Development Manual, Volume 3A: Table 4-16]
 *  "Table 4-16. Format of a Page-Directory-Pointer-Table Entry (PDPTE) that Maps a 1-GByte Page"
 */
typedef union _PDPT_ENTRY_LARGE
{
    struct
    {
        UINT64 Present            : 1;    /* 0     */
        UINT64 ReadWrite          : 1;    /* 1     */
        UINT64 UserSupervisor     : 1;    /* 2     */
        UINT64 PageWriteThrough   : 1;    /* 3     */
        UINT64 PageCacheDisable   : 1;    /* 4     */
        UINT64 Accessed           : 1;    /* 5     */
        UINT64 Dirty              : 1;    /* 6     */
        UINT64 PageSize           : 1;    /* 7     */
        UINT64 Global             : 1;    /* 8     */
        UINT64 _Ignored0          : 3;    /* 11:9  */
        UINT64 PageAttributeTable : 1;    /* 12    */
        UINT64 _Reserved0         : 17;   /* 29:13 */
        UINT64 PhysicalAddress    : 22;   /* 51:30 */
        UINT64 _Ignored1          : 7;    /* 58:52 */
        UINT64 ProtectionKey      : 4;    /* 62:59 */
        UINT64 ExecuteDisable     : 1;    /* 63    */
    } Bits;
    UINT64 All;
} PDPTE_LARGE;
 
/*
 * [Intel Software Development Manual, Volume 3A: Table 4-17]
 *  "Format of a Page-Directory-Pointer-Table Entry (PDPTE) that References a Page Directory"
 */
typedef union _PDPT_ENTRY
{
    struct
    {
        UINT64 Present          : 1;    /* 0     */
        UINT64 ReadWrite        : 1;    /* 1     */
        UINT64 UserSupervisor   : 1;    /* 2     */
        UINT64 PageWriteThrough : 1;    /* 3     */
        UINT64 PageCacheDisable : 1;    /* 4     */
        UINT64 Accessed         : 1;    /* 5     */
        UINT64 _Ignored0        : 1;    /* 6     */
        UINT64 PageSize         : 1;    /* 7     */
        UINT64 _Ignored1        : 4;    /* 11:8  */
        UINT64 PhysicalAddress  : 40;   /* 51:12 */
        UINT64 _Ignored2        : 11;   /* 62:52 */
        UINT64 ExecuteDisable   : 1;    /* 63    */
    } Bits;
    UINT64 All;
} PDPTE;
 
/*
 * [Intel Software Development Manual, Volume 3A: Table 4-18]
 *  "Table 4-18. Format of a Page-Directory Entry that Maps a 2-MByte Page"
 */
typedef union _PD_ENTRY_LARGE
{
    struct
    {
        UINT64 Present            : 1;    /* 0     */
        UINT64 ReadWrite          : 1;    /* 1     */
        UINT64 UserSupervisor     : 1;    /* 2     */
        UINT64 PageWriteThrough   : 1;    /* 3     */
        UINT64 PageCacheDisable   : 1;    /* 4     */
        UINT64 Accessed           : 1;    /* 5     */
        UINT64 Dirty              : 1;    /* 6     */
        UINT64 PageSize           : 1;    /* 7     */
        UINT64 Global             : 1;    /* 8     */
        UINT64 _Ignored0          : 3;    /* 11:9  */
        UINT64 PageAttributeTalbe : 1;    /* 12    */
        UINT64 _Reserved0         : 8;    /* 20:13 */
        UINT64 PhysicalAddress    : 29;   /* 49:21 */
        UINT64 _Reserved1         : 2;    /* 51:50 */
        UINT64 _Ignored1          : 7;    /* 58:52 */
        UINT64 ProtectionKey      : 4;    /* 62:59 */
        UINT64 ExecuteDisable     : 1;    /* 63    */
    } Bits;
    UINT64 All;
} PDE_LARGE;
 
/*
 * [Intel Software Development Manual, Volume 3A: Table 4-19]
 *  "Format of a Page-Directory Entry that References a Page Table"
 */
typedef union _PD_ENTRY
{
    struct
    {
        UINT64 Present            : 1;    /* 0     */
        UINT64 ReadWrite          : 1;    /* 1     */
        UINT64 UserSupervisor     : 1;    /* 2     */
        UINT64 PageWriteThrough   : 1;    /* 3     */
        UINT64 PageCacheDisable   : 1;    /* 4     */
        UINT64 Accessed           : 1;    /* 5     */
        UINT64 _Ignored0          : 1;    /* 6     */
        UINT64 PageSize           : 1;    /* 7     */
        UINT64 _Ignored1          : 4;    /* 11:8  */
        UINT64 PhysicalAddress    : 38;   /* 49:12 */
        UINT64 _Reserved0         : 2;    /* 51:50 */
        UINT64 _Ignored2          : 11;   /* 62:52 */
        UINT64 ExecuteDisable     : 1;    /* 63    */
    } Bits;
    UINT64 All;
} PDE;
 
/*
 * [Intel Software Development Manual, Volume 3A: Table 4-20]
 *  "Format of a Page-Table Entry that Maps a 4-KByte Page"
 */
typedef union _PT_ENTRY
{
    struct
    {
        UINT64 Present            : 1;    /* 0     */
        UINT64 ReadWrite          : 1;    /* 1     */
        UINT64 UserSupervisor     : 1;    /* 2     */
        UINT64 PageWriteThrough   : 1;    /* 3     */
        UINT64 PageCacheDisable   : 1;    /* 4     */
        UINT64 Accessed           : 1;    /* 5     */
        UINT64 Dirty              : 1;    /* 6     */
        UINT64 PageAttributeTable : 1;    /* 7     */
        UINT64 Global             : 1;    /* 8     */
        UINT64 _Ignored0          : 3;    /* 11:9  */
        UINT64 PhysicalAddress    : 38;   /* 49:12 */
        UINT64 _Reserved0         : 2;    /* 51:50 */
        UINT64 _Ignored1          : 7;    /* 58:52 */
        UINT64 ProtectionKey      : 4;    /* 62:59 */
        UINT64 ExecuteDisable     : 1;    /* 63    */
    } Bits;
    UINT64 All;
} PTE;
 
/*
 * Above I'm making use of some paging structures I
 *  created while parsing out definitions within the SDM.
 *  The address bits in the above structures should be
 *  right. You can also use the previously-mentioned
 *  Windows-specific general page table structure definition,
 *  which I have taken out of KD and added a definition
 *  for below.
 *
 * 1: kd> dt ntkrnlmp!_MMPTE_HARDWARE
 *    +0x000 Valid            : Pos 0, 1 Bit
 *    +0x000 Dirty1           : Pos 1, 1 Bit
 *    +0x000 Owner            : Pos 2, 1 Bit
 *    +0x000 WriteThrough     : Pos 3, 1 Bit
 *    +0x000 CacheDisable     : Pos 4, 1 Bit
 *    +0x000 Accessed         : Pos 5, 1 Bit
 *    +0x000 Dirty            : Pos 6, 1 Bit
 *    +0x000 LargePage        : Pos 7, 1 Bit
 *    +0x000 Global           : Pos 8, 1 Bit
 *    +0x000 CopyOnWrite      : Pos 9, 1 Bit
 *    +0x000 Unused           : Pos 10, 1 Bit
 *    +0x000 Write            : Pos 11, 1 Bit
 *    +0x000 PageFrameNumber  : Pos 12, 36 Bits
 *    +0x000 ReservedForHardware : Pos 48, 4 Bits
 *    +0x000 ReservedForSoftware : Pos 52, 4 Bits
 *    +0x000 WsleAge          : Pos 56, 4 Bits
 *    +0x000 WsleProtection   : Pos 60, 3 Bits
 *    +0x000 NoExecute        : Pos 63, 1 Bit
 */
typedef union _MMPTE_HARDWARE
{
    struct
    {
        UINT64 Valid               : 1;    /* 0     */
        UINT64 Dirty1              : 1;    /* 1     */
        UINT64 Owner               : 1;    /* 2     */
        UINT64 WriteThrough        : 1;    /* 3     */
        UINT64 CacheDisable        : 1;    /* 4     */
        UINT64 Accessed            : 1;    /* 5     */
        UINT64 Dirty               : 1;    /* 6     */
        UINT64 LargePage           : 1;    /* 7     */
        UINT64 Global              : 1;    /* 8     */
        UINT64 CopyOnWrite         : 1;    /* 9     */
        UINT64 Unused              : 1;    /* 10    */
        UINT64 Write               : 1;    /* 11    */
        UINT64 PageFrameNumber     : 36;   /* 47:12 */
        UINT64 ReservedForHardware : 4;    /* 51:48 */
        UINT64 ReservedForSoftware : 4;    /* 55:52 */
        UINT64 WsleAge             : 4;    /* 59:56 */
        UINT64 WsleProtection      : 3;    /* 62:60 */
        UINT64 NoExecute           : 1;    /* 63 */
    } Bits;
    UINT64 All;
} MMPTE_HARDWARE;
 
#pragma warning(pop)
 


BOOLEAN
ReadPhysicalAddress(
    _In_ UINT64 Source,
    _In_ PVOID  Destination,
    _In_ UINT32 Length
    )
{
    /*
     * This function is just a wrapper to call MmCopyMemory
     */
 
    NTSTATUS status = STATUS_SUCCESS;
 
    SIZE_T bytesCopied = 0;
    MM_COPY_ADDRESS copyAddress = { 0 };
 
    copyAddress.PhysicalAddress.QuadPart = Source;
 
    status = MmCopyMemory(
        Destination,
        copyAddress,
        Length,
        MM_COPY_MEMORY_PHYSICAL,
        &bytesCopied
        );
 
    return NT_SUCCESS( status );
}

#define calctrans(x, y)  ( x << PAGE_4KB_SHIFT ) + ( y * 8 )
 
UINT64 GetTLB(PEPROCESS process, uint64 Address)
{     
    uint64 DIRBASE = 0;
     
        DIRBASE = getcr3(process);

            if(!DIRBASE)
            {
                auto Udir = getUserdir(process);
                printval("ERROR NO DIR USING USErDIR ->  ", &Udir);
                DIRBASE = Udir;
            }  
            

    printval("DirBase ->  ", &DIRBASE);
    return DIRBASE;
}
UINT64 CopePhys(UINT64 DirBase, UINT64 Address);

#define deadmem_log 0


#if deadmem_log == 1
#define DEBUG_phys
#endif


bool dm::ReadPhys(HANDLE pid, uint64 Address, size_t size, void_ptr physmeme)
{
    PEPROCESS process = {0};
    KAPC_STATE state = {0};
    auto error = PsLookupProcessByProcessId(pid, &process);

   

    if(error == STATUS_INVALID_CID)
    {
        print("INVALID CID PROCESS, PROCESS MAYBE DEAD!");
        return false;
    }

    if(!Address)
    {
        ObDereferenceObject(process);
        return false;        
    }    

   auto DirBase = GetTLB(process, Address);
   auto copePhys = CopePhys(DirBase, Address);

    if(!copePhys)
    {
        ObDereferenceObject(process);
        return false;        
    }    
    
   printval("VirtualAddress = ", &Address);
  
   printval("CopePhys Pasted =", &copePhys);
    
    
    
  ReadPhysicalAddress(copePhys, physmeme, (UINT32)size );
  ObDereferenceObject(process);

    return true;
}
#define NOT_PRESENT 941

UINT64 calc4kb(uint64 x, uint64 y)
{ 
    return calctrans(x, y); 
}

 

int NotPresent(UINT64 isPresent)
{
    if(isPresent == 0)
        return NOT_PRESENT;
    else
        return 0;
}

UINT64 CopePhys(UINT64 DirBase, UINT64 Address)
{
    VIRTUAL_ADDRESS virtAddr     = { 0 };
    DIR_TABLE_BASE  dirTableBase = { 0 };
    PML4E           pml4e        = { 0 };
    PDPTE           pdpte        = { 0 };
    PDPTE_LARGE     pdpteLarge   = { 0 };
    PDE             pde          = { 0 };
    PDE_LARGE       pdeLarge     = { 0 };
    PTE             pte          = { 0 };
    


    virtAddr.All = Address;
    dirTableBase.All = DirBase;

            
    ReadPhysicalAddress(calc4kb(dirTableBase.Bits.PhysicalAddress, virtAddr.Bits.Pml4Index), &pml4e, sizeof(PML4E));

    if(NotPresent(pml4e.Bits.Present) == NOT_PRESENT)
        return 0;

    ReadPhysicalAddress(calc4kb(pml4e.Bits.PhysicalAddress, virtAddr.Bits.PdptIndex), &pdpte, sizeof(PDPTE));

       if(NotPresent(pdpte.Bits.Present) == NOT_PRESENT)
        return 0;

    if ( IS_LARGE_PAGE(pdpte.All) == TRUE )
    {
        pdpteLarge.All = pdpte.All;
 
        return ( pdpteLarge.Bits.PhysicalAddress << PAGE_1GB_SHIFT )
            + PAGE_1GB_OFFSET( virtAddr.Bits.PageIndex );
    }

    ReadPhysicalAddress(calc4kb(pdpte.Bits.PhysicalAddress, virtAddr.Bits.PdIndex), &pde, sizeof(PDE));

       if(NotPresent(pde.Bits.Present) == NOT_PRESENT)
        return 0;

     if ( IS_LARGE_PAGE(pde.All) == TRUE )
    {
    
        pdeLarge.All = pde.All;
 
        return ( pdeLarge.Bits.PhysicalAddress << PAGE_2MB_SHIFT )
            + PAGE_2MB_OFFSET( Address );
    }

    ReadPhysicalAddress(calc4kb(pde.Bits.PhysicalAddress, virtAddr.Bits.PtIndex), &pte, sizeof(PTE));

     

      return ( pte.Bits.PhysicalAddress << PAGE_4KB_SHIFT )
        + virtAddr.Bits.PageIndex;
    
}




typedef struct Write_Operation_vir64
{
  PHYSICAL_ADDRESS address;
  UINT32 Length;
  pvoid Source;
  pvoid MapSpace;
  bool MapSpace_result;
} WO_VIRTUAL, * PWO_VIRTUAL;

#define _MAPSPACE_SUCCESS 1
#define _MAPSPACE_FAIL 0
#define _MAPIOSPACE_ERROR_NULL 0
#define MAPSPACE_MAP 1
#define MAPSPACE_UNMAP 0

    typedef void (*CALLBACK_MAPIOSPACE)(WO_VIRTUAL, bool);
    //* MAP == TRUE
    //? UMAP == FALSE
    void CBACK_MapIoSpace(WO_VIRTUAL & WO, bool MAP1_UNMAP0) 
    {
            if(MAP1_UNMAP0 == MAPSPACE_MAP)
            {
                   WO.MapSpace = MmMapIoSpace(WO.address, WO.Length, MmNonCached);

                  if(WO.MapSpace == _MAPIOSPACE_ERROR_NULL)
                      WO.MapSpace_result = _MAPSPACE_FAIL;
                  else
                      WO.MapSpace_result = _MAPSPACE_SUCCESS;
            }
            else if(WO.MapSpace_result == _MAPSPACE_SUCCESS && MAP1_UNMAP0 == MAPSPACE_UNMAP)
            {
                MmUnmapIoSpace(WO.MapSpace, WO.Length);
                print("SUCCESS WRITE WO OPERATION!");
            }
    }



bool Write_PhysicalAddress(uint64 Target_Address, pvoid Source_Address, UINT32 Length )
{
    if(!Target_Address || !Source_Address)
        return false;

    WO_VIRTUAL WO = {0};
    WO.address.QuadPart = (LONGLONG)Target_Address;
    WO.Length = Length;
    WO.Source = Source_Address;

    CBACK_MapIoSpace(WO, MAPSPACE_MAP);

	if (WO.MapSpace_result == _MAPSPACE_SUCCESS)
	{
		memcpy(WO.MapSpace, WO.Source, WO.Length);
        CBACK_MapIoSpace(WO, MAPSPACE_UNMAP);
		return true;
	}
	return false;
}
bool dm::WriteToPhys(HANDLE pid, uint64 Address, size_t size_write, void_ptr src_value)
{

    PEPROCESS process = {0};
    KAPC_STATE state = {0};
    auto error = PsLookupProcessByProcessId(pid, &process);

    if(error == STATUS_INVALID_CID)
    {
        print("INVALID CID PROCESS, PROCESS MAYBE DEAD!");
        return false;
    }

    if(!Address)
    {
        ObDereferenceObject(process);
        return false;        
    }    

   auto DirBase = GetTLB(process, Address);
   auto copePhys = CopePhys(DirBase, Address);

    if(!copePhys)
    {
        ObDereferenceObject(process);
        return false;        
    }   

   printval("VirtualAddress = ", &Address);
   printval("CopePhys Pasted =", &copePhys);
    
   Write_PhysicalAddress(copePhys, src_value, (UINT32)size_write);
  ObDereferenceObject(process);
    return false;
}



bool Attach(HANDLE pid, bool toggle)
{

    if(!toggle)
    {

        print("Detaching");
        KeDetachProcess();
        return false;
    }

    PEPROCESS process = {0};
    KAPC_STATE state = {0};
    PsLookupProcessByProcessId(pid, &process);
    KeStackAttachProcess(process, &state);    
    
    print("Attached Succesfully");

    return true;
}
bool virRead(uint64 Address, size_t size, void_ptr physmeme)
{
        memcpy(physmeme, (void_ptr)Address, size);

    print("Read Succesfully");
    return true;
}
bool dm::AttachRead(HANDLE pid, uint64 Address, size_t size, void_ptr physmeme)
{
    if(Attach(pid, true))
    {        
        virRead(Address, size, physmeme);
        Attach(0, false);    
        print("Success R/W");    
        return true;
    }   

  return false;
}