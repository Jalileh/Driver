#pragma once
#include "defines.h"
#include "arch.h"
#define uniprint %wZ\n
#define R 111
#define MASK 1
#define crit_error -0x915071
#define zero 0

typedef unsigned short int8u;


class DeadCorp 
{ public:
    static byte_ptr SmartPattern(unsigned char Pattern[], int size, void_ptr Start, int ALIGN = 0, bool Mode_MASK = false, const char * segment = ".data");
    static PIMAGE_NT_HEADERS getHeader(PVOID module);

  typedef struct CPU_INFO
  {
    PRTL_PROCESS_MODULE_INFORMATION KERNEL_data = zero;
    arch::PSYSTEM_PROCESS_INFO PROC_alt_data = zero;
    arch::PSYSTEM_PROCESS_INFORMATION PROC_data = zero;
    arch::PSYSTEM_THREAD_INFORMATION THREAD_data = zero;
    arch::PRTL_PROCESS_MODULES PROC_modules = zero;
  } * ptr_cpu_info;
    
};

typedef struct _hive_worker
{
  const char * ID;
  void_ptr  isolated_Data; 
  void_ptr (*toggleHive)(void_ptr work_code, void_ptr dataPointer);
  void_ptr dataPointer;

} * hiveWorker;

typedef struct SENTIENT_HIVE
{
  hiveWorker (*create_hiveWorker)(unsigned char Pattern[], int PREALIGN,  const char * pathModule, const char * region, const char * id);
} SENTIENT_HIVE, * HiveMaster;

namespace Api_DC { 

  HiveMaster Init_HiveMaster(void_ptr _HiveHandler);

}
 
typedef struct API_SYSMASTER
{
  arch::SYSTEM_INFORMATION_CLASS cpu_arg;
  const wchar_t * Name = zero;
  int flag = zero;
} api_sysMaster; 



typedef struct SYSTEM_MASTER_INTERFACE
{
  api_sysMaster * API_input;
  DeadCorp::ptr_cpu_info CPU_obj;

    void (*DumpCpu)(SYSTEM_MASTER_INTERFACE * _MASTER);
    uint64 (*find_exe_ByName)(SYSTEM_MASTER_INTERFACE * _MASTER);
    void (*Display_Exes)(SYSTEM_MASTER_INTERFACE * _MASTER);
    void (*find_kernel_function)(SYSTEM_MASTER_INTERFACE * _MASTER);
   
} * ptr_SysMaster;

 
namespace Api_DC 
{ 
  ptr_SysMaster init_sysMaster(void_ptr AOH = 0);
  bool unload_sysMaster(ptr_SysMaster  master);
}

class safe 
{ 
/*
  int PASSIVE_LEVEl = 0;    // Passive release level
  int LOW_LEVEl 0;         // Lowest interrupt level
  int APC_LEVEl 1;       // APC interrupt level
  int DISPATCH_LEVEl 2; // Dispatcher level
  int CMCI_LEVEl 5;
*/
public:
  void set_level( int8u newlevel);
  void revert_level();
private:
  int8u old_level = 0;
};

 
namespace dm
{
  bool AttachRead(HANDLE pid, uint64 Address, size_t size, void_ptr physmeme);
  bool ReadPhys(HANDLE pid, uint64 Address, size_t size, void_ptr physmeme);
  bool WriteToPhys(HANDLE pid, uint64 Address, size_t size_write, void_ptr src_value);

}
typedef struct _Process_Object
{
      wchar_t * HashName;
      uint64 ModuleBase;
      HANDLE oldHandle;
      int size_hash;
      int id;
      uint64 EPROCESS;
} PROCESS_OBJECT, * Process_Object;

typedef struct zProcess_Object_Query
{
  bool (*KnownProcess)(const wchar_t* ProcessName, uint64 & ModBase, Process_Object * out_aQueriedProc, int & notify_remote);
}_Process_Query, *Process_Object_Query;

#define NotFoundInQuery 0 
typedef struct zProcess_Object_Data_Manager
{
  bool (*QueryProcess)(wchar_t * Name, Process_Object * ManagedProcess_out );
  void (*RegisterData_Object)(wchar_t* Name, void_ptr handle, uint64 ModuleBase);
  Process_Object (*GetFreeRegisterObject)();

} _Process_Manager,*Process_Object_Manager;

#define Wants_Return_Only 0
namespace objs
{
  Process_Object_Query FetchProcs(Process_Object_Manager*  out_Manager);
  
}
int GetStringSize(void * source_buffer, int in_sizeof_type);

bool callback_GetKProcess(void(*callbackfunc)(pvoid kProcess, pvoid UM),pvoid UM, pvoid Handle, int & notify_remote);
