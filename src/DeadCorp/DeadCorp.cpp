#include "defines.h" 
#include "DeadCorp.h"
#include "utils.h"
#include "deathcrypt.h"

#define global_zero 0
/*
 
section .text

global callptr

?hide:
    cmp rdx, 10
    je  equal
    ret
    equal:
    jmp rcx
    ret

 */
PIMAGE_NT_HEADERS DeadCorp::getHeader(PVOID module) {
		return (PIMAGE_NT_HEADERS)((byte_ptr)module + PIMAGE_DOS_HEADER(module)->e_lfanew);
}
byte_ptr travel(byte_ptr move, int Val)
{
  return (move + Val);
}


using namespace tool;

typedef struct Hook_body
{
  const char * Segment;
  bool Stack_RAX;
  int EXTRA_ALIGN;
  const char * attachName;
  const char * full_path;
  bool AutoHook;
  void (*ToggleHook)(Hook_body * Hook, bool off_on);
  qword_ptr DataPointer;
  qword_ptr original;
  qword_ptr OurHook;
  char * ID;
} Hook_BODY,  * HOOK_OBJECT; 
  void_ptr Hooker( unsigned char Signature[], int PRE_ALIGN, const char * ModuleName, void_ptr _INTERCEPTOR, HOOK_OBJECT  MODE );


void ToggleHook(HOOK_OBJECT Hook, bool off_on)
{ 
    if(off_on == FALSE)
      PtrExchange((void_ptr*)Hook->DataPointer,(qword_ptr) Hook->original );
    else
      PtrExchange((void_ptr*)Hook->DataPointer,(qword_ptr) Hook->OurHook);
}

void hook_log_args(const char * ModPath, qword_ptr ModuleBase)
{
  
  auto wrap = combine_str("Hooking ModPath ... ", ModPath);
  printval(wrap, &ModuleBase );
  FreePool((void_ptr)wrap);
}
void_ptr Hooker( unsigned char Signature[], int PRE_ALIGN, const char * ModuleName, void_ptr _INTERCEPTOR,  HOOK_OBJECT  MODE)
{ 
  using namespace tool;

  const char * ModPath = 0;
  qword_ptr Module = 0;
   
  
    if(MODE->full_path)
    {  
       
        ModPath = MODE->full_path;
        Module = (qword_ptr)tool::GetModuleBase(ModPath);
    }
    else
    {  
        ModPath = tool::combine_str(Root, ModuleName, true);
        
        Module = (qword_ptr)tool::GetModuleBase(ModPath);
    }

    if(!Module)
    {
      output("Error : Module Not Found!");
      FreePool((void_ptr)ModPath);
      return FAILURE;
    }
#ifdef DEBUG
    hook_log_args(ModPath, Module);
#endif

  qword_ptr interceptor = NULL;
  int alignment = zero;
  int sig_size = zero;
  qword_ptr dataPointer = NULL;

    interceptor = recast<qword_ptr>(_INTERCEPTOR);
    sig_size = (int)-PRE_ALIGN;
    alignment = PRE_ALIGN;
    printval("Signature Size = ", &sig_size, "int");
    dataPointer = (qword_ptr)DeadCorp::SmartPattern(Signature, sig_size, Module, alignment, MASK, MODE->Segment);

  bool attachFlag = NULL;
  KAPC_STATE state = {0};
  if(MODE->attachName != nullptr)
  {
    state = tool::attachtoProcess((char*)MODE->attachName);
    attachFlag = 1; 
  }


  if(MODE->Stack_RAX && dataPointer)
  {
    UINT64 qword_ptr_derf = (UINT64)(dataPointer);
     qword_ptr_derf = (UINT64)qword_ptr_derf + *(PINT)((PBYTE)qword_ptr_derf + 3) + 7;
      dataPointer = (qword_ptr)qword_ptr_derf;
  }

  PVOID Original = NULL;

      if(dataPointer)
      {
          output("Sucess:(DataPointer): Success scan!, Address :", (qword_ptr)dataPointer);
        
        if(!MODE->AutoHook){
          Original = dataPointer;
        }
        else
        {

         
          Original = tool::PtrExchange((void_ptr*)dataPointer, interceptor );
            MODE->DataPointer = dataPointer;
              MODE->original = (qword_ptr)Original;
              MODE->ToggleHook = &ToggleHook;
              MODE->OurHook = (qword_ptr)interceptor;
        }
      }
      else
      {
        output("Error: (DataPointer): Signature Fail!");
      }
      
  if(attachFlag)
    KeUnstackDetachProcess(&state);

  return Original;
}

typedef struct HIVE_handler
{
  void_ptr Data_entry[10];
  void_ptr worker_entries[10];
  int scope;
} HIVE_HANDLER, * hiveHandler;

static hiveHandler handler_hive = global_zero;
#define alloc(content) tool::allocPool_NP(content)

PVOID toggleHive(void_ptr work_code, void_ptr dataPointer)
{
  PVOID original = NULL;

  original = tool::PtrExchange((void_ptr*)dataPointer, work_code);
  return original;
}
hiveWorker create_hiveWorker(unsigned char Pattern[], int PREALIGN, const char * pathModule, const char * region, const char * id)
{
  int * scope = &handler_hive->scope;
  auto data_entry = handler_hive->Data_entry;
  auto worker_entries = handler_hive->worker_entries;
  hiveWorker worker = (hiveWorker) alloc(sizeof(_hive_worker));

  data_entry[*scope] = worker->isolated_Data;
  worker_entries[*scope] = worker;
   

  worker->ID = id;
  HOOK_OBJECT setup = (HOOK_OBJECT) alloc(sizeof(Hook_BODY));

  setup->Segment = region;
  setup->AutoHook = false;

  if(region[1] == 't')
      setup->Stack_RAX = true;

  if(pathModule[0] == '\\')
  {
      setup->full_path = pathModule;

  }
   
  worker->dataPointer = Hooker(Pattern, PREALIGN, pathModule, 0, setup);
  worker->toggleHive = &toggleHive;


  *scope++;
  return worker;
}
HiveMaster  Api_DC::Init_HiveMaster(void_ptr _HiveHandler)
{
  handler_hive = (hiveHandler)tool::allocPool_NP(sizeof(HIVE_HANDLER));
  HiveMaster  hivemaster = (HiveMaster)alloc(sizeof(SENTIENT_HIVE));
  hivemaster->create_hiveWorker =  &create_hiveWorker;

  _HiveHandler =  (void_ptr)handler_hive;
  return hivemaster;
}


  static int nearest_cig = 0;
  byte_ptr ScanInstance(int & sig_Index, bool Mode_MASK, int ALIGN, int sig_size, unsigned char Pattern[], byte_ptr scan_region);
 
byte_ptr DeadCorp::SmartPattern(unsigned char Pattern[], int sig_size,  void_ptr Start, int ALIGN, bool Mode_MASK, const char * segment)
{
    auto Header = getHeader(Start);
    int  Section_count = Header->FileHeader.NumberOfSections;
    auto section = IMAGE_FIRST_SECTION(Header);

      for(int region = 0; region < Section_count ; section++, region++)
      {
          if(memcmp(section->Name, segment, 5) == 0)
          {
            auto scan_region = recast<byte_ptr>(Start) + section->VirtualAddress;
            byte_ptr region_end = scan_region  + section->SizeOfRawData;
            int sig_Index = 0;

              for( scan_region ; scan_region != region_end  ; scan_region++ )
              { 
                auto found = ScanInstance(sig_Index, Mode_MASK, ALIGN, sig_size, Pattern, scan_region); 

                  if(found != FAILURE){
                    return found;
                  };
              }

          }
      }
         printval("Failed sig column: ", &nearest_cig, "int");
        return FAILURE;
}

 

#define RESET_SCAN 0 
byte_ptr ScanInstance(int & sig_Index, bool Mode_MASK, int ALIGN, int sig_size, unsigned char Pattern[], byte_ptr scan_region)
{
    if(sig_Index == sig_size){
      return travel(scan_region, ALIGN);
    }
    
      if(*scan_region == Pattern[sig_Index]){
        sig_Index++;
      }
      else
      {     if(Mode_MASK && sig_Index != NULL)
            {
                if(Pattern[sig_Index] == R)
                    sig_Index++;
                else{
                  if(nearest_cig < sig_Index)
                      nearest_cig = sig_Index;
                     
                      sig_Index = RESET_SCAN;
                } 
            }  
            else
                  sig_Index = RESET_SCAN;
  
      }
            return FAILURE;
} 


/*
int DeadCorp::str_GetSize(unsigned char Arg[])
{
    unsigned char Storing[100] = {0};
    int size_return = 0;

    RtlZeroMemory(Storing, 100);
        RtlCopyMemory(Storing, Arg, 100);
            for(int i = 0; i < 100; i++ ,size_return++)
                if(Storing[i] == 204)
                    return size_return;

    return 0;
}*/
 
void safe::set_level(int8u newlevel)
{
   KeRaiseIrql((KIRQL)newlevel, (PKIRQL)&this->old_level);
}
void safe::revert_level()
{
  KeLowerIrql((KIRQL)this->old_level);
} using namespace tool;

//? SYSTEM_MASTER API ///////////////////////////////////////////////////////////////////////////////
 
 
 

uint64 Find_Exe_ByName(SYSTEM_MASTER_INTERFACE * _MASTER)
{
  DeadCorp::ptr_cpu_info cpu = _MASTER->CPU_obj;
  api_sysMaster * api = _MASTER->API_input;
  UNICODE_STRING uniName = {zero};
  uint64 ModuleBase = zero;

    
    wchar_t uncryptName[0x100];
    memcpy(uncryptName, api->Name, 0x100);
    decrypt(uncryptName);
    RtlInitUnicodeString(&uniName, uncryptName);
      
        auto Process = cpu->PROC_data;
        bool found_proc = false;
        
          while (Process->NextEntryOffset)
          {   
              if(!RtlCompareUnicodeString(&uniName, &Process->ImageName, false))
              { 
                    PEPROCESS  proc;
                        
                        PsLookupProcessByProcessId(Process->UniqueProcessId, &proc);
                          
                    auto peb = PsGetProcessSectionBaseAddress(proc);
                    
                    if(!peb)
                    {

                        print("empty");
                    }
                    else  
                    {
                        output("Module", (uint64*)peb);
                    }

                    found_proc = true;
                    ModuleBase = (uint64)peb;

                      Process_Object_Manager Manager = {0};

                        objs::FetchProcs(&Manager);
                        Process_Object aQueriedProc = {0};
                        

                    if(Manager->QueryProcess((wchar_t*)api->Name, &aQueriedProc) == NotFoundInQuery)
                    {
                        Manager->RegisterData_Object((wchar_t*)api->Name, Process->UniqueProcessId,(uint64) ModuleBase);

                    }
                    else
                    {
                      aQueriedProc->ModuleBase = ModuleBase;
                      aQueriedProc->oldHandle = Process->UniqueProcessId;

                    }
                    ObDereferenceObject(proc);
                    //! BUGFIX FOR EXISting OBJ
                break;
              }
                  Process = reinterpret_cast<arch::PSYSTEM_PROCESS_INFORMATION>(
                  reinterpret_cast<ULONG_PTR>(Process) + Process->NextEntryOffset);
          }

    if(!found_proc)
    {
        print("Diagnostics: Could Not find Proc!");
    }
    return ModuleBase;
}

 
 
void display_procs(SYSTEM_MASTER_INTERFACE * _MASTER)
{
  DeadCorp::ptr_cpu_info cpu = _MASTER->CPU_obj;

   auto Process = cpu->PROC_data;

        while (Process->NextEntryOffset)
        {
          #ifdef DEBUG
            DbgPrintEx(0, 0, "%wZ\n", Process->ImageName);
          #endif
            Process = reinterpret_cast<arch::PSYSTEM_PROCESS_INFORMATION>(
                reinterpret_cast<ULONG_PTR>(Process) + Process->NextEntryOffset);
        }
}

DeadCorp::ptr_cpu_info cpu_obj_alloc()
{
  return recast<DeadCorp::ptr_cpu_info>(tool::allocPool_NP(sizeof(DeadCorp::CPU_INFO)));
}
 

void DumpCpu(SYSTEM_MASTER_INTERFACE * _MASTER)
{ using namespace tool;

  api_sysMaster * api = _MASTER->API_input;
  DeadCorp::ptr_cpu_info  cpu =  _MASTER->CPU_obj;
  void_ptr * Source = zero;

    if(api->cpu_arg == SystemProcessInformation)
           Source = (void_ptr*) &cpu->PROC_data;
    else
          Source = (void_ptr*) &cpu->KERNEL_data;
    
        
  ULONG info_length = zero;
      
      NTSTATUS info = ZwQuerySystemInformation(api->cpu_arg, 0, 0, &info_length );

      if(!info) { 
          print("Failed to Get System Processes! : Platform Error?");
          return;
      }
      
        print("Preparing process size DiagNostics:");
        *Source = tool::allocPool_NP(info_length);  
        ZwQuerySystemInformation(api->cpu_arg, *Source, info_length, 0);
}
ptr_SysMaster  Api_DC::init_sysMaster(void_ptr AOH)
{ 
  ptr_SysMaster Master = (ptr_SysMaster)tool::allocPool_NP(sizeof(SYSTEM_MASTER_INTERFACE));
  Master->API_input = (api_sysMaster*)tool::allocPool_NP(sizeof(API_SYSMASTER));
  Master->CPU_obj = cpu_obj_alloc();

    Master->DumpCpu = &DumpCpu;
    Master->Display_Exes = &display_procs;
    Master->find_exe_ByName = &Find_Exe_ByName;
  
  
   
  print("SysMaster Loaded");
  return Master;
}
  void FreeCpuObjs(ptr_SysMaster unload);
void clear_inputs(api_sysMaster *api)
{
    FreePool(api);
}
bool Api_DC::unload_sysMaster(ptr_SysMaster unload)
{  
  clear_inputs(unload->API_input);
  FreeCpuObjs(unload);
  FreePool(unload);

  return true;
}

//? POST CLEAN //////////////////////////////////////
void FreeCpuObjs(ptr_SysMaster unload)
{

 if(unload->CPU_obj != zero)
  {
      if(unload->CPU_obj->KERNEL_data != zero)
      {
        print("Diagnostics: Freeing Kernel");
        FreePool(unload->CPU_obj->KERNEL_data);
      }
      if(unload->CPU_obj->PROC_alt_data != zero)
      { 
        print("Diagnostics: Freeing alt PROC");
        FreePool(unload->CPU_obj->PROC_alt_data);
      }
      if(unload->CPU_obj->PROC_data != zero)
      {
        print("Diagnostics: Freeing PROC");
        FreePool(unload->CPU_obj->PROC_data);
      }
      if(unload->CPU_obj->PROC_modules != zero)
      {
        print("Diagnostics: Freeing Modules");
        FreePool(unload->CPU_obj->PROC_modules);
      }
      if(unload->CPU_obj->THREAD_data != zero)
      {
        print("Diagnostics: Freeing Core Data");
        FreePool(unload->CPU_obj->THREAD_data);
      }
  }
    
}
namespace crypt 
{ 
char * crypt(char * encrypted)
{
  char* decryptedString = encrypted;
  
    while (*decryptedString)
    {
        *decryptedString = encryptChar(*decryptedString);
          if(*decryptedString == '\0')
              break;

        ++decryptedString;
    }
    return encrypted;
}
wchar_t * w_crypt(wchar_t * encrypted)
{
  wchar_t * decryptedString = encrypted;

    while (*decryptedString)
    {
        *decryptedString = w_encryptChar(*decryptedString);
          if(*decryptedString == '\0')
              break;

        ++decryptedString;
    } 


    return encrypted;
}
}




