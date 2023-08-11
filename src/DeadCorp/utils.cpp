#include "defines.h"
#include "utils.h"
void tool::sleep(int ms)
{
    LARGE_INTEGER time;  
	  time.QuadPart = -(ms) * 10 * 1000; //10000 = 1ms 1000= 100ys 100 = 10ys 10= 1ys 
	  KeDelayExecutionThread(KernelMode, TRUE, &time); 

}
void tool::zprint(const char * str)
{ 
#ifdef DEBUG
    auto buffer = tool::combine_str(str, ".");
    DbgPrintEx(0, 0, buffer);
    tool::FreePool(buffer);
#endif
}

NTSTATUS tool::CreateSystemThread(PKSTART_ROUTINE StartRoutine)
{  
    HANDLE hThread;
    OBJECT_ATTRIBUTES oa;
    NTSTATUS status;

    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = PsCreateSystemThread(&hThread, 0, &oa, NULL, NULL, StartRoutine, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return status;
}
void* tool::get_system_information(SYSTEM_INFORMATION_CLASS information_class) 
{
        unsigned long size = 32;
        char buffer[32];

        ZwQuerySystemInformation(information_class, buffer, size, &size);

        void* info = ExAllocatePoolZero(NonPagedPool, size, 'amfd');
        if (!info)
            return nullptr;

        if (!NT_SUCCESS(ZwQuerySystemInformation(information_class, info, size, &size))) {
            ExFreePool(info);
            return nullptr;
        }

        return info;
}
 
void tool::Display_KernelModulesinfo()
{
	ULONG info = 0;
	NTSTATUS status = 0;
    
        status = ZwQuerySystemInformation(SystemModuleInformation, 0, info, &info);

		if (!info) {
			return;
		}

		PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolZero(NonPagedPool, info, 'amdf');

		status = ZwQuerySystemInformation(SystemModuleInformation, modules, info, &info);

		if (!NT_SUCCESS(status)) {
			return;
		}

	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
    uint64 * modulebase = 0;

        for (ULONG walkModules = 0; walkModules < modules->NumberOfModules; walkModules++, module++)
        {   
          
            modulebase = recast<uint64*>(module->ImageBase);
            DbgPrintEx(0, 0, "Path: %s", module->FullPathName );
            DbgPrintEx(0, 0, " ModBase: %p\n", modulebase );
          
        }

    ExFreePool(modules);
}
NTSTATUS tool::find_process(char* process_name, PEPROCESS* process)
{
        PEPROCESS sys_process = PsInitialSystemProcess;
        PEPROCESS curr_entry = sys_process;
        char image_name[15];

        do {
            RtlCopyMemory((PVOID)(&image_name), (PVOID)((uintptr_t)curr_entry + 0x5a8), sizeof(image_name));

            if (strstr(image_name, process_name)) {
                DWORD active_threads;
                RtlCopyMemory((PVOID)&active_threads, (PVOID)((uintptr_t)curr_entry + 0x5f0), sizeof(active_threads));
                if (active_threads) {
                    *process = curr_entry;
                    return STATUS_SUCCESS;
                }
            }

            PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry)+0x448);
            curr_entry = (PEPROCESS)((uintptr_t)list->Flink - 0x448);

        } while (curr_entry != sys_process);

        return STATUS_NOT_FOUND;
}

 

PVOID tool::PtrExchange(void_ptr * target, void_ptr impostor, int align)
{
  void_ptr original = 0;

        if(target && impostor)
        {
            if(align != NULL){
                  byte_ptr deref_target = *recast<byte_ptr*>(target);
                  deref_target += align;
                  *target = recast<void_ptr>(deref_target);
            }    
              original = InterlockedExchangePointer(target, impostor);

                  if(recast<qword_ptr>(*target) == recast<qword_ptr>(impostor))
                  {
                      print("sucess swap");
                  }  
        }
        return original;
}


 

void tool::zoutput(const char * msg, uint64 * Address_ID, void_ptr VP,  void(*tlfree)(void_ptr))
{
  #ifdef DEBUG

    if(Address_ID != NULL)
    { 
        auto str = tool::combine_str(msg, "%I64X\n");
        DbgPrintEx(0, 0, str, recast<uint64*>(Address_ID)); 
        tool::FreePool(recast<void_ptr>(str));
    }
    else
    {
        DbgPrintEx(0,0, msg);
    }

    if(tlfree)
    { 
        if(VP)
        {
          tlfree(VP);
        }
        else
        {
          DbgPrintEx(0, 0, "already Freed");
        }
    }
  #endif
}
void_ptr tool::cbError_msg(const char * msg, void_ptr res, int error, void(*CbMsg)(const char * , uint64*, void_ptr, void(*)(void_ptr)))
{ 
#ifdef DEBUG
  if(!res)
    goto cb2;
  else if(error == *recast<int*>(res))
  { cb2:
        const char * estr = "\nCRIT_ERROR: ";   
          auto CBM = tool::combine_str(estr, msg); 
          CbMsg(CBM, 0, CBM, &tool::FreePool);
  }
#endif
    return res;
}
char * tool::combine_str(const char * str1, const char * str2, bool Disable_NewLine)
{
  void_ptr tomem = 0;
  byte_ptr move_pos = 0;
  size_t length = 0,
  strSize1 = 0,
  strSize2 = 0;
    
    length = (strlen(str1) + strlen(str2));
    strSize1 = strlen(str1),
    strSize2 = strlen(str2);
    tomem = allocPool_NP(length + 1);
    memcpy(tomem, str1, strSize1);
    
  move_pos = reinterpret_cast<byte_ptr>(tomem) + (strSize1);
  memcpy(reinterpret_cast<void_ptr>(move_pos), str2, strSize2);
        
    if(Disable_NewLine == FALSE)
    {
       auto annot = reinterpret_cast<byte_ptr>(tomem) + (length);
      *annot = '\n';
    }

  return reinterpret_cast<char*>(tomem);
}
#define driver_tag 'AMD5' //? TAG FOR ALLOCATING

void_ptr tool::allocPool_NP(size_t size)
{
  void_ptr VP = 0;
  KIRQL oldIrq = 0;

  KeRaiseIrql(DISPATCH_LEVEL, &oldIrq);
  VP = ExAllocatePoolZero(NonPagedPool, size, driver_tag);
  KeLowerIrql(oldIrq);
  return VP;
}
void tool::FreePool( void_ptr VP)
{
  KIRQL oldIrq = 0;
  KeRaiseIrql(DISPATCH_LEVEL, &oldIrq);
  ExFreePoolWithTag(VP, driver_tag);
  KeLowerIrql(oldIrq);
  return;
}
void cb_freeStr(const char * Label,  void(*cbFreePool)(void_ptr)){

}
 
void tool::zprintval(const char * Label , void_ptr value, const char * type )
{
#ifdef DEBUG
    
    if(!strcmp(type, "qword"))
    {
      auto str = tool::combine_str(Label, "%I64X\n"  );
      DbgPrintEx(0,0, str , *recast<uint64*>(value));
      FreePool(recast<void_ptr>(str));
    }
    else if(!strcmp(type, "byte"))
    {
      auto str = tool::combine_str(Label, "%02x\n" );
      DbgPrintEx(0,0, str , *(byte_ptr)(value));
      FreePool(recast<void_ptr>(str));
    }
    else if(!strcmp(type, "wbyte"))
    {
      auto str = tool::combine_str(Label, "%S\n" );
      DbgPrintEx(0,0, str , *recast<wchar_t*>(value));
      FreePool(recast<void_ptr>(str));
    }
     else if(!strcmp(type, "wbyte"))
    {
      auto str = tool::combine_str(Label, "%S\n" );
      DbgPrintEx(0,0, str , *recast<wchar_t*>(value));
      FreePool(recast<void_ptr>(str));
    } 
    else if(!strcmp(type, "int"))
    {
      auto str = tool::combine_str(Label, "%d\n" );
      DbgPrintEx(0,0, str , *recast<int*>(value));
      FreePool(recast<void_ptr>(str));
    }
    
#endif
}

PVOID tool::GetModuleBase(LPCSTR moduleName) {

		PVOID moduleBase = NULL;
		ULONG info = 0;
		NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, info, &info);

		if (!info) {
			return moduleBase;
		}

		PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolZero(NonPagedPool, info, 'amd5');
    
		status = ZwQuerySystemInformation(SystemModuleInformation, modules, info, &info);

		if (!NT_SUCCESS(status)) {
			return moduleBase;
		}

		PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;

  
		if (modules->NumberOfModules > 0) {

			if (!moduleName) {
				moduleBase = modules->Modules[0].ImageBase;
			}
			else {

				for (auto i = 0; (ULONG)i < modules->NumberOfModules; i++) {
          
					if (!strcmp((CHAR*)module[i].FullPathName, moduleName)) {
						moduleBase = module[i].ImageBase;
					}
				}
			}
		}

		if (modules) {
			tool::FreePool(modules);
		}

		return moduleBase;
}


KAPC_STATE tool::attachtoProcess(char * Name, bool Grab_Process_Only )
{
  PEPROCESS winload = 0;
  KAPC_STATE state = {0};
  NTSTATUS error = tool::find_process(Name, &winload);
    
  if(error == STATUS_NOT_FOUND)
  {
    output("Unable to find Process for attachment!");
        return state;
  }
  else
  {
    if(!Grab_Process_Only)
      KeStackAttachProcess(winload, &state);

        return state;
  }
}