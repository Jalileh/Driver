#include "DeadCorp/defines.h"
#include "DeadCorp/arch.h"
#include "DeadCorp/utils.h"
#include "DeadCorp/DeadCorp.h"
#include "DeadCorp/deathcrypt.h"
#define wait 100
#define KILL -0x917091
#include "cdriver.h"
 


/*
  ! R6 cheat = win32kfull.dll - win32kfull.sys
  *Wow Pattern =  00 78 00 C0 01 00 00 00 |> 60 7D 22 C0 01 00 00 00
*/
 
typedef int64(__fastcall * ip_Param3)(int64  a1, int64 a2, unsigned int a3);
typedef int64(__fastcall * ip_Param5)(int64 a1, unsigned int a2, int64 a3, int64 a4, unsigned int a5);
ip_Param3 param3;
ip_Param3 param33;
ip_Param5 param5;

static HiveMaster st_hivemaster;
static hiveWorker worker1;
 

#define COMM_READ_FROM_MODULE 0
#define COMM_READFROM_ADDRESS 1
#define COMM_WRITE_TO_ADDRESS 2
#define COMM_GETMODULE 3
#define COMM_NEWINSTANCE 0x400
#define COMM_CHECK_STATE 0x1900
#define COMM_ESTABLISHED 0x4932
#define COMM_WRITE_VIRTUAL 0x7879
#define COMM_DRIVER_RUNNING 0x19930

static void_ptr physmeme = 0;
typedef struct Commune
{ 
  uint64 ModuleBase;
  const wchar_t * ModuleName;
  int write;
  uint64 * value_ptr;
  int offset;
  bool unhook;
  bool crit_security;
  const char * RelayInfo;
  bool hide_module;
  void_ptr dump_analysis;
  size_t Size_Write;
  size_t Size_Read;
  uint64 Address;
  int mode;
  int stat;
  bool status_online;
} commune, * PCOMMUNE;

  static PCOMMUNE um_cb = zero;
   bool COMM_Error( const char * str, bool stat);
  bool COMM_callbackError( bool(*cb_error)(const char*, bool), const char * str, bool stat);
  uint64 GetProcess(const wchar_t * Name);
  void unhook(bool unhook);
  static bool passid = 0;

#define RelayInfo_allocated_Size 100

#ifdef DEBUG
#define commerr(str, error) COMM_callbackError(&COMM_Error, str, error)
#else
#define commerr(str, error)  return error
#endif



bool ReadModule(PCOMMUNE UM)
{  

    if(UM->ModuleName && UM->ModuleBase == NULL)
    {   
        Process_Object_Manager Manager = {0};
        Process_Object aQuieredProc = {0};
        auto funcs = objs::FetchProcs(&Manager);
        
        if(!funcs->KnownProcess(UM->ModuleName, UM->ModuleBase, &aQuieredProc, UM->stat))
            UM->ModuleBase = GetProcess((wchar_t*)UM->ModuleName);

        if(!passid)
        {
            memcpy((char *)UM->RelayInfo, worker1->ID, 100);
            tool::FreePool((void_ptr)worker1->ID);
            passid = true;
        }
        commerr("Got Module!", false);
    }
    return true;
}
 bool COMM_Error( const char * str, bool ret)
 {
    memcpy((char *)um_cb->RelayInfo, str, 100);
    return ret;
 }
    bool COMM_callbackError( bool(*cb_error)(const char*, bool), const char * str, bool stat)
    {
          return cb_error(str, stat);
    }
void ReadAddress(PCOMMUNE UM)
{
  if(!UM->ModuleBase)
    return;

  
    
    if(UM->mode == COMM_READFROM_ADDRESS)
    {    
        Process_Object aQueriedProc = {0}; Process_Object_Manager Manager = {0};
        auto funcs = objs::FetchProcs(&Manager);
          
        if(funcs->KnownProcess(UM->ModuleName, UM->ModuleBase, &aQueriedProc, UM->stat))
        {
          dm::ReadPhys(aQueriedProc->oldHandle, UM->Address, UM->Size_Read, UM->dump_analysis);
        }
    }
    else if(UM->mode == COMM_WRITE_VIRTUAL)
    {
        
        Process_Object aQueriedProc = {0}; Process_Object_Manager Manager = {0};
        auto funcs = objs::FetchProcs(&Manager);

        if(funcs->KnownProcess(UM->ModuleName, UM->ModuleBase, &aQueriedProc, UM->stat))
        {
          dm::WriteToPhys(aQueriedProc->oldHandle, UM->Address, UM->Size_Write, UM->value_ptr); 
        }
    }
}
  void GreatWall(PCOMMUNE UM)
  {
      if(UM->stat == COMM_NEWINSTANCE)
      {
        print("CD 1.0 V");
        print("New Connection");
        um_cb = UM;
        UM->stat = COMM_ESTABLISHED;
      }
      if(UM->mode == COMM_DRIVER_RUNNING)
      {
        UM->status_online = true;
      }
  }
void CommHandler(PCOMMUNE UM)
{ 
  GreatWall(UM);

    if(UM->mode == COMM_GETMODULE)
        ReadModule(UM);
    else  
    ReadAddress(UM);
}
int64 __fastcall Hooked_1(int64  a1, int64 a2, unsigned int a3)
{
    if(a3 == 0x194993)
    {         
        auto um = recast<PCOMMUNE>(a1);
        CommHandler(um);

          if(um->unhook)
            unhook(um->unhook);
    }
  return param3(a1, a2, a3);
}
void unhook(bool unhook)
{
      print("Unhooking...");
          worker1->toggleHive((void_ptr)param3, worker1->dataPointer);
}


 
void InitHook();

void cdriver::Driver_init()
{  
     InitHook();
}



static void_ptr st_hiveHandler;
#define cryptus(content) crypt::crypt(crypt::encrypt(content))
using namespace crypt;
void InitHook()
{ 
  using namespace Api_DC;
  using namespace tool;

    auto xkey5 = -39;
    HiveMaster hivemaster = Api_DC::Init_HiveMaster(st_hiveHandler);
 

    byte Pattern5[] = {0x48,0x8B,0x05,R,R,R,R,0x41,0x8B,0xD8,0x48,0x8B,0xFA,0x48,0x8B,0xF1,0x48,0x85,0xC0,0x74,0x08,0xFF,0x15,R,R,R,R,0xEB,0x05,0xB8,0xBB,R,R,0xC0,0x85,0xC0,0x78,0x31, R};
    Pattern5[21] = R;
    Pattern5[22] = R;
  
     
    auto region = cryptus(".text");
    auto Hive_ID = cryptus("Patel");

  
 auto hostModule = tool::combine_str(cryptus("win32k"), cryptus("base.sys"), true);

      hiveWorker hive_Patel = hivemaster->create_hiveWorker( Pattern5, 
                                                       xkey5, 
                                                        hostModule,
                                                        region, 
                                                        Hive_ID
                                                      );

    //FreePool(Hive_ID);
    FreePool(region);
    FreePool(hostModule);
  
    worker1 = hive_Patel;
  print(worker1->ID);

    param3 = (ip_Param3)  hive_Patel->toggleHive((void_ptr)&Hooked_1, hive_Patel->dataPointer);
    st_hivemaster = hivemaster;
}

      uint64 GetProcess(const wchar_t * Name)
      {
          auto sysm = Api_DC::init_sysMaster();
          sysm->API_input->cpu_arg = SystemProcessInformation;
          sysm->API_input->Name = Name;
          sysm->DumpCpu(sysm);
          uint64 addr = sysm->find_exe_ByName(sysm);
          printval("Found Address ", &addr);
          Api_DC::unload_sysMaster(sysm);
          return addr;
      }