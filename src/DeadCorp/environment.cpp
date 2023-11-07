#include "defines.h" 
#include "DeadCorp.h"
#include "utils.h"
#include "deathcrypt.h"

#define alloc(content) tool::allocPool_NP(content)


 
#define Eprocess_FileName_Off 0x5a8
#define HashName_key L'D'
#define Max_Compare 4 

#define REMOTE_NOTIFY_DEAD 0x4EDD
#define REMOTE_NOTIFY_SAFE 1

bool callback_GetKProcess(void(*callbackfunc)(pvoid kProcess, pvoid _UM),pvoid UM, pvoid Handle, int & notify_remote){

  PEPROCESS  proc = {0}; 
  NTSTATUS  invalid_cid; 
  invalid_cid = PsLookupProcessByProcessId(Handle, &proc); 
  
          if(invalid_cid == STATUS_INVALID_CID) 
          { 
             notify_remote = REMOTE_NOTIFY_DEAD;
             return false;
          } 
                   
  callbackfunc(proc, UM);  
  ObDereferenceObject(proc);
  return true;
}
bool KnownProcess(const wchar_t* ProcessName, uint64 & ModBase, Process_Object  * out_aQueriedProc, int & notify_remote) 
{ 
  print(" KnownProcess Entry fetch PRE");
  bool Unknown = false; 
  Process_Object aQueriedProc = 0;
  Process_Object_Manager Manager = 0;
  objs::FetchProcs(&Manager);
  notify_remote = REMOTE_NOTIFY_DEAD;
  
    print(" KnownProcess Entry fetch Post");

       if(Manager->QueryProcess((wchar_t*)ProcessName, &aQueriedProc) == NotFoundInQuery) 
       { 
          print("KnownProcess(), !!QueryProcess fail. this process does not exist, returning false >: GetProcess > realloc SysMaster"); 
          return Unknown; 
       } 
       else 
       { 
            print("KnownProcess() FOUND ACQUIRED PROC in QueryCall!"); 
  
             if(aQueriedProc->oldHandle == nullptr) 
             { 
                print("KnownProcess() old handle got cleared elsewhere"); 
                return Unknown;  
             } 
             else 
             { 
                  PEPROCESS  proc = {0}; 
                  NTSTATUS  invalid_cid; 
                  invalid_cid = PsLookupProcessByProcessId(aQueriedProc->oldHandle, &proc); 
  
                   if(invalid_cid == STATUS_INVALID_CID) 
                   { 
                      notify_remote = REMOTE_NOTIFY_DEAD;
                      print("KnownProcess() INVALID CID DEAD PROCESS."); 
                   } 
                   else 
                   { 
                      uint64 pid_modulebase = (uint64)PsGetProcessSectionBaseAddress(proc); 
                      bool IsKnownProcess = true;  
                      byte_ptr ProcName = (byte_ptr)(proc) + Eprocess_FileName_Off; 
                      print((const char*)ProcName);
                      wchar_t * StoredHash = aQueriedProc->HashName;

                         for(; *ProcName;  StoredHash++, ProcName++) 
                         {    
                           char achar = (char) (*ProcName);

                               if(*StoredHash == (achar ^ HashName_key)) 
                                  IsKnownProcess = true;
                               else 
                               { 
                                  print("UNKNOWNPROCESS(LOOPSTR) NO MATCHING UNKNOWN");
                                    IsKnownProcess = false; 
                               } 
                         } 
  
                           if(IsKnownProcess) 
                           { 
                              print("Known Process, skipping sysMaster reallocation!"); 
                              ObDereferenceObject(proc); 
                                
                              if(pid_modulebase != aQueriedProc->ModuleBase)
                                  return false;

                              ModBase = pid_modulebase;    
                              *out_aQueriedProc = aQueriedProc;

                                
                              notify_remote = REMOTE_NOTIFY_SAFE;
                              return true; 
                           }
                           else
                           {
                                notify_remote = REMOTE_NOTIFY_DEAD;
                                ObDereferenceObject(proc); 
                           }
                   }     
             } 
       } 
   return Unknown; 
}

void_ptr AliveObjectHandler = NULL;
#define AOH_unitialized !AliveObjectHandler
typedef struct AliveObjects
{
  PROCESS_OBJECT Process[AOH_OBJHANDLER_MAX];
} ALIVEOBJ, * aliveObjects_ptr;

#define PROCESS_FOUND 1
#define PROCESS_UNKNOWN 0

bool QueryProcess(wchar_t * Name, Process_Object * ManagedProcess_out )
{
          print("Querying Managed Processes -------");  
              int HashSize = 4;
              aliveObjects_ptr aoh = recast<aliveObjects_ptr>(AliveObjectHandler);
              for(int i = 0; i < AOH_OBJHANDLER_MAX; i++)
              {
                   //! min 4 process name chars

                  
                    
                    if(!memcmp(Name, aoh->Process[i].HashName,  HashSize))
                    {
                        print("(QUERYPROCESS STRCMP LINK )Found Existing Object, returning");
                          *ManagedProcess_out = &aoh->Process[i];

                        return PROCESS_FOUND;                      
                    }
              }
  
  print("Failed to find its managed memory, register object instead ----------------");
  return NotFoundInQuery;
}
#define UNOCCUPIED_ID L'\0'
Process_Object GetFreeRegisterObject()
{
           print("GetFreeRegisterObject Called");

              aliveObjects_ptr aoh = recast<aliveObjects_ptr>(AliveObjectHandler);
              for(int i = 0; i < AOH_OBJHANDLER_MAX; i++)
              {
                printval("Checking object if occupied :", &aoh->Process[i].id, "int");

                    if(*aoh->Process[i].HashName == UNOCCUPIED_ID)
                    {   
                        print("Succesful Retrieval of free Process Manage Space!");
                        return &aoh->Process[i];
                    }
              }
  print("All Objects are already Occupied! RUNTIME ERROR:");
  return 0;
}      
void RegisterData_Object(wchar_t* Name, void_ptr handle, uint64 ModuleBase)
{

      print("RegisterDataObject Entry Page flow:");

      auto Object = GetFreeRegisterObject();

      print("Entry Page 2: Retrieved a free object slot");

      memcpy(Object->HashName, Name, 0x100);
      //Object->size_hash = GetStringSize(Object->HashName, sizeof(wchar_t));
      //printval("SizeHash", &Object->id, "int");
      Object->oldHandle = handle;
      Object->ModuleBase = ModuleBase;
      
      print("RegisterDataObject Entry exit sucessfully");
}
void setup_initialization(void_ptr in_aoh)
{
  aliveObjects_ptr aoh = recast<aliveObjects_ptr>(in_aoh);
            for(int i = 0; i < AOH_OBJHANDLER_MAX; i++)
            {
                aoh->Process[i].id = i;
                aoh->Process[i].HashName = (wchar_t*)alloc(0x100);
                //aoh->Process[i].oldHandle = (wchar_t*)alloc(8);
                aoh->Process[i].size_hash = 0;
            }
}
namespace global
{
  Process_Object_Query Process_Query = NULL;
  Process_Object_Manager Process_Manager = NULL;
}
void setup_QM(Process_Object_Query Process_Query, Process_Object_Manager Process_Manager)
{
  Process_Manager->RegisterData_Object = &RegisterData_Object;
  Process_Manager->GetFreeRegisterObject = &GetFreeRegisterObject;
  Process_Manager->QueryProcess = &QueryProcess;
  Process_Query->KnownProcess = &KnownProcess;
}
Process_Object_Query objs::FetchProcs(Process_Object_Manager * out_Manager)
{
    if(AliveObjectHandler == nullptr)
    {
        print("Initializing AOH RING:0 DATA MANAGER --------------------");
          AliveObjectHandler = alloc(sizeof(ALIVEOBJ));
          global::Process_Manager = (Process_Object_Manager) alloc(sizeof(_Process_Manager));
          global::Process_Query   = (Process_Object_Query) alloc(sizeof(_Process_Query));
          setup_initialization(AliveObjectHandler);
          setup_QM(global::Process_Query, global::Process_Manager);
        
      *out_Manager = global::Process_Manager;
      return global::Process_Query;
    }
    else
    {
      *out_Manager = global::Process_Manager;
      return global::Process_Query;
    }
    
}

#define max_pool 100
int GetStringSize(void * source_buffer, int in_sizeof_type)
{
 
    wchar_t * type_wchar = nullptr;
    char * type_char = nullptr;
    int result = 0;
    
        void * memBuffer = (void*)tool::allocPool_NP(max_pool);
        memcpy(memBuffer, source_buffer, max_pool);
            
            type_char = (char*)memBuffer;
            type_wchar = (wchar_t*)memBuffer;
            
        if(in_sizeof_type == sizeof(wchar_t))
        {
            for(; *type_wchar;  type_wchar++)
                result++;
        }
        else
        {
            for(; *type_char;  type_char++)
                result++;
        }
        
    tool::FreePool(memBuffer);
    return result;
}