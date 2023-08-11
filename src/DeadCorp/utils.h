#pragma once
#include "defines.h"
#include "arch.h"
namespace tool {


  void zprint(const char * str);
  void zoutput(const char * msg, uint64 * Address_ID = 0, void_ptr VP = 0,  void(*tlfree)(void_ptr) = 0);
  void zprintval(const char * Label , void_ptr value, const char * type = "qword");
}

#if defined(DEBUG)
    #define print tool::zprint
    #define output tool::zoutput
    #define printval tool::zprintval
#else
    #define print(content)
    #define output(msg, ...)
    #define printval(Label, ...)
#endif


namespace tool {  
  void_ptr cbError_msg(const char * msg, void_ptr res, int error, void(*CbMsg)(const char * , uint64*, void_ptr, void(*)(void_ptr)));
  char * combine_str(const char * str1, const char * str2, bool Disable_NewLine = false );
  void_ptr allocPool_NP(size_t size);
  void FreePool( void_ptr VP);
  PVOID GetModuleBase(LPCSTR moduleName);
  PVOID PtrExchange(void_ptr * target, void_ptr impostor, int align = 0);
  
  void sleep(int ms);
  NTSTATUS CreateSystemThread(PKSTART_ROUTINE StartRoutine);
  void* get_system_information(SYSTEM_INFORMATION_CLASS information_class);
  void Display_KernelModulesinfo();
  NTSTATUS find_process(char* process_name, PEPROCESS* process);
  KAPC_STATE attachtoProcess(char * Name, bool Grab_Process_Only = false);

} 

constexpr char encryptionKey = 'K';  
constexpr wchar_t w_encryptionKey = L'K'; 

constexpr char encryptChar(char c)
{
    return c ^ encryptionKey;  
}
constexpr wchar_t w_encryptChar(wchar_t c)
{
    return c ^ w_encryptionKey;  
}

#define BIG 15
namespace crypt 
{
template <size_t N>
constexpr auto encrypt(const char (&str)[N])
{
     char* encrypted = (char*)tool::allocPool_NP(N + 1);
    for (size_t i = 0; i < N; i++)
    {
        encrypted[i] = encryptChar(str[i]);
    }
        encrypted[N] = '\0';
    return encrypted;
}
template <size_t N>
constexpr auto w_encrypt(const wchar_t (&str)[N])
{
    wchar_t* encrypted =  (wchar_t*)tool::allocPool_NP(N + 1);
    for (size_t i = 0; i < N; i++)
    {
        encrypted[i] = w_encryptChar(str[i]);
    }
        
    return encrypted;
}
wchar_t * w_crypt(wchar_t * encrypted);
char * crypt(char* encrypted);




}