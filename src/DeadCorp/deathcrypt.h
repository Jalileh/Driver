#pragma once
#include "defines.h" 
#include "utils.h"



  
auto inline decrypt(wchar_t * str)
{  
  auto nix = str;
  while(*nix != L'\0')
  {   
            *nix = *nix ^ L'D'; 
            nix++;
  }
}
 