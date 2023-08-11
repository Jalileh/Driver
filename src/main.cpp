 
 
#include "DeadCorp/defines.h"
#include "DeadCorp/arch.h"
#include "cdriver.h"

 
/*   
#define POOL_ZERO_DOWN_LEVEL_SUPPORT
void win(DRIVER_RUNTIME_INIT_FLAGS flag)
{
  ExInitializeDriverRuntime(flag);
} //win(DrvRtPoolNxOptIn); < call
*/

NTSTATUS CopeDriver(_In_ PDRIVER_OBJECT  c1, _In_ PUNICODE_STRING c2)
{  
	UNREFERENCED_PARAMETER(c1), UNREFERENCED_PARAMETER(c2);
	
	cdriver::Driver_init();
	
 
	return STATUS_UNSUCCESSFUL;
}

 