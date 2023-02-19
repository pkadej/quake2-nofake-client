#include <stdio.h>

#ifdef PELLESC
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
BOOL APIENTRY DllMain(HINSTANCE hInstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	return(1);
}
#else
int _stdcall DLLMain(void *hinstDll,unsigned long dwReason,void *reserved)
{
	return(1);
}
#endif
