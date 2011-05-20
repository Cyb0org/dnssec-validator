// dllmain.cpp : Implementation of DllMain.
#include "stdafx.h"
#include "resource.h"
#include "DNSSECValidator_i.h"
#include "dllmain.h"
#include <initguid.h>

CDNSSECValidatorModule _AtlModule;
//global hInstance, to be implemented when MSIE draws icons, StatusBarPane and their menus
HINSTANCE GHins;

// DLL Entry Point
extern "C" BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hInstance);
		GHins=hInstance;
    }
    return _AtlModule.DllMain(dwReason, lpReserved); 
}

