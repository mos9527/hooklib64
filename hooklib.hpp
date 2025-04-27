#pragma once
/* DEFINES BEGIN */
#ifndef HOOKLIB_MODULE_NAME
static_assert(false && "HOOKLIB_MODULE_NAME undefined. Change this to the Image name of your target DLL or NULL if you only need the main process.");
#endif // !MODULE_NAME
#define WIN32_LEAN_AND_MEAN

/* DEFINES END */

/* INCLUDES BEGIN */

#include <cstdint>
#include <stdlib.h>
#include <stdio.h>
#include <initializer_list>

#include <Windows.h>
#include <detours.h>
#include <Psapi.h>
#include <shellapi.h>
#include <commctrl.h>
#include <strsafe.h>

/* INCLUDES END*/

/* FUNCTIONS BEGIN */
static wchar_t* _moduleBaseName = nullptr;
FORCEINLINE const wchar_t* hooklibGetBaseName() 
{
    if (_moduleBaseName)
        return _moduleBaseName;

    _moduleBaseName = new wchar_t[1024];
    if (!GetModuleBaseNameW(GetCurrentProcess(), NULL, _moduleBaseName, 1024))
        delete _moduleBaseName, _moduleBaseName = nullptr;
    return _moduleBaseName;
}
#define HOOKLIB_IS_PROCESS(PROCESS_NAME) (lstrcmpW(hooklibGetBaseName(),PROCESS_NAME) == 0u)
static MODULEINFO* _moduleInfo = nullptr;
FORCEINLINE const MODULEINFO* hooklibGetModuleInfo()
{
    if (_moduleInfo)
        return _moduleInfo;

    _moduleInfo = new MODULEINFO();
    ZeroMemory(&_moduleInfo, sizeof(MODULEINFO));
    if (!GetModuleInformation(GetCurrentProcess(), GetModuleHandle((LPCSTR)HOOKLIB_MODULE_NAME), _moduleInfo, sizeof(MODULEINFO)))
        delete _moduleInfo, _moduleInfo = nullptr;
    return _moduleInfo;
}
FORCEINLINE void* hooklibSigScan(const char* signature, const char* mask, size_t sigSize, void* memory, const size_t memorySize)
{
    if (sigSize == 0)
        sigSize = strlen(mask);

    for (size_t i = 0; i < memorySize; i++)
    {
        char* currMemory = (char*)memory + i;

        size_t j;
        for (j = 0; j < sigSize; j++)
        {
            if (mask[j] != '?' && signature[j] != currMemory[j])
                break;
        }

        if (j == sigSize)
            return currMemory;
    }

    return nullptr;
}

FORCEINLINE void* hooklibSigScan(const char* signature, const char* mask, void* hint)
{
    const MODULEINFO* info = hooklibGetModuleInfo();
    if (info == nullptr)
        return nullptr;

    const size_t sigSize = strlen(mask);

    // Ensure hint address is within the process memory region so there are no crashes.
    if ((hint >= info->lpBaseOfDll) && ((char*)hint + sigSize <= (char*)info->lpBaseOfDll + info->SizeOfImage))
    {
        void* result = hooklibSigScan(signature, mask, sigSize, hint, sigSize);

        if (result)
            return result;
    }

    return hooklibSigScan(signature, mask, sigSize, info->lpBaseOfDll, info->SizeOfImage);
}

/* FUNCTIONS END */

/* MACROS BEGIN */
#ifdef _DEBUG
#define HOOKLIB_LOG(fmt,...) \
	{ \
		printf("[%s] ",__FILE__); \
		printf(fmt,__VA_ARGS__); \
		printf("\n"); \
	}
#else
#define HOOKLIB_LOG(fmt,...)
#endif

#define HOOKLIB_FUNCTION_PTR(returnType, callingConvention, function, location, ...) \
	returnType (callingConvention *function)(__VA_ARGS__) = (returnType(callingConvention*)(__VA_ARGS__))(location)

#define HOOKLIB_PROC_ADDRESS(libraryName, procName) \
	GetProcAddress(LoadLibrary(TEXT(libraryName)), procName)

#define HOOKLIB_RUNTIME_FUNCTION(returnType, callingConvention, libraryName, procName, ...) \
	typedef returnType callingConvention _##procName(__VA_ARGS__); \
	_##procName* procName = (_##procName*)HOOKLIB_PROC_ADDRESS(libraryName, #procName); 

#define HOOKLIB_HOOK(returnType, callingConvention, functionName, location, ...) \
	typedef returnType callingConvention _##functionName(__VA_ARGS__); \
	_##functionName* original##functionName = (_##functionName*)(location); \
	returnType callingConvention implOf##functionName(__VA_ARGS__)

#define HOOKLIB_INSTALL_HOOK(functionName) \
	{ \
		HOOKLIB_LOG("Installing hook %s at %llx",#functionName,original##functionName); \
		DetourTransactionBegin(); \
		DetourUpdateThread(GetCurrentThread()); \
		DetourAttach((void**)&original##functionName, implOf##functionName); \
		DetourTransactionCommit(); \
	}

#define HOOKLIB_WRITE_MEMORY(location, type, ...) \
	{ \
		const type data[] = { __VA_ARGS__ }; \
		DWORD oldProtect; \
		VirtualProtect((void*)(location), sizeof(data), PAGE_EXECUTE_READWRITE, &oldProtect); \
		memcpy((void*)(location), data, sizeof(data)); \
		VirtualProtect((void*)(location), sizeof(data), oldProtect, &oldProtect); \
	}

#define HOOKLIB_WRITE_NOP(location, count) \
	{ \
		DWORD oldProtect; \
		VirtualProtect((void*)(location), (size_t)(count), PAGE_EXECUTE_READWRITE, &oldProtect); \
		for (size_t i = 0; i < (size_t)(count); i++) \
			*((uint8_t*)(location) + i) = 0x90; \
		VirtualProtect((void*)(location), (size_t)(count), oldProtect, &oldProtect); \
	}

#define HOOKLIB_SIG_SCAN(x, y, ...) \
    inline void* x(); \
    inline void* x##Addr = x(); \
    inline void* x() \
    { \
        constexpr const char* x##Data[] = { __VA_ARGS__ }; \
        constexpr size_t x##Size = _countof(x##Data); \
        if (!x##Addr) \
        { \
            if constexpr (x##Size == 2) \
            { \
                x##Addr = hooklibSigScan(x##Data[0], x##Data[1], (void*)(y)); \
                if (x##Addr) \
                    return x##Addr; \
            } \
            else \
            { \
                for (int i = 0; i < x##Size; i += 2) \
                { \
                    x##Addr = hooklibSigScan(x##Data[i], x##Data[i + 1], (void*)(y)); \
                    if (x##Addr) \
                        return x##Addr; \
                } \
            } \
        } \
        return x##Addr; \
    }
/* MACROS END */


/* DLL SPOOFING BEGIN */
//  C:\Windows\System32\d3d9.dll (d3d9)
#pragma comment(linker, "/EXPORT:D3DPERF_BeginEvent=C:\\Windows\\System32\\d3d9.D3DPERF_BeginEvent")
#pragma comment(linker, "/EXPORT:D3DPERF_EndEvent=C:\\Windows\\System32\\d3d9.D3DPERF_EndEvent")
#pragma comment(linker, "/EXPORT:D3DPERF_GetStatus=C:\\Windows\\System32\\d3d9.D3DPERF_GetStatus")
#pragma comment(linker, "/EXPORT:D3DPERF_QueryRepeatFrame=C:\\Windows\\System32\\d3d9.D3DPERF_QueryRepeatFrame")
#pragma comment(linker, "/EXPORT:D3DPERF_SetMarker=C:\\Windows\\System32\\d3d9.D3DPERF_SetMarker")
#pragma comment(linker, "/EXPORT:D3DPERF_SetOptions=C:\\Windows\\System32\\d3d9.D3DPERF_SetOptions")
#pragma comment(linker, "/EXPORT:D3DPERF_SetRegion=C:\\Windows\\System32\\d3d9.D3DPERF_SetRegion")
#pragma comment(linker, "/EXPORT:DebugSetLevel=C:\\Windows\\System32\\d3d9.DebugSetLevel")
#pragma comment(linker, "/EXPORT:DebugSetMute=C:\\Windows\\System32\\d3d9.DebugSetMute")
#pragma comment(linker, "/EXPORT:Direct3D9EnableMaximizedWindowedModeShim=C:\\Windows\\System32\\d3d9.Direct3D9EnableMaximizedWindowedModeShim")
#pragma comment(linker, "/EXPORT:Direct3DCreate9=C:\\Windows\\System32\\d3d9.Direct3DCreate9")
#pragma comment(linker, "/EXPORT:Direct3DCreate9Ex=C:\\Windows\\System32\\d3d9.Direct3DCreate9Ex")
#pragma comment(linker, "/EXPORT:Direct3DCreate9On12=C:\\Windows\\System32\\d3d9.Direct3DCreate9On12")
#pragma comment(linker, "/EXPORT:Direct3DCreate9On12Ex=C:\\Windows\\System32\\d3d9.Direct3DCreate9On12Ex")
#pragma comment(linker, "/EXPORT:Direct3DShaderValidatorCreate9=C:\\Windows\\System32\\d3d9.Direct3DShaderValidatorCreate9")
#pragma comment(linker, "/EXPORT:PSGPError=C:\\Windows\\System32\\d3d9.PSGPError")
#pragma comment(linker, "/EXPORT:PSGPSampleTexture=C:\\Windows\\System32\\d3d9.PSGPSampleTexture")
//  C:\Windows\System32\d3d10.dll (d3d10)
#pragma comment(linker, "/EXPORT:D3D10CompileEffectFromMemory=C:\\Windows\\System32\\d3d10.D3D10CompileEffectFromMemory")
#pragma comment(linker, "/EXPORT:D3D10CompileShader=C:\\Windows\\System32\\d3d10.D3D10CompileShader")
#pragma comment(linker, "/EXPORT:D3D10CreateBlob=C:\\Windows\\System32\\d3d10.D3D10CreateBlob")
#pragma comment(linker, "/EXPORT:D3D10CreateDevice=C:\\Windows\\System32\\d3d10.D3D10CreateDevice")
#pragma comment(linker, "/EXPORT:D3D10CreateDeviceAndSwapChain=C:\\Windows\\System32\\d3d10.D3D10CreateDeviceAndSwapChain")
#pragma comment(linker, "/EXPORT:D3D10CreateEffectFromMemory=C:\\Windows\\System32\\d3d10.D3D10CreateEffectFromMemory")
#pragma comment(linker, "/EXPORT:D3D10CreateEffectPoolFromMemory=C:\\Windows\\System32\\d3d10.D3D10CreateEffectPoolFromMemory")
#pragma comment(linker, "/EXPORT:D3D10CreateStateBlock=C:\\Windows\\System32\\d3d10.D3D10CreateStateBlock")
#pragma comment(linker, "/EXPORT:D3D10DisassembleEffect=C:\\Windows\\System32\\d3d10.D3D10DisassembleEffect")
#pragma comment(linker, "/EXPORT:D3D10DisassembleShader=C:\\Windows\\System32\\d3d10.D3D10DisassembleShader")
#pragma comment(linker, "/EXPORT:D3D10GetGeometryShaderProfile=C:\\Windows\\System32\\d3d10.D3D10GetGeometryShaderProfile")
#pragma comment(linker, "/EXPORT:D3D10GetInputAndOutputSignatureBlob=C:\\Windows\\System32\\d3d10.D3D10GetInputAndOutputSignatureBlob")
#pragma comment(linker, "/EXPORT:D3D10GetInputSignatureBlob=C:\\Windows\\System32\\d3d10.D3D10GetInputSignatureBlob")
#pragma comment(linker, "/EXPORT:D3D10GetOutputSignatureBlob=C:\\Windows\\System32\\d3d10.D3D10GetOutputSignatureBlob")
#pragma comment(linker, "/EXPORT:D3D10GetPixelShaderProfile=C:\\Windows\\System32\\d3d10.D3D10GetPixelShaderProfile")
#pragma comment(linker, "/EXPORT:D3D10GetShaderDebugInfo=C:\\Windows\\System32\\d3d10.D3D10GetShaderDebugInfo")
#pragma comment(linker, "/EXPORT:D3D10GetVersion=C:\\Windows\\System32\\d3d10.D3D10GetVersion")
#pragma comment(linker, "/EXPORT:D3D10GetVertexShaderProfile=C:\\Windows\\System32\\d3d10.D3D10GetVertexShaderProfile")
#pragma comment(linker, "/EXPORT:D3D10PreprocessShader=C:\\Windows\\System32\\d3d10.D3D10PreprocessShader")
#pragma comment(linker, "/EXPORT:D3D10ReflectShader=C:\\Windows\\System32\\d3d10.D3D10ReflectShader")
#pragma comment(linker, "/EXPORT:D3D10RegisterLayers=C:\\Windows\\System32\\d3d10.D3D10RegisterLayers")
#pragma comment(linker, "/EXPORT:D3D10StateBlockMaskDifference=C:\\Windows\\System32\\d3d10.D3D10StateBlockMaskDifference")
#pragma comment(linker, "/EXPORT:D3D10StateBlockMaskDisableAll=C:\\Windows\\System32\\d3d10.D3D10StateBlockMaskDisableAll")
#pragma comment(linker, "/EXPORT:D3D10StateBlockMaskDisableCapture=C:\\Windows\\System32\\d3d10.D3D10StateBlockMaskDisableCapture")
#pragma comment(linker, "/EXPORT:D3D10StateBlockMaskEnableAll=C:\\Windows\\System32\\d3d10.D3D10StateBlockMaskEnableAll")
#pragma comment(linker, "/EXPORT:D3D10StateBlockMaskEnableCapture=C:\\Windows\\System32\\d3d10.D3D10StateBlockMaskEnableCapture")
#pragma comment(linker, "/EXPORT:D3D10StateBlockMaskGetSetting=C:\\Windows\\System32\\d3d10.D3D10StateBlockMaskGetSetting")
#pragma comment(linker, "/EXPORT:D3D10StateBlockMaskIntersect=C:\\Windows\\System32\\d3d10.D3D10StateBlockMaskIntersect")
#pragma comment(linker, "/EXPORT:D3D10StateBlockMaskUnion=C:\\Windows\\System32\\d3d10.D3D10StateBlockMaskUnion")
//  C:\Windows\System32\d3d11.dll (d3d11)
#pragma comment(linker, "/EXPORT:CreateDirect3D11DeviceFromDXGIDevice=C:\\Windows\\System32\\d3d11.CreateDirect3D11DeviceFromDXGIDevice")
#pragma comment(linker, "/EXPORT:CreateDirect3D11SurfaceFromDXGISurface=C:\\Windows\\System32\\d3d11.CreateDirect3D11SurfaceFromDXGISurface")
#pragma comment(linker, "/EXPORT:D3D11CoreCreateDevice=C:\\Windows\\System32\\d3d11.D3D11CoreCreateDevice")
#pragma comment(linker, "/EXPORT:D3D11CoreCreateLayeredDevice=C:\\Windows\\System32\\d3d11.D3D11CoreCreateLayeredDevice")
#pragma comment(linker, "/EXPORT:D3D11CoreGetLayeredDeviceSize=C:\\Windows\\System32\\d3d11.D3D11CoreGetLayeredDeviceSize")
#pragma comment(linker, "/EXPORT:D3D11CoreRegisterLayers=C:\\Windows\\System32\\d3d11.D3D11CoreRegisterLayers")
#pragma comment(linker, "/EXPORT:D3D11CreateDevice=C:\\Windows\\System32\\d3d11.D3D11CreateDevice")
#pragma comment(linker, "/EXPORT:D3D11CreateDeviceAndSwapChain=C:\\Windows\\System32\\d3d11.D3D11CreateDeviceAndSwapChain")
#pragma comment(linker, "/EXPORT:D3D11CreateDeviceForD3D12=C:\\Windows\\System32\\d3d11.D3D11CreateDeviceForD3D12")
#pragma comment(linker, "/EXPORT:D3D11On12CreateDevice=C:\\Windows\\System32\\d3d11.D3D11On12CreateDevice")
#pragma comment(linker, "/EXPORT:D3DKMTCloseAdapter=C:\\Windows\\System32\\d3d11.D3DKMTCloseAdapter")
#pragma comment(linker, "/EXPORT:D3DKMTCreateAllocation=C:\\Windows\\System32\\d3d11.D3DKMTCreateAllocation")
#pragma comment(linker, "/EXPORT:D3DKMTCreateContext=C:\\Windows\\System32\\d3d11.D3DKMTCreateContext")
#pragma comment(linker, "/EXPORT:D3DKMTCreateDevice=C:\\Windows\\System32\\d3d11.D3DKMTCreateDevice")
#pragma comment(linker, "/EXPORT:D3DKMTCreateSynchronizationObject=C:\\Windows\\System32\\d3d11.D3DKMTCreateSynchronizationObject")
#pragma comment(linker, "/EXPORT:D3DKMTDestroyAllocation=C:\\Windows\\System32\\d3d11.D3DKMTDestroyAllocation")
#pragma comment(linker, "/EXPORT:D3DKMTDestroyContext=C:\\Windows\\System32\\d3d11.D3DKMTDestroyContext")
#pragma comment(linker, "/EXPORT:D3DKMTDestroyDevice=C:\\Windows\\System32\\d3d11.D3DKMTDestroyDevice")
#pragma comment(linker, "/EXPORT:D3DKMTDestroySynchronizationObject=C:\\Windows\\System32\\d3d11.D3DKMTDestroySynchronizationObject")
#pragma comment(linker, "/EXPORT:D3DKMTEscape=C:\\Windows\\System32\\d3d11.D3DKMTEscape")
#pragma comment(linker, "/EXPORT:D3DKMTGetContextSchedulingPriority=C:\\Windows\\System32\\d3d11.D3DKMTGetContextSchedulingPriority")
#pragma comment(linker, "/EXPORT:D3DKMTGetDeviceState=C:\\Windows\\System32\\d3d11.D3DKMTGetDeviceState")
#pragma comment(linker, "/EXPORT:D3DKMTGetDisplayModeList=C:\\Windows\\System32\\d3d11.D3DKMTGetDisplayModeList")
#pragma comment(linker, "/EXPORT:D3DKMTGetMultisampleMethodList=C:\\Windows\\System32\\d3d11.D3DKMTGetMultisampleMethodList")
#pragma comment(linker, "/EXPORT:D3DKMTGetRuntimeData=C:\\Windows\\System32\\d3d11.D3DKMTGetRuntimeData")
#pragma comment(linker, "/EXPORT:D3DKMTGetSharedPrimaryHandle=C:\\Windows\\System32\\d3d11.D3DKMTGetSharedPrimaryHandle")
#pragma comment(linker, "/EXPORT:D3DKMTLock=C:\\Windows\\System32\\d3d11.D3DKMTLock")
#pragma comment(linker, "/EXPORT:D3DKMTOpenAdapterFromHdc=C:\\Windows\\System32\\d3d11.D3DKMTOpenAdapterFromHdc")
#pragma comment(linker, "/EXPORT:D3DKMTOpenResource=C:\\Windows\\System32\\d3d11.D3DKMTOpenResource")
#pragma comment(linker, "/EXPORT:D3DKMTPresent=C:\\Windows\\System32\\d3d11.D3DKMTPresent")
#pragma comment(linker, "/EXPORT:D3DKMTQueryAdapterInfo=C:\\Windows\\System32\\d3d11.D3DKMTQueryAdapterInfo")
#pragma comment(linker, "/EXPORT:D3DKMTQueryAllocationResidency=C:\\Windows\\System32\\d3d11.D3DKMTQueryAllocationResidency")
#pragma comment(linker, "/EXPORT:D3DKMTQueryResourceInfo=C:\\Windows\\System32\\d3d11.D3DKMTQueryResourceInfo")
#pragma comment(linker, "/EXPORT:D3DKMTRender=C:\\Windows\\System32\\d3d11.D3DKMTRender")
#pragma comment(linker, "/EXPORT:D3DKMTSetAllocationPriority=C:\\Windows\\System32\\d3d11.D3DKMTSetAllocationPriority")
#pragma comment(linker, "/EXPORT:D3DKMTSetContextSchedulingPriority=C:\\Windows\\System32\\d3d11.D3DKMTSetContextSchedulingPriority")
#pragma comment(linker, "/EXPORT:D3DKMTSetDisplayMode=C:\\Windows\\System32\\d3d11.D3DKMTSetDisplayMode")
#pragma comment(linker, "/EXPORT:D3DKMTSetDisplayPrivateDriverFormat=C:\\Windows\\System32\\d3d11.D3DKMTSetDisplayPrivateDriverFormat")
#pragma comment(linker, "/EXPORT:D3DKMTSetGammaRamp=C:\\Windows\\System32\\d3d11.D3DKMTSetGammaRamp")
#pragma comment(linker, "/EXPORT:D3DKMTSetVidPnSourceOwner=C:\\Windows\\System32\\d3d11.D3DKMTSetVidPnSourceOwner")
#pragma comment(linker, "/EXPORT:D3DKMTSignalSynchronizationObject=C:\\Windows\\System32\\d3d11.D3DKMTSignalSynchronizationObject")
#pragma comment(linker, "/EXPORT:D3DKMTUnlock=C:\\Windows\\System32\\d3d11.D3DKMTUnlock")
#pragma comment(linker, "/EXPORT:D3DKMTWaitForSynchronizationObject=C:\\Windows\\System32\\d3d11.D3DKMTWaitForSynchronizationObject")
#pragma comment(linker, "/EXPORT:D3DKMTWaitForVerticalBlankEvent=C:\\Windows\\System32\\d3d11.D3DKMTWaitForVerticalBlankEvent")
#pragma comment(linker, "/EXPORT:D3DPerformance_BeginEvent=C:\\Windows\\System32\\d3d11.D3DPerformance_BeginEvent")
#pragma comment(linker, "/EXPORT:D3DPerformance_EndEvent=C:\\Windows\\System32\\d3d11.D3DPerformance_EndEvent")
#pragma comment(linker, "/EXPORT:D3DPerformance_GetStatus=C:\\Windows\\System32\\d3d11.D3DPerformance_GetStatus")
#pragma comment(linker, "/EXPORT:D3DPerformance_SetMarker=C:\\Windows\\System32\\d3d11.D3DPerformance_SetMarker")
#pragma comment(linker, "/EXPORT:EnableFeatureLevelUpgrade=C:\\Windows\\System32\\d3d11.EnableFeatureLevelUpgrade")
#pragma comment(linker, "/EXPORT:OpenAdapter10=C:\\Windows\\System32\\d3d11.OpenAdapter10")
#pragma comment(linker, "/EXPORT:OpenAdapter10_2=C:\\Windows\\System32\\d3d11.OpenAdapter10_2")
//  C:\Windows\System32\xinput1_3.dll (xinput1_3)
#pragma comment(linker, "/EXPORT:XInputEnable=C:\\Windows\\System32\\xinput1_3.XInputEnable")
#pragma comment(linker, "/EXPORT:XInputGetBatteryInformation=C:\\Windows\\System32\\xinput1_3.XInputGetBatteryInformation")
#pragma comment(linker, "/EXPORT:XInputGetCapabilities=C:\\Windows\\System32\\xinput1_3.XInputGetCapabilities")
#pragma comment(linker, "/EXPORT:XInputGetDSoundAudioDeviceGuids=C:\\Windows\\System32\\xinput1_3.XInputGetDSoundAudioDeviceGuids")
#pragma comment(linker, "/EXPORT:XInputGetKeystroke=C:\\Windows\\System32\\xinput1_3.XInputGetKeystroke")
#pragma comment(linker, "/EXPORT:XInputGetState=C:\\Windows\\System32\\xinput1_3.XInputGetState")
#pragma comment(linker, "/EXPORT:XInputSetState=C:\\Windows\\System32\\xinput1_3.XInputSetState")
//  C:\Windows\System32\winmm.dll (winmm)
#pragma comment(linker, "/EXPORT:CloseDriver=C:\\Windows\\System32\\winmm.CloseDriver")
#pragma comment(linker, "/EXPORT:DefDriverProc=C:\\Windows\\System32\\winmm.DefDriverProc")
#pragma comment(linker, "/EXPORT:DriverCallback=C:\\Windows\\System32\\winmm.DriverCallback")
#pragma comment(linker, "/EXPORT:DrvGetModuleHandle=C:\\Windows\\System32\\winmm.DrvGetModuleHandle")
#pragma comment(linker, "/EXPORT:GetDriverModuleHandle=C:\\Windows\\System32\\winmm.GetDriverModuleHandle")
#pragma comment(linker, "/EXPORT:OpenDriver=C:\\Windows\\System32\\winmm.OpenDriver")
#pragma comment(linker, "/EXPORT:PlaySound=C:\\Windows\\System32\\winmm.PlaySound")
#pragma comment(linker, "/EXPORT:PlaySoundA=C:\\Windows\\System32\\winmm.PlaySoundA")
#pragma comment(linker, "/EXPORT:PlaySoundW=C:\\Windows\\System32\\winmm.PlaySoundW")
#pragma comment(linker, "/EXPORT:SendDriverMessage=C:\\Windows\\System32\\winmm.SendDriverMessage")
#pragma comment(linker, "/EXPORT:WOWAppExit=C:\\Windows\\System32\\winmm.WOWAppExit")
#pragma comment(linker, "/EXPORT:auxGetDevCapsA=C:\\Windows\\System32\\winmm.auxGetDevCapsA")
#pragma comment(linker, "/EXPORT:auxGetDevCapsW=C:\\Windows\\System32\\winmm.auxGetDevCapsW")
#pragma comment(linker, "/EXPORT:auxGetNumDevs=C:\\Windows\\System32\\winmm.auxGetNumDevs")
#pragma comment(linker, "/EXPORT:auxGetVolume=C:\\Windows\\System32\\winmm.auxGetVolume")
#pragma comment(linker, "/EXPORT:auxOutMessage=C:\\Windows\\System32\\winmm.auxOutMessage")
#pragma comment(linker, "/EXPORT:auxSetVolume=C:\\Windows\\System32\\winmm.auxSetVolume")
#pragma comment(linker, "/EXPORT:joyConfigChanged=C:\\Windows\\System32\\winmm.joyConfigChanged")
#pragma comment(linker, "/EXPORT:joyGetDevCapsA=C:\\Windows\\System32\\winmm.joyGetDevCapsA")
#pragma comment(linker, "/EXPORT:joyGetDevCapsW=C:\\Windows\\System32\\winmm.joyGetDevCapsW")
#pragma comment(linker, "/EXPORT:joyGetNumDevs=C:\\Windows\\System32\\winmm.joyGetNumDevs")
#pragma comment(linker, "/EXPORT:joyGetPos=C:\\Windows\\System32\\winmm.joyGetPos")
#pragma comment(linker, "/EXPORT:joyGetPosEx=C:\\Windows\\System32\\winmm.joyGetPosEx")
#pragma comment(linker, "/EXPORT:joyGetThreshold=C:\\Windows\\System32\\winmm.joyGetThreshold")
#pragma comment(linker, "/EXPORT:joyReleaseCapture=C:\\Windows\\System32\\winmm.joyReleaseCapture")
#pragma comment(linker, "/EXPORT:joySetCapture=C:\\Windows\\System32\\winmm.joySetCapture")
#pragma comment(linker, "/EXPORT:joySetThreshold=C:\\Windows\\System32\\winmm.joySetThreshold")
#pragma comment(linker, "/EXPORT:mciDriverNotify=C:\\Windows\\System32\\winmm.mciDriverNotify")
#pragma comment(linker, "/EXPORT:mciDriverYield=C:\\Windows\\System32\\winmm.mciDriverYield")
#pragma comment(linker, "/EXPORT:mciExecute=C:\\Windows\\System32\\winmm.mciExecute")
#pragma comment(linker, "/EXPORT:mciFreeCommandResource=C:\\Windows\\System32\\winmm.mciFreeCommandResource")
#pragma comment(linker, "/EXPORT:mciGetCreatorTask=C:\\Windows\\System32\\winmm.mciGetCreatorTask")
#pragma comment(linker, "/EXPORT:mciGetDeviceIDA=C:\\Windows\\System32\\winmm.mciGetDeviceIDA")
#pragma comment(linker, "/EXPORT:mciGetDeviceIDFromElementIDA=C:\\Windows\\System32\\winmm.mciGetDeviceIDFromElementIDA")
#pragma comment(linker, "/EXPORT:mciGetDeviceIDFromElementIDW=C:\\Windows\\System32\\winmm.mciGetDeviceIDFromElementIDW")
#pragma comment(linker, "/EXPORT:mciGetDeviceIDW=C:\\Windows\\System32\\winmm.mciGetDeviceIDW")
#pragma comment(linker, "/EXPORT:mciGetDriverData=C:\\Windows\\System32\\winmm.mciGetDriverData")
#pragma comment(linker, "/EXPORT:mciGetErrorStringA=C:\\Windows\\System32\\winmm.mciGetErrorStringA")
#pragma comment(linker, "/EXPORT:mciGetErrorStringW=C:\\Windows\\System32\\winmm.mciGetErrorStringW")
#pragma comment(linker, "/EXPORT:mciGetYieldProc=C:\\Windows\\System32\\winmm.mciGetYieldProc")
#pragma comment(linker, "/EXPORT:mciLoadCommandResource=C:\\Windows\\System32\\winmm.mciLoadCommandResource")
#pragma comment(linker, "/EXPORT:mciSendCommandA=C:\\Windows\\System32\\winmm.mciSendCommandA")
#pragma comment(linker, "/EXPORT:mciSendCommandW=C:\\Windows\\System32\\winmm.mciSendCommandW")
#pragma comment(linker, "/EXPORT:mciSendStringA=C:\\Windows\\System32\\winmm.mciSendStringA")
#pragma comment(linker, "/EXPORT:mciSendStringW=C:\\Windows\\System32\\winmm.mciSendStringW")
#pragma comment(linker, "/EXPORT:mciSetDriverData=C:\\Windows\\System32\\winmm.mciSetDriverData")
#pragma comment(linker, "/EXPORT:mciSetYieldProc=C:\\Windows\\System32\\winmm.mciSetYieldProc")
#pragma comment(linker, "/EXPORT:midiConnect=C:\\Windows\\System32\\winmm.midiConnect")
#pragma comment(linker, "/EXPORT:midiDisconnect=C:\\Windows\\System32\\winmm.midiDisconnect")
#pragma comment(linker, "/EXPORT:midiInAddBuffer=C:\\Windows\\System32\\winmm.midiInAddBuffer")
#pragma comment(linker, "/EXPORT:midiInClose=C:\\Windows\\System32\\winmm.midiInClose")
#pragma comment(linker, "/EXPORT:midiInGetDevCapsA=C:\\Windows\\System32\\winmm.midiInGetDevCapsA")
#pragma comment(linker, "/EXPORT:midiInGetDevCapsW=C:\\Windows\\System32\\winmm.midiInGetDevCapsW")
#pragma comment(linker, "/EXPORT:midiInGetErrorTextA=C:\\Windows\\System32\\winmm.midiInGetErrorTextA")
#pragma comment(linker, "/EXPORT:midiInGetErrorTextW=C:\\Windows\\System32\\winmm.midiInGetErrorTextW")
#pragma comment(linker, "/EXPORT:midiInGetID=C:\\Windows\\System32\\winmm.midiInGetID")
#pragma comment(linker, "/EXPORT:midiInGetNumDevs=C:\\Windows\\System32\\winmm.midiInGetNumDevs")
#pragma comment(linker, "/EXPORT:midiInMessage=C:\\Windows\\System32\\winmm.midiInMessage")
#pragma comment(linker, "/EXPORT:midiInOpen=C:\\Windows\\System32\\winmm.midiInOpen")
#pragma comment(linker, "/EXPORT:midiInPrepareHeader=C:\\Windows\\System32\\winmm.midiInPrepareHeader")
#pragma comment(linker, "/EXPORT:midiInReset=C:\\Windows\\System32\\winmm.midiInReset")
#pragma comment(linker, "/EXPORT:midiInStart=C:\\Windows\\System32\\winmm.midiInStart")
#pragma comment(linker, "/EXPORT:midiInStop=C:\\Windows\\System32\\winmm.midiInStop")
#pragma comment(linker, "/EXPORT:midiInUnprepareHeader=C:\\Windows\\System32\\winmm.midiInUnprepareHeader")
#pragma comment(linker, "/EXPORT:midiOutCacheDrumPatches=C:\\Windows\\System32\\winmm.midiOutCacheDrumPatches")
#pragma comment(linker, "/EXPORT:midiOutCachePatches=C:\\Windows\\System32\\winmm.midiOutCachePatches")
#pragma comment(linker, "/EXPORT:midiOutClose=C:\\Windows\\System32\\winmm.midiOutClose")
#pragma comment(linker, "/EXPORT:midiOutGetDevCapsA=C:\\Windows\\System32\\winmm.midiOutGetDevCapsA")
#pragma comment(linker, "/EXPORT:midiOutGetDevCapsW=C:\\Windows\\System32\\winmm.midiOutGetDevCapsW")
#pragma comment(linker, "/EXPORT:midiOutGetErrorTextA=C:\\Windows\\System32\\winmm.midiOutGetErrorTextA")
#pragma comment(linker, "/EXPORT:midiOutGetErrorTextW=C:\\Windows\\System32\\winmm.midiOutGetErrorTextW")
#pragma comment(linker, "/EXPORT:midiOutGetID=C:\\Windows\\System32\\winmm.midiOutGetID")
#pragma comment(linker, "/EXPORT:midiOutGetNumDevs=C:\\Windows\\System32\\winmm.midiOutGetNumDevs")
#pragma comment(linker, "/EXPORT:midiOutGetVolume=C:\\Windows\\System32\\winmm.midiOutGetVolume")
#pragma comment(linker, "/EXPORT:midiOutLongMsg=C:\\Windows\\System32\\winmm.midiOutLongMsg")
#pragma comment(linker, "/EXPORT:midiOutMessage=C:\\Windows\\System32\\winmm.midiOutMessage")
#pragma comment(linker, "/EXPORT:midiOutOpen=C:\\Windows\\System32\\winmm.midiOutOpen")
#pragma comment(linker, "/EXPORT:midiOutPrepareHeader=C:\\Windows\\System32\\winmm.midiOutPrepareHeader")
#pragma comment(linker, "/EXPORT:midiOutReset=C:\\Windows\\System32\\winmm.midiOutReset")
#pragma comment(linker, "/EXPORT:midiOutSetVolume=C:\\Windows\\System32\\winmm.midiOutSetVolume")
#pragma comment(linker, "/EXPORT:midiOutShortMsg=C:\\Windows\\System32\\winmm.midiOutShortMsg")
#pragma comment(linker, "/EXPORT:midiOutUnprepareHeader=C:\\Windows\\System32\\winmm.midiOutUnprepareHeader")
#pragma comment(linker, "/EXPORT:midiStreamClose=C:\\Windows\\System32\\winmm.midiStreamClose")
#pragma comment(linker, "/EXPORT:midiStreamOpen=C:\\Windows\\System32\\winmm.midiStreamOpen")
#pragma comment(linker, "/EXPORT:midiStreamOut=C:\\Windows\\System32\\winmm.midiStreamOut")
#pragma comment(linker, "/EXPORT:midiStreamPause=C:\\Windows\\System32\\winmm.midiStreamPause")
#pragma comment(linker, "/EXPORT:midiStreamPosition=C:\\Windows\\System32\\winmm.midiStreamPosition")
#pragma comment(linker, "/EXPORT:midiStreamProperty=C:\\Windows\\System32\\winmm.midiStreamProperty")
#pragma comment(linker, "/EXPORT:midiStreamRestart=C:\\Windows\\System32\\winmm.midiStreamRestart")
#pragma comment(linker, "/EXPORT:midiStreamStop=C:\\Windows\\System32\\winmm.midiStreamStop")
#pragma comment(linker, "/EXPORT:mixerClose=C:\\Windows\\System32\\winmm.mixerClose")
#pragma comment(linker, "/EXPORT:mixerGetControlDetailsA=C:\\Windows\\System32\\winmm.mixerGetControlDetailsA")
#pragma comment(linker, "/EXPORT:mixerGetControlDetailsW=C:\\Windows\\System32\\winmm.mixerGetControlDetailsW")
#pragma comment(linker, "/EXPORT:mixerGetDevCapsA=C:\\Windows\\System32\\winmm.mixerGetDevCapsA")
#pragma comment(linker, "/EXPORT:mixerGetDevCapsW=C:\\Windows\\System32\\winmm.mixerGetDevCapsW")
#pragma comment(linker, "/EXPORT:mixerGetID=C:\\Windows\\System32\\winmm.mixerGetID")
#pragma comment(linker, "/EXPORT:mixerGetLineControlsA=C:\\Windows\\System32\\winmm.mixerGetLineControlsA")
#pragma comment(linker, "/EXPORT:mixerGetLineControlsW=C:\\Windows\\System32\\winmm.mixerGetLineControlsW")
#pragma comment(linker, "/EXPORT:mixerGetLineInfoA=C:\\Windows\\System32\\winmm.mixerGetLineInfoA")
#pragma comment(linker, "/EXPORT:mixerGetLineInfoW=C:\\Windows\\System32\\winmm.mixerGetLineInfoW")
#pragma comment(linker, "/EXPORT:mixerGetNumDevs=C:\\Windows\\System32\\winmm.mixerGetNumDevs")
#pragma comment(linker, "/EXPORT:mixerMessage=C:\\Windows\\System32\\winmm.mixerMessage")
#pragma comment(linker, "/EXPORT:mixerOpen=C:\\Windows\\System32\\winmm.mixerOpen")
#pragma comment(linker, "/EXPORT:mixerSetControlDetails=C:\\Windows\\System32\\winmm.mixerSetControlDetails")
#pragma comment(linker, "/EXPORT:mmDrvInstall=C:\\Windows\\System32\\winmm.mmDrvInstall")
#pragma comment(linker, "/EXPORT:mmGetCurrentTask=C:\\Windows\\System32\\winmm.mmGetCurrentTask")
#pragma comment(linker, "/EXPORT:mmTaskBlock=C:\\Windows\\System32\\winmm.mmTaskBlock")
#pragma comment(linker, "/EXPORT:mmTaskCreate=C:\\Windows\\System32\\winmm.mmTaskCreate")
#pragma comment(linker, "/EXPORT:mmTaskSignal=C:\\Windows\\System32\\winmm.mmTaskSignal")
#pragma comment(linker, "/EXPORT:mmTaskYield=C:\\Windows\\System32\\winmm.mmTaskYield")
#pragma comment(linker, "/EXPORT:mmioAdvance=C:\\Windows\\System32\\winmm.mmioAdvance")
#pragma comment(linker, "/EXPORT:mmioAscend=C:\\Windows\\System32\\winmm.mmioAscend")
#pragma comment(linker, "/EXPORT:mmioClose=C:\\Windows\\System32\\winmm.mmioClose")
#pragma comment(linker, "/EXPORT:mmioCreateChunk=C:\\Windows\\System32\\winmm.mmioCreateChunk")
#pragma comment(linker, "/EXPORT:mmioDescend=C:\\Windows\\System32\\winmm.mmioDescend")
#pragma comment(linker, "/EXPORT:mmioFlush=C:\\Windows\\System32\\winmm.mmioFlush")
#pragma comment(linker, "/EXPORT:mmioGetInfo=C:\\Windows\\System32\\winmm.mmioGetInfo")
#pragma comment(linker, "/EXPORT:mmioInstallIOProcA=C:\\Windows\\System32\\winmm.mmioInstallIOProcA")
#pragma comment(linker, "/EXPORT:mmioInstallIOProcW=C:\\Windows\\System32\\winmm.mmioInstallIOProcW")
#pragma comment(linker, "/EXPORT:mmioOpenA=C:\\Windows\\System32\\winmm.mmioOpenA")
#pragma comment(linker, "/EXPORT:mmioOpenW=C:\\Windows\\System32\\winmm.mmioOpenW")
#pragma comment(linker, "/EXPORT:mmioRead=C:\\Windows\\System32\\winmm.mmioRead")
#pragma comment(linker, "/EXPORT:mmioRenameA=C:\\Windows\\System32\\winmm.mmioRenameA")
#pragma comment(linker, "/EXPORT:mmioRenameW=C:\\Windows\\System32\\winmm.mmioRenameW")
#pragma comment(linker, "/EXPORT:mmioSeek=C:\\Windows\\System32\\winmm.mmioSeek")
#pragma comment(linker, "/EXPORT:mmioSendMessage=C:\\Windows\\System32\\winmm.mmioSendMessage")
#pragma comment(linker, "/EXPORT:mmioSetBuffer=C:\\Windows\\System32\\winmm.mmioSetBuffer")
#pragma comment(linker, "/EXPORT:mmioSetInfo=C:\\Windows\\System32\\winmm.mmioSetInfo")
#pragma comment(linker, "/EXPORT:mmioStringToFOURCCA=C:\\Windows\\System32\\winmm.mmioStringToFOURCCA")
#pragma comment(linker, "/EXPORT:mmioStringToFOURCCW=C:\\Windows\\System32\\winmm.mmioStringToFOURCCW")
#pragma comment(linker, "/EXPORT:mmioWrite=C:\\Windows\\System32\\winmm.mmioWrite")
#pragma comment(linker, "/EXPORT:mmsystemGetVersion=C:\\Windows\\System32\\winmm.mmsystemGetVersion")
#pragma comment(linker, "/EXPORT:sndPlaySoundA=C:\\Windows\\System32\\winmm.sndPlaySoundA")
#pragma comment(linker, "/EXPORT:sndPlaySoundW=C:\\Windows\\System32\\winmm.sndPlaySoundW")
#pragma comment(linker, "/EXPORT:timeBeginPeriod=C:\\Windows\\System32\\winmm.timeBeginPeriod")
#pragma comment(linker, "/EXPORT:timeEndPeriod=C:\\Windows\\System32\\winmm.timeEndPeriod")
#pragma comment(linker, "/EXPORT:timeGetDevCaps=C:\\Windows\\System32\\winmm.timeGetDevCaps")
#pragma comment(linker, "/EXPORT:timeGetSystemTime=C:\\Windows\\System32\\winmm.timeGetSystemTime")
#pragma comment(linker, "/EXPORT:timeGetTime=C:\\Windows\\System32\\winmm.timeGetTime")
#pragma comment(linker, "/EXPORT:timeKillEvent=C:\\Windows\\System32\\winmm.timeKillEvent")
#pragma comment(linker, "/EXPORT:timeSetEvent=C:\\Windows\\System32\\winmm.timeSetEvent")
#pragma comment(linker, "/EXPORT:waveInAddBuffer=C:\\Windows\\System32\\winmm.waveInAddBuffer")
#pragma comment(linker, "/EXPORT:waveInClose=C:\\Windows\\System32\\winmm.waveInClose")
#pragma comment(linker, "/EXPORT:waveInGetDevCapsA=C:\\Windows\\System32\\winmm.waveInGetDevCapsA")
#pragma comment(linker, "/EXPORT:waveInGetDevCapsW=C:\\Windows\\System32\\winmm.waveInGetDevCapsW")
#pragma comment(linker, "/EXPORT:waveInGetErrorTextA=C:\\Windows\\System32\\winmm.waveInGetErrorTextA")
#pragma comment(linker, "/EXPORT:waveInGetErrorTextW=C:\\Windows\\System32\\winmm.waveInGetErrorTextW")
#pragma comment(linker, "/EXPORT:waveInGetID=C:\\Windows\\System32\\winmm.waveInGetID")
#pragma comment(linker, "/EXPORT:waveInGetNumDevs=C:\\Windows\\System32\\winmm.waveInGetNumDevs")
#pragma comment(linker, "/EXPORT:waveInGetPosition=C:\\Windows\\System32\\winmm.waveInGetPosition")
#pragma comment(linker, "/EXPORT:waveInMessage=C:\\Windows\\System32\\winmm.waveInMessage")
#pragma comment(linker, "/EXPORT:waveInOpen=C:\\Windows\\System32\\winmm.waveInOpen")
#pragma comment(linker, "/EXPORT:waveInPrepareHeader=C:\\Windows\\System32\\winmm.waveInPrepareHeader")
#pragma comment(linker, "/EXPORT:waveInReset=C:\\Windows\\System32\\winmm.waveInReset")
#pragma comment(linker, "/EXPORT:waveInStart=C:\\Windows\\System32\\winmm.waveInStart")
#pragma comment(linker, "/EXPORT:waveInStop=C:\\Windows\\System32\\winmm.waveInStop")
#pragma comment(linker, "/EXPORT:waveInUnprepareHeader=C:\\Windows\\System32\\winmm.waveInUnprepareHeader")
#pragma comment(linker, "/EXPORT:waveOutBreakLoop=C:\\Windows\\System32\\winmm.waveOutBreakLoop")
#pragma comment(linker, "/EXPORT:waveOutClose=C:\\Windows\\System32\\winmm.waveOutClose")
#pragma comment(linker, "/EXPORT:waveOutGetDevCapsA=C:\\Windows\\System32\\winmm.waveOutGetDevCapsA")
#pragma comment(linker, "/EXPORT:waveOutGetDevCapsW=C:\\Windows\\System32\\winmm.waveOutGetDevCapsW")
#pragma comment(linker, "/EXPORT:waveOutGetErrorTextA=C:\\Windows\\System32\\winmm.waveOutGetErrorTextA")
#pragma comment(linker, "/EXPORT:waveOutGetErrorTextW=C:\\Windows\\System32\\winmm.waveOutGetErrorTextW")
#pragma comment(linker, "/EXPORT:waveOutGetID=C:\\Windows\\System32\\winmm.waveOutGetID")
#pragma comment(linker, "/EXPORT:waveOutGetNumDevs=C:\\Windows\\System32\\winmm.waveOutGetNumDevs")
#pragma comment(linker, "/EXPORT:waveOutGetPitch=C:\\Windows\\System32\\winmm.waveOutGetPitch")
#pragma comment(linker, "/EXPORT:waveOutGetPlaybackRate=C:\\Windows\\System32\\winmm.waveOutGetPlaybackRate")
#pragma comment(linker, "/EXPORT:waveOutGetPosition=C:\\Windows\\System32\\winmm.waveOutGetPosition")
#pragma comment(linker, "/EXPORT:waveOutGetVolume=C:\\Windows\\System32\\winmm.waveOutGetVolume")
#pragma comment(linker, "/EXPORT:waveOutMessage=C:\\Windows\\System32\\winmm.waveOutMessage")
#pragma comment(linker, "/EXPORT:waveOutOpen=C:\\Windows\\System32\\winmm.waveOutOpen")
#pragma comment(linker, "/EXPORT:waveOutPause=C:\\Windows\\System32\\winmm.waveOutPause")
#pragma comment(linker, "/EXPORT:waveOutPrepareHeader=C:\\Windows\\System32\\winmm.waveOutPrepareHeader")
#pragma comment(linker, "/EXPORT:waveOutReset=C:\\Windows\\System32\\winmm.waveOutReset")
#pragma comment(linker, "/EXPORT:waveOutRestart=C:\\Windows\\System32\\winmm.waveOutRestart")
#pragma comment(linker, "/EXPORT:waveOutSetPitch=C:\\Windows\\System32\\winmm.waveOutSetPitch")
#pragma comment(linker, "/EXPORT:waveOutSetPlaybackRate=C:\\Windows\\System32\\winmm.waveOutSetPlaybackRate")
#pragma comment(linker, "/EXPORT:waveOutSetVolume=C:\\Windows\\System32\\winmm.waveOutSetVolume")
#pragma comment(linker, "/EXPORT:waveOutUnprepareHeader=C:\\Windows\\System32\\winmm.waveOutUnprepareHeader")
#pragma comment(linker, "/EXPORT:waveOutWrite=C:\\Windows\\System32\\winmm.waveOutWrite")
//  C:\Windows\System32\winhttp.dll (winhttp)
#pragma comment(linker, "/EXPORT:Private1=C:\\Windows\\System32\\winhttp.Private1")
#pragma comment(linker, "/EXPORT:SvchostPushServiceGlobals=C:\\Windows\\System32\\winhttp.SvchostPushServiceGlobals")
#pragma comment(linker, "/EXPORT:WinHttpAddRequestHeaders=C:\\Windows\\System32\\winhttp.WinHttpAddRequestHeaders")
#pragma comment(linker, "/EXPORT:WinHttpAddRequestHeadersEx=C:\\Windows\\System32\\winhttp.WinHttpAddRequestHeadersEx")
#pragma comment(linker, "/EXPORT:WinHttpAutoProxySvcMain=C:\\Windows\\System32\\winhttp.WinHttpAutoProxySvcMain")
#pragma comment(linker, "/EXPORT:WinHttpCheckPlatform=C:\\Windows\\System32\\winhttp.WinHttpCheckPlatform")
#pragma comment(linker, "/EXPORT:WinHttpCloseHandle=C:\\Windows\\System32\\winhttp.WinHttpCloseHandle")
#pragma comment(linker, "/EXPORT:WinHttpConnect=C:\\Windows\\System32\\winhttp.WinHttpConnect")
#pragma comment(linker, "/EXPORT:WinHttpConnectionDeletePolicyEntries=C:\\Windows\\System32\\winhttp.WinHttpConnectionDeletePolicyEntries")
#pragma comment(linker, "/EXPORT:WinHttpConnectionDeleteProxyInfo=C:\\Windows\\System32\\winhttp.WinHttpConnectionDeleteProxyInfo")
#pragma comment(linker, "/EXPORT:WinHttpConnectionFreeNameList=C:\\Windows\\System32\\winhttp.WinHttpConnectionFreeNameList")
#pragma comment(linker, "/EXPORT:WinHttpConnectionFreeProxyInfo=C:\\Windows\\System32\\winhttp.WinHttpConnectionFreeProxyInfo")
#pragma comment(linker, "/EXPORT:WinHttpConnectionFreeProxyList=C:\\Windows\\System32\\winhttp.WinHttpConnectionFreeProxyList")
#pragma comment(linker, "/EXPORT:WinHttpConnectionGetNameList=C:\\Windows\\System32\\winhttp.WinHttpConnectionGetNameList")
#pragma comment(linker, "/EXPORT:WinHttpConnectionGetProxyInfo=C:\\Windows\\System32\\winhttp.WinHttpConnectionGetProxyInfo")
#pragma comment(linker, "/EXPORT:WinHttpConnectionGetProxyList=C:\\Windows\\System32\\winhttp.WinHttpConnectionGetProxyList")
#pragma comment(linker, "/EXPORT:WinHttpConnectionOnlyConvert=C:\\Windows\\System32\\winhttp.WinHttpConnectionOnlyConvert")
#pragma comment(linker, "/EXPORT:WinHttpConnectionOnlyReceive=C:\\Windows\\System32\\winhttp.WinHttpConnectionOnlyReceive")
#pragma comment(linker, "/EXPORT:WinHttpConnectionOnlySend=C:\\Windows\\System32\\winhttp.WinHttpConnectionOnlySend")
#pragma comment(linker, "/EXPORT:WinHttpConnectionSetPolicyEntries=C:\\Windows\\System32\\winhttp.WinHttpConnectionSetPolicyEntries")
#pragma comment(linker, "/EXPORT:WinHttpConnectionSetProxyInfo=C:\\Windows\\System32\\winhttp.WinHttpConnectionSetProxyInfo")
#pragma comment(linker, "/EXPORT:WinHttpConnectionUpdateIfIndexTable=C:\\Windows\\System32\\winhttp.WinHttpConnectionUpdateIfIndexTable")
#pragma comment(linker, "/EXPORT:WinHttpCrackUrl=C:\\Windows\\System32\\winhttp.WinHttpCrackUrl")
#pragma comment(linker, "/EXPORT:WinHttpCreateProxyList=C:\\Windows\\System32\\winhttp.WinHttpCreateProxyList")
#pragma comment(linker, "/EXPORT:WinHttpCreateProxyManager=C:\\Windows\\System32\\winhttp.WinHttpCreateProxyManager")
#pragma comment(linker, "/EXPORT:WinHttpCreateProxyResolver=C:\\Windows\\System32\\winhttp.WinHttpCreateProxyResolver")
#pragma comment(linker, "/EXPORT:WinHttpCreateProxyResult=C:\\Windows\\System32\\winhttp.WinHttpCreateProxyResult")
#pragma comment(linker, "/EXPORT:WinHttpCreateUiCompatibleProxyString=C:\\Windows\\System32\\winhttp.WinHttpCreateUiCompatibleProxyString")
#pragma comment(linker, "/EXPORT:WinHttpCreateUrl=C:\\Windows\\System32\\winhttp.WinHttpCreateUrl")
#pragma comment(linker, "/EXPORT:WinHttpDetectAutoProxyConfigUrl=C:\\Windows\\System32\\winhttp.WinHttpDetectAutoProxyConfigUrl")
#pragma comment(linker, "/EXPORT:WinHttpFreeProxyResult=C:\\Windows\\System32\\winhttp.WinHttpFreeProxyResult")
#pragma comment(linker, "/EXPORT:WinHttpFreeProxyResultEx=C:\\Windows\\System32\\winhttp.WinHttpFreeProxyResultEx")
#pragma comment(linker, "/EXPORT:WinHttpFreeProxySettings=C:\\Windows\\System32\\winhttp.WinHttpFreeProxySettings")
#pragma comment(linker, "/EXPORT:WinHttpFreeProxySettingsEx=C:\\Windows\\System32\\winhttp.WinHttpFreeProxySettingsEx")
#pragma comment(linker, "/EXPORT:WinHttpFreeQueryConnectionGroupResult=C:\\Windows\\System32\\winhttp.WinHttpFreeQueryConnectionGroupResult")
#pragma comment(linker, "/EXPORT:WinHttpGetDefaultProxyConfiguration=C:\\Windows\\System32\\winhttp.WinHttpGetDefaultProxyConfiguration")
#pragma comment(linker, "/EXPORT:WinHttpGetIEProxyConfigForCurrentUser=C:\\Windows\\System32\\winhttp.WinHttpGetIEProxyConfigForCurrentUser")
#pragma comment(linker, "/EXPORT:WinHttpGetProxyForUrl=C:\\Windows\\System32\\winhttp.WinHttpGetProxyForUrl")
#pragma comment(linker, "/EXPORT:WinHttpGetProxyForUrlEx=C:\\Windows\\System32\\winhttp.WinHttpGetProxyForUrlEx")
#pragma comment(linker, "/EXPORT:WinHttpGetProxyForUrlEx2=C:\\Windows\\System32\\winhttp.WinHttpGetProxyForUrlEx2")
#pragma comment(linker, "/EXPORT:WinHttpGetProxyForUrlHvsi=C:\\Windows\\System32\\winhttp.WinHttpGetProxyForUrlHvsi")
#pragma comment(linker, "/EXPORT:WinHttpGetProxyResult=C:\\Windows\\System32\\winhttp.WinHttpGetProxyResult")
#pragma comment(linker, "/EXPORT:WinHttpGetProxyResultEx=C:\\Windows\\System32\\winhttp.WinHttpGetProxyResultEx")
#pragma comment(linker, "/EXPORT:WinHttpGetProxySettingsEx=C:\\Windows\\System32\\winhttp.WinHttpGetProxySettingsEx")
#pragma comment(linker, "/EXPORT:WinHttpGetProxySettingsResultEx=C:\\Windows\\System32\\winhttp.WinHttpGetProxySettingsResultEx")
#pragma comment(linker, "/EXPORT:WinHttpGetProxySettingsVersion=C:\\Windows\\System32\\winhttp.WinHttpGetProxySettingsVersion")
#pragma comment(linker, "/EXPORT:WinHttpGetTunnelSocket=C:\\Windows\\System32\\winhttp.WinHttpGetTunnelSocket")
#pragma comment(linker, "/EXPORT:WinHttpOpen=C:\\Windows\\System32\\winhttp.WinHttpOpen")
#pragma comment(linker, "/EXPORT:WinHttpOpenRequest=C:\\Windows\\System32\\winhttp.WinHttpOpenRequest")
#pragma comment(linker, "/EXPORT:WinHttpPacJsWorkerMain=C:\\Windows\\System32\\winhttp.WinHttpPacJsWorkerMain")
#pragma comment(linker, "/EXPORT:WinHttpProbeConnectivity=C:\\Windows\\System32\\winhttp.WinHttpProbeConnectivity")
#pragma comment(linker, "/EXPORT:WinHttpProtocolCompleteUpgrade=C:\\Windows\\System32\\winhttp.WinHttpProtocolCompleteUpgrade")
#pragma comment(linker, "/EXPORT:WinHttpProtocolReceive=C:\\Windows\\System32\\winhttp.WinHttpProtocolReceive")
#pragma comment(linker, "/EXPORT:WinHttpProtocolSend=C:\\Windows\\System32\\winhttp.WinHttpProtocolSend")
#pragma comment(linker, "/EXPORT:WinHttpQueryAuthSchemes=C:\\Windows\\System32\\winhttp.WinHttpQueryAuthSchemes")
#pragma comment(linker, "/EXPORT:WinHttpQueryConnectionGroup=C:\\Windows\\System32\\winhttp.WinHttpQueryConnectionGroup")
#pragma comment(linker, "/EXPORT:WinHttpQueryDataAvailable=C:\\Windows\\System32\\winhttp.WinHttpQueryDataAvailable")
#pragma comment(linker, "/EXPORT:WinHttpQueryHeaders=C:\\Windows\\System32\\winhttp.WinHttpQueryHeaders")
#pragma comment(linker, "/EXPORT:WinHttpQueryHeadersEx=C:\\Windows\\System32\\winhttp.WinHttpQueryHeadersEx")
#pragma comment(linker, "/EXPORT:WinHttpQueryOption=C:\\Windows\\System32\\winhttp.WinHttpQueryOption")
#pragma comment(linker, "/EXPORT:WinHttpReadData=C:\\Windows\\System32\\winhttp.WinHttpReadData")
#pragma comment(linker, "/EXPORT:WinHttpReadDataEx=C:\\Windows\\System32\\winhttp.WinHttpReadDataEx")
#pragma comment(linker, "/EXPORT:WinHttpReadProxySettings=C:\\Windows\\System32\\winhttp.WinHttpReadProxySettings")
#pragma comment(linker, "/EXPORT:WinHttpReadProxySettingsHvsi=C:\\Windows\\System32\\winhttp.WinHttpReadProxySettingsHvsi")
#pragma comment(linker, "/EXPORT:WinHttpReceiveResponse=C:\\Windows\\System32\\winhttp.WinHttpReceiveResponse")
#pragma comment(linker, "/EXPORT:WinHttpRefreshProxySettings=C:\\Windows\\System32\\winhttp.WinHttpRefreshProxySettings")
#pragma comment(linker, "/EXPORT:WinHttpRegisterProxyChangeNotification=C:\\Windows\\System32\\winhttp.WinHttpRegisterProxyChangeNotification")
#pragma comment(linker, "/EXPORT:WinHttpResetAutoProxy=C:\\Windows\\System32\\winhttp.WinHttpResetAutoProxy")
#pragma comment(linker, "/EXPORT:WinHttpResolverGetProxyForUrl=C:\\Windows\\System32\\winhttp.WinHttpResolverGetProxyForUrl")
#pragma comment(linker, "/EXPORT:WinHttpSaveProxyCredentials=C:\\Windows\\System32\\winhttp.WinHttpSaveProxyCredentials")
#pragma comment(linker, "/EXPORT:WinHttpSendRequest=C:\\Windows\\System32\\winhttp.WinHttpSendRequest")
#pragma comment(linker, "/EXPORT:WinHttpSetCredentials=C:\\Windows\\System32\\winhttp.WinHttpSetCredentials")
#pragma comment(linker, "/EXPORT:WinHttpSetDefaultProxyConfiguration=C:\\Windows\\System32\\winhttp.WinHttpSetDefaultProxyConfiguration")
#pragma comment(linker, "/EXPORT:WinHttpSetOption=C:\\Windows\\System32\\winhttp.WinHttpSetOption")
#pragma comment(linker, "/EXPORT:WinHttpSetProxySettingsPerUser=C:\\Windows\\System32\\winhttp.WinHttpSetProxySettingsPerUser")
#pragma comment(linker, "/EXPORT:WinHttpSetSecureLegacyServersAppCompat=C:\\Windows\\System32\\winhttp.WinHttpSetSecureLegacyServersAppCompat")
#pragma comment(linker, "/EXPORT:WinHttpSetStatusCallback=C:\\Windows\\System32\\winhttp.WinHttpSetStatusCallback")
#pragma comment(linker, "/EXPORT:WinHttpSetTimeouts=C:\\Windows\\System32\\winhttp.WinHttpSetTimeouts")
#pragma comment(linker, "/EXPORT:WinHttpTimeFromSystemTime=C:\\Windows\\System32\\winhttp.WinHttpTimeFromSystemTime")
#pragma comment(linker, "/EXPORT:WinHttpTimeToSystemTime=C:\\Windows\\System32\\winhttp.WinHttpTimeToSystemTime")
#pragma comment(linker, "/EXPORT:WinHttpUnregisterProxyChangeNotification=C:\\Windows\\System32\\winhttp.WinHttpUnregisterProxyChangeNotification")
#pragma comment(linker, "/EXPORT:WinHttpWebSocketClose=C:\\Windows\\System32\\winhttp.WinHttpWebSocketClose")
#pragma comment(linker, "/EXPORT:WinHttpWebSocketCompleteUpgrade=C:\\Windows\\System32\\winhttp.WinHttpWebSocketCompleteUpgrade")
#pragma comment(linker, "/EXPORT:WinHttpWebSocketQueryCloseStatus=C:\\Windows\\System32\\winhttp.WinHttpWebSocketQueryCloseStatus")
#pragma comment(linker, "/EXPORT:WinHttpWebSocketReceive=C:\\Windows\\System32\\winhttp.WinHttpWebSocketReceive")
#pragma comment(linker, "/EXPORT:WinHttpWebSocketSend=C:\\Windows\\System32\\winhttp.WinHttpWebSocketSend")
#pragma comment(linker, "/EXPORT:WinHttpWebSocketShutdown=C:\\Windows\\System32\\winhttp.WinHttpWebSocketShutdown")
#pragma comment(linker, "/EXPORT:WinHttpWriteData=C:\\Windows\\System32\\winhttp.WinHttpWriteData")
#pragma comment(linker, "/EXPORT:WinHttpWriteProxySettings=C:\\Windows\\System32\\winhttp.WinHttpWriteProxySettings")
//  C:\Windows\System32\version.dll (version)
#pragma comment(linker, "/EXPORT:GetFileVersionInfoA=C:\\Windows\\System32\\version.GetFileVersionInfoA")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoByHandle=C:\\Windows\\System32\\version.GetFileVersionInfoByHandle")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoExA=C:\\Windows\\System32\\version.GetFileVersionInfoExA")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoExW=C:\\Windows\\System32\\version.GetFileVersionInfoExW")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeA=C:\\Windows\\System32\\version.GetFileVersionInfoSizeA")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeExA=C:\\Windows\\System32\\version.GetFileVersionInfoSizeExA")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeExW=C:\\Windows\\System32\\version.GetFileVersionInfoSizeExW")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeW=C:\\Windows\\System32\\version.GetFileVersionInfoSizeW")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoW=C:\\Windows\\System32\\version.GetFileVersionInfoW")
#pragma comment(linker, "/EXPORT:VerFindFileA=C:\\Windows\\System32\\version.VerFindFileA")
#pragma comment(linker, "/EXPORT:VerFindFileW=C:\\Windows\\System32\\version.VerFindFileW")
#pragma comment(linker, "/EXPORT:VerInstallFileA=C:\\Windows\\System32\\version.VerInstallFileA")
#pragma comment(linker, "/EXPORT:VerInstallFileW=C:\\Windows\\System32\\version.VerInstallFileW")
#pragma comment(linker, "/EXPORT:VerLanguageNameA=C:\\Windows\\System32\\version.VerLanguageNameA")
#pragma comment(linker, "/EXPORT:VerLanguageNameW=C:\\Windows\\System32\\version.VerLanguageNameW")
#pragma comment(linker, "/EXPORT:VerQueryValueA=C:\\Windows\\System32\\version.VerQueryValueA")
#pragma comment(linker, "/EXPORT:VerQueryValueW=C:\\Windows\\System32\\version.VerQueryValueW")
/* DLL SPOOFING END */
