#include <Windows.h>
#include <stdio.h>
#include <vector>
#include "ASSERT.h"
#include "Compiler.h"
#include "Util.h"
#include "Gadgets.h"
#include "dbghelp.h"
#include "RandomGenerator.h"


std::vector<RopCode*> RopGadgets;

struct GadgetPosition
{
	RopCode* RopGadget;
	DWORD_PTR Start;
	DWORD_PTR End;
};
std::vector< struct GadgetPosition > PlacedGadgets;
DWORD_PTR SelfAllocatedGadgetBuffer = NULL;

bool IsPositionOccupied( /*IN*/ const DWORD_PTR Offset, /*IN*/ const DWORD_PTR Size )
{
	for (size_t i = 0; i < (size_t)PlacedGadgets.size(); i++)
	{
		const struct GadgetPosition* p = &PlacedGadgets.at(i);
		for (DWORD_PTR j = Offset; j < (DWORD_PTR)(Offset+Size); j++)
		{
			if ( p->Start <= j && j <= p->End )
				return true;
		}

	}
	return false;
}

//https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmappedfilenamea
DWORD WINAPI
WrapperGetMappedFileNameW (
    HANDLE hProcess,
    LPVOID lpv,
    LPWSTR lpFilename,
    DWORD nSize
    )
{
	__ASSERT__( lpFilename != NULL );
	__ASSERT__( lpv != NULL );

	static DWORD (WINAPI* fncGetMappedFileNameW)(
		HANDLE hProcess,
		LPVOID lpv,
		LPWSTR lpFilename,
		DWORD nSize
    ) = NULL;

	if ( fncGetMappedFileNameW == NULL )
	{
		HMODULE Kernel32 = GetModuleHandleW( L"kernel32.dll" );
		if ( Kernel32 == NULL )
			 Kernel32 = LoadLibraryW( L"kernel32.dll" );
		__ASSERT__( Kernel32 != NULL );
		void*FunctionAddress = GetProcAddress( Kernel32, "GetMappedFileNameW" );
		if ( FunctionAddress == NULL )
			 FunctionAddress = GetProcAddress( Kernel32, "K32GetMappedFileNameW" );

		fncGetMappedFileNameW = ( decltype(fncGetMappedFileNameW) )FunctionAddress;
	}
	if ( fncGetMappedFileNameW == NULL )
		return NULL;

	return fncGetMappedFileNameW( hProcess, lpv, lpFilename, nSize );
}

struct MemoryRegionInfo
{
	DWORD_PTR BaseAddress;
	SIZE_T RegionSize;
};
struct MemorySearchThreadInfo
{
	HANDLE hGame;
	struct MemoryRegionInfo MemInfo;
	LONG* MemorySearchThreadCount;
	CRITICAL_SECTION* CriticalSection;
	HANDLE hThreadHandle;
};

DWORD __stdcall MemorySearchThread( /*IN OUT*/ MemorySearchThreadInfo* Parameter )
{
	__ASSERT__( Parameter != NULL );

	const DWORD_PTR BaseAddress = Parameter->MemInfo.BaseAddress;
	const SIZE_T RegionSize = Parameter->MemInfo.RegionSize;

	CRITICAL_SECTION* CriticalSection = Parameter->CriticalSection;

	BYTE* PageBuffer = (BYTE*)VirtualAlloc( NULL, RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
	__ASSERT__( PageBuffer != NULL );
	SIZE_T NumberOfBytesRead = NULL;
	const BOOL bSuccess = ReadProcessMemory( Parameter->hGame, (LPCVOID)BaseAddress, PageBuffer, RegionSize, &NumberOfBytesRead );
	if (bSuccess == TRUE && NumberOfBytesRead == RegionSize)
	{
		//printf("[%u] => ReadProcessMemory( 0x%X, 0x%X );\n",bSuccess,Base,RegionSize);

		for (DWORD r = 0; r < RopGadgets.size(); r++)
		{
			RopCode RG = {};
			ZeroMemory( &RG, sizeof(RopCode) );

			if ( CriticalSection != NULL ) EnterCriticalSection( CriticalSection );

			RG = *(RopCode*)RopGadgets.at(r);

			if ( CriticalSection != NULL ) LeaveCriticalSection( CriticalSection );
			
			for (DWORD_PTR s = 0; s < ( (DWORD_PTR)RegionSize - (DWORD_PTR)(RG.CodeLen) ); s++)
			{
				if ( __memcmp__( PageBuffer + s , RG.Code, RG.CodeLen ) == 0 )
				{
					if ( CriticalSection != NULL ) EnterCriticalSection( CriticalSection );
					RopCode* pRG = (RopCode*)RopGadgets.at(r);
					pRG->AddAddress( BaseAddress + s );
					if ( CriticalSection != NULL ) LeaveCriticalSection( CriticalSection );

					break;
				}
			}

		}
	}
	VirtualFree( PageBuffer, NULL, MEM_RELEASE );

	if ( Parameter->MemorySearchThreadCount != NULL )
	_InterlockedDecrement( Parameter->MemorySearchThreadCount );
	return 0;
}

void VirtualQueryScanner( /*IN*/ const HANDLE hGame )
{
	__ASSERT__( hGame != INVALID_HANDLE_VALUE && hGame != NULL );

	SYSTEM_INFO SystemInfo = {};
	ZeroMemory(&SystemInfo, sizeof(SYSTEM_INFO) );

	GetSystemInfo( &SystemInfo );

	std::vector< struct MemoryRegionInfo > MemoryRegions;
	MemoryRegions.clear();

	printf("[+] Searching for executable memory regions\n");

	wchar_t ModuleName[256] = {};

	DWORD_PTR Addr = (DWORD_PTR)SystemInfo.lpMinimumApplicationAddress;
	while (Addr < (DWORD_PTR)SystemInfo.lpMaximumApplicationAddress)
	{
		MEMORY_BASIC_INFORMATION MemInfo = {};
		ZeroMemory( &MemInfo, sizeof(MEMORY_BASIC_INFORMATION) );

		const SIZE_T 
		     Result = VirtualQueryEx( hGame, (void*)Addr, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION) );
		if ( Result == sizeof(MEMORY_BASIC_INFORMATION) )
		{
			if ( MemInfo.State == MEM_COMMIT && ( MemInfo.Type == MEM_IMAGE || MemInfo.Type == MEM_MAPPED ) )
			{
				if ( (MemInfo.Protect & (PAGE_NOACCESS|PAGE_GUARD)) == 0 )
				{
					
					if ( (MemInfo.Protect & ( PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY )) != 0 )
					{
						BOOLEAN SkipMemoryRegion = FALSE;
						DWORD ModuleNameLen = WrapperGetMappedFileNameW( hGame, MemInfo.BaseAddress, ModuleName, 255 );
						if ( ModuleNameLen > NULL )
						{
							ModuleName[ModuleNameLen] = NULL;
							for (DWORD tl = 0; tl < ModuleNameLen; tl++)
								ModuleName[tl] = (wchar_t)towlower( ModuleName[tl] );
							//this module is only present in the main menu
							//L"vaudio_celt.dll",

							if ( wcsstr( ModuleName, L"vaudio_celt" ) != NULL )
								SkipMemoryRegion = TRUE;
						}
						if ( SkipMemoryRegion == FALSE )
						{
							struct MemoryRegionInfo Info = {};
							Info.BaseAddress = (DWORD_PTR)MemInfo.BaseAddress;
							Info.RegionSize = (SIZE_T)MemInfo.RegionSize;

							MemoryRegions.push_back( Info );
						}
					}

				}
			}
			Addr += MemInfo.RegionSize;
		}
		else
			Addr += (DWORD_PTR)0x1000;
	}
	const UINT MemoryRegionsSize = (UINT)MemoryRegions.size();

	printf("[+] Searching %u found memory regions\n",MemoryRegionsSize);

	Progressbar Progress("Searching for gadgets",50);
	
	std::vector< MemorySearchThreadInfo* > Threads; Threads.clear();

	static CRITICAL_SECTION CriticalSection = {};
	InitializeCriticalSection( &CriticalSection );

	static LONG MemorySearchThreadCount = 0;

	for (UINT m = 0; m < (UINT)MemoryRegionsSize; m++)
	{
		Progress.update( "",(double)( m + 1 ) / (double)(MemoryRegionsSize) );

		const struct MemoryRegionInfo* p = &MemoryRegions.at( m );
		
		struct MemorySearchThreadInfo InfoStruct = {};
		ZeroMemory( &InfoStruct, sizeof(struct MemorySearchThreadInfo) );

		InfoStruct.hGame = hGame;
		InfoStruct.MemInfo = *(struct MemoryRegionInfo*)p;

		if ( p->RegionSize > (SIZE_T)(256*1024) )
		{
			struct MemorySearchThreadInfo* Info = (struct MemorySearchThreadInfo*)malloc( sizeof(MemorySearchThreadInfo) );
			__ASSERT__( Info != NULL );

			memcpy( Info, &InfoStruct, sizeof(struct MemorySearchThreadInfo) );
			_InterlockedIncrement( &MemorySearchThreadCount );

			Info->CriticalSection = &CriticalSection;
			Info->MemorySearchThreadCount = &MemorySearchThreadCount;

			Info->hThreadHandle = CreateThread( NULL, NULL, (LPTHREAD_START_ROUTINE)MemorySearchThread, Info, NULL, NULL );
			if ( Info->hThreadHandle == NULL || Info->hThreadHandle == INVALID_HANDLE_VALUE )
			{
				printf("ERROR: [%s] FAILED TO START \"MemorySearchThread\" THREAD INDEX:[%u]\n",__FUNCTION__,m);
				_InterlockedDecrement( &MemorySearchThreadCount );
				free( Info );
			}
			else
				Threads.push_back( Info );
		}
		else
		{
			InfoStruct.CriticalSection = NULL;
			InfoStruct.MemorySearchThreadCount = NULL;

			MemorySearchThread( &InfoStruct );
		}
	}

	//faster compare to waiting using the thread handles
	while ( _InterlockedCompareExchange( &MemorySearchThreadCount, (long)0, (long)0 ) != 0 )
				Sleep( 1 );
	
	const UINT ThreadCount = (UINT)Threads.size();
	for (UINT t = 0; t < ThreadCount; t++)
	{
		MemorySearchThreadInfo* ThreadInfo = Threads.at(t);
		__ASSERT__( ThreadInfo != NULL );

		HANDLE hThreadHandle = ThreadInfo->hThreadHandle;
		CloseHandle( hThreadHandle );
		ZeroMemory( ThreadInfo, sizeof(MemorySearchThreadInfo) );
		free( ThreadInfo );
	}
	Threads.clear();
	const DWORD TotalGadgetsCounter = (DWORD)(RopGadgets.size());
	DWORD GadgetsCounter = 0;
	for (DWORD r = 0; r < TotalGadgetsCounter; r++)
	{
		
		const RopCode* RG = RopGadgets.at(r);
		/*
		if ( RG->Addresses != 0 )
		{
			for (DWORD r2 = 0; r2 < (DWORD)RG->Addresses->Addresses.size(); r2++)
			{
				printf("[0x%X] [%s]\n",RG->Addresses->Addresses.at(r2),RG->Instruction);
			}
		}*/

		if ( RG->Addresses != 0 )
		{
			//printf("FOUND [%s] %u TIMES\n",RG->Instruction,RG->Addresses->Addresses.size());
			GadgetsCounter++;
			continue;
		}
		else
			;//printf("NOT FOUND [%s]\n",RG->Instruction);
	}
	printf("[+] [%u/%u] Gadgets found\n",GadgetsCounter,TotalGadgetsCounter);
	MemoryRegions.clear();	

	DeleteCriticalSection( &CriticalSection );
}

struct SearchThreadParameters
{
	CRITICAL_SECTION* CriticalSection;

	HANDLE hGame;

	HMODULE DllAddress;
	HMODULE RemoteDllAddress;

	DWORD_PTR VirtualAddress;
	DWORD VirtualSize;
	
	DWORD NumberOfGadgetsFound;
	LONG* ActiveThreadCount;
};

DWORD __stdcall SearchDllThread( /*IN OUT*/ SearchThreadParameters* Parameters )
{
	__ASSERT__( Parameters != NULL );

	RopCode RG = {};
	const DWORD_PTR VirtualAddress = Parameters->VirtualAddress;
	const HMODULE DllAddress = Parameters->DllAddress;
	const HMODULE RemoteDllAddress = Parameters->RemoteDllAddress;

	for (DWORD r = 0; r < (DWORD)(RopGadgets.size()); r++)
	{	
		ZeroMemory( &RG, sizeof(RopCode) );
		EnterCriticalSection( Parameters->CriticalSection );
		RG = *(RopCode*)RopGadgets.at(r);
		LeaveCriticalSection( Parameters->CriticalSection );

		for (DWORD p = 0; p < (DWORD)( (DWORD)Parameters->VirtualSize - (DWORD)RG.CodeLen ); p++)
		{
			const DWORD_PTR Addr = VirtualAddress + (DWORD_PTR)p;

			if ( __memcmp__( (void*)( Addr ), RG.Code, RG.CodeLen ) == 0)
			{
				//printf("Gadget [%s] found in [%ws]->[%s]\n",RG->Instruction,DynamicLinkLibrary[i],SectionHeader->Name);
				DWORD_PTR GadgetAddr = (DWORD_PTR)Addr;
				if ( RemoteDllAddress != NULL )
					GadgetAddr = (GadgetAddr - (DWORD_PTR)DllAddress) + (DWORD_PTR)RemoteDllAddress;

				BYTE* RemoteGadgetBuffer = (BYTE*)malloc( RG.CodeLen + 1 );
				__ASSERT__( RemoteGadgetBuffer != NULL );
				ZeroMemory( RemoteGadgetBuffer, RG.CodeLen + 1 );

				//Make sure it is correct:
				ReadProcessMemory( Parameters->hGame, (void*)GadgetAddr, RemoteGadgetBuffer, RG.CodeLen, NULL );
				if ( __memcmp__( (void*)( RemoteGadgetBuffer ), RG.Code, RG.CodeLen ) == 0)
				{
					EnterCriticalSection( Parameters->CriticalSection );
					RopCode* pRG = RopGadgets.at(r);
					pRG->AddAddress( GadgetAddr );
					LeaveCriticalSection( Parameters->CriticalSection );
				}
				free( RemoteGadgetBuffer );
			}
		}
	}
	_InterlockedDecrement( Parameters->ActiveThreadCount );
	return 0;
}

void SearchRemoteDynamicLinkLibrary( /*IN*/ const HANDLE hGame )
{
	__ASSERT__( hGame != INVALID_HANDLE_VALUE && hGame != NULL );
	
	
	const WCHAR* 
	DynamicLinkLibrary[] = {
		L"ntdll.dll",
		L"kernel32.dll",
		L"kernelbase.dll",

		L"csgo.exe",

		//sorted by size
		L"client_panorama.dll",
		L"phonon.dll",
		L"nvd3dum_cfg.dll",
		L"shell32.dll",
		L"nvd3dum.dll",
		L"steamclient.dll",
		L"v8.dll",
		L"server.dll",
		L"engine.dll",
		L"windows.storage.dll",
		L"studiorender.dll",
		L"d2d1.dll",
		L"nvapi.dll",
		L"wininet.dll",
		L"video.dll",
		L"libavcodec-56.dll",
		L"tier0.dll",
		L"panorama.dll",
		L"steamnetworkingsockets.dll",
		L"iertutil.dll",
		L"icui18n.dll",
		L"nvspcap.dll",
		L"D3DX9_43.dll",
		L"d3d9.dll",
		L"setupapi.dll",
		L"icuuc.dll",
		L"crypt32.dll",
		L"panoramauiclient.dll",
		L"combase.dll",
		L"CoreUIComponents.dll",
		L"AcGenral.dll",
		L"GameOverlayRenderer.dll",
		L"user32.dll",
		L"d3d11.dll",
		L"urlmon.dll",
		L"libglib-2.0-0.dll",
		L"vguimatsurface.dll",
		L"dbghelp.dll",
		L"propsys.dll",
		L"vphysics.dll",
		L"stdshader_dx9.dll",
		L"ole32.dll",
		L"serverbrowser.dll",
		L"twinapi.appcore.dll",
		L"msctf.dll",
		L"materialsystem.dll",
		L"gdi32.dll",
		L"gdi32full.dll",
		L"cairo.dll",
		L"nvldumd.dll",
		L"uxtheme.dll",
		L"libfreetype-6.dll",
		L"v8_libbase.dll",
		L"matchmaking.dll",
		L"vscript.dll",
		L"shaderapidx9.dll",
		L"v8_libplatform.dll",
		L"Windows.UI.dll",
		L"WinTypes.dll",
		L"fastprox.dll",
		L"ucrtbase.dll",
		L"rpcrt4.dll",
		L"panorama_text_pango.dll",
		L"crashhandler.dll",
		L"nvSCPAPI.dll",
		L"apphelp.dll",
		L"winhttp.dll",
		L"tier0_s.dll",
		L"oleaut32.dll",
		L"XAudio2_7.dll",
		L"clbcatq.dll",
		L"SHCore.dll",
		L"comctl32.dll",
		L"mss32.dll",
		L"dsound.dll",
		L"dnsapi.dll",
		L"advapi32.dll",
		L"TextInputFramework.dll",
		L"libswscale-3.dll",
		L"vgui2.dll",
		L"libavformat-56.dll",
		L"datacache.dll",
		L"libavutil-54.dll",
		L"mscms.dll",
		L"filesystem_stdio.dll",
		L"dxgi.dll",
		L"libfontconfig-1.dll",
		L"wbemcomn.dll",
		L"CoreMessaging.dll",
		L"AudioSes.dll",
		L"InputHost.dll",
		L"vstdlib_s.dll",
		L"libpango-1.0-0.dll",
		L"libavresample-2.dll",
		L"Wldap32.dll",
		L"bcryptprimitives.dll",
		L"MMDevAPI.dll",
		L"stdshader_dbg.dll",
		L"soundsystem.dll",
		L"nvStereoApiI.dll",
		L"libpangoft2-1.0-0.dll",
		L"ws2_32.dll",
		L"mswsock.dll",
		L"launcher.dll",
		L"libgobject-2.0-0.dll",
		L"FWPUCLNT.DLL",
		L"shlwapi.dll",
		L"vstdlib.dll",
		L"sechost.dll",
		L"powrprof.dll",
		L"wlanapi.dll",
		L"soundemittersystem.dll",
		L"localize.dll",
		L"wintrust.dll",
		L"inputsystem.dll",
		L"imemanager.dll",
		L"cfgmgr32.dll",
		L"steam_api.dll",
		L"valve_avi.dll",
		L"rsaenh.dll",

		//MSVC
		L"msvcrt.dll",
		L"msvcp_win.dll",
		L"msvcr90.dll",
		L"msvcp140.dll",
		L"msvcp110.dll",
		L"MSVCR120.dll",
		L"msvcr110.dll",
		L"MSVCP120.dll",

		//this module is only present in the main menu
		//L"vaudio_celt.dll",

		L"ntasn1.dll",
		L"ntmarta.dll",
		L"imm32.dll",
		L"cryptnet.dll",
		L"dinput.dll",
		L"winmm.dll",
		L"winmmbase.dll",
		L"msvfw32.dll",
		L"devobj.dll",
		L"IPHLPAPI.DLL",
		L"ncrypt.dll",
		L"gpapi.dll",
		L"rmclient.dll",
		L"sspicli.dll",
		L"bcrypt.dll",
		L"userenv.dll",
		L"dwmapi.dll",
		L"avifil32.dll",
		L"scenefilecache.dll",
		L"cryptsp.dll",
		L"vaudio_miles.dll",
		L"mpr.dll",
		L"parsifal.dll",
		L"msacm32.dll",
		L"libgmodule-2.0-0.dll",
		L"pnrpnsp.dll",
		L"win32u.dll",
		L"usp10.dll",
		L"imagehlp.dll",
		L"dhcpcsvc.dll",
		L"nlaapi.dll",
		L"xinput1_3.dll",
		L"dhcpcsvc6.dll",
		L"samcli.dll",
		L"NapiNSP.dll",
		L"wbemsvc.dll",
		L"profapi.dll",
		L"msasn1.dll",
		L"wbemprox.dll",
		L"cryptbase.dll",
		L"wshbth.dll",
		L"winrnr.dll",
		L"secur32.dll",
		L"hid.dll",
		L"avrt.dll",
		L"winnsi.dll",
		L"rasadhlp.dll",
		L"version.dll",
		L"wsock32.dll",
		L"midimap.dll",
		L"nsi.dll",
		L"ksuser.dll",
		L"psapi.dll",
		L"coloradapterclient.dll",
		L"normaliz.dll",

		//BF3:
		L"EACore.dll",
		L"IGO32.dll",
		L"pbsv.dll",
		L"pbag.dll",
		L"pbcl.dll",
		L"nvwgf2um.dll",
		L"awc.dll",
		L"D3DCompiler_43.dll",
		L"ddraw.dll",
		L"comdlg32.dll",
		L"webio.dll",
		L"d3dx11_43.dll",
		L"dinput8.dll",
		L"winsta.dll",
		L"vcruntime140.dll",
		L"RpcRtRemote.dll",
		L"wtsapi32.dll",
		L"lpk.dll",
		L"XInput9_1_0.dll",
		L"dciman32.dll",
		L"d3d8thk.dll",
		L"WSHTCPIP.DLL",

		L"api-ms-win-crt-math-l1-1-0.dll",
		L"api-ms-win-crt-runtime-l1-1-0.dll",
		L"api-ms-win-crt-string-l1-1-0.dll",
		L"api-ms-win-crt-stdio-l1-1-0.dll",
		L"api-ms-win-crt-convert-l1-1-0.dll",
		L"api-ms-win-downlevel-shlwapi-l2-1-0.dll",
		L"api-ms-win-core-timezone-l1-1-0.dll",
		L"api-ms-win-core-file-l2-1-0.dll",
		L"api-ms-win-core-localization-l1-2-0.dll",
		L"api-ms-win-core-processthreads-l1-1-1.dll",
		L"api-ms-win-core-file-l1-2-0.dll",
		L"api-ms-win-crt-heap-l1-1-0.dll",
		L"api-ms-win-crt-locale-l1-1-0.dll",
		L"api-ms-win-crt-filesystem-l1-1-0.dll",
		L"api-ms-win-crt-time-l1-1-0.dll",
		L"api-ms-win-core-synch-l1-2-0.dll",
		L"api-ms-win-crt-environment-l1-1-0.dll",
		L"api-ms-win-crt-utility-l1-1-0.dll",
		L"api-ms-win-downlevel-version-l1-1-0.dll",
		L"api-ms-win-downlevel-ole32-l1-1-0.dll",
		L"api-ms-win-downlevel-user32-l1-1-0.dll",
		L"api-ms-win-downlevel-normaliz-l1-1-0.dll",
		L"api-ms-win-downlevel-shlwapi-l1-1-0.dll",
		L"api-ms-win-downlevel-advapi32-l1-1-0.dll",

		//bf4:
		L"Engine.BuildInfo_Win32_retail.dll",
		L"Extension.Twinkle.Codec_Win32_retail.dll",
		L"Activation.dll",
		L"AcLayers.dll",
		L"duser.dll",
		L"dui70.dll",

		//other:
		L"ExplorerFrame.dll",
		L"ResourcePolicyClient.dll",
		L"kernel.appcore.dll",
		L"winnlsres.dll",

		L"fraps32.dll",
		L"DiscordHook.dll",
		L"GraphicsCaptureHook.dll",
		L"RTSSHooks.dll",

		L"shfolder.dll",
	};

	CRITICAL_SECTION SearchThreadCriticalSection = {};
	ZeroMemory( &SearchThreadCriticalSection, sizeof(CRITICAL_SECTION) );
	InitializeCriticalSection( &SearchThreadCriticalSection );

	Progressbar Progress( "Searching for gadgets", 50 );

	char StatusText[64] = {};
	ZeroMemory( StatusText, sizeof(StatusText) );

	const DWORD ProcessId = GetProcessId( hGame );

	DWORD NumberOfGadgetsFound = 0;

	for (UINT i = 0; i < (UINT)ARRAYSIZE(DynamicLinkLibrary); i++)
	{
		HMODULE DllAddress = (HMODULE)NULL;
		HMODULE RemoteDllAddress = (HMODULE)NULL;
		
		const wchar_t* DllName = (const wchar_t*)DynamicLinkLibrary[i];

		sprintf_s( StatusText, "File: [%ws]%*s", DllName, 45 - wcslen(DllName), "" );
		Progress.update( StatusText,(double)( i + 1) / (double)(ARRAYSIZE(DynamicLinkLibrary)) );

		if ( i < 3 )
			DllAddress = GetModuleHandleW( DllName );
			//the first three system dlls are always mapped to the same address in every process
		else
		{
			struct RemoteProcessModuleInfo RemoteDllInfo = {};
			ZeroMemory(&RemoteDllInfo, sizeof(struct RemoteProcessModuleInfo) );

			if ( GetRemoteProcessModuleInfo( ProcessId, DllName, &RemoteDllInfo ) == true )
			{
				BYTE* DiskDllImage = (BYTE*)NULL;
				DWORD DiskDllImageSize = (DWORD)NULL;
				LoadFileToMemory( RemoteDllInfo.szExePath, &DiskDllImage, &DiskDllImageSize );

				if ( DiskDllImage != NULL && DiskDllImageSize != NULL )
				{
					RemoteDllAddress = (HMODULE)RemoteDllInfo.modBaseAddr;
					DllAddress = (HMODULE)ManualMapDynamicLinkLibrary( DiskDllImage, (DWORD_PTR)RemoteDllInfo.modBaseAddr );
					free( DiskDllImage );
				}
			}
		}
		if ( DllAddress == NULL ) continue;
		
		IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)DllAddress;
		const IMAGE_NT_HEADERS* NtHeaders = (IMAGE_NT_HEADERS*)ImageNtHeader( DosHeader );
		if ( NtHeaders == NULL ) continue;

		const WORD NumberOfSections = NtHeaders->FileHeader.NumberOfSections;
		if ( NumberOfSections < 1 ) continue;
		
		IMAGE_SECTION_HEADER* SectionHeaders = (IMAGE_SECTION_HEADER*)( (DWORD_PTR)NtHeaders + sizeof(IMAGE_NT_HEADERS) );
		for (WORD j = 0; j < (WORD)NumberOfSections; j++)
		{
			const IMAGE_SECTION_HEADER* SectionHeader = &SectionHeaders[j];
			if ( (SectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) != IMAGE_SCN_MEM_EXECUTE ) continue;

			//Ignore discardable sections:
			if ( (SectionHeader->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == IMAGE_SCN_MEM_DISCARDABLE ) continue;

			const DWORD_PTR VirtualAddress = (DWORD_PTR)SectionHeader->VirtualAddress + (DWORD_PTR)DosHeader;
			const DWORD VirtualSize = SectionHeader->Misc.VirtualSize;

			DWORD SearchOffset = 0;

			//for each ~100KB of data create a thread
			const DWORD PerThreadDataSize = 1024 * 100;
			const DWORD ThreadCount = ( VirtualSize / PerThreadDataSize ) + 1;

			HANDLE* ThreadHandles = (HANDLE*)malloc( sizeof(HANDLE) * ThreadCount );
			__ASSERT__( ThreadHandles != NULL );

			HANDLE* ThreadParametersList = (HANDLE*)malloc( sizeof(SearchThreadParameters) * (ThreadCount+1) );
			__ASSERT__( ThreadParametersList != NULL );

			static LONG ActiveThreadCount = 0;
			InterlockedExchange( &ActiveThreadCount, ThreadCount );
			
			for (DWORD t = 0; t < ThreadCount; t++)
			{
				SearchThreadParameters* ThreadParameters = (SearchThreadParameters*)( (DWORD_PTR)ThreadParametersList + ( sizeof(SearchThreadParameters) * t ) );
				ZeroMemory( ThreadParameters, sizeof(SearchThreadParameters) );

				ThreadParameters->CriticalSection = (CRITICAL_SECTION*)&SearchThreadCriticalSection;

				ThreadParameters->hGame = hGame;

				ThreadParameters->DllAddress = DllAddress;
				ThreadParameters->RemoteDllAddress = RemoteDllAddress;

				ThreadParameters->VirtualAddress = VirtualAddress + (DWORD_PTR)SearchOffset;

				ThreadParameters->ActiveThreadCount = &ActiveThreadCount;

				ThreadParameters->NumberOfGadgetsFound = (DWORD)NULL;

				DWORD VS = PerThreadDataSize + SearchOffset;

				if ( VS > VirtualSize )
					 VS = VirtualSize - SearchOffset;
				else
					VS = PerThreadDataSize;
				ThreadParameters->VirtualSize = VS;

				if ( ThreadCount == 1 )
				{
					//Don't create a thread use the current one:
					ThreadHandles[t] = INVALID_HANDLE_VALUE;
					SearchDllThread( ThreadParameters );
					break;
				}
				else
				{
					HANDLE hThreadHandle = CreateThread( NULL, NULL, (LPTHREAD_START_ROUTINE)SearchDllThread, (void*)ThreadParameters, NULL, NULL );
					if ( hThreadHandle == NULL || hThreadHandle == INVALID_HANDLE_VALUE )
					{
						printf("ERROR: [%s] FAILED TO START \"SearchDllThread\" THREAD INDEX:[%u]\n",__FUNCTION__,t);
						_InterlockedDecrement( &ActiveThreadCount );
					}
					ThreadHandles[t] = hThreadHandle;
				}
			

				SearchOffset += PerThreadDataSize;
			}

			while ( ThreadCount > 1 && _InterlockedCompareExchange( &ActiveThreadCount, (long)0, (long)0 ) != (long)0 )
				Sleep( 1 );
		
			for (DWORD w = 0; w < ThreadCount; w++)
			{
				SearchThreadParameters* ThreadParameters = (SearchThreadParameters*)( (DWORD_PTR)ThreadParametersList + ( sizeof(SearchThreadParameters) * w ) );

				NumberOfGadgetsFound += ThreadParameters->NumberOfGadgetsFound;
				
				HANDLE hThreadHandle = ThreadHandles[w];
				if ( hThreadHandle != NULL && hThreadHandle != INVALID_HANDLE_VALUE )
					CloseHandle( hThreadHandle );
			}
			free( ThreadParametersList );
			free( ThreadHandles );
			//printf("Searching [%ws]->[%s] at [0x%X] Size:[0x%X]\n",DynamicLinkLibrary[i],SectionHeader->Name,VirtualAddress,VirtualSize);
		}
		if ( RemoteDllAddress != NULL )
		{
			const DWORD SizeOfImage = NtHeaders->OptionalHeader.SizeOfImage;
			      DWORD MappedPageSize = (SizeOfImage / (DWORD)0x1000ui32) * (DWORD)0x1000ui32;
			if ( (SizeOfImage % (DWORD)0x1000ui32) != 0 )
				MappedPageSize += (DWORD)0x1000ui32;

			VirtualFree( (void*)DllAddress, NULL, MEM_RELEASE );
		}
	}

	DeleteCriticalSection( &SearchThreadCriticalSection );
	DWORD GadgetsCounter = 0;
	const DWORD TotalGadgetsCounter = (DWORD)(RopGadgets.size());
	for (DWORD r = 0; r < TotalGadgetsCounter; r++)
	{
		
		const RopCode* RG = RopGadgets.at(r);
		/*
		if ( RG->Addresses != 0 )
		{
			for (DWORD r2 = 0; r2 < (DWORD)RG->Addresses->Addresses.size(); r2++)
			{
				printf("[0x%X] [%s]\n",RG->Addresses->Addresses.at(r2),RG->Instruction);
			}
		}*/
		if ( RG->Addresses != 0 )
		{
			//printf("FOUND [%s] %u TIMES\n",RG->Instruction,RG->Addresses->Addresses.size());
			GadgetsCounter++;
			continue;
		}
		else
			;//printf("NOT FOUND [%s]\n",RG->Instruction);
	}
	printf("[+] [%u/%u] Gadgets found\n",GadgetsCounter,TotalGadgetsCounter);
}

void InitializeRopGadgets( /*IN*/ const HANDLE hGame )
{
	__ASSERT__( hGame != INVALID_HANDLE_VALUE && hGame != NULL );

	RopGadgets.clear();
	for (DWORD i = 0; i < (DWORD)ARRAYSIZE(g_RopGadgets); i++)
	{
		struct RopCode* RopGadget = &g_RopGadgets[i];
		RopGadget->Addresses = NULL;
		RopGadget->RefCntr = NULL;
		RopGadgets.push_back( RopGadget );
	}

	if ( g_CompilerSettings.SearchDlls == true )
		SearchRemoteDynamicLinkLibrary( hGame );

	if ( g_CompilerSettings.VirtualQuerySearch == true )
		VirtualQueryScanner( hGame );
}

void ReleaseRopGadgets( void )
{
	const DWORD GadgetCount = (DWORD)RopGadgets.size();
	for (DWORD i = 0; i < GadgetCount; i++)
	{
		struct RopCode* RopGadget = RopGadgets.at(i);
		if ( RopGadget != NULL )
		{
			RopCode::RopAddresses* RopAddresses = RopGadget->Addresses;
			if ( RopAddresses != NULL )
			{
				RopGadget->Destructor();
				RopGadget->Addresses = NULL; 

				//To prevent free after free ;)
				for (DWORD j = 0; j < GadgetCount; j++)
				{
					struct RopCode* RopGadget2 = RopGadgets.at(j);
					if ( RopGadget2 != NULL && RopGadget2->Addresses == RopAddresses )
						RopGadget2->Addresses = NULL;
				}
			}
		}
	}
	RopGadgets.clear();
}

void BringYourOwnGadgets( /*IN*/ const HANDLE hGame )
{
	__ASSERT__( hGame != INVALID_HANDLE_VALUE && hGame != NULL );

	PlacedGadgets.clear();

	DWORD NumberOfNotFoundGadgets = NULL;
	for (DWORD r = NULL; r < (DWORD)RopGadgets.size(); r++)
	{
		const RopCode* RG = RopGadgets.at(r);
		if ( RG->Addresses != NULL ) continue;
		NumberOfNotFoundGadgets++;
	}
	if ( NumberOfNotFoundGadgets == NULL ) return;

	DWORD RandomFlags[] = { PAGE_READWRITE, PAGE_EXECUTE_READWRITE };
	const DWORD ProtectionFlags = *(DWORD*)SelectRandomElement( RandomFlags, getArraySize( RandomFlags, DWORD ), sizeof(DWORD) );
	
	DWORD RandomSize = (DWORD)0x4000ui32;

	if ( (NumberOfNotFoundGadgets / (DWORD)10ui32) > 0 )
		RandomSize += (DWORD)0x1000ui32 * (NumberOfNotFoundGadgets / (DWORD)10ui32);

	RandomSize += (DWORD)( g_RandomGenerator.GetDword() % (DWORD)0x4001ui32 );

	DWORD GadgetBufferSize = (DWORD)( (DWORD)(RandomSize / 0x1000ui32) * 0x1000ui32 );
	if ( (DWORD)(RandomSize % 0x1000ui32) != (DWORD)NULL )
		GadgetBufferSize += (DWORD)0x1000ui32;

	BYTE* AllocatedMem = (BYTE*)VirtualAllocEx( hGame, NULL, GadgetBufferSize, MEM_COMMIT | MEM_RESERVE, ProtectionFlags );
	if ( AllocatedMem == NULL )
	{
		printf("[%s] ERROR FAILED TO ALLOCATE GADGET BUFFER [0x%X]\n",__FUNCTION__, GetLastError() );
		system("pause");
		 return;
	}
	SelfAllocatedGadgetBuffer = (DWORD_PTR)AllocatedMem;
	printf("[+] Allocating Gadget buffer [0x%p][0x%X]\n", AllocatedMem, GadgetBufferSize );
	

	BYTE* LocalBuffer = (BYTE*)malloc( GadgetBufferSize );
	__ASSERT__( LocalBuffer != NULL );

	g_RandomGenerator.GetBuffer( LocalBuffer, GadgetBufferSize );

	for (DWORD r = 0; r < (DWORD)RopGadgets.size(); r++)
	{
		RopCode* RG = RopGadgets.at(r);
		if ( RG->Addresses != NULL ) continue;
		
		DWORD RandomOffset = NULL;
		do
		{
			RandomOffset = g_RandomGenerator.GetDword() % ( GadgetBufferSize - RG->CodeLen - 1 );
		}
		while ( IsPositionOccupied( RandomOffset, RG->CodeLen + 1 ) != false );

		memcpy( (void*)( (DWORD_PTR)LocalBuffer + (DWORD_PTR)RandomOffset ), RG->Code, RG->CodeLen );

		RG->AddAddress( (DWORD_PTR)( (DWORD_PTR)AllocatedMem + (DWORD_PTR)RandomOffset) );

		struct GadgetPosition Info = {};
		ZeroMemory(&Info, sizeof(GadgetPosition) );

		Info.Start = RandomOffset;
		Info.End = RandomOffset + RG->CodeLen + 1;
		Info.RopGadget = RG;
		PlacedGadgets.push_back( Info );
		
		if ( (DWORD)(r+1) < (DWORD)(RopGadgets.size()) )
		{
			for (DWORD r2 = (DWORD)(r+1); r2 < (DWORD)(RopGadgets.size()); r2++)
			{
				struct RopCode* RG2 = RopGadgets.at(r2);
				if ( RG2->Addresses != NULL ) continue;
				if ( RG2->CodeLen != RG->CodeLen ) continue;
				if ( memcmp( RG2->Code, RG->Code, RG->CodeLen) != 0 ) continue;
				//same instruction:
				RG2->Addresses = RG->Addresses;
			}
		}
		
	}
	WriteProcessMemory( hGame, AllocatedMem, LocalBuffer, (SIZE_T)GadgetBufferSize, nullptr );
	free( LocalBuffer );

	DWORD NewRandomFlags[] = { PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY };

	DWORD NewProtectionFlags = *(DWORD*)SelectRandomElement( NewRandomFlags, getArraySize( NewRandomFlags, DWORD ), sizeof(DWORD) );
	DWORD dwOldProtection = NULL;
	VirtualProtectEx( hGame, AllocatedMem, (SIZE_T)GadgetBufferSize, NewProtectionFlags, &dwOldProtection );

	for (DWORD Counter = 0; Counter < (DWORD)( GadgetBufferSize / 0x1000ui32 ); Counter++)
	{
		NewProtectionFlags = *(DWORD*)SelectRandomElement( NewRandomFlags, getArraySize( NewRandomFlags, DWORD ), sizeof(DWORD) );
		dwOldProtection = NULL;
		VirtualProtectEx( hGame, AllocatedMem + (DWORD)(Counter * 0x1000ui32), (SIZE_T)0x1000, NewProtectionFlags, &dwOldProtection );
	}
	
}

void RemoveUnusedGadgets( /*IN*/ const HANDLE hGame )
{
	__ASSERT__( hGame != INVALID_HANDLE_VALUE && hGame != NULL );

	DWORD RemovedGadgetCounter = NULL;
	const UINT PlacedGadgetsCount = (UINT)PlacedGadgets.size();
	if ( PlacedGadgetsCount == NULL )
		return;
	
	__ASSERT__( SelfAllocatedGadgetBuffer != NULL );

	for (UINT i = 0; i < (UINT)PlacedGadgetsCount; i++)
	{
		const struct GadgetPosition* GP = &PlacedGadgets.at(i);

		DWORD Ref = NULL;

		const RopCode* RG = GP->RopGadget;
		for (DWORD r2 = 0; r2 < (DWORD)(RopGadgets.size()); r2++)
		{
			const struct RopCode* RG2 = RopGadgets.at(r2);
			if ( RG2->Addresses == NULL ) continue;

			if ( RG2->CodeLen != RG->CodeLen ) continue;
			if ( __memcmp__( RG2->Code, RG->Code, RG->CodeLen) != 0 ) continue;
			//same instruction:
			Ref += RG2->RefCntr;
		}

		if ( Ref == 0 )
		{
			//printf("REMOVING: [%s] at [0x%X]\n",RG->Instruction,GP->Start);
			RemovedGadgetCounter++;
			BYTE* RandomBuffer = (BYTE*)malloc( RG->CodeLen + 1 );
			__ASSERT__( RandomBuffer != NULL );

			g_RandomGenerator.GetBuffer( RandomBuffer, RG->CodeLen + 1 );
			DWORD dwOldProtection = NULL;
			VirtualProtectEx( hGame, (void*)GP->Start, RG->CodeLen, PAGE_EXECUTE_READWRITE, &dwOldProtection );
			WriteProcessMemory( hGame, (void*)GP->Start, RandomBuffer, RG->CodeLen, NULL );
			VirtualProtectEx( hGame, (void*)GP->Start, RG->CodeLen, dwOldProtection, &dwOldProtection );
			free( RandomBuffer ); RandomBuffer = NULL;
		}
		else
		{
			//printf("RopGadget: [%s]\n",RG->Instruction);
		}

	}
	PlacedGadgets.clear();

	if ( RemovedGadgetCounter == PlacedGadgetsCount )
	{
		//delete page because its not used!
		VirtualFreeEx( hGame, (PVOID)SelfAllocatedGadgetBuffer, NULL, MEM_RELEASE );
		SelfAllocatedGadgetBuffer = NULL;
	}

	
	printf("[+] Removed %u unused Gadgets\n", RemovedGadgetCounter);
}

void AllocateVirtualRegs( /*IN*/ const HANDLE hGame )
{
	__ASSERT__( hGame != INVALID_HANDLE_VALUE && hGame != NULL );

	DWORD RandomFlags[] = { PAGE_READWRITE, PAGE_EXECUTE_READWRITE };

	for (DWORD i = 0; i < (DWORD)ARRAYSIZE(VirtualRegisterAddresses); i++)
	{
		const DWORD ProtectionFlags = *(DWORD*)SelectRandomElement( RandomFlags, getArraySize( RandomFlags, DWORD ), sizeof(DWORD) );

		BYTE* RemoteMemory = (BYTE*)VirtualAllocEx( hGame, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, ProtectionFlags );
		if ( RemoteMemory == NULL )
		{
			printf("ERROR: Failed to allocate Virtual Register %u with error:[0x%X]\n",i,GetLastError());
			continue;
		}

		BYTE* localPtr = (BYTE*)malloc( 0x1000 );
		__ASSERT__( localPtr != NULL );

		g_RandomGenerator.GetBuffer( localPtr, 0x1000 );

		WriteProcessMemory( hGame, RemoteMemory, localPtr, (SIZE_T)0x1000, 0 );

		RemoteMemory += ( g_RandomGenerator.GetDword() % ( 0x1000 - sizeof(DWORD_PTR) ) );
		VirtualRegisterAddresses[i] = (DWORD_PTR)RemoteMemory;
		printf("[+] Allocated Virtual Register %u -> 0x%p\n", i, (PVOID)RemoteMemory );
		
		free( localPtr );
	}
	const DWORD ProtectionFlags = *(DWORD*)SelectRandomElement( RandomFlags, getArraySize( RandomFlags, DWORD ), sizeof(DWORD) );

	VirtualMemoryRegisterAddresses = (DWORD_PTR)VirtualAllocEx( hGame, 0, (SIZE_T)0x2000, MEM_COMMIT | MEM_RESERVE, ProtectionFlags );
	printf("[+] Allocated Virtual Memory Register -> 0x%p\n", (PVOID)VirtualMemoryRegisterAddresses);
}
