#include <Windows.h>
#include <stdio.h>
#include "Compiler.h"
#include "Util.h"
#include "GameOffsets.h"
#include "RandomGenerator.h"
#include "ASSERT.h"


//https://github.com/Speedi13/CPUID
#include "CpuInformation.h"

int __cdecl main( /*IN*/ const int argc, /*IN*/ const CHAR* argv[])
{
	UNREFERENCED_PARAMETER( argc );
	UNREFERENCED_PARAMETER( argv );

	InitializeConsole();	

	EnableAllPrivileges();

	//Retrieve cpu-information using the CPUID instruction
	//https://github.com/Speedi13/CPUID
	//=> https://en.wikipedia.org/wiki/CPUID
	const struct CpuInfo CpuInformation = CpuInfo();

	//Check cpu-feature information:
	g_ConditionalMoveSupported = CpuInformation.AMDFeatureExtendedInformation.CMOV || CpuInformation.FeatureInformation.CMOV;
	
	//https://en.wikipedia.org/wiki/RdRand
	g_HardwareRngSupported_RDRND  = CpuInformation.FeatureInformation.RDRND;
	g_HardwareRngSupported_RDSEED = CpuInformation.FeatureExtendedInformation.RDSEED;
	
	if ( g_ConditionalMoveSupported != true )
		printf("WARNING: WTF Seems like your CPU doesn't support conditional moves\n");

	if ( g_HardwareRngSupported_RDRND == true )
		printf("[+] Hardware RDRND supported\n");
	if ( g_HardwareRngSupported_RDSEED == true )
		printf("[+] Hardware RDSEED supported\n");

	if ( g_HardwareRngSupported_RDRND == true || g_HardwareRngSupported_RDSEED == true )
	{
		//check if hardware random number generator is bugged.
		//Some CPUs always return the same for some reason.
		if ( g_RandomGenerator.checkHardwareRNG() == false )
		{
			g_HardwareRngSupported_RDRND = false;
			g_HardwareRngSupported_RDSEED = false;
		}
	}
	
	g_RandomGenerator.Initialize();

	char RandomAsciiText[64] = {};
	g_RandomGenerator.GetString( RandomAsciiText, 64 );

	SetConsoleTitleA( RandomAsciiText );

	//Turn Ascii string in to Wide-Char:
	RandomAsciiText[ 62 ] = NULL;
	for (DWORD i = 0; i < 64; i+=2)
		RandomAsciiText[ i + 1 ] = NULL;

	const WCHAR* FileDialogTitle = L"[ROP-Assembly code file]";
	memcpy( (PVOID)&RandomAsciiText[6], (PVOID)FileDialogTitle, wcslen(FileDialogTitle)*2);

	const wchar_t* SourceCodeFilePath = OpenFileDialog( (LPCWSTR)RandomAsciiText );
	if ( SourceCodeFilePath == NULL || SourceCodeFilePath[0] == NULL )
		return ERROR_SUCCESS;

	const
	//acquire highest priority possible to reduce the time this program is running:
	DWORD PriorityClasses[] = { (DWORD)REALTIME_PRIORITY_CLASS, (DWORD)HIGH_PRIORITY_CLASS, (DWORD)ABOVE_NORMAL_PRIORITY_CLASS };
	for (DWORD i = 0; i < 3; i++)
		if ( SetPriorityClass( GetCurrentProcess(), PriorityClasses[i] ) == TRUE ) 
			break;

	printf("[+] Searching for game...\n");

	HANDLE hGame = INVALID_HANDLE_VALUE;

	enum GameIndexEnum
	{
		Game_CSGO,
		Game_BF3,
		Game_BF4,
		Game_Invalid,
	};
	const char*
	GameExecutables[] = {
		"csgo.exe",		// => Game_CSGO
		"bf3.exe",		// => Game_BF3
		"bf4_x86.exe",	// => Game_BF4
	};
	DWORD GameIndex = Game_Invalid;

	unsigned long ProcessId = (unsigned long)NULL;
	while ( hGame == INVALID_HANDLE_VALUE )
	{
		Sleep( 100 );
		
		for ( GameIndex = Game_CSGO ; GameIndex < ARRAYSIZE(GameExecutables) && ProcessId < 8; GameIndex++)
			ProcessId = GetProcessIdByName( GameExecutables[GameIndex] );
		
		GameIndex -= 1;

		if ( ProcessId < 8 )
			continue;

		hGame = OpenProcess( PROCESS_ALL_ACCESS, FALSE, ProcessId );
		if ( hGame == NULL || hGame == INVALID_HANDLE_VALUE )
		{
			hGame = INVALID_HANDLE_VALUE;
			ProcessId = 0;
			printf("[!] ERROR: failed to access process id:[0x%X] error:[0x%X]!\n",ProcessId,GetLastError());
		}
	}
	if ( GameIndex == Game_CSGO )
	{
		printf( "[+] CSGO ProcessId: %u\n", ProcessId );
	
		struct RemoteProcessModuleInfo ClientDllInfo = {};
		ZeroMemory(&ClientDllInfo, sizeof(struct RemoteProcessModuleInfo) );

		while ( GetRemoteProcessModuleInfo( ProcessId, L"client_panorama.dll", &ClientDllInfo ) != true )
			Sleep( 3000 );
	
		if ( (DWORD_PTR)ClientDllInfo.modBaseAddr != (DWORD_PTR)ClientDllInfo.hModule )
		{
			printf("ERROR: ClientDllInfo seems to be corrupted!\n");
			system("pause");
		}
		const DWORD_PTR ClientDllAddress = (DWORD_PTR)ClientDllInfo.hModule;

		printf("[+] CSGO Client dll: 0x%X\n",ClientDllAddress);

		ClientDllSearchForOffsets( &ClientDllInfo );
	}
	else
	if ( GameIndex == Game_BF3 )
		printf( "[+] BF3 ProcessId: %u\n", ProcessId );
	else
	if ( GameIndex == Game_BF4 )
		printf( "[+] BF4 ProcessId: %u\n", ProcessId );

	BYTE* AsmSourceCode = (BYTE*)NULL;
	DWORD AsmSourceCodeSize = (DWORD)NULL;

	if ( LoadFileToMemory( SourceCodeFilePath, &AsmSourceCode, &AsmSourceCodeSize ) != true 
		|| AsmSourceCode == NULL || AsmSourceCodeSize < (DWORD)(2) )
	{
		printf("ERROR while loading source-code file [%ws]\n",SourceCodeFilePath);
		system("pause");
	}
	AsmSourceCode[AsmSourceCodeSize] = 0;

	/////////////////////////// Default settings ///////////////////////////
	g_CompilerSettings.UseRandomPadding = false;
	g_CompilerSettings.g_constMaxObfuscationPaddingEntrys = 8;
	g_CompilerSettings.PrintDebugOutput = false;
	g_CompilerSettings.SearchDlls = true;
	g_CompilerSettings.VirtualQuerySearch = true;

	//to be even more undetected place the rop-chain into the original stack
	g_CompilerSettings.HijackThreadStack = true;
	////////////////////////////////////////////////////////////////////////

	//Read settings from source-code file
	GetCompilerSettings( (char*)AsmSourceCode, strlen((char*)AsmSourceCode), &g_CompilerSettings );

	//Search for Rop-Gadgets:
	InitializeRopGadgets( hGame );

	//Allocate the Gadgets that weren't found:
	BringYourOwnGadgets( hGame );

	DWORD_PTR StackTable = (DWORD_PTR)NULL;
	DWORD_PTR StackTableStart = (DWORD_PTR)NULL;
	HANDLE hThreadHandle = INVALID_HANDLE_VALUE;
	HANDLE* pThreadHandle = &hThreadHandle;
	if ( g_CompilerSettings.HijackThreadStack != true )
		pThreadHandle = NULL;

	CompileCode( (char*)AsmSourceCode, hGame, &StackTable, &StackTableStart, pThreadHandle );

	ZeroMemory( AsmSourceCode, AsmSourceCodeSize );
	free( AsmSourceCode );

	RemoveUnusedGadgets( hGame );

	SYSTEM_INFO SystemInfo = {};
	ZeroMemory(&SystemInfo, sizeof(SYSTEM_INFO) );

	GetSystemInfo( &SystemInfo );

	GLOBAL_MinimumAddress = (DWORD_PTR)SystemInfo.lpMinimumApplicationAddress;
	
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	printf("-------------------------------------------------------------\n");
	if ( GameIndex == Game_CSGO )
	{
		
		printf("[+] Initializing VR9 -> OFFSET_GlowObjectManager\n");
		WriteProcessMemory( hGame, (LPVOID)VirtualRegisterAddresses[9], (LPCVOID)&OFFSET_GlowObjectManager, sizeof(DWORD_PTR), NULL );

		printf("[+] Initializing VR8 -> OFFSET_LocalPlayer\n");
		WriteProcessMemory( hGame, (LPVOID)VirtualRegisterAddresses[8], (LPCVOID)&OFFSET_LocalPlayer,       sizeof(DWORD_PTR), NULL );

		printf("[+] Initializing VR7 -> OFFSET_EntityList\n");
		WriteProcessMemory( hGame, (LPVOID)VirtualRegisterAddresses[7], (LPCVOID)&OFFSET_EntityList,        sizeof(DWORD_PTR), NULL );

		printf("[+] Initializing VR6 -> OFFSET_FORCE_ATTACK\n");
		WriteProcessMemory( hGame, (LPVOID)VirtualRegisterAddresses[6], (LPCVOID)&OFFSET_FORCE_ATTACK,      sizeof(DWORD_PTR), NULL );

		printf("[+] Initializing VR5 -> OFFSET_CrosshairId\n");
		WriteProcessMemory( hGame, (LPVOID)VirtualRegisterAddresses[5], (LPCVOID)&OFFSET_CrosshairId,       sizeof(DWORD_PTR), NULL );

		printf("[+] Initializing VR4 -> OFFSET_TeamNum\n");
		WriteProcessMemory( hGame, (LPVOID)VirtualRegisterAddresses[4], (LPCVOID)&OFFSET_TeamNum,           sizeof(DWORD_PTR), NULL );

		printf("[+] Initializing VR3 -> OFFSET_bSpotted\n");
		WriteProcessMemory( hGame, (LPVOID)VirtualRegisterAddresses[3], (LPCVOID)&OFFSET_bSpotted,          sizeof(DWORD_PTR), NULL );
	}
	printf("[+] Initializing VR0 -> GLOBAL_MinimumAddress\n");
	WriteProcessMemory	  ( hGame, (LPVOID)VirtualRegisterAddresses[0], (LPCVOID)&GLOBAL_MinimumAddress,    sizeof(DWORD_PTR), NULL );
	printf("-------------------------------------------------------------\n");
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


	printf("[+] Rop-Chain start: 0x%p\n",(PVOID)StackTableStart);
	DWORD ThreadId = (DWORD)0;

	if ( g_CompilerSettings.HijackThreadStack == true && pThreadHandle != NULL )
	{
		ThreadId = GetThreadId( hThreadHandle );
		const
		DWORD ThreadSuspendCount = ResumeThread( hThreadHandle );
		if ( ThreadSuspendCount == (DWORD)(0xFFFFFFFFui32) )
		{
			printf("ERROR ResumeThread failed: 0x%X\n",GetLastError());
			system("pause");
		}
		CloseHandle( hThreadHandle );
	}
	else
		ThreadId = ExecuteRopChain( hGame, StackTableStart );

	CloseHandle( hGame );

	free( (void*)SourceCodeFilePath );

	g_RandomGenerator.release();

	ReleaseRopGadgets();

	SetPriorityClass( GetCurrentProcess(), NORMAL_PRIORITY_CLASS );

	if ( ThreadId > (DWORD)NULL )
	{
		char MessageBoxMsg[64] = {};
		sprintf_s( MessageBoxMsg, "ROP-Chain started in thread %u!", ThreadId );

		MessageBoxA( NULL, MessageBoxMsg, "ROP-Compiler", MB_OK | MB_ICONINFORMATION );
	}
	else
		system("pause");

	ClearConsole();

	return ERROR_SUCCESS;
}
