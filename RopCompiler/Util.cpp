#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

#include "ASSERT.h"
#include "Util.h"
#include "Compiler.h"
#include "dbghelp.h"
#include "RandomGenerator.h"

void GetDecimalNumber( /*IN*/ const char* inString, /*OUT*/ DWORD64* outNumber, /*OUT*/ size_t* outI )
{
	__ASSERT__( inString != NULL );
	__ASSERT__( outNumber != NULL );
	__ASSERT__( outI != NULL );

    DWORD64 Number = (DWORD64)NULL;
	size_t i = (size_t)NULL;
    for ( ; inString[i] >= (const char)'0' && inString[i] <= (const char)'9' ; i++)
	{
        Number = ((DWORD64)(10ui64) * Number) + (DWORD64)( (unsigned __int8)inString[i] - (unsigned __int8)'0');
	}
	*(size_t*)outI = (size_t)i;
	*(DWORD64*)outNumber = (DWORD64)Number;
    return ;
}

bool GetHeximalNumber( /*IN*/ const char *inString, /*OUT*/ DWORD64* outNumber, /*OUT*/ size_t* outI )
{
	__ASSERT__( inString != NULL );
	__ASSERT__( outNumber != NULL );
	__ASSERT__( outI != NULL );

	*outNumber = (DWORD64)NULL;
	*outI = (size_t)NULL;

	if ( inString[0] != (const char)'0' || tolower( (int)inString[1] ) != (int)'x' )
		return false;

	DWORD64 Number = (DWORD64)NULL;
	size_t i = (size_t)NULL;
	for ( bool InvalidChar = false; InvalidChar == false; i++)
	{
		unsigned __int8 c = (unsigned __int8)inString[2+i];
		if ( c >= (unsigned __int8)'A' && c <= (unsigned __int8)'F' )
			c += (unsigned __int8)' ';

		if ( c >= (unsigned __int8)'a' && c <= (unsigned __int8)'f' )
		{
			const DWORD64 temp = (DWORD64)( (unsigned __int8)c - (unsigned __int8)'a' ) + (DWORD64)10ui64;
			Number <<= (DWORD64)4ui64;
			Number |= temp;
			
			continue;
		}
		if ( c >= (unsigned __int8)'0' && c <= (unsigned __int8)'9' )
		{
			const DWORD64 temp = (DWORD64)( (unsigned __int8)c - (unsigned __int8)'0' );
			Number <<= (DWORD64)4ui64;
			Number |= temp;
			
			continue;
		}
		i--;
		InvalidChar = true;
	}
	*(size_t*)outI = (size_t)i;
	*(DWORD64*)outNumber = (DWORD64)Number;
	return true;

}

char* RegToString( /*IN*/ const enum Regs Reg )
{
	switch (Reg)
	{
	case REG_EAX:
		return "EAX";
		break;
	case REG_ECX:
		return "ECX";
		break;
	case REG_EDX:
		return "EDX";
		break;
	case REG_EBX:
		return "EBX";
		break;
	case REG_ESP:
		return "ESP";
		break;
	case REG_EBP:
		return "EBP";
		break;
	case REG_ESI:
		return "ESI";
		break;
	case REG_EDI:
		return "EDI";
		break;
	case REG_VR0:
		return "VR0";
		break;
	case REG_VR1:
		return "VR1";
		break;
	case REG_VR2:
		return "VR2";
		break;
	case REG_VR3:
		return "VR3";
		break;
	case REG_VR4:
		return "VR4";
		break;
	case REG_VR5:
		return "VR5";
		break;
	case REG_VR6:
		return "VR6";
		break;
	case REG_VR7:
		return "VR7";
		break;
	case REG_VR8:
		return "VR8";
		break;
	case REG_VR9:
		return "VR9";
		break;
	case REG_VMM:
		return "VMM";
		break;
	default:
		break;
	}
	return nullptr;
}

enum Regs GetReg( /*IN*/ const char* p)
{
	if ( (int)tolower(p[0]) == (int)'e' &&
		 (int)tolower(p[2]) == (int)'x')
	{
		if ( (int)tolower(p[1]) == (int)'a' )
			 return REG_EAX;
		if ( (int)tolower(p[1]) == (int)'b' )
			 return REG_EBX;
		if ( (int)tolower(p[1]) == (int)'c' )
			 return REG_ECX;
		if ( (int)tolower(p[1]) == (int)'d' )
			 return REG_EDX;
	}
	if ( (int)tolower(p[0]) == (int)'e' &&
		 (int)tolower(p[2]) == (int)'p')
	{
		if ( (int)tolower(p[1]) == (int)'s' )
			 return REG_ESP;
		if ( (int)tolower(p[1]) == (int)'b' )
			 return REG_EBP;
	}

	if ( (int)tolower(p[0]) == (int)'e' &&
		 (int)tolower(p[2]) == (int)'i')
	{
		if ( (int)tolower(p[1]) == (int)'s' )
			 return REG_ESI;
		if ( (int)tolower(p[1]) == (int)'d' )
			 return REG_EDI;
	}

	if ( (int)tolower(p[0]) == (int)'v' &&
		 (int)tolower(p[1]) == (int)'r')
	{
		if ( (int)tolower(p[2]) == (int)'0' )
			 return REG_VR0;
		if ( (int)tolower(p[2]) == (int)'1' )
			 return REG_VR1;
		if ( (int)tolower(p[2]) == (int)'2' )
			 return REG_VR2;
		if ( (int)tolower(p[2]) == (int)'3' )
			 return REG_VR3;
		if ( (int)tolower(p[2]) == (int)'4' )
			 return REG_VR4;
		if ( (int)tolower(p[2]) == (int)'5' )
			 return REG_VR5;
		if ( (int)tolower(p[2]) == (int)'6' )
			 return REG_VR6;
		if ( (int)tolower(p[2]) == (int)'7' )
			 return REG_VR7;
		if ( (int)tolower(p[2]) == (int)'8' )
			 return REG_VR8;
		if ( (int)tolower(p[2]) == (int)'9' )
			 return REG_VR9;
	}
	if ( (int)tolower(p[0]) == (int)'v' &&
		 (int)tolower(p[1]) == (int)'m' &&
		 (int)tolower(p[2]) == (int)'m' )
		 return REG_VMM;

	return REG_ERROR;
}

unsigned long GetProcessIdByName( /*IN*/ const char *ProcessName )
{
	__ASSERT__( ProcessName != NULL );

	HANDLE SnapshotHandle = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, NULL );
	if (SnapshotHandle == NULL || SnapshotHandle == INVALID_HANDLE_VALUE) return 0;

	WCHAR ProcName[MAX_PATH+1] = {};
	ZeroMemory( ProcName, sizeof(ProcName) );

	for (UINT i = 0; i < ((UINT)(MAX_PATH)); i++)
	{
		unsigned char c = (unsigned char)(ProcessName[i]);
		if ( (UINT8)c < 31ui8 || (UINT8)c > 128ui8 )
			c = (UINT8)NULL;
		ProcName[i] = (UINT8)c;
		if (c == NULL) break;
	}
	ProcName[MAX_PATH] = (WCHAR)NULL;

	unsigned long pid = (unsigned long)NULL;

	PROCESSENTRY32W ProcessEntry;	
	ZeroMemory( &ProcessEntry, sizeof(PROCESSENTRY32W) );
	
	ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);
	BOOL Loop = Process32FirstW(SnapshotHandle, &ProcessEntry);
	while (Loop == TRUE)
	{
		if (_wcsicmp(ProcessEntry.szExeFile, ProcName) == 0) 
		{
			pid = ProcessEntry.th32ProcessID;
			break;
		}
		ZeroMemory( &ProcessEntry, sizeof(PROCESSENTRY32W) );
		ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);
		Loop = Process32NextW(SnapshotHandle, &ProcessEntry);
	}
	CloseHandle( SnapshotHandle );
	return pid;
}

bool GetRemoteProcessModuleInfo( /*IN*/ const DWORD ProcessId, /*IN*/ const wchar_t* wcModuleName, /*OUT*/ struct RemoteProcessModuleInfo* outInfo )
{
	__ASSERT__( ProcessId > 4 );
	__ASSERT__( wcModuleName != NULL  );
	__ASSERT__( outInfo != NULL  );

	bool SuccessStatus = false;

	ZeroMemory( outInfo, sizeof(RemoteProcessModuleInfo) );

	HANDLE SnapshotHandle = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcessId );
	if (SnapshotHandle == NULL || SnapshotHandle == INVALID_HANDLE_VALUE) return SuccessStatus;	

	MODULEENTRY32W ModuleEntry = {};
	ZeroMemory( &ModuleEntry, sizeof(MODULEENTRY32W) );
	
	ModuleEntry.dwSize = sizeof(MODULEENTRY32W);
	BOOL Loop = Module32FirstW(SnapshotHandle, &ModuleEntry);
	while (Loop == TRUE)
	{
		if (_wcsicmp(ModuleEntry.szModule, wcModuleName) == 0) 
		{
			outInfo->modBaseAddr = ModuleEntry.modBaseAddr;
			outInfo->modBaseSize = ModuleEntry.modBaseSize;
			outInfo->hModule = ModuleEntry.hModule;
			memcpy( outInfo->szModule, ModuleEntry.szModule, MAX_MODULE_NAME32 + 1 );
			memcpy( outInfo->szExePath, ModuleEntry.szExePath, MAX_PATH );
			SuccessStatus = true;
			break;
		}
		ZeroMemory( &ModuleEntry, sizeof(MODULEENTRY32W) );
		ModuleEntry.dwSize = sizeof(MODULEENTRY32W);
		Loop = Module32NextW(SnapshotHandle, &ModuleEntry);
	}
	CloseHandle( SnapshotHandle );

	return SuccessStatus;
}

bool GetRemoteProcessModuleExportAddress( /*IN*/ const DWORD ProcessId, /*IN*/ const char* ModuleName, /*IN*/ const char* ExportName, /*OUT*/ DWORD_PTR* outAddress )
{
	__ASSERT__( ProcessId > 4 );
	__ASSERT__( ModuleName != NULL  );
	__ASSERT__( ExportName != NULL  );
	__ASSERT__( outAddress != NULL  );

	bool SuccessStatus = false;
	HANDLE SnapshotHandle = NULL;

	*outAddress = 0;
	
	SnapshotHandle = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcessId );
	if (SnapshotHandle == NULL || SnapshotHandle == INVALID_HANDLE_VALUE) return SuccessStatus;
	
	WCHAR wcModuleName[MAX_PATH+1] = {};
	ZeroMemory( wcModuleName, sizeof(wcModuleName) );

	for (UINT i = 0; i < (UINT)MAX_PATH; i++)
	{
		unsigned char c = (unsigned char)(ModuleName[i]);
		if ( (UINT8)c < (UINT8)31ui8 || (UINT8)c > (UINT8)128ui8 )
			c = (UINT8)NULL;
		wcModuleName[i] = (UINT8)c;
		if (c == NULL) break;
	}
	wcModuleName[MAX_PATH] = (WCHAR)NULL;
	

	MODULEENTRY32W ModuleEntry = {};
	ZeroMemory( &ModuleEntry, sizeof(MODULEENTRY32W) );
	
	ModuleEntry.dwSize = sizeof(MODULEENTRY32W);
	BOOL Loop = Module32FirstW(SnapshotHandle, &ModuleEntry);
	while (Loop == TRUE)
	{
		if (_wcsicmp(ModuleEntry.szModule, wcModuleName) == 0) 
		{
			HMODULE hDllModule = LoadLibraryW( ModuleEntry.szExePath );
			if ( hDllModule != 0 )
			{
				DWORD_PTR ExportAddr = (DWORD_PTR)GetProcAddressToLower( hDllModule, ExportName, TRUE );
				if ( ExportAddr != 0 )
				{
					ExportAddr -= (DWORD_PTR)hDllModule;

					ExportAddr += (DWORD_PTR)ModuleEntry.modBaseAddr;

					*outAddress = ExportAddr;

					SuccessStatus = true;
				}
			}
			break;
		}
		ZeroMemory( &ModuleEntry, sizeof(MODULEENTRY32W) );
		ModuleEntry.dwSize = sizeof(MODULEENTRY32W);
		Loop = Module32NextW(SnapshotHandle, &ModuleEntry);
	}
	CloseHandle( SnapshotHandle );

	return SuccessStatus;
}

bool RemoteSuspendProcessThreads( /*IN*/ const DWORD ProcessId, /*IN*/ bool Resume )
{
	__ASSERT__( ProcessId > 4 );

	bool SuccessStatus = false;

	HANDLE SnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, ProcessId);
	if (SnapshotHandle == NULL || SnapshotHandle == INVALID_HANDLE_VALUE) return SuccessStatus;

	THREADENTRY32 ThreadEntry = {};
	ZeroMemory( &ThreadEntry, sizeof(THREADENTRY32) ); 
	ThreadEntry.dwSize = sizeof(THREADENTRY32);

	BOOL Loop = Thread32First(SnapshotHandle, &ThreadEntry);
	while (Loop == TRUE)
	{
		if (ThreadEntry.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(ThreadEntry.th32OwnerProcessID)) 
		{
			if(ThreadEntry.th32OwnerProcessID == ProcessId)
			{
				HANDLE ThreadHandle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, ThreadEntry.th32ThreadID);
				if(ThreadHandle != NULL && ThreadHandle != INVALID_HANDLE_VALUE)
				{
					DWORD SuspendCount = (DWORD)0xFFFFFFFFui32;
					if ( Resume == true )
						SuspendCount = ResumeThread(ThreadHandle);
					else
						SuspendCount = SuspendThread(ThreadHandle);

					if ( SuspendCount != (DWORD)(0xFFFFFFFFui32) )
						SuccessStatus = true;

					CloseHandle(ThreadHandle);
				}
			}
		}
		ZeroMemory( &ThreadEntry, sizeof(THREADENTRY32) ); 
		ThreadEntry.dwSize = sizeof(THREADENTRY32);
		Loop = Thread32Next(SnapshotHandle, &ThreadEntry);
	}
	CloseHandle(SnapshotHandle);

	return SuccessStatus;
}

bool NtSuspendProcess( /*IN*/ const HANDLE hProcess )
{
	__ASSERT__( hProcess != INVALID_HANDLE_VALUE && hProcess != NULL );

	static NTSTATUS(__stdcall* fncNtSuspendProcess)(HANDLE ProcessHandle) = NULL;

	if ( fncNtSuspendProcess == NULL )
	{
		HMODULE hNtDll = GetModuleHandleW( L"ntdll.dll" );
		if ( hNtDll == NULL )
			 hNtDll = LoadLibraryW( L"ntdll.dll" );
		__ASSERT__( hNtDll != NULL );

		void* Function = GetProcAddress( hNtDll, "NtSuspendProcess" );
		if ( Function == NULL )
			 Function = GetProcAddress( hNtDll, "ZwSuspendProcess" );

		fncNtSuspendProcess = ( decltype(fncNtSuspendProcess) )Function;
	}

	return fncNtSuspendProcess( hProcess ) == (NTSTATUS)(0x00000000l);
}

bool NtResumeProcess( /*IN*/ const HANDLE hProcess )
{
	__ASSERT__( hProcess != INVALID_HANDLE_VALUE && hProcess != NULL );

	static NTSTATUS(__stdcall* fncNtResumeProcess)(HANDLE ProcessHandle) = NULL;

	if ( fncNtResumeProcess == NULL )
	{
		HMODULE hNtDll = GetModuleHandleW( L"ntdll.dll" );
		if ( hNtDll == NULL )
			 hNtDll = LoadLibraryW( L"ntdll.dll" );
		__ASSERT__( hNtDll != NULL );
		void* Function = GetProcAddress( hNtDll, "NtResumeProcess" );
		if ( Function == NULL )
			 Function = GetProcAddress( hNtDll, "ZwResumeProcess" );

		fncNtResumeProcess = ( decltype(fncNtResumeProcess) )Function;
	}

	return fncNtResumeProcess( hProcess ) == (NTSTATUS)(0x00000000l);
}

bool LoadFileToMemory( /*IN*/ const wchar_t* FilePath, /*OUT*/ BYTE** Image, /*OUT*/ DWORD* ImageSize )
{
	__ASSERT__( FilePath != NULL );
	__ASSERT__( Image != NULL );
	__ASSERT__( ImageSize != NULL );

	*(void**)Image = (void*)NULL;
	*(DWORD*)ImageSize = (DWORD)NULL;
	bool ReturnState = false;

	const HANDLE FileHandle = CreateFileW( FilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL );
	if ( FileHandle == NULL || FileHandle == INVALID_HANDLE_VALUE ) return ReturnState;

	const ULONG FileSize = GetFileSize(FileHandle, NULL);
	if ( FileSize != NULL && FileSize != (ULONG)(0xFFFFFFFFui32) )
	{
		BYTE* ImageInMemory = (BYTE*)malloc( FileSize + 0x100 );
		if ( ImageInMemory != NULL )
		{
			DWORD NumberOfBytesRead = (DWORD)NULL;
			if ( ReadFile(FileHandle, ImageInMemory, FileSize, &NumberOfBytesRead, NULL) == TRUE )
			{
				*(void**)Image = (void*)ImageInMemory;
				*(DWORD*)ImageSize = (DWORD)FileSize;
				ReturnState =  true;
			}
			else
				free( ImageInMemory );
		}
	}
	CloseHandle(FileHandle);
	return ReturnState;
};

BYTE HexNmbrToByte( /*IN*/ const char* a ){
	BYTE b[2] = {};

	__ASSERT__( a != NULL );

	for (int i1 = 0; i1 < ((int)2i32); i1++)
	{
		if ( a[i1] >= '0' && a[i1] <= '9' )
			b[i1] = a[i1] - '0';
		else
		if ( a[i1] >= 'A' && a[i1] <= 'F' )
			b[i1] = a[i1] - 'A' + 10;
		else
		if ( a[i1] >= 'a' && a[i1] <= 'f' )
			b[i1] = a[i1] - 'a' + 10;
	}

	BYTE outValue = 0;
	
	if ( a[1] == NULL || a[1] == ' ' )
		outValue = (b[0]&0xF);
	else
		outValue = ((b[0]&0xF) << 4) | (b[1]&0xF);

	*(WORD*)&b[0] = 0;
	return outValue;
}

BYTE* FindPattern( /*IN*/ const HMODULE hModule, /*IN*/ const DWORD dwSize, /*IN*/ const char* szSig)
{
	__ASSERT__( hModule != NULL );
	__ASSERT__( dwSize > 0 );
	__ASSERT__( szSig != NULL );

	const size_t SigLen = (size_t)strlen(szSig) + (size_t)1;
	__ASSERT__( SigLen > 0 );

	BYTE* byteSig = (BYTE*)malloc( SigLen + 2 );
	__ASSERT__( byteSig != NULL );
	ZeroMemory( byteSig, SigLen );
	
	size_t byteSigPos = (size_t)NULL;

	char* Mask = (char*)malloc( SigLen + 2 );
	__ASSERT__( Mask != NULL );
	ZeroMemory( Mask, SigLen );

	size_t MaskPos = (size_t)NULL;

	for (size_t i = 0; i < SigLen; )
	{
		const char* p = &szSig[i];
		if (p[0] == NULL)
			break;
		else
		if ( p[0] == ' ' )
		{
			i++;
			continue;
		}
		else
		if ( p[0] == (char)'?' && p[1] == (char)'?' )
		{
			Mask[ MaskPos++ ] = (char)'?';
			byteSig[ byteSigPos++ ] = (BYTE)0x00ui8;
			i += 2;
			continue;
		}
		else
		if ( p[0] == (char)'?' )
		{
			Mask[ MaskPos++ ] = (char)'?';
			byteSig[ byteSigPos++ ] = (BYTE)0x00ui8;
			i += 1;
			continue;
		}
		else
		{
			Mask[ MaskPos++ ] = (char)'x';
			byteSig[ byteSigPos++ ] = HexNmbrToByte( p );
			i += 2;
			continue;
		}
		continue;
	}
	if ( MaskPos == NULL || byteSigPos == NULL )
		return (BYTE*)NULL;

	Mask[ MaskPos++ ] = (char)NULL;
	byteSig[ byteSigPos++ ] = (BYTE)NULL;

	BYTE* Result = FindPattern( (BYTE*)hModule, dwSize, byteSig, Mask );
	
	ZeroMemory( byteSig, SigLen );
	free( byteSig ); byteSig = 0;

	ZeroMemory( Mask, SigLen );
	free( Mask ); Mask = 0;

	return Result;
}

DWORD GetValue( /*IN*/ const char* String )
{
	__ASSERT__( String != NULL );

	if ( (int)tolower(String[0]) == (int)'t' && 
		 (int)tolower(String[1]) == (int)'r' && 
		 (int)tolower(String[2]) == (int)'u' && 
		 (int)tolower(String[3]) == (int)'e' )
		 return TRUE;

	if ( (int)tolower(String[0]) == (int)'f' && 
		 (int)tolower(String[1]) == (int)'a' && 
		 (int)tolower(String[2]) == (int)'l' && 
		 (int)tolower(String[3]) == (int)'s' && 
		 (int)tolower(String[4]) == (int)'e' )
		 return FALSE;

	return (DWORD)atoi( String );
}

void GetCompilerSettings( /*IN*/ const char* FileContent, /*IN*/ const DWORD FileSize, /*OUT*/ struct CompilerSettings* Setting )
{
	__ASSERT__( FileContent != NULL );
	__ASSERT__( FileSize > 1 );
	__ASSERT__( Setting != NULL );

	//<cfg=Name>???</cfg>

	char CfgName[64] = {};
	ZeroMemory(CfgName, sizeof(CfgName) );

	for (DWORD i = 0; i < FileSize; i++)
	{
		if ( (int)tolower(FileContent[i+0]) == (int)'<' &&
			 (int)tolower(FileContent[i+1]) == (int)'c' &&
			 (int)tolower(FileContent[i+2]) == (int)'f' &&
			 (int)tolower(FileContent[i+3]) == (int)'g' &&
			 (int)tolower(FileContent[i+4]) == (int)'=' )
		{
			if ( FileContent[i+5] == '"' ) i+=1;

			
			DWORD j = 0;
			for ( ; (j+i+5) < FileSize; j++)
			{
				const char c = FileContent[j+i+5];
				CfgName[ j ] = c;
				if ( c == '>' || c == '"' || c == 0 ||c == '"' ||  c == '\n' || c == '\r' ) break;
			}
			CfgName[ j++ ] = 0;
			

			if ( _stricmp( CfgName, "RandomPadding" ) == 0 )
			{
				DWORD k = 0;
				for (; ; k++)
				{
					const char c = FileContent[k+j+i+5];
					CfgName[ k ] = c;
					if ( c == '<' || c == 0 || c == '"' || c == '\n' || c == '\r' )
						break;
				}
				CfgName[ k ] = 0;
				Setting->UseRandomPadding = GetValue( CfgName ) == TRUE;
			}
			else
			if ( _stricmp( CfgName, "RandomPaddingSize" ) == 0 )
			{
				DWORD k = 0;
				for (; ; k++)
				{
					const char c = FileContent[k+j+i+5];
					CfgName[k] = c;
					if ( c == '<' || c == 0 || c == '"' || c == '\n' || c == '\r' )
						break;
				}
				CfgName[k] = 0;
				Setting->g_constMaxObfuscationPaddingEntrys = GetValue( CfgName );
			}
			else
			if ( _stricmp( CfgName, "PrintDebugOutput" ) == 0 )
			{
				DWORD k = 0;
				for (; ; k++)
				{
					const char c = FileContent[k+j+i+5];
					CfgName[k] = c;
					if ( c == '<' || c == 0 || c == '"' || c == '\n' || c == '\r' )
						break;
				}
				CfgName[k] = 0;
				Setting->PrintDebugOutput = GetValue( CfgName ) == TRUE;
			}
			else
			if ( _stricmp( CfgName, "SearchDlls" ) == 0 )
			{
				DWORD k = 0;
				for (; ; k++)
				{
					const char c = FileContent[k+j+i+5];
					CfgName[k] = c;
					if ( c == '<' || c == 0 || c == '"' || c == '\n' || c == '\r' )
						break;
				}
				CfgName[k] = 0;
				Setting->SearchDlls = GetValue( CfgName ) == TRUE;
			}
			else
			if ( _stricmp( CfgName, "VirtualQuerySearch" ) == 0 )
			{
				DWORD k = 0;
				for (; ; k++)
				{
					const char c = FileContent[k+j+i+5];
					CfgName[k] = c;
					if ( c == '<' || c == 0 || c == '"' || c == '\n' || c == '\r' )
						break;
				}
				CfgName[k] = 0;
				Setting->VirtualQuerySearch = GetValue( CfgName ) == TRUE;
			}
			else
			{
				printf("[!] UNKNOWN COMPILER SETTING [%s]\n",CfgName);
				system("pause");
			}
		}

	}
	return;
}



wchar_t* OpenFileDialog( LPCWSTR DialogTitle )
{
	__ASSERT__( DialogTitle != NULL );

	static BOOL (APIENTRY* l_GetOpenFileNameW)(LPOPENFILENAMEW) = NULL;

	if ( l_GetOpenFileNameW == NULL )
	{
		HMODULE hCOMDLG32 = LoadLibraryW( L"COMDLG32.dll" );
		if ( hCOMDLG32 != NULL )
			l_GetOpenFileNameW = ( decltype(l_GetOpenFileNameW) )GetProcAddress( hCOMDLG32, "GetOpenFileNameW" );
		else
		{
			printf("[!]ERROR: failed to load COMDLG32\n");
			system("pause");
			return nullptr;
		}
	}
	if ( l_GetOpenFileNameW == NULL )
	{
		printf("[!]ERROR: failed to find GetOpenFileNameW\n");
		system("pause");
		return nullptr;
	}
	wchar_t* FilePath = (wchar_t*)malloc( 1025*2 );
	__ASSERT__( FilePath != NULL );

	OPENFILENAMEW OpenFileNameStruct = {};
	do
	{
		ZeroMemory( &OpenFileNameStruct, sizeof(OPENFILENAMEW) );
		ZeroMemory( FilePath, 1025 * 2 );

		OpenFileNameStruct.lStructSize = sizeof(OPENFILENAMEW);
		OpenFileNameStruct.lpstrFilter = L"ROP-Assembly code file ( .asm )\0*.asm;*.txt\0All\0*.*\0\0\0\0";
		OpenFileNameStruct.nFileOffset = 1;
		OpenFileNameStruct.lpstrFile = FilePath;
		OpenFileNameStruct.nMaxFile = 1024;
		OpenFileNameStruct.lpstrTitle = DialogTitle;
		OpenFileNameStruct.Flags = OFN_FILEMUSTEXIST;

		if ( l_GetOpenFileNameW( &OpenFileNameStruct ) != TRUE )
		{
			free( FilePath );
			FilePath = NULL;
		}
		else
		{
			HANDLE hFileHandle = CreateFileW( FilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL );
			if (	CloseHandle( hFileHandle ) != TRUE 
				||	hFileHandle == NULL 
				||	hFileHandle == INVALID_HANDLE_VALUE )
				FilePath[0] = NULL;
		}
	}
	while ( FilePath != NULL && FilePath[0] == NULL );

	return FilePath;
}

//-------------------------------------------------------------------------------
//https://github.com/learn-more/findpattern-bench/blob/master/patterns/kokole.h
bool DataCompare( /*IN*/ const BYTE* pData, /*IN*/ const BYTE* bSig, /*IN*/ const char* szMask)
{
	__ASSERT__( pData != NULL );
	__ASSERT__( bSig != NULL );
	__ASSERT__( szMask != NULL );

	for (; *szMask; ++szMask, ++pData, ++bSig)
	{
		if (*szMask == 'x' && *pData != *bSig)
			return false;
	}
	return (*szMask) == NULL;
}
BYTE* FindPattern( /*IN*/ const BYTE* dwAddress, /*IN*/ const DWORD dwSize, /*IN*/ const BYTE* pbSig, /*IN*/ const char* szMask)
{
	__ASSERT__( dwAddress != NULL );
	__ASSERT__( dwSize > 0 );
	__ASSERT__( pbSig != NULL );
	__ASSERT__( szMask != NULL );

	const DWORD length = (DWORD)strlen(szMask);
	__ASSERT__( length > 0 );

	for (DWORD i = NULL; i < dwSize - length; i++)
	{
		if (DataCompare(dwAddress + i, pbSig, szMask))
			return (BYTE*)(dwAddress + i);
	}
	return 0;
}
//-------------------------------------------------------------------------------


void RemoteLoadLibraryW( /*IN*/ const HANDLE hProcess, /*IN*/ const wchar_t* DllPath )
{
	__ASSERT__( hProcess != INVALID_HANDLE_VALUE && hProcess != NULL );
	__ASSERT__( DllPath != NULL );

	const SIZE_T DllPathLen = ( (SIZE_T)wcslen(DllPath) + (SIZE_T)1 ) * 2;

	__ASSERT__( DllPathLen > 2 );

	// The System Dlls get mapped to the same virtual address in every process :D
	HMODULE hKernel32 = GetModuleHandleW( L"kernel32.dll" );
	__ASSERT__( hKernel32 != NULL );

	PVOID FncLoadLibraryAddr = (PVOID)GetProcAddress( hKernel32, "LoadLibraryW" );
	__ASSERT__( FncLoadLibraryAddr != NULL );

	//Allocate space in the targets process for our string
	DWORD_PTR RemoteDllPath = (DWORD_PTR)VirtualAllocEx(hProcess, 0, (SIZE_T)( DllPathLen + (SIZE_T)8 ), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	__ASSERT__( RemoteDllPath != NULL );

	//write the string into the fresh allocated space:
	WriteProcessMemory(hProcess, (LPVOID)RemoteDllPath, (LPVOID)DllPath, DllPathLen, NULL);

	//Remote starting LoadLibrary:
	HANDLE hThread = CreateRemoteThread(	hProcess, 
											NULL, 
											NULL, 
											(LPTHREAD_START_ROUTINE)FncLoadLibraryAddr,
											(LPVOID)RemoteDllPath, //<= The parameter
											NULL, 
											NULL
										);
	__ASSERT__( hThread != NULL && hThread != INVALID_HANDLE_VALUE );
	//Lets wait till LoadLibrary is finished:
	WaitForSingleObject( hThread, INFINITE );DWORD ExitCode = 0;
	GetExitCodeThread( hThread, &ExitCode );

	//the dll path is not longer needed lets free that:
	VirtualFreeEx( hProcess, (LPVOID)RemoteDllPath, NULL, MEM_RELEASE );
}

void LoadAllDlls( /*IN*/ const HANDLE hGame )
{
	__ASSERT__( hGame != INVALID_HANDLE_VALUE && hGame != NULL );

	wchar_t Path[1024] = {};
	wcscpy_s( Path, L"c:\\windows\\syswow64\\" );

	UINT PathLen = (UINT)wcslen(Path);

	WIN32_FIND_DATAW FindData = {};
	ZeroMemory( &FindData, sizeof(WIN32_FIND_DATAW) );
	

	HANDLE hFind = FindFirstFileW( L"c:\\windows\\syswow64\\*.dll", &FindData );
	if ( hFind != NULL && hFind != INVALID_HANDLE_VALUE )
	{
		do
		{
			printf("FileName: [%ws]\n",FindData.cFileName);
			wcscpy_s( &Path[PathLen], (UINT)(1024ui32)-PathLen-(UINT)(1ui32), FindData.cFileName);
			RemoteLoadLibraryW( hGame, Path );

			ZeroMemory( &FindData, sizeof(WIN32_FIND_DATAW) );
		}
		while(FindNextFileW(hFind,&FindData) == TRUE);

		FindClose(hFind);
	}
}

void* ManualMapDynamicLinkLibrary( /*IN*/ void* DiskImage, /*IN OPTIONAL*/ DWORD_PTR RelocationPositionOverwrite )
{
	__ASSERT__( DiskImage != NULL );

	IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)DiskImage;
	if ( DosHeader->e_magic != IMAGE_DOS_SIGNATURE ) 
		return (void*)NULL;

	const IMAGE_NT_HEADERS* NtHeaders = (IMAGE_NT_HEADERS*)ImageNtHeader( DosHeader );
	if ( NtHeaders == NULL || NtHeaders->Signature != IMAGE_NT_SIGNATURE ) 
		return (void*)NULL;

	const IMAGE_FILE_HEADER* FileHeader = (IMAGE_FILE_HEADER*)&NtHeaders->FileHeader;
	if ( (FileHeader->Characteristics & IMAGE_FILE_DLL ) != IMAGE_FILE_DLL && 
		 (FileHeader->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE ) != IMAGE_FILE_EXECUTABLE_IMAGE ) 
		return (void*)NULL;

	const IMAGE_OPTIONAL_HEADER* OptionalHeader = (IMAGE_OPTIONAL_HEADER*)&NtHeaders->OptionalHeader;
	if (   (OptionalHeader->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && (sizeof(IMAGE_OPTIONAL_HEADER) == sizeof(IMAGE_OPTIONAL_HEADER32)) )
		|| (OptionalHeader->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC && (sizeof(IMAGE_OPTIONAL_HEADER) == sizeof(IMAGE_OPTIONAL_HEADER64)) ) )
		return (void*)NULL;

	const DWORD SizeOfImage = OptionalHeader->SizeOfImage;
	const DWORD SizeOfHeaders = OptionalHeader->SizeOfHeaders;
	const WORD  NumberOfSections = FileHeader->NumberOfSections;
	const WORD  SizeOfOptionalHeader = FileHeader->SizeOfOptionalHeader;

	if (   SizeOfImage <= (DWORD)0x1000 
		|| SizeOfHeaders < (DWORD)( sizeof(IMAGE_DOS_HEADER) )
		|| NumberOfSections < 1 
		|| SizeOfOptionalHeader < 1 )
		return (void*)NULL;

	DWORD MappedPageSize = (SizeOfImage / (DWORD)0x1000ui32) * (DWORD)0x1000ui32;
		if ( (SizeOfImage % (DWORD)0x1000ui32) != 0 )
			MappedPageSize += (DWORD)0x1000ui32;

	IMAGE_DOS_HEADER* MappedDosHeader = (IMAGE_DOS_HEADER*)VirtualAlloc( NULL, MappedPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
	if ( MappedDosHeader == NULL )
	{
		printf("[%s] failed to allocate buffer for image! [0x%X]\n",__FUNCTION__,GetLastError());
		return (void*)NULL;
	}
	
	/////////////////////////////////////////////////////////////// Image Sections //////////////////////////////////////////////////////////////
	//Copy Headers
	memcpy( MappedDosHeader, DosHeader, SizeOfHeaders );
	ZeroMemory( (void*)( (DWORD_PTR)MappedDosHeader + (DWORD_PTR)SizeOfHeaders ), (DWORD)0x1000 - SizeOfHeaders );

	//Copy Sections
	IMAGE_SECTION_HEADER* SectionHeaders = (IMAGE_SECTION_HEADER*)( (DWORD_PTR)OptionalHeader + SizeOfOptionalHeader );
	for( WORD i = 0; i< NumberOfSections; i++ )
	{
		const IMAGE_SECTION_HEADER* SectionHeader = (IMAGE_SECTION_HEADER*)&SectionHeaders[i];

		const DWORD VirtualAddress = SectionHeader->VirtualAddress;
		if ( VirtualAddress < (DWORD)0x1000ui32 || VirtualAddress > SizeOfImage ) continue;

		const PVOID Destination = (PVOID)( (DWORD_PTR)MappedDosHeader + (DWORD_PTR)VirtualAddress );

		const DWORD VirtualSize = SectionHeader->Misc.VirtualSize;
		if ( VirtualSize < (DWORD)1 ) continue;

		const DWORD SizeOfRawData = SectionHeader->SizeOfRawData;
		if ( SizeOfRawData < 1 || (SectionHeader->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) == IMAGE_SCN_CNT_UNINITIALIZED_DATA )
			ZeroMemory( Destination, VirtualSize );
		else
		{
			const DWORD PointerToRawData = SectionHeader->PointerToRawData;
			if ( PointerToRawData < SizeOfHeaders || SizeOfRawData < 1 ) continue;

			PVOID Source = (PVOID)( (DWORD_PTR)DiskImage + PointerToRawData );
			memcpy( Destination, Source, SizeOfRawData );

			if ( SizeOfRawData > VirtualSize )
				ZeroMemory( (void*)( (DWORD_PTR)Destination + VirtualSize ), (SizeOfRawData - VirtualSize) );
		}
	}
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	
	///////////////////////////////////////////////////////////// Image Relocations /////////////////////////////////////////////////////////////
	const DWORD_PTR ImageBase = OptionalHeader->ImageBase;

	DWORD_PTR ImageDelta = NULL;
	if ( RelocationPositionOverwrite != NULL )
		ImageDelta = (DWORD_PTR)( (DWORD_PTR)RelocationPositionOverwrite - (DWORD_PTR)ImageBase );
	else
		ImageDelta = (DWORD_PTR)( (DWORD_PTR)MappedDosHeader - (DWORD_PTR)ImageBase );

	if ( ImageDelta != NULL )
	{
		const IMAGE_DATA_DIRECTORY* BaseRelocationDirectory = &OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		if ( BaseRelocationDirectory->Size > (DWORD)1ui32 && 
			 BaseRelocationDirectory->VirtualAddress > (DWORD)0x1000ui32 &&
			 BaseRelocationDirectory->VirtualAddress < SizeOfImage)
		{
			const DWORD_PTR BaseRelocationVA = BaseRelocationDirectory->VirtualAddress;
			IMAGE_BASE_RELOCATION* BaseRelocation = (IMAGE_BASE_RELOCATION*)( (DWORD_PTR)MappedDosHeader + (DWORD_PTR)BaseRelocationVA );
		
			while( BaseRelocation->VirtualAddress != NULL )
			{
				const DWORD dwSizeOfBlock = BaseRelocation->SizeOfBlock;
				DWORD_PTR RelocationBaseAddress = BaseRelocation->VirtualAddress;
				
				if( dwSizeOfBlock > sizeof(IMAGE_BASE_RELOCATION) && RelocationBaseAddress > (DWORD_PTR)(0x1000) )
				{
					RelocationBaseAddress += (DWORD_PTR)MappedDosHeader;
					const WORD* Relocations = (WORD*)( (DWORD_PTR)BaseRelocation + sizeof(IMAGE_BASE_RELOCATION) );
					const DWORD RelocationCount = ( dwSizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) ) / sizeof(WORD);
					for( DWORD i = 0; i < RelocationCount; i++ )
					{
						const WORD Entry = Relocations[i];

						const WORD RelocationType = (Entry >> 12);
						const WORD RelocationOffset = Entry & 0xfff;

						const DWORD_PTR VirtualAddress = RelocationBaseAddress + (DWORD_PTR)RelocationOffset;
						
						//https://doxygen.reactos.org/df/da2/sdk_2lib_2rtl_2image_8c.html#a79a460be03d9da50f71d427b26238496

						//https://github.com/DarthTon/Blackbone/blob/43bc59f68dc1e86347a76192ef3eadc0bf21af67/src/BlackBoneDrv/ldrreloc.c#L229

						if ( RelocationType == IMAGE_REL_BASED_ABSOLUTE )
						{
							//
							// Absolute - no fixup required.
							//
						}
						else
						if ( RelocationType == IMAGE_REL_BASED_HIGH )
						{
							//
							// High - (16-bits) relocate the high half of an address.
							//
							
							LONG Temp = *(WORD*)(VirtualAddress) << 16;
							Temp += (ULONG)(ImageDelta & 0xFFFFFFFF);
							*(WORD*)VirtualAddress = (WORD)(Temp >> 16);
							
							//*(WORD*)VirtualAddress = HIWORD(MAKELONG(0, *(WORD*)VirtualAddress) + (ImageDelta & 0xFFFFFFFF));
						}
						else
						if ( RelocationType == IMAGE_REL_BASED_LOW )
						{
							//
							// Low - (16-bit) relocate the low half of an address.
							//
							*(WORD*)VirtualAddress += (WORD)(ImageDelta & 0xFFFF);
						}
						else
						if ( RelocationType == IMAGE_REL_BASED_HIGHLOW )
						{
							//
							// HighLow - (32-bits) relocate the high and low half
							//      of an address.
							//
							*(DWORD*)VirtualAddress = (DWORD)(ImageDelta & 0xFFFFFFFF);
						}
						else
						if ( RelocationType == IMAGE_REL_BASED_HIGHADJ )
						{
							//
							// Adjust high - (16-bits) relocate the high half of an
							//      address and adjust for sign extension of low half.
							//

							//
							// If the address has already been relocated then don't
							// process it again now or information will be lost.
							//
							if (RelocationOffset & 2/*LDRP_RELOCATION_FINAL*/ ) {
								;
							}
							else
							{
								LONG
								Temp = *(WORD*)(VirtualAddress) << 16;
								Temp += (LONG)( Relocations[i+1] );
								Temp += (ULONG)(ImageDelta & 0xFFFFFFFF);
								Temp += 0x8000;
								*(WORD*)VirtualAddress = (WORD)(Temp >> 16);
							}
							i++;
						}
						else
						if (   RelocationType == IMAGE_REL_BASED_MACHINE_SPECIFIC_5
							|| RelocationType == IMAGE_REL_BASED_RESERVED
							|| RelocationType == IMAGE_REL_BASED_MACHINE_SPECIFIC_7
							|| RelocationType == IMAGE_REL_BASED_MACHINE_SPECIFIC_8
							|| RelocationType == IMAGE_REL_BASED_MACHINE_SPECIFIC_9)
						{
							;
						}
						else
						if ( RelocationType == IMAGE_REL_BASED_DIR64 )
							*(unsigned __int64*)VirtualAddress += ImageDelta;
						
						
					}
				}
				BaseRelocation = (IMAGE_BASE_RELOCATION*)( (DWORD_PTR)BaseRelocation + (DWORD_PTR)dwSizeOfBlock );
			}
		}
	}
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	
	/////////////////////////////////////////////////////////////// Image Imports ///////////////////////////////////////////////////////////////
	const IMAGE_DATA_DIRECTORY* DirectoryEntryImport = &OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	const DWORD DirectoryEntryImportVA = DirectoryEntryImport->VirtualAddress;
	if ( DirectoryEntryImportVA > (DWORD)0x1000ui32 && DirectoryEntryImportVA < SizeOfImage )
	{
		IMAGE_IMPORT_DESCRIPTOR* ImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)( (DWORD_PTR)MappedDosHeader + DirectoryEntryImportVA );

		IMAGE_THUNK_DATA* OrigFirstThunk	= (IMAGE_THUNK_DATA*)NULL;
		IMAGE_THUNK_DATA* FirstThunk		= (IMAGE_THUNK_DATA*)NULL;
	
		while( ImportDescriptor->Characteristics != (DWORD)NULL )
		{
			OrigFirstThunk	= (PIMAGE_THUNK_DATA)( (DWORD_PTR)MappedDosHeader + (DWORD_PTR)ImportDescriptor->OriginalFirstThunk );
			FirstThunk		= (PIMAGE_THUNK_DATA)( (DWORD_PTR)MappedDosHeader + (DWORD_PTR)ImportDescriptor->FirstThunk );

			const char* ModuleName = (const char*)( (DWORD_PTR)MappedDosHeader + (DWORD_PTR)ImportDescriptor->Name );
		
			const HMODULE LibraryAddr = (HMODULE)LoadLibraryA( ModuleName );
			if ( LibraryAddr != NULL ) 
			{
				while( OrigFirstThunk->u1.AddressOfData )
				{
					if(OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
						FirstThunk->u1.Function = (DWORD_PTR)GetProcAddress( LibraryAddr, (char*)( IMAGE_ORDINAL(OrigFirstThunk->u1.Ordinal) ) );
					else
					{
						const DWORD AddressOfData = OrigFirstThunk->u1.AddressOfData;
						if ( AddressOfData > (DWORD)0x1000ui32 && AddressOfData < SizeOfImage )
						{
							const IMAGE_IMPORT_BY_NAME* ImportByName = (IMAGE_IMPORT_BY_NAME*)( (DWORD_PTR)MappedDosHeader + (DWORD_PTR)AddressOfData );
							FirstThunk->u1.Function = (DWORD_PTR)GetProcAddress( LibraryAddr, (LPCSTR)ImportByName->Name );
						}
					}
					OrigFirstThunk = (IMAGE_THUNK_DATA*)( (DWORD_PTR)OrigFirstThunk + (DWORD_PTR)sizeof(IMAGE_THUNK_DATA) );
					FirstThunk     = (IMAGE_THUNK_DATA*)( (DWORD_PTR)FirstThunk     + (DWORD_PTR)sizeof(IMAGE_THUNK_DATA) );
				}
			}
			ImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)( (DWORD_PTR)ImportDescriptor + (DWORD_PTR)sizeof(IMAGE_IMPORT_DESCRIPTOR) );
		}
	}
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		
	return MappedDosHeader;
}

//Code from ReactOS:
int __cdecl __memcmp__( /*IN*/ const void *s1, /*IN*/ const void *s2, /*IN*/ size_t n)
{
	if ( n != (size_t)NULL ) 
	{
		__ASSERT__( s1 != NULL && s2 != NULL );

		//https://doxygen.reactos.org/d5/d21/memcmp_8c.html

		const unsigned char *p1 = (const unsigned char *)s1, *p2 = (const unsigned char *)s2;
		do 
		{
			if (*p1++ != *p2++)
				return (*--p1 - *--p2);
		} while (--n != 0);
	}
	return 0;
}

Progressbar::Progressbar( /*IN*/ char* Text, /*IN*/ int Size )
{
	__ASSERT__( Text != NULL );

	CONSOLE_SCREEN_BUFFER_INFO ConsoleScreenBufferInfo = {};
	ZeroMemory( &ConsoleScreenBufferInfo, sizeof(CONSOLE_SCREEN_BUFFER_INFO) );

	this->hStdOutHandle = GetStdHandle(STD_OUTPUT_HANDLE);

	GetConsoleScreenBufferInfo( hStdOutHandle, (CONSOLE_SCREEN_BUFFER_INFO*)&ConsoleScreenBufferInfo );

	this->dwCursorPosition = ConsoleScreenBufferInfo.dwCursorPosition;

	this->ProgressText = Text;
	this->Size = Size;
}

void Progressbar::update( /*IN*/ char* Status, /*IN*/ double percentage )
{
	__ASSERT__( Status != NULL );

	const BOOL ConsoleCursorPositionUpdated =
	SetConsoleCursorPosition( this->hStdOutHandle, this->dwCursorPosition );

	if ( ConsoleCursorPositionUpdated == TRUE )
	{
		const int ProgressPercentage= (int)( (double)percentage * (double)(100.f)		);
		const int ProgressSize		= (int)( (double)percentage * (double)this->Size	);
		const int ProgressLeft		= (int)( (int)this->Size	- (int)ProgressSize		);

		char* ProgressBuffer = (char*)malloc( ProgressSize + 1 );
		__ASSERT__( ProgressBuffer != NULL );

		memset( ProgressBuffer, '=', ProgressSize );
		ProgressBuffer[ProgressSize] = NULL;

		printf ("%s\n%s [%.*s%*s] %3d%%\n", Status, this->ProgressText, ProgressSize, ProgressBuffer,ProgressLeft, "",ProgressPercentage);

		free( ProgressBuffer );
	}
}

template< typename T >
T* SelectRandomElement( /*IN*/ T* Array, /*IN*/ DWORD ArraySize )
{
	__ASSERT__( Array != NULL );
	__ASSERT__( ArraySize > 0 );

	DWORD RandomSelection = NULL;
	if ( ArraySize < (DWORD)1000000000ui32 )
	{
		DWORD MaxNumber = (DWORD)100ui32;
		for ( ; (DWORD)( ArraySize / MaxNumber ) != (DWORD)NULL ; MaxNumber *= 10ui32 )
			;

		const DWORD Steps = (DWORD)MaxNumber / ArraySize;

		RandomSelection = (DWORD)(GetRandomDword() % (DWORD)(Steps * ArraySize)) + (DWORD)1ui32;

		for (DWORD i = 0, j = ( (DWORD)ArraySize - (DWORD)1ui32 ); i < ArraySize; i++, j--)
		{
			const DWORD CompareValue =  j * Steps;
			if ( RandomSelection > CompareValue )
				return (T*)( (DWORD_PTR)Array + (sizeof(T) * (DWORD_PTR)(i)) );
		}
	}
	printf("FATAL ERROR in SelectRandomElement => { RandomSelection:[%u] }\n",RandomSelection);
	system("pause");
	return NULL;
}

void* SelectRandomElement( /*IN*/ void* Array, /*IN*/ DWORD ArraySize, /*IN*/ DWORD ArrayDataTypeSize )
{
	__ASSERT__( Array != NULL );
	__ASSERT__( ArraySize > 0 );
	__ASSERT__( ArrayDataTypeSize > 0 );

	DWORD RandomSelection = NULL;
	if ( ArraySize < (DWORD)1000000000ui32 )
	{
		DWORD MaxNumber = (DWORD)100ui32;
		for ( ; (DWORD)( ArraySize / MaxNumber ) != (DWORD)NULL ; MaxNumber *= 10ui32 )
			;

		const DWORD Steps = (DWORD)MaxNumber / ArraySize;

		RandomSelection = (DWORD)(g_RandomGenerator.GetDword() % (DWORD)(Steps * ArraySize)) + 1;

		for (DWORD i = 0, j = ( (DWORD)ArraySize - (DWORD)1ui32 ); i < ArraySize; i++, j--)
		{
			const DWORD CompareValue = j * Steps;
			if ( RandomSelection > CompareValue )
				return (void*)( (DWORD_PTR)Array + (ArrayDataTypeSize * (DWORD_PTR)(i)) );
		}
	}
	__ASSERT__( ArraySize < (DWORD)1000000000ui32 );

	printf("FATAL ERROR in SelectRandomElement => { RandomSelection:[%u] }\n",RandomSelection);
	system("pause");
	return NULL;
}

bool EnablePrivilege( /*IN*/ LPCWSTR PrivilegeName )
{
	__ASSERT__( PrivilegeName != NULL );

	BOOL bResult = FALSE;
	
	HANDLE TokenHandle = NULL;
	bResult = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &TokenHandle);
	if ( bResult != TRUE || TokenHandle == NULL || TokenHandle == INVALID_HANDLE_VALUE )
		return false;

	LUID Luid = {};
	ZeroMemory( &Luid, sizeof(LUID) );

	bResult = LookupPrivilegeValueW( NULL, PrivilegeName, &Luid );
	if ( bResult == TRUE )
	{
		TOKEN_PRIVILEGES TokenPrivileges = {};
		ZeroMemory( &TokenPrivileges, sizeof(TOKEN_PRIVILEGES) );

		TokenPrivileges.PrivilegeCount = (DWORD)1ui32;
		TokenPrivileges.Privileges[0].Luid = Luid;
		TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		bResult = AdjustTokenPrivileges( TokenHandle, FALSE, &TokenPrivileges, NULL, NULL, NULL );
	}
	CloseHandle(TokenHandle);

	return bResult == TRUE; 
}

void EnableAllPrivileges( void )
{
	const LPCWSTR PrivilegeNames[] = 
	{
		SE_CREATE_TOKEN_NAME              ,
		SE_ASSIGNPRIMARYTOKEN_NAME        ,
		SE_LOCK_MEMORY_NAME               ,
		SE_INCREASE_QUOTA_NAME            ,
		SE_UNSOLICITED_INPUT_NAME         ,
		SE_MACHINE_ACCOUNT_NAME           ,
		SE_TCB_NAME                       ,
		SE_SECURITY_NAME                  ,
		SE_TAKE_OWNERSHIP_NAME            ,
		SE_LOAD_DRIVER_NAME               ,
		SE_SYSTEM_PROFILE_NAME            ,
		SE_SYSTEMTIME_NAME                ,
		SE_PROF_SINGLE_PROCESS_NAME       ,
		SE_INC_BASE_PRIORITY_NAME         ,
		SE_CREATE_PAGEFILE_NAME           ,
		SE_CREATE_PERMANENT_NAME          ,
		SE_BACKUP_NAME                    ,
		SE_RESTORE_NAME                   ,
		SE_SHUTDOWN_NAME                  ,
		SE_DEBUG_NAME                     ,
		SE_AUDIT_NAME                     ,
		SE_SYSTEM_ENVIRONMENT_NAME        ,
		SE_CHANGE_NOTIFY_NAME             ,
		SE_REMOTE_SHUTDOWN_NAME           ,
		SE_UNDOCK_NAME                    ,
		SE_SYNC_AGENT_NAME                ,
		SE_ENABLE_DELEGATION_NAME         ,
		SE_MANAGE_VOLUME_NAME             ,
		SE_IMPERSONATE_NAME               ,
		SE_CREATE_GLOBAL_NAME             ,
		SE_TRUSTED_CREDMAN_ACCESS_NAME    ,
		SE_RELABEL_NAME                   ,
		SE_INC_WORKING_SET_NAME           ,
		SE_TIME_ZONE_NAME                 ,
		SE_CREATE_SYMBOLIC_LINK_NAME      ,
	};

	for (DWORD i = 0; i < (DWORD)35ui32; i++)
		EnablePrivilege( (LPCWSTR)PrivilegeNames[i] );
}

void ClearConsole()
{
	HANDLE StdOutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	__ASSERT__( StdOutHandle != INVALID_HANDLE_VALUE && StdOutHandle != NULL );

	COORD ConsoleStartCoord  = {};
	ZeroMemory( &ConsoleStartCoord, sizeof(COORD) );

	CONSOLE_SCREEN_BUFFER_INFO ConsoleScreenBufferInfo = {};
	ZeroMemory( &ConsoleScreenBufferInfo, sizeof(CONSOLE_SCREEN_BUFFER_INFO) );
	if ( GetConsoleScreenBufferInfo( StdOutHandle, &ConsoleScreenBufferInfo ) != TRUE )
		return;

	ConsoleStartCoord.X = (SHORT)NULL;
	ConsoleStartCoord.Y = (SHORT)NULL;
	if ( SetConsoleCursorPosition( StdOutHandle, ConsoleStartCoord ) != TRUE )
		return;

	const SHORT ConsoleBufferSizeX = ConsoleScreenBufferInfo.dwSize.X;
	const SHORT ConsoleBufferSizeY = ConsoleScreenBufferInfo.dwSize.Y;

	const DWORD ConsoleBufferSize = (DWORD)ConsoleBufferSizeX * (DWORD)ConsoleBufferSizeY;

	DWORD NumberOfCharsWritten = 0;
	FillConsoleOutputCharacterA( StdOutHandle, ' ', ConsoleBufferSize, ConsoleStartCoord, &NumberOfCharsWritten );

	DWORD NumberOfAttrsWritten = 0;
	FillConsoleOutputAttribute( StdOutHandle, 
								ConsoleScreenBufferInfo.wAttributes,
								ConsoleBufferSize, 
								ConsoleStartCoord, 
								&NumberOfAttrsWritten
							 );
}