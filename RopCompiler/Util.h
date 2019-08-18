#pragma once

#define getArraySize( Array, ElementDataType ) (sizeof(Array) / sizeof(ElementDataType))

void GetDecimalNumber( /*IN*/ const char* inString, /*OUT*/ DWORD64* outNumber, /*OUT*/ size_t* outI );
bool GetHeximalNumber( /*IN*/ const char *inString, /*OUT*/ DWORD64* outNumber, /*OUT*/ size_t* outI );

char* RegToString( /*IN*/ const enum Regs Reg );
enum Regs GetReg(  /*IN*/ const char* p);

unsigned long GetProcessIdByName( /*IN*/ const char *ProcessName);

struct RemoteProcessModuleInfo
{
	BYTE  * modBaseAddr;        // Base address of module in th32ProcessID's context
    DWORD   modBaseSize;        // Size in bytes of module starting at modBaseAddr
    HMODULE hModule;            // The hModule of this module in th32ProcessID's context
    WCHAR   szModule[255 + 1];
    WCHAR   szExePath[MAX_PATH];
};
bool GetRemoteProcessModuleInfo( /*IN*/ const DWORD ProcessId, /*IN*/ const wchar_t* ModuleName, /*OUT*/ struct RemoteProcessModuleInfo* outInfo );

bool GetRemoteProcessModuleExportAddress( /*IN*/ const DWORD ProcessId, /*IN*/ const char* ModuleName, /*IN*/ const char* ExportName, /*OUT*/ DWORD_PTR* outAddress );

bool RemoteSuspendProcessThreads( /*IN*/ const DWORD ProcessId, /*IN*/ bool Resume );

bool NtSuspendProcess( /*IN*/ const HANDLE hProcess );
bool NtResumeProcess ( /*IN*/ const HANDLE hProcess );

bool EnablePrivilege( /*IN*/ LPCWSTR PrivilegeName );
void EnableAllPrivileges( void );

bool LoadFileToMemory( /*IN*/ const wchar_t* FilePath, /*OUT*/ BYTE** Image, /*OUT*/ DWORD* ImageSize );

BYTE* FindPattern(/*IN*/ const BYTE* dwAddress, /*IN*/ const DWORD dwSize, /*IN*/ const BYTE* pbSig, /*IN*/ const char* szMask);
BYTE* FindPattern(/*IN*/ const HMODULE hModule , /*IN*/const DWORD dwSize, /*IN*/ const char* szSig);

void GetCompilerSettings( const char* FileContent, const DWORD FileSize, struct CompilerSettings* Setting );

wchar_t* OpenFileDialog( LPCWSTR DialogTitle );

void RemoteLoadLibraryW( const HANDLE hProcess, const wchar_t* DllPath );
void LoadAllDlls( const HANDLE hProcess );

void* ManualMapDynamicLinkLibrary( /*IN*/ void* DiskImage, /*IN OPTIONAL*/ DWORD_PTR RelocationPositionOverwrite = NULL );

int __cdecl __memcmp__( /*IN*/ const void *s1, /*IN*/ const void *s2, /*IN*/ size_t n );

struct Progressbar
{
	HANDLE hStdOutHandle;
	COORD dwCursorPosition;
	char* ProgressText;
	int Size;

	Progressbar( /*IN*/ char* Text, /*IN*/ int Size );
	void update( /*IN*/ char* Status, /*IN*/ double percentage );
};

void* SelectRandomElement( /*IN*/ void* Array, /*IN*/ DWORD ArraySize, /*IN*/ DWORD ArrayDataTypeSize );

void ClearConsole();

