#include <Windows.h>
#include <stdio.h>
#include "Util.h"
#include "dbghelp.h"
#include "GameOffsets.h"
#include "ASSERT.h"

DWORD_PTR OFFSET_GlowObjectManager = NULL;	// -> VR9
DWORD_PTR OFFSET_LocalPlayer = NULL;		// -> VR8
DWORD_PTR OFFSET_EntityList = NULL;			// -> VR7
DWORD_PTR OFFSET_FORCE_ATTACK = NULL;		// -> VR6

DWORD_PTR OFFSET_CrosshairId = NULL;		// -> VR5
DWORD_PTR OFFSET_TeamNum = NULL;			// -> VR4
DWORD_PTR OFFSET_bSpotted = NULL;			// -> VR3

DWORD_PTR GLOBAL_MinimumAddress = (DWORD_PTR)(0x10000);// -> VR0

bool IsValidCodeRegion( /*IN*/ const IMAGE_DOS_HEADER* DosHeader, /*IN*/ const DWORD_PTR Address )
{
	__ASSERT__( DosHeader != NULL );
	__ASSERT__( (DWORD_PTR)Address >= (DWORD_PTR)DosHeader );

	const DWORD_PTR RVA = (DWORD_PTR)Address - (DWORD_PTR)DosHeader;

	const IMAGE_NT_HEADERS* ImageNtHeader = (IMAGE_NT_HEADERS*)( (DWORD_PTR)DosHeader + (DWORD_PTR)DosHeader->e_lfanew );
	const IMAGE_SECTION_HEADER* SectionHeader = ImageRvaToSection( ImageNtHeader, (const PVOID)DosHeader, (ULONG)(RVA & 0xFFFFFFFF) );
	if ( SectionHeader == nullptr ) return false;
	const DWORD Flags = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
	return (SectionHeader->Characteristics & Flags) == Flags;
}

DWORD ResolveToOffset( /*IN*/ const IMAGE_DOS_HEADER* DosHeader, /*IN*/ const DWORD_PTR Address )
{
	__ASSERT__( DosHeader != NULL );
	__ASSERT__( (DWORD_PTR)Address >= (DWORD_PTR)DosHeader );

	const DWORD_PTR RVA = (DWORD_PTR)Address - (DWORD_PTR)DosHeader;

	const IMAGE_NT_HEADERS* ImageNtHeader = (IMAGE_NT_HEADERS*)( (DWORD_PTR)DosHeader + (DWORD_PTR)DosHeader->e_lfanew );
	
	const DWORD_PTR VA = (DWORD_PTR)ImageRvaToVa( ImageNtHeader, DosHeader, (DWORD)(RVA & 0xFFFFFFFF) );
	return ( VA & 0xFFFFFFFF );
}

bool ClientDllSearchForOffsets( /*IN*/ const struct RemoteProcessModuleInfo* ClientDllInfo )
{
	__ASSERT__( ClientDllInfo != NULL );

	BYTE* ClientImage = (BYTE*)NULL;
	DWORD ClientImageSize = (DWORD)NULL;

	LoadFileToMemory( ClientDllInfo->szExePath, &ClientImage, &ClientImageSize );
	if ( ClientImage == NULL || ClientImageSize == NULL )
	{
		printf("ERROR: Failed to load [%ws] into memory!\n",ClientDllInfo->szModule);
		system("pause");
		return false;
	}
	printf("[+] Loaded [%ws] into memory [0x%p]!\n", ClientDllInfo->szModule, ClientImage );
	const IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)ClientImage;
	const IMAGE_NT_HEADERS* NtHeader  = (IMAGE_NT_HEADERS*)ImageNtHeader( ClientImage );
	if ( DosHeader->e_magic != IMAGE_DOS_SIGNATURE || NtHeader == NULL )
	{
		printf("ERROR file [%ws] is not a valid PE-Image!\n", ClientDllInfo->szModule );
		system("pause");
		free( ClientImage );
		return false;
	}

	const DWORD VirtualImageBase = (DWORD)NtHeader->OptionalHeader.ImageBase;
	printf("[+] Search for offsets in [%ws]\n",ClientDllInfo->szModule);
	printf("-------------------------------------------------------------\n");

	OFFSET_GlowObjectManager = (DWORD_PTR)FindPattern( (HMODULE)ClientImage, ClientImageSize, "75 ?? 0F 57 C0 C7 05 ?? ?? ?? ?? 00 00 00 00 0F 11 05");
	if ( OFFSET_GlowObjectManager == NULL || IsValidCodeRegion( DosHeader, OFFSET_GlowObjectManager ) == false )
		printf("[!] ERROR OFFSET_GlowObjectManager NOT FOUND!\n");
	else
	{
		OFFSET_GlowObjectManager += (DWORD_PTR)18;
		OFFSET_GlowObjectManager = *(__int32*)OFFSET_GlowObjectManager - VirtualImageBase;
		printf("[+] OFFSET_GlowObjectManager: 0x%X\n",OFFSET_GlowObjectManager);
		OFFSET_GlowObjectManager += (DWORD_PTR)ClientDllInfo->modBaseAddr;
	}
	OFFSET_LocalPlayer = (DWORD_PTR)FindPattern( (HMODULE)ClientImage, ClientImageSize, "8D 34 85 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 8B 41 08 8B 48 04 83 F9 FF");
	if ( OFFSET_LocalPlayer == NULL || IsValidCodeRegion( DosHeader, OFFSET_LocalPlayer ) == false )
		printf("[!] ERROR OFFSET_LocalPlayer NOT FOUND!\n");
	else
	{
		OFFSET_LocalPlayer += (DWORD_PTR)3;
		OFFSET_LocalPlayer = *(__int32*)OFFSET_LocalPlayer + 4 - VirtualImageBase;
		printf("[+] OFFSET_LocalPlayer: 0x%X\n",OFFSET_LocalPlayer);
		OFFSET_LocalPlayer += (DWORD_PTR)ClientDllInfo->modBaseAddr;
	}
	
	
	OFFSET_FORCE_ATTACK = (DWORD_PTR)FindPattern( (HMODULE)ClientImage, ClientImageSize, "89 0D ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 8B F2 8B C1 83 CE 04");
	if ( OFFSET_FORCE_ATTACK == NULL || IsValidCodeRegion( DosHeader, OFFSET_FORCE_ATTACK ) == false )
		printf("[!] ERROR OFFSET_FORCE_ATTACK NOT FOUND!\n");
	else
	{
		OFFSET_FORCE_ATTACK += (DWORD_PTR)2;
		OFFSET_FORCE_ATTACK = *(__int32*)OFFSET_FORCE_ATTACK - VirtualImageBase;
		printf("[+] OFFSET_FORCE_ATTACK: 0x%X\n",OFFSET_FORCE_ATTACK);
		OFFSET_FORCE_ATTACK += (DWORD_PTR)ClientDllInfo->modBaseAddr;
	}

	OFFSET_EntityList = (DWORD_PTR)FindPattern( (HMODULE)ClientImage, ClientImageSize, "8B 89 ?? ?? ?? ?? 85 C9 74 52");
	if ( OFFSET_EntityList == NULL || IsValidCodeRegion( DosHeader, OFFSET_EntityList ) == false )
		printf("[!] ERROR OFFSET_EntityList NOT FOUND!\n");
	else
	{
		OFFSET_EntityList += (DWORD_PTR)2;
		OFFSET_EntityList = *(__int32*)OFFSET_EntityList - VirtualImageBase;
		printf("[+] OFFSET_EntityList: 0x%X\n",OFFSET_EntityList);
		OFFSET_EntityList += (DWORD_PTR)ClientDllInfo->modBaseAddr;
	}
	

	OFFSET_CrosshairId = (DWORD_PTR)FindPattern( (HMODULE)ClientImage, ClientImageSize, "73 ?? 8B 81 ?? ?? 00 00 85 C0 75 ?? 8B 81 ?? ?? 00 00 85 C0 74");
	if ( OFFSET_CrosshairId == NULL || IsValidCodeRegion( DosHeader, OFFSET_CrosshairId ) == false )
		printf("[!] ERROR OFFSET_CrosshairId NOT FOUND!\n");
	else
	{
		OFFSET_CrosshairId += (DWORD_PTR)4;
		OFFSET_CrosshairId = *(__int32*)OFFSET_CrosshairId;
		printf("[+] OFFSET_CrosshairId: 0x%X\n",OFFSET_CrosshairId);
	}
	
	
	OFFSET_bSpotted = (DWORD_PTR)FindPattern( (HMODULE)ClientImage, ClientImageSize, "80 B9 ?? ?? ?? 00 00 74 ?? 8B 41 08");
	if ( OFFSET_bSpotted == NULL || IsValidCodeRegion( DosHeader, OFFSET_bSpotted ) == false )
		printf("[!] ERROR OFFSET_bSpotted NOT FOUND!\n");
	else
	{
		OFFSET_bSpotted += 2;
		OFFSET_bSpotted = *(__int32*)OFFSET_bSpotted;
		printf("[+] OFFSET_bSpotted: 0x%X\n",OFFSET_bSpotted);
	}


	OFFSET_TeamNum = (DWORD_PTR)0xF4;
	printf("[+] OFFSET_TeamNum: 0x%X\n",OFFSET_TeamNum);

	printf("-------------------------------------------------------------\n");

	ZeroMemory( ClientImage, ClientImageSize );
	free( ClientImage ); ClientImage = NULL;

	return true;
}