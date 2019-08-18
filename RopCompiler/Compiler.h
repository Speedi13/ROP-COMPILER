#pragma once
#include <vector>
struct CompilerSettings{
	//;<cfg=RandomPadding>true</cfg>
	bool UseRandomPadding;

	//;<cfg=RandomPaddingSize>8</cfg>
	DWORD g_constMaxObfuscationPaddingEntrys;

	//;<cfg=PrintDebugOutput>false</cfg>
	bool PrintDebugOutput;

	//;<cfg=SearchDlls>false</cfg>
	bool SearchDlls;

	//;<cfg=VirtualQuerySearch>true</cfg>
	bool VirtualQuerySearch;

	//to be even more undetected place the rop-chain into the original stack
	bool HijackThreadStack;//= true;
};
extern struct CompilerSettings g_CompilerSettings;


extern bool g_ConditionalMoveSupported;
extern bool g_HardwareRngSupported_RDRND;
extern bool g_HardwareRngSupported_RDSEED;

struct RopCode
{
	struct RopAddresses
	{
		std::vector<DWORD_PTR> Addresses;
	};

	char* Instruction;
	unsigned __int8* Code;
	unsigned __int8 CodeLen;
	struct RopAddresses* Addresses;
	DWORD RefCntr;
	
	void AddAddress( /*IN*/ DWORD_PTR Address );
	void* GetRandomAddress( void );
	void Destructor( void );
};
extern std::vector<RopCode*> RopGadgets;

extern DWORD_PTR VirtualRegisterAddresses[10];
extern DWORD_PTR VirtualMemoryRegisterAddresses;

enum Regs
{
	REG_EAX, REG_ECX, REG_EDX, REG_EBX,

	REG_ESP, REG_EBP, REG_ESI, REG_EDI,

	REG_VR0, REG_VR1, REG_VR2, REG_VR3, REG_VR4,

	REG_VR5, REG_VR6, REG_VR7, REG_VR8, REG_VR9,

	REG_VMM, //Virtual Machine Memory

	REG_ERROR,
};

#define DummyJumpAddress ((DWORD_PTR)(0xC0DEC0DE))

DWORD ExecuteRopChain( /*IN*/ const HANDLE hGame, /*IN*/ const DWORD_PTR StackTableStart );

void CompileCode( /*IN*/ const char* TextCode, /*IN*/ const HANDLE hGame, /*OUT*/ DWORD_PTR* StackTable, /*OUT*/ DWORD_PTR* StackTableStart, /*OUT OPTIONAL*/ HANDLE* OutThreadHandle );

void AllocateVirtualRegs ( /*IN*/ const HANDLE hGame );
void InitializeRopGadgets( /*IN*/ const HANDLE hGame );
void BringYourOwnGadgets ( /*IN*/ const HANDLE hGame );
void RemoveUnusedGadgets ( /*IN*/ const HANDLE hGame );

void ReleaseRopGadgets( void );

void InitializeConsole( void );

