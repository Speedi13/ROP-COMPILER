#include <Windows.h>
#include "Util.h"
#include <vector>
#include "ASSERT.h"
#include "Compiler.h"
#include "RandomGenerator.h"
struct CompilerSettings g_CompilerSettings = {};

bool g_ConditionalMoveSupported = false;
bool g_HardwareRngSupported_RDRND = false;
bool g_HardwareRngSupported_RDSEED = false;

struct InstructionCache
{
	char CodeLineForDebugging[128];
	char CodeLine[128];
	int CodeLineIndex;
	bool IsFunctionStart;
	DWORD_PTR CodeOffset;
};
struct RelocationData
{
	struct InstructionCache* JumpTarget;
	DWORD_PTR JumpTargetIndex;
	DWORD_PTR CodeOffset;
};

typedef bool (*t_AdvancedInstructionHandler)( /*IN OUT*/ struct InstructionCache* IC );

std::vector<struct InstructionCache> Instructions;
std::vector<struct RelocationData> Relocations;
std::vector<DWORD_PTR> RopChain;

DWORD_PTR VirtualRegisterAddresses[10] = {};
DWORD_PTR VirtualMemoryRegisterAddresses = 0;

//Reads code to instruction cache vector
void ReadInCode( /*IN*/ const char* TextCode );

//main function: it translates instruction cache to return-address array
void ConvertToROP( /*IN*/ const HANDLE hGame );


void HijackThreadStack	( /*IN*/ const HANDLE hGame, /*OUT*/ HANDLE* OutThreadHandle, /*OUT*/ DWORD_PTR* StackTable, /*OUT*/ DWORD_PTR* StackTableStart, /*OUT OPTIONAL*/DWORD* outStackTableSize = nullptr );
void CreateRopStack		( /*IN*/ const HANDLE hGame, /*OUT*/ HANDLE* OutThreadHandle, /*OUT*/ DWORD_PTR* StackTable, /*OUT*/ DWORD_PTR* StackTableStart, /*OUT OPTIONAL*/DWORD* outStackTableSize = nullptr );

//Prints compilation debug info
void PrintDebugOutput( /*IN OPTIONAL*/ DWORD_PTR CallStackStartAddr = NULL );

/////////////////////////////////////////////// compiler utility functions ///////////////////////////////////////////////
/**/struct RopCode* FindMatchingRopGadget( /*IN*/ const char* C, /*IN OPTIONAL*/ bool f = false );                      //
/**/struct RopCode* FindMatchingRopGadgetByOpCode( /*IN*/ const char* C, /*IN*/ BYTE* Code, /*IN*/ BYTE CodeSize );     //
/**/struct InstructionCache* GetJumpTarget( const char* labelName );                                                    //
/**/void addJumpToRopChain( struct InstructionCache* IC, char* InstructionString, BYTE StringOffset, const char* Move );//
/**/bool mov_ptr_eax__ebx( struct InstructionCache* IC );                                                               //
/**/bool mov_byte_ptr__eax__ebx( struct InstructionCache* IC );                                                         //
/**/void RelocatingJumps( const DWORD_PTR RemoteStackTableStartPosition );                                              //
/**/void InsertObfuscationPadding( /*IN OPTIONAL*/ const struct InstructionCache* NextInstruction );                    //
/**/bool IsCodeLineComment(const char c);                                                                               //
/**/bool IsCodeLineEnd(const char c);                                                                                   //
/**/void CopyWithoutSpacesToLower( /*OUT*/ char* out, /*IN*/ const char* in, /*IN*/ const size_t len );                 //
/**/bool mov_ecx__eax( struct InstructionCache* IC );                                                                   //
/**/bool mov_ebx__ecx( struct InstructionCache* IC );                                                                   //
/**/bool mov_ebx__eax( struct InstructionCache* IC );                                                                   //
/**/bool mov_edx__eax( struct InstructionCache* IC );                                                                   //
/**/t_AdvancedInstructionHandler g_AdvancedInstructionHandler[] = {                                                     //
/**/	mov_ecx__eax,                                                                                                   //
/**/	mov_ebx__ecx,                                                                                                   // 
/**/	mov_ebx__eax,                                                                                                   //
/**/	mov_edx__eax,                                                                                                   //
/**/	mov_ptr_eax__ebx,                                                                                               //
/**/	mov_byte_ptr__eax__ebx, };                                                                                      //
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define STACK_PADDING if ( g_CompilerSettings.UseRandomPadding == true ){ InsertObfuscationPadding( NULL ); };

void CompileCode( /*IN*/ const char* TextCode, /*IN*/ const HANDLE hGame, /*OUT*/ DWORD_PTR* StackTable, /*OUT*/ DWORD_PTR* StackTableStart, /*OUT OPTIONAL*/ HANDLE* OutThreadHandle )
{
	__ASSERT__( TextCode != NULL );
	__ASSERT__( hGame != INVALID_HANDLE_VALUE && hGame != NULL );
	__ASSERT__( StackTable != NULL );
	__ASSERT__( StackTableStart != NULL );

	ReadInCode( TextCode );
	ConvertToROP( hGame );

	if ( g_CompilerSettings.HijackThreadStack == true || OutThreadHandle != NULL )
	{
		//don't create our own stack, use the stack of the thread:
		HijackThreadStack( hGame, OutThreadHandle, StackTable, StackTableStart, NULL );
	}
	else
		CreateRopStack( hGame, OutThreadHandle, StackTable, StackTableStart, NULL );

	if ( g_CompilerSettings.PrintDebugOutput == true )
	{
		PrintDebugOutput( *(DWORD_PTR*)StackTableStart );
		system("pause");
	}
}

//main function: it translates instruction cache to return-address array
void ConvertToROP( /*IN*/ const HANDLE hGame )
{
	__ASSERT__( hGame != INVALID_HANDLE_VALUE && hGame != NULL );

	RopChain.clear();
	Relocations.clear();

	AllocateVirtualRegs(hGame);

	printf("[+] Building ROP-Chain\n");

	for (size_t i = 0; i < (size_t)(Instructions.size()); i++)
	{
		struct InstructionCache* p = &Instructions.at(i);
		if ( p->IsFunctionStart == true )
		{
			p->CodeOffset = (DWORD_PTR)RopChain.size();
			continue;
		}

		char* C = p->CodeLine;
		if ( C[0] == NULL )
			continue;

		RopCode* c = FindMatchingRopGadget( C, true );
		if ( c != NULL )
		{
			if ( g_CompilerSettings.UseRandomPadding == true )
				InsertObfuscationPadding( p );

			p->CodeOffset = (DWORD_PTR)(RopChain.size());
			RopChain.push_back( (DWORD_PTR)c->GetRandomAddress() ); c->RefCntr+=1;

			STACK_PADDING;
			continue;
		}
		else
		{
			//For the instructions below no gadgets are found so they get replaced using gadgets that got found
			const DWORD AdvancedInstructionHandlerSize = (DWORD)( (DWORD)sizeof(g_AdvancedInstructionHandler) / (DWORD)sizeof(t_AdvancedInstructionHandler) );
			bool InstructionHandled = false;
			for (DWORD w = 0; w < (DWORD)AdvancedInstructionHandlerSize; w++)
			{
				if ( g_AdvancedInstructionHandler[w]( p ) == true )
				{
					InstructionHandled = true;
					break;
				}
			}
			if ( InstructionHandled == true )
				continue;

			//mov???,???
			if ( C[0] == 'm' && C[1] == 'o' && C[2] == 'v' && C[6] == ',')
			{
				const Regs R = GetReg( &C[3] );
				if ( R <= REG_EDI )
				{
					//mov R, ??
					const Regs R2 = GetReg( &C[7] );
					if ( R2 >= REG_VR0 && R2 <= REG_VMM )
					{
						if ( g_CompilerSettings.UseRandomPadding == true )
							InsertObfuscationPadding( p );
							
						if ( R2 <= REG_VR9 )
						{
							//mov R, VirtualRegister
							const BYTE VirtualRegisterIndex = (BYTE)R2 - (BYTE)REG_VR0;

							char* RegName = RegToString( R );

							char ExchangeCode[64] = {};
							sprintf_s( ExchangeCode, "xchg eax, %s", RegName );

							RopCode* ExchangeEAX_With_R1 = NULL;
							if ( R != REG_EAX )
								ExchangeEAX_With_R1 = FindMatchingRopGadget( ExchangeCode );
							
							RopCode* SetAddr = FindMatchingRopGadget( "pop eax" );
							RopCode* ReadVR = FindMatchingRopGadget( "mov eax, DWORD PTR[eax]" );

							p->CodeOffset = RopChain.size();
							if ( ExchangeEAX_With_R1 != NULL )
							{
								RopChain.push_back( (DWORD_PTR)ExchangeEAX_With_R1->GetRandomAddress() ); ExchangeEAX_With_R1->RefCntr += 1;
								STACK_PADDING;
							}
							RopChain.push_back( (DWORD_PTR)SetAddr->GetRandomAddress() ); SetAddr->RefCntr += 1;
							RopChain.push_back( (DWORD_PTR)VirtualRegisterAddresses[VirtualRegisterIndex] );
							STACK_PADDING;
							RopChain.push_back( (DWORD_PTR)ReadVR->GetRandomAddress() ); ReadVR->RefCntr += 1;
							STACK_PADDING;
							if ( ExchangeEAX_With_R1 != NULL )
							{
								RopChain.push_back( (DWORD_PTR)ExchangeEAX_With_R1->GetRandomAddress() ); ExchangeEAX_With_R1->RefCntr += 1;
								STACK_PADDING;
							}
							continue;
						}
						else 
						if ( R2 == REG_VMM )
						{
							if ( g_CompilerSettings.UseRandomPadding == true )
								InsertObfuscationPadding( p );

							char* RegName = RegToString( R );

							char ReadCode[64] = {};
							sprintf_s( ReadCode, "pop %s\0", RegName );

							RopCode* SetRegister = FindMatchingRopGadget( ReadCode );
							if ( SetRegister == NULL )
							{
								printf("[%s] <%u> POP %s NOT FOUND!\n",__FUNCTION__, (UINT)p->CodeLineIndex+1,RegName);
								system("pause");
							}
							else
							{RopChain.push_back( (DWORD_PTR)SetRegister->GetRandomAddress() );SetRegister->RefCntr += 1;}
							p->CodeOffset = (DWORD_PTR)RopChain.size() - 1;
							const DWORD_PTR DwordPtr = (DWORD_PTR)VirtualMemoryRegisterAddresses;
							RopChain.push_back( (DWORD_PTR)DwordPtr );

							STACK_PADDING;
							continue;
						}
					}
					else
					{
						if ( C[7] == '@' )
						{
							//Get Address of label:
							char* RegName = RegToString( R );

							char ReadCode[64] = {};
							sprintf_s( ReadCode, "pop %s\0", RegName );

							RopCode* SetRegister = FindMatchingRopGadget( ReadCode );
							if ( SetRegister == NULL )
							{
								printf("[%s] <%u> POP %s NOT FOUND!\n", __FUNCTION__, (UINT)p->CodeLineIndex+1,RegName);
								system("pause");
							}
							else
							{RopChain.push_back( (DWORD_PTR)SetRegister->GetRandomAddress() );SetRegister->RefCntr += 1;}
							const DWORD_PTR DwordPtr = (DWORD_PTR)DummyJumpAddress;
							RopChain.push_back( (DWORD_PTR)DwordPtr );
							const DWORD CodeOffset = (DWORD)(RopChain.size()) - 1;
							p->CodeOffset = (DWORD_PTR)( CodeOffset - 1 );

							RelocationData RelocData = {};
							ZeroMemory(&RelocData, sizeof(RelocationData) );
							RelocData.JumpTargetIndex = NULL;
							RelocData.CodeOffset = CodeOffset;
							RelocData.JumpTarget = GetJumpTarget( &C[8] );
							Relocations.push_back( RelocData );

							STACK_PADDING;
							continue;

						}
						else
						if ( C[7] == '#' )
						{
							//get gadget-addr

							RopCode* OpCodeAddr = FindMatchingRopGadget( &C[8] );
							if ( OpCodeAddr == NULL )
							{
								printf("[ERROR] gadget not found! {%s}\n",p->CodeLineForDebugging);
								system("pause");
								DebugBreak();
							}
							else
							{
								char* RegName = RegToString( R );

								char ReadCode[64] = {};
								sprintf_s( ReadCode, "pop %s\0", RegName );

								RopCode* SetRegister = FindMatchingRopGadget( ReadCode );
								if ( SetRegister == NULL )
								{
									printf("[%s] <%u> POP %s NOT FOUND!\n", __FUNCTION__,(UINT)p->CodeLineIndex+1,RegName);
									system("pause");
								}
								else
								{RopChain.push_back( (DWORD_PTR)SetRegister->GetRandomAddress() ); SetRegister->RefCntr += 1;}
								p->CodeOffset = (DWORD_PTR)RopChain.size() - 1;
								const
								DWORD_PTR DwordPtr = (DWORD_PTR)OpCodeAddr->GetRandomAddress(); OpCodeAddr->RefCntr += 1;
								RopChain.push_back( (DWORD_PTR)DwordPtr );

								STACK_PADDING;
								continue;
							}
						}
						else
						if ( C[7] == '!' )
						{
							//get API
							char DllName[64] = {};
							ZeroMemory(DllName, sizeof(DllName) );

							char* ExportName = strstr( &C[7],".");

							DWORD_PTR DllNameSize = (char*)ExportName - (char*)&C[8];
							memcpy( DllName, &C[8], DllNameSize );
							DllName[DllNameSize+0] = '.';
							DllName[DllNameSize+1] = 'd';
							DllName[DllNameSize+2] = 'l';
							DllName[DllNameSize+3] = 'l';
							DllName[DllNameSize+4] = NULL;

							DWORD_PTR ExportAddress = NULL;

							ExportName = ExportName + 1;

							if ( GetRemoteProcessModuleExportAddress( GetProcessId( hGame ), DllName, ExportName, &ExportAddress ) != true )
							{
								printf("[ERROR] API Dll [%s] or Export [%s] not found! {%s}\n", DllName, ExportName, p->CodeLineForDebugging );
								system("pause");
							}
							
							char* RegName = RegToString( R );

							char ReadCode[64] = {};
							sprintf_s( ReadCode, "pop %s\0", RegName );

							RopCode* SetRegister = FindMatchingRopGadget( ReadCode );
							if ( SetRegister == NULL )
							{
								printf("[%s] <%u> POP %s NOT FOUND!\n", __FUNCTION__,(UINT)p->CodeLineIndex+1,RegName);
								system("pause");
							}
							else
							{RopChain.push_back( (DWORD_PTR)SetRegister->GetRandomAddress() ); SetRegister->RefCntr += 1;}

							p->CodeOffset = (DWORD_PTR)RopChain.size() - 1;

							const
							DWORD_PTR DwordPtr = (DWORD_PTR)ExportAddress;
							RopChain.push_back( (DWORD_PTR)DwordPtr );

							STACK_PADDING;
							continue;

						}
						else
						{
						//mov R, Constant Number
						DWORD64 Value64 = NULL;
						size_t End = NULL;
						if ( GetHeximalNumber( &C[7], &Value64, &End ) == false )
							 GetDecimalNumber( &C[7], &Value64, &End );
						
						if ( End > 0 )
						{
							if ( g_CompilerSettings.UseRandomPadding == true )
								InsertObfuscationPadding( p );

							char* RegName = RegToString( R );

							char ReadCode[64] = {};
							sprintf_s( ReadCode, "pop %s\0", RegName );

							RopCode* SetRegister = FindMatchingRopGadget( ReadCode );
							if ( SetRegister == NULL )
							{
								printf("[%s] <%u> POP %s NOT FOUND!\n", __FUNCTION__,(UINT)p->CodeLineIndex+1,RegName);
								system("pause");
								DebugBreak();
							}
							else
							{
								p->CodeOffset = (DWORD_PTR)RopChain.size();
								RopChain.push_back( (DWORD_PTR)SetRegister->GetRandomAddress() ); SetRegister->RefCntr += 1;
								const DWORD_PTR DwordPtr = (DWORD_PTR)Value64;
								RopChain.push_back( (DWORD_PTR)DwordPtr );
							}
							STACK_PADDING;
							continue;
						}
						}
					}
				}
				if ( R >= REG_VR0 && R <= REG_VR9 )
				{
					//mov VirtualRegister, R2

					const BYTE VirtualRegisterIndex = (BYTE)R - (BYTE)REG_VR0;
					const Regs R2 = GetReg( &C[7] );
					if ( R2 >= REG_VR0 )
					{
						if ( R2 < REG_ERROR )
							printf("[%s] ERROR: move from VirtualRegister to VirtualRegister directly not supported yet!\n{%s}\n", __FUNCTION__,p->CodeLineForDebugging);
						else
							printf("[%s] ERROR: move from value directly to VirtualRegister directly not supported yet!\n{%s}\n",__FUNCTION__,p->CodeLineForDebugging);
						system("pause");
						continue;
					}
					if ( R2 == REG_EBX )
					{
						printf("[%s] ERROR: EBX can not be written to a VirtualRegister!\n",__FUNCTION__);
						system("pause");
						continue;
					}
					if ( g_CompilerSettings.UseRandomPadding == true )
						InsertObfuscationPadding( p );

					char* RegName = RegToString( R2 );

					char ExchangeCode[64] = {};
					sprintf_s( ExchangeCode, "xchg eax, %s", RegName );

					RopCode* ExchangeEAX_With_R2 = NULL;
					if ( R2 != REG_EAX )
						ExchangeEAX_With_R2 = FindMatchingRopGadget( ExchangeCode );

					//mov DWORD PTR[ebx], eax; "\x89\x03\xC3"

					RopCode* SetAddr = FindMatchingRopGadget( "pop ebx" );
					RopCode* SetVR = FindMatchingRopGadget( "mov DWORD PTR[ebx], eax" );

					p->CodeOffset = (DWORD_PTR)RopChain.size();
					RopChain.push_back( (DWORD_PTR)SetAddr->GetRandomAddress() ); SetAddr->RefCntr += 1;
					RopChain.push_back( (DWORD_PTR)VirtualRegisterAddresses[VirtualRegisterIndex] );
					if ( ExchangeEAX_With_R2 != NULL )
					{
						RopChain.push_back( (DWORD_PTR)ExchangeEAX_With_R2->GetRandomAddress() ); ExchangeEAX_With_R2->RefCntr += 1;
						STACK_PADDING;
					}
					STACK_PADDING;
					RopChain.push_back( (DWORD_PTR)SetVR->GetRandomAddress() ); SetVR->RefCntr += 1;
					STACK_PADDING;
					if ( ExchangeEAX_With_R2 != NULL )
					{
						RopChain.push_back( (DWORD_PTR)ExchangeEAX_With_R2->GetRandomAddress() ); ExchangeEAX_With_R2->RefCntr += 1;
						STACK_PADDING;
					}
					continue;
				}
			}
			
			//Unsigned Conditional Jumps
			//  JA - JNBE - Above/not below or equal    - (CF or ZF) = 0 
			//  JAE - JNB - Above or equal/not below    - CF = 0
			//  JB - JNAE - Below/not above or equal    - CF = 1
			//  JBE - JNA - Below or equal/not above    - (CF or ZF) = 1
			//  JC        - Carry                       - CF = 1
			//  JE - JZ   - Equal/zero                  - ZF = 1
			//  JNC       - Not carry                   - CF = 0
			//  JNE - JNZ - Not equal/not zero          - ZF = 0
			//  JNP - JPO - Not parity/parity odd       - PF = 0
			//  JP - JPE  - Parity/parity even          - PF = 1
			//  JCXZ      - Register CX is zero         - CX = 0
			//  JECXZ     - Register ECX is zero        - ECX = 0

			//Signed Conditional Jumps
			//  JG/JNLE -   Greater/not less or equal   - ((SF xor OF) or ZF) = 0
			//  JGE/JNL -   Greater or equal/not less   - (SF xor OF) = 0
			//  JL/JNGE -   Less/not greater or equal   - (SF xor OF) = 1
			//  JLE/JNG -   Less or equal/not greater   - ((SF xor OF) or ZF) = 1
			//  JO      -   Overflow                    - OF = 1
			//  JNO     -   Not overflow                - OF = 0
			//  JS      -   Sign (negative)             - SF = 1
			//  JNS     -   Not sign (non-negative)     - SF = 0
			
			//Unsigned Conditional Jumps
			//  JCXZ      - Register CX is zero         - CX = 0
			if ( memcmp( C, "jcxz", 4 ) == 0 || memcmp( C, "jecxz", 5 ) == 0 )
			{
				printf("ERROR UNSUPPORTED JUMP! [%s]\n",C);
				system("pause");
				continue;
			}

			//Signed Conditional Jumps
			//  JG/JNLE -   Greater/not less or equal   - ((SF xor OF) or ZF) = 0
			if ( memcmp( C, "jnle", 4 ) == 0 )
			{
				printf("ERROR UNSUPPORTED JUMP! {3} [%s]\n",C);
				system("pause");
				continue;
			}

			//Signed Conditional Jumps
			//  JGE/JNL -   Greater or equal/not less   - (SF xor OF) = 0
			if ( memcmp( C, "jge", 3 ) == 0 || memcmp( C, "jnl", 3 ) == 0 )
			{
				//RopCode* SetESP = FindMatchingRopGadget( "CMOVGE esp,ebx" );
				addJumpToRopChain( p, C, 3, "CMOVGE" ); 
				continue;
			}
			
			//Signed Conditional Jumps
			//  JG/JNLE -   Greater/not less or equal   - ((SF xor OF) or ZF) = 0
			if ( memcmp( C, "jg", 2 ) == 0 )
			{
				printf("ERROR UNSUPPORTED JUMP! {2} [%s]\n",C);
				system("pause");
				continue;
			}

			//Unsigned Conditional Jumps
			//  JA - JNBE - Above/not below or equal    - (CF or ZF) = 0 
			if ( memcmp( C, "jnbe", 4 ) == 0 )
			{
				//RopCode* SetESP = FindMatchingRopGadget( "CMOVA esp,ebx" );
				addJumpToRopChain( p, C, 4, "CMOVA" );
				continue;
			}

			//Unsigned Conditional Jumps
			//  JAE - JNB - Above or equal/not below    - CF = 0
			if ( memcmp( C, "jae", 3 ) == 0 || memcmp( C, "jnb", 3 ) == 0 )
			{
				//RopCode* SetESP = FindMatchingRopGadget( "CMOVAE esp,ebx" );
				addJumpToRopChain( p, C, 3, "CMOVAE" );
				continue;
			}

			//Unsigned Conditional Jumps
			//  JA - JNBE - Above/not below or equal    - (CF or ZF) = 0 
			if ( memcmp( C, "ja", 2 ) == 0 )
			{
				//RopCode* SetESP = FindMatchingRopGadget( "CMOVA esp,ebx" );
				addJumpToRopChain( p, C, 2, "CMOVA" );
				continue;
			}
			
			//Unsigned Conditional Jumps
			//  JB - JNAE - Below/not above or equal    - CF = 1
			if ( memcmp( C, "jnae", 4 ) == 0 )
			{
				//RopCode* SetESP = FindMatchingRopGadget( "CMOVB esp,ebx" );
				addJumpToRopChain( p, C, 4, "CMOVB" );
				continue;
			}
			

			//Unsigned Conditional Jumps
			//  JBE - JNA - Below or equal/not above    - (CF or ZF) = 1
			if ( memcmp( C, "jbe", 3 ) == 0 || memcmp( C, "jna", 3 ) == 0 )
			{
				//RopCode* SetESP = FindMatchingRopGadget( "CMOVBE esp,ebx" );
				addJumpToRopChain( p, C, 3, "CMOVBE" );
				continue;
			}

			//Unsigned Conditional Jumps
			//  JB - JNAE - Below/not above or equal    - CF = 1
			if ( memcmp( C, "jb", 2 ) == 0 )
			{
				//RopCode* SetESP = FindMatchingRopGadget( "CMOVB esp,ebx" );
				addJumpToRopChain( p, C, 2, "CMOVB" );
				continue;
			}
			

			//Unsigned Conditional Jumps
			//  JC        - Carry                       - CF = 1
			if ( memcmp( C, "jc", 2 ) == 0 )
			{
				//RopCode* SetESP = FindMatchingRopGadget( "CMOVC esp,ebx" );
				addJumpToRopChain( p, C, 2, "CMOVC" );
				continue;
			}

			//Unsigned Conditional Jumps
			//  JE - JZ   - Equal/zero                  - ZF = 1
			if ( memcmp( C, "je", 2 ) == 0 || memcmp( C, "jz", 2 ) == 0 )
			{
				//struct RopCode* SetESP = FindMatchingRopGadget( "cmove esp,ebx" );
				addJumpToRopChain( p, C, 2, "cmove" );
				continue;
				
			}
			
			//Unsigned Conditional Jumps
			//  JNE - JNZ - Not equal/not zero          - ZF = 0
			if ( memcmp( C, "jne", 3 ) == 0 )
			{
				//struct RopCode* SetESP = FindMatchingRopGadget( "cmovne esp,ebx" );
				addJumpToRopChain( p, C, 3, "cmovne" );
				continue;
				
			}
			if ( memcmp( C, "jnz", 3 ) == 0 )
			{
				//struct RopCode* SetESP = FindMatchingRopGadget( "cmovne esp,ebx" );
				addJumpToRopChain( p, C, 3, "cmovne" );
				continue;
			}

			//Unsigned Conditional Jumps
			//  JNC       - Not carry                   - CF = 0
			if ( memcmp( C, "jnc", 3 ) == 0 )
			{
				//struct RopCode* SetESP = FindMatchingRopGadget( "CMOVNC esp,ebx" );
				addJumpToRopChain( p, C, 3, "CMOVNC" );
				continue;
			}

			//Unsigned Conditional Jumps
			//  JNP - JPO - Not parity/parity odd       - PF = 0
			if ( memcmp( C, "jnp", 3 ) == 0 || memcmp( C, "jpo", 3 ) == 0 )
			{
				//struct RopCode* SetESP = FindMatchingRopGadget( "CMOVNP esp,ebx" );
				addJumpToRopChain( p, C, 3, "CMOVNP" );
				continue;
			}

			//Unsigned Conditional Jumps
			//  JP - JPE  - Parity/parity even          - PF = 1
			if ( memcmp( C, "jpe", 3 ) == 0 )
			{
				//struct RopCode* SetESP = FindMatchingRopGadget( "CMOVP esp,ebx" );
				addJumpToRopChain( p, C, 3, "CMOVP" );
				continue;
			}
			if ( memcmp( C, "jp", 2 ) == 0 )
			{
				//struct RopCode* SetESP = FindMatchingRopGadget( "CMOVP esp,ebx" );
				addJumpToRopChain( p, C, 2, "CMOVP" );
				continue;
			}
			
			//Signed Conditional Jumps
			//  JL/JNGE -   Less/not greater or equal   - (SF xor OF) = 1
			if ( memcmp( C, "jnge", 4 ) == 0 )
			{
				//struct RopCode* SetESP = FindMatchingRopGadget( "CMOVL esp,ebx" );
				addJumpToRopChain( p, C, 4, "CMOVL" );
				continue;
			}

			//Signed Conditional Jumps
			//  JLE/JNG -   Less or equal/not greater   - ((SF xor OF) or ZF) = 1
			if ( memcmp( C, "jle", 3 ) == 0 || memcmp( C, "jng", 3 ) == 0 )
			{
				//struct RopCode* SetESP = FindMatchingRopGadget( "CMOVLE esp,ebx" );
				addJumpToRopChain( p, C, 3, "CMOVLE" );
				continue;
			}			

			//Signed Conditional Jumps
			//  JL/JNGE -   Less/not greater or equal   - (SF xor OF) = 1
			if ( memcmp( C, "jl", 2 ) == 0 )
			{
				//struct RopCode* SetESP = FindMatchingRopGadget( "CMOVL esp,ebx" );
				addJumpToRopChain( p, C, 2, "CMOVL" );
				continue;
			}
			

			//Signed Conditional Jumps
			//  JO      -   Overflow                    - OF = 1
			if ( memcmp( C, "jo", 2 ) == 0 )
			{
				//struct RopCode* SetESP = FindMatchingRopGadget( "CMOVO esp,ebx" );
				addJumpToRopChain( p, C, 2, "CMOVO" );
				continue;
			}
			//Signed Conditional Jumps
			//  JNO     -   Not overflow                - OF = 0
			if ( memcmp( C, "jno", 3 ) == 0 )
			{
				//struct RopCode* SetESP = FindMatchingRopGadget( "CMOVNO esp,ebx" );
				addJumpToRopChain( p, C, 3, "CMOVNO" );
				continue;
			}

			//Signed Conditional Jumps
			//  JS      -   Sign (negative)             - SF = 1
			if ( memcmp( C, "js", 2 ) == 0 )
			{
				//struct RopCode* SetESP = FindMatchingRopGadget( "cmovs esp,ebx" );
				addJumpToRopChain( p, C, 2, "cmovs" );
				continue;
			}
			//Signed Conditional Jumps
			//  JNS     -   Not sign (non-negative)     - SF = 0
			if ( memcmp( C, "jns", 3 ) == 0 )
			{
				//struct RopCode* SetESP = FindMatchingRopGadget( "CMOVNS esp,ebx" );
				addJumpToRopChain( p, C, 3, "CMOVNS" );
				continue;
			}
			//JUMP
			if ( memcmp( C, "jmp", 3 ) == 0 )
			{
				const DWORD_PTR JmpToAddress = DummyJumpAddress;
				//pop    esp
				struct RopCode* SetAddr = FindMatchingRopGadget( "pop esp" );

				RopChain.push_back( (DWORD_PTR)SetAddr->GetRandomAddress() );
				RopChain.push_back( JmpToAddress );
				const DWORD CodeOffset = (DWORD)(RopChain.size()) - 1;
				struct RelocationData RelocData = {};
				ZeroMemory(&RelocData, sizeof(RelocationData) );
				RelocData.JumpTargetIndex = NULL;
				RelocData.CodeOffset = CodeOffset;
				RelocData.JumpTarget = GetJumpTarget( &C[3] );
				p->CodeOffset = (DWORD_PTR)( CodeOffset - 1 );
				Relocations.push_back( RelocData );

				STACK_PADDING;
				continue;
			}
		}
		printf("ERROR: UNKNOWN INSTRUCTION at LINE:%u [%s]{%s}!\n", (UINT)p->CodeLineIndex + 1, p->CodeLine, p->CodeLineForDebugging );
		system("pause");
	}

	printf("[+] ROP-Chain compiled!\n");
}

void HijackThreadStack	( /*IN*/ const HANDLE hGame, /*OUT*/ HANDLE* OutThreadHandle, /*OUT*/ DWORD_PTR* StackTable, /*OUT*/ DWORD_PTR* StackTableStart, /*OUT OPTIONAL*/ DWORD* outStackTableSize )
{
	__ASSERT__( hGame != INVALID_HANDLE_VALUE && hGame != NULL );
	__ASSERT__( OutThreadHandle != NULL );
	__ASSERT__( StackTable != NULL );
	__ASSERT__( StackTableStart != NULL );

	if ( g_CompilerSettings.HijackThreadStack != true || OutThreadHandle == NULL )
	{
		printf("ERROR: don't call the function HijackThreadStack!!!\n");
		system("pause");
		return CreateRopStack( hGame, OutThreadHandle, StackTable, StackTableStart, outStackTableSize );
	}

	//printf("[+] preparing thread hijacking\n");

	/////////////////////////////////////// WINDOWS STRUCTS ///////////////////////////////////////
	//https://processhacker.sourceforge.io/doc/ntpebteb_8h_source.html#l00166
	struct TEB
	{
		NT_TIB NtTib; //=> winnt.h
		PVOID EnvironmentPointer;
		HANDLE ClientId[2];
		PVOID ActiveRpcHandle;
		PVOID ThreadLocalStoragePointer;
		struct PEB* ProcessEnvironmentBlock;
		//...
	};

	//https://processhacker.sourceforge.io/doc/ntpsapi_8h_source.html#l00700
	typedef struct _THREAD_BASIC_INFORMATION
	{
		NTSTATUS ExitStatus;
		TEB* TebBaseAddress;
		HANDLE ClientId[2];
		ULONG_PTR AffinityMask;
		LONG Priority;
		LONG BasePriority;
	} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;
	///////////////////////////////////////////////////////////////////////////////////////////////
	static
	NTSTATUS (__stdcall* fncNtQueryInformationThread)(
	  IN HANDLE			ThreadHandle,
	  IN UINT			ThreadInformationClass,
	  OUT PVOID			ThreadInformation,
	  IN ULONG			ThreadInformationLength,
	  OUT PULONG		ReturnLength
	) = NULL;

	if ( fncNtQueryInformationThread == NULL )
	{
		HMODULE hNtDll = GetModuleHandleW( L"ntdll.dll" );
		if ( hNtDll == NULL )
			 hNtDll = LoadLibraryW( L"ntdll.dll" );

		void* Function = GetProcAddress( hNtDll, "NtQueryInformationThread" );
		if ( Function == NULL )
			 Function = GetProcAddress( hNtDll, "ZwQueryInformationThread" );

		 fncNtQueryInformationThread = (decltype(fncNtQueryInformationThread))Function;
	}

	DWORD ThreadResultAddress = NULL;
	DWORD ThreadResultValue = NULL;

	//////////////////////////////////// Setup Thread shellcode ///////////////////////////////////
	BYTE* RemoteShellCodeBuffer = (BYTE*)VirtualAllocEx( hGame, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
	if ( RemoteShellCodeBuffer == NULL )
	{
		printf("[%s] ERROR FAILED TO ALLOCATE THREAD STARTUP CODE [0x%X]\n", __FUNCTION__,GetLastError() );
		system("pause");
	}

	BYTE* LocalShellCodeBuffer = (BYTE*)malloc( 0x1000 );
	__ASSERT__( LocalShellCodeBuffer != NULL );

	g_RandomGenerator.GetBuffer( LocalShellCodeBuffer, 0x1000 );

	BYTE ByteCode[] = { 0xC7, 0x05, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, //mov DWORD PTR[0x8],1
						0xEB, 0xFE, //jmp to itself, endless loop
					  };
	

	DWORD RandomStartOffset = g_RandomGenerator.GetDword() % ( 0x1000ui32 - 0x20ui32 );

	if ( RandomStartOffset < 0x20 )
		 RandomStartOffset += 0x20;

	ThreadResultAddress = (DWORD)( (DWORD_PTR)RemoteShellCodeBuffer + (DWORD_PTR)RandomStartOffset - (DWORD_PTR)0x10ui32 );
	ThreadResultValue = g_RandomGenerator.GetDword();

	*(DWORD*)&ByteCode[ 2 ] = ThreadResultAddress;
	*(DWORD*)&ByteCode[ 6 ] = ThreadResultValue;
	memcpy( (void*)( LocalShellCodeBuffer + RandomStartOffset ), ByteCode, ARRAYSIZE(ByteCode) );

	const BOOL bWriteThreadStartCode = 
	WriteProcessMemory( hGame, RemoteShellCodeBuffer, LocalShellCodeBuffer, 0x1000, NULL );
	if ( bWriteThreadStartCode != TRUE )
	{
		printf("[%s] ERROR WRITING THREAD STARTUP CODE [0x%X]\n",__FUNCTION__,GetLastError());
		system("pause");
	}

	free( LocalShellCodeBuffer ); LocalShellCodeBuffer = NULL;
	///////////////////////////////////////////////////////////////////////////////////////////////

	printf("[+] Creating Rop-Chain Thread\n");

	
	const DWORD RopChainSize = (DWORD)( (DWORD)(RopChain.size()) * sizeof(DWORD_PTR) );
	
	const DWORD StackTableStartOffset = (DWORD)((g_RandomGenerator.GetDword() % (0x6001ui32)) & (DWORD)0xFFFFFFFCui32) + (DWORD)0x4000ui32;

	const DWORD RandomSize = RopChainSize + StackTableStartOffset + (DWORD)0x1000ui32 + (DWORD)(g_RandomGenerator.GetDword() % (DWORD)(0x8001ui32) );
	DWORD RandomStackSize = (RandomSize / (DWORD)0x1000ui32) * (DWORD)0x1000ui32;
	if ( (DWORD)( RandomStackSize % (DWORD)0x1000ui32 ) != NULL )
		RandomStackSize += (DWORD)0x1000ui32;
	
	DWORD ThreadId = 0;
	HANDLE hThreadHandle = CreateRemoteThread( hGame, NULL, RandomStackSize, (LPTHREAD_START_ROUTINE)( RemoteShellCodeBuffer + RandomStartOffset ), (LPVOID)StackTableStart, NULL, &ThreadId );
	if ( hThreadHandle == NULL || hThreadHandle == INVALID_HANDLE_VALUE || ThreadId == 0 )
	{
		printf("ERROR in [%s] CreateRemoteThread: Error:[0x%X] Handle:0x%p ThreadId:0x%X\n", __FUNCTION__, GetLastError(), hThreadHandle, ThreadId );
		ThreadId = 0;
		hThreadHandle = INVALID_HANDLE_VALUE;
		system("pause");
	}
	else
		printf("[+]=> Thread %u started\n",ThreadId);
	
	///////////////////////////// WAIT FOR THREAD TO REACH SHELLCODE //////////////////////////////
	DWORD Value = 0;
	do
	{
		Value = 0;
		Sleep( 1000 );
		ZeroMemory( (void*)&Value, sizeof(DWORD) );
		ReadProcessMemory( hGame, (LPCVOID)ThreadResultAddress, &Value, sizeof(DWORD), NULL );

	} while ( Value != ThreadResultValue );
	///////////////////////////////////////////////////////////////////////////////////////////////
	const
	DWORD ThreadSuspendCount = SuspendThread( hThreadHandle );
	if ( ThreadSuspendCount == (DWORD)0xFFFFFFFFui32 )
	{
		printf("[%s] ERROR SuspendThread failed: 0x%X\n", __FUNCTION__, GetLastError());
		system("pause");
	}
	VirtualFreeEx( hGame, RemoteShellCodeBuffer, NULL, MEM_RELEASE );

	//////////////////////////////// GET THREAD STACK INFORMATION /////////////////////////////////
	THREAD_BASIC_INFORMATION ThreadBasicInfo = {};
	ZeroMemory( &ThreadBasicInfo, sizeof(THREAD_BASIC_INFORMATION) );

	ULONG StructSize = 0;
	const NTSTATUS NtStatus =
	fncNtQueryInformationThread( hThreadHandle,
								0,//=> ThreadInformationBasic
								&ThreadBasicInfo,
								sizeof(THREAD_BASIC_INFORMATION),
								&StructSize );
	if ( NtStatus != (NTSTATUS)(0x00000000l) || StructSize != sizeof(THREAD_BASIC_INFORMATION) )
	{
		printf("[%s] NtQueryInformationThread failed with 0x%X\n", __FUNCTION__ ,NtStatus);
		system("pause");
	}

	void* ThreadEnvironmentBlockAddress = ThreadBasicInfo.TebBaseAddress;
	if ( ThreadEnvironmentBlockAddress == NULL )
	{
		printf("[%s] Failed to retrieve ThreadEnvironmentBlock address!\n", __FUNCTION__);
		system("pause");
	}

	TEB ThreadEnvironmentBlock = {};
	ZeroMemory( &ThreadEnvironmentBlock, sizeof(TEB) );

	const BOOL bTebRead =
	ReadProcessMemory( hGame, (LPCVOID)ThreadEnvironmentBlockAddress, &ThreadEnvironmentBlock, sizeof(TEB), NULL );
	if ( bTebRead != TRUE )
	{
		printf("[%s] FAILED TO READ THREAD TEB [0x%X]\n", __FUNCTION__, GetLastError() );
		system("pause");
	}
	///////////////////////////////////////////////////////////////////////////////////////////////

	const NT_TIB* ThreadInformationBlock = &ThreadEnvironmentBlock.NtTib;

	const DWORD_PTR StackBufferEnd   = (DWORD_PTR)ThreadInformationBlock->StackBase;
	const DWORD_PTR StackBufferStart = (DWORD_PTR)ThreadInformationBlock->StackLimit;
	if ( StackBufferEnd == NULL || StackBufferStart == NULL )
	{
		printf("[%s] FAILED TO ACCESS THREAD STACK INFORMATION\n", __FUNCTION__);
		system("pause");
	}

	const DWORD_PTR ThreadStackSize = StackBufferEnd - StackBufferStart - (DWORD_PTR)(0x1000);


	printf("[+]=> Thread Stack Address:[0x%p] Size:[0x%X]\n", (PVOID)StackBufferStart, ThreadStackSize );
	
	DWORD_PTR* LocalStackTable = (DWORD_PTR*)malloc( ThreadStackSize + (DWORD_PTR)0x1000 );
	__ASSERT__( LocalStackTable != NULL );

	DWORD_PTR* WriteToTablePtr = (DWORD_PTR*)( (DWORD_PTR)LocalStackTable + StackTableStartOffset );
	g_RandomGenerator.GetBuffer( LocalStackTable, (DWORD)ThreadStackSize );

	
	///////////////////////////////////////// Relocation //////////////////////////////////////////

	RelocatingJumps( (DWORD_PTR)StackBufferStart + (DWORD_PTR)StackTableStartOffset );

	///////////////////////////////////////////////////////////////////////////////////////////////


	DWORD_PTR StackTablePos = NULL;
	for (size_t j = NULL; j < (size_t)RopChain.size(); j++)
		WriteToTablePtr[ StackTablePos++ ] = (DWORD_PTR)RopChain.at(j);

	printf("[+] Compiled to RemoteStackTable: [0x%p] Size: [0x%X]\n", (PVOID)StackBufferStart, (DWORD)( (DWORD_PTR)StackTablePos * (DWORD_PTR)sizeof(DWORD_PTR) ) );
	BOOL bWriteDataToStack = FALSE;
	SIZE_T NumberOfBytesWritten = (SIZE_T)NULL;
	DWORD_PTR w = (DWORD_PTR)NULL;
	for ( ; w < ThreadStackSize; w += (DWORD_PTR)(0x1000) )
	{
		LPVOID RemotePageAddress = (LPVOID)( (DWORD_PTR)StackBufferStart + (DWORD_PTR)w );
		LPVOID LocalPageAddress  = (LPVOID)( (DWORD_PTR)LocalStackTable  + (DWORD_PTR)w );

		//Impossible but visual studio complains xD
		if ( RemotePageAddress == NULL || LocalPageAddress == NULL )
		{
			bWriteDataToStack = FALSE;
			break;
		}

		bWriteDataToStack = 
		WriteProcessMemory( hGame, RemotePageAddress, LocalPageAddress, 0x1000, &NumberOfBytesWritten );
		if ( bWriteDataToStack != TRUE || NumberOfBytesWritten != 0x1000 ) break;
	}
	

	if ( bWriteDataToStack != TRUE )
	{
		printf("[%s] FAILED TO WRITE THREAD STACK [0x%X] offset:[0x%X] written:[0x%X]\n",__FUNCTION__,GetLastError(),w,NumberOfBytesWritten);
		system("pause");
	}
	
	//////////////////////////////////// SETUP THREAD CONTEXT /////////////////////////////////////
	CONTEXT ThreadContext = {};
	ZeroMemory( &ThreadContext, sizeof(CONTEXT) );

	ThreadContext.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;

	const BOOL bGetThreadContext = 
	GetThreadContext( hThreadHandle, &ThreadContext );
	if ( bGetThreadContext != TRUE )
	{
		printf("[%s] FAILED TO ACCESS THREAD CONTEXT [0x%X]\n", __FUNCTION__, GetLastError() );
		system("pause");
	}

	ThreadContext.Eax = (StackBufferStart + StackTableStartOffset) - ((DWORD_PTR)0x2A00 + (DWORD_PTR)( ( g_RandomGenerator.GetDword() % 0x400ui32 ) & 0xFFFFFFFC ));
	ThreadContext.Esp = StackBufferStart + (DWORD_PTR)StackTableStartOffset + (DWORD_PTR)sizeof(DWORD_PTR);
	ThreadContext.Eip = WriteToTablePtr[0];

	if ( ThreadContext.Eip == NULL )
	{
		printf("[%s] FIRST TREAD GADGET IS NULL-POINTER\n", __FUNCTION__ );
		system("pause");
	}

	const BOOL bSetThreadContext = 
	SetThreadContext( hThreadHandle, &ThreadContext );

	if ( bSetThreadContext != TRUE )
	{
		printf("[%s] FAILED TO SET THREAD CONTEXT [0x%X]\n", __FUNCTION__,GetLastError());
		system("pause");
	}
	ZeroMemory( &ThreadContext, sizeof(CONTEXT) );
	///////////////////////////////////////////////////////////////////////////////////////////////


	*(DWORD_PTR*)StackTable = (DWORD_PTR)StackBufferStart;
	*(DWORD_PTR*)StackTableStart = (DWORD_PTR)StackBufferStart + (DWORD_PTR)StackTableStartOffset;
	if ( outStackTableSize != NULL )
		 *(DWORD*)outStackTableSize = (DWORD)ThreadStackSize;
	*OutThreadHandle = hThreadHandle;

	free( LocalStackTable ); LocalStackTable = NULL;
}

void CreateRopStack		( /*IN*/ const HANDLE hGame, /*OUT*/ HANDLE* OutThreadHandle, /*OUT*/ DWORD_PTR* StackTable, /*OUT*/ DWORD_PTR* StackTableStart, /*OUT OPTIONAL*/ DWORD* outStackTableSize )
{
	__ASSERT__( hGame != INVALID_HANDLE_VALUE && hGame != NULL );
	__ASSERT__( OutThreadHandle != NULL );
	__ASSERT__( StackTable != NULL );
	__ASSERT__( StackTableStart != NULL );

	if ( g_CompilerSettings.HijackThreadStack == true || OutThreadHandle != NULL )
	{
		//don't create our own stack, use the stack of the thread:
		return HijackThreadStack( hGame, OutThreadHandle, StackTable, StackTableStart, outStackTableSize );
	}

	const DWORD StackTableStartOffset = (g_RandomGenerator.GetDword() % (0x3001ui32)) & 0xFFFFFFFC;
	const DWORD RopChainSize = (DWORD)( (DWORD)(RopChain.size()) * sizeof(DWORD_PTR) );

	//Creating our own stack, but it might be a potential detection vector!
	const DWORD RandomSize = RopChainSize + (DWORD)0x1200ui32 + (g_RandomGenerator.GetDword() % (0x6001ui32)) + StackTableStartOffset;
	DWORD StackTableSize = (RandomSize / (DWORD)0x1000ui32) * (DWORD)0x1000ui32;
	if ( (DWORD)( StackTableSize % (DWORD)0x1000ui32 ) != NULL )
		StackTableSize += (DWORD)0x1000ui32;

	
	
	DWORD RandomFlags[] = { PAGE_READWRITE, PAGE_EXECUTE_READWRITE };
	const DWORD ProtectionFlags = *(DWORD*)SelectRandomElement( RandomFlags, getArraySize( RandomFlags, DWORD ), sizeof(DWORD) );
	

	const DWORD_PTR RemoteStackTable = (DWORD_PTR)VirtualAllocEx( hGame, 0, StackTableSize, MEM_COMMIT | MEM_RESERVE, ProtectionFlags );
	if ( RemoteStackTable == NULL )
	{
		printf("[%s] ERROR FAILED TO ALLOCATE REMOTE STACK TABLE [0x%X]\n", __FUNCTION__, GetLastError() );
		system("pause");
	}

	DWORD_PTR* LocalStackTable = (DWORD_PTR*)malloc( StackTableSize );
	__ASSERT__( LocalStackTable != NULL );

	DWORD_PTR* WriteToTablePtr = (DWORD_PTR*)( (DWORD_PTR)LocalStackTable + (DWORD_PTR)StackTableStartOffset );
	__ASSERT__( WriteToTablePtr != NULL );

	g_RandomGenerator.GetBuffer( LocalStackTable, StackTableSize );

	///////////////////////////////// Relocation /////////////////////////////////

	RelocatingJumps( (DWORD_PTR)RemoteStackTable + (DWORD_PTR)StackTableStartOffset );

	//////////////////////////////////////////////////////////////////////////////

	DWORD StackTablePos = NULL;
	for (size_t j = NULL; j < (size_t)RopChain.size(); j++)
	{
		const DWORD_PTR Value = (DWORD_PTR)RopChain.at(j);
		WriteToTablePtr[ StackTablePos++ ] = Value;
	}

	printf("[+] Compiled to RemoteStackTable: [0x%p] Size: [0x%X]\n", (PVOID)RemoteStackTable, (StackTablePos*sizeof(DWORD_PTR)));
	WriteProcessMemory( hGame, (LPVOID)RemoteStackTable, LocalStackTable, StackTableSize, NULL );
	free( LocalStackTable );

	DWORD NewRandomFlags[] = {	PAGE_READONLY, 
								PAGE_READWRITE, 
								PAGE_WRITECOPY, 
								PAGE_EXECUTE, 
								PAGE_EXECUTE_READ, 
								PAGE_EXECUTE_READWRITE, 
								PAGE_EXECUTE_WRITECOPY };

	DWORD NewProtectionFlags = *(DWORD*)SelectRandomElement( NewRandomFlags, getArraySize( NewRandomFlags, DWORD ), sizeof(DWORD) );
	
	DWORD OldProtection = NULL;
	VirtualProtectEx( hGame, (LPVOID)RemoteStackTable, StackTableSize, NewProtectionFlags, &OldProtection );

	for (DWORD Counter = NULL; Counter < (DWORD)( StackTableSize / (DWORD)0x1000ui32 ); Counter++)
	{
		NewProtectionFlags = *(DWORD*)SelectRandomElement( NewRandomFlags, getArraySize( NewRandomFlags, DWORD ), sizeof(DWORD) );
		OldProtection = NULL;
		VirtualProtectEx( hGame, (BYTE*)RemoteStackTable + (DWORD)(Counter * (DWORD)0x1000ui32), (SIZE_T)0x1000, NewProtectionFlags, &OldProtection );
	}

	*(DWORD_PTR*)StackTable = (DWORD_PTR)RemoteStackTable;
	*(DWORD_PTR*)StackTableStart = (DWORD_PTR)RemoteStackTable + (DWORD_PTR)StackTableStartOffset;
	if ( outStackTableSize != NULL )
		 *(DWORD*)outStackTableSize = (DWORD)StackTableSize;
}

//Reads code to instruction cache vector
void ReadInCode( /*IN*/ const char* TextCode )
{
	__ASSERT__( TextCode != NULL );

	Instructions.clear();

	printf("[+] Reading code...\n");

	char CodeLine[128] = {};
	ZeroMemory(CodeLine, sizeof(CodeLine) );

	int CodeLineI = 0;
	int CodeLineCntr = 0;
	for (size_t i = NULL; i < (size_t)strlen(TextCode)+1; i++)
	{
		if ( CodeLineI > 127 ) CodeLineI = 127;
		CodeLine[CodeLineI] = TextCode[i];
		if ( IsCodeLineEnd( TextCode[i] ) == true || IsCodeLineComment( TextCode[i] ) == true )			
		{
			CodeLine[CodeLineI] = 0;

			InstructionCache I = {};
			ZeroMemory(&I, sizeof(InstructionCache) );
			
			CopyWithoutSpacesToLower( I.CodeLine, CodeLine, CodeLineI+1 );
			const size_t len = strlen(I.CodeLine);
			if ( len > 2 )
			{
				I.CodeLineIndex = CodeLineCntr++;
				memcpy( I.CodeLineForDebugging, CodeLine, CodeLineI+1 );
				
				I.IsFunctionStart = CodeLine[0] == '@';
				Instructions.push_back( I );
			}
			CodeLineI = 0;

			while (IsCodeLineEnd( TextCode[i] ) != true)
				i++;
		}
		else
			CodeLineI++;
	}
}

void addJumpToRopChain( /*IN OUT*/ struct InstructionCache* IC, /*IN*/ char* InstructionString, /*IN*/ BYTE StringOffset, /*IN*/ const char* Move )
{
	__ASSERT__( IC != NULL );
	__ASSERT__( InstructionString != NULL );
	__ASSERT__( Move != NULL );

	struct RelocationData RelocData = {};
	ZeroMemory(&RelocData, sizeof(RelocationData) );
	const DWORD_PTR JmpToAddress = DummyJumpAddress;
	
	//pop    ebx
	RopCode* SetAddr = FindMatchingRopGadget( "pop ebx" );
	if ( SetAddr == NULL )
	{
		printf("[!] ERROR [%s] {pop ebx} gadget not found!\n", __FUNCTION__);
		system("pause");
		DebugBreak();
	}
	else
	//>>
		{RopChain.push_back( (DWORD_PTR)SetAddr->GetRandomAddress() ); SetAddr->RefCntr += 1;}

	const DWORD CodeOffset = (DWORD)RopChain.size();

	//>>
		RopChain.push_back( JmpToAddress );

	IC->CodeOffset = CodeOffset;
	RelocData.CodeOffset = CodeOffset;
	RelocData.JumpTargetIndex = NULL;

	struct InstructionCache* JumpTarget = GetJumpTarget( &InstructionString[StringOffset] );
	if ( JumpTarget == NULL )
	{
		printf("ERROR: Jump target [%s] not found!\n",&InstructionString[StringOffset]);
		system("pause");
	}
	
	RelocData.JumpTarget = JumpTarget;
	Relocations.push_back( RelocData );
	
	RopCode* Exchange_EAX_EBX = FindMatchingRopGadget( "xchg eax, ebx" );
	RopCode* Exchange_EAX_ECX = FindMatchingRopGadget( "xchg eax, ecx" );
	RopCode* Exchange_EAX_EBP = FindMatchingRopGadget( "xchg eax, ebp" );
	RopCode* Exchange_EBP_ESP = FindMatchingRopGadget( "xchg ebp, esp" );
/*
//xchg ecx, ebx <= not found so do below

xchg eax, ebx
xchg eax, ecx
xchg eax, ebx
*/

	__ASSERT__( Exchange_EAX_EBX != NULL );
	__ASSERT__( Exchange_EAX_ECX != NULL );
	__ASSERT__( Exchange_EAX_EBP != NULL );
	__ASSERT__( Exchange_EBP_ESP != NULL );

	STACK_PADDING;

	//xchg eax, ebx
	RopChain.push_back( (DWORD_PTR)Exchange_EAX_EBX->GetRandomAddress() ); Exchange_EAX_EBX->RefCntr += 1; STACK_PADDING;
	//xchg eax, ecx
	RopChain.push_back( (DWORD_PTR)Exchange_EAX_ECX->GetRandomAddress() ); Exchange_EAX_ECX->RefCntr += 1; STACK_PADDING;
	//xchg eax, ebx
	RopChain.push_back( (DWORD_PTR)Exchange_EAX_EBX->GetRandomAddress() ); Exchange_EAX_EBX->RefCntr += 1; STACK_PADDING;
	//xchg eax, ebp
	RopChain.push_back( (DWORD_PTR)Exchange_EAX_EBP->GetRandomAddress() ); Exchange_EAX_EBP->RefCntr += 1; STACK_PADDING;
	

	//pop    eax
	RopCode* SetAltJmpAddr = FindMatchingRopGadget( "pop eax" );
	__ASSERT__( SetAltJmpAddr != NULL );

	RopChain.push_back( (DWORD_PTR)SetAltJmpAddr->GetRandomAddress() ); SetAltJmpAddr->RefCntr += 1;

	ZeroMemory(&RelocData, sizeof(RelocationData) );

	RelocData.CodeOffset = (DWORD_PTR)RopChain.size();
	//>>
	RopChain.push_back( JmpToAddress );
	RelocData.JumpTarget = NULL;

	char MoveCode[64] = {};
	sprintf_s( MoveCode, "%s eax,ecx",Move);

	RopCode* ConditionalMove = FindMatchingRopGadget( MoveCode );
	if ( ConditionalMove == NULL )
	{
		printf("ERROR: jump instruction [%s] not found!\n",MoveCode);
		system("pause");
		DebugBreak();
	}
	else
		{RopChain.push_back( (DWORD_PTR)ConditionalMove->GetRandomAddress() ); ConditionalMove->RefCntr += 1;}
	STACK_PADDING;

	//xchg eax, ebx
	RopChain.push_back( (DWORD_PTR)Exchange_EAX_EBX->GetRandomAddress() ); Exchange_EAX_EBX->RefCntr += 1; STACK_PADDING;
	//xchg eax, ecx
	RopChain.push_back( (DWORD_PTR)Exchange_EAX_ECX->GetRandomAddress() ); Exchange_EAX_ECX->RefCntr += 1; STACK_PADDING;
	//xchg eax, ebx
	RopChain.push_back( (DWORD_PTR)Exchange_EAX_EBX->GetRandomAddress() ); Exchange_EAX_EBX->RefCntr += 1; STACK_PADDING;


	//xchg eax, ebp
	RopChain.push_back( (DWORD_PTR)Exchange_EAX_EBP->GetRandomAddress() ); Exchange_EAX_EBP->RefCntr += 1; STACK_PADDING;


	//JUMP!!!
	RopChain.push_back( (DWORD_PTR)Exchange_EBP_ESP->GetRandomAddress() ); Exchange_EBP_ESP->RefCntr += 1;STACK_PADDING;

	RelocData.JumpTargetIndex = (DWORD_PTR)RopChain.size();

	Relocations.push_back( RelocData );
	
}

bool mov_ecx__eax( /*IN OUT*/ struct InstructionCache* IC )
{
	__ASSERT__( IC != NULL );

	const char Instruction[] = "movecx,eax";
	if ( memcmp( Instruction, IC->CodeLine, strlen(Instruction) ) != 0 )
		return false;

	RopCode* ExchangeInstruction = FindMatchingRopGadget( "xchg eax, ecx" );
	if ( ExchangeInstruction == NULL )
		return false;

	RopCode* MoveInstruction = FindMatchingRopGadget( "mov eax, ecx" );
	if ( MoveInstruction == NULL )
		return false;

	IC->CodeOffset = (DWORD_PTR)RopChain.size();
	RopChain.push_back( (DWORD_PTR)ExchangeInstruction->GetRandomAddress() );ExchangeInstruction->RefCntr+=1; 
	STACK_PADDING;
	RopChain.push_back( (DWORD_PTR)MoveInstruction->GetRandomAddress() );MoveInstruction->RefCntr+=1;
	STACK_PADDING;
	RopChain.push_back( (DWORD_PTR)ExchangeInstruction->GetRandomAddress() );ExchangeInstruction->RefCntr+=1;
	STACK_PADDING;
	return true;
}

bool mov_ebx__ecx( /*IN OUT*/ struct InstructionCache* IC )
{
	__ASSERT__( IC != NULL );

	const char Instruction[] = "movebx,ecx";
	if ( memcmp( Instruction, IC->CodeLine, strlen(Instruction) ) != 0 )
		return false;

	RopCode* ExchangeInstruction = FindMatchingRopGadget( "xchg eax, ebx" );
	if ( ExchangeInstruction == NULL )
		return false;

	RopCode* MoveInstruction = FindMatchingRopGadget( "mov eax, ecx" );
	if ( MoveInstruction == NULL )
		return false;

	IC->CodeOffset = (DWORD_PTR)RopChain.size();
	RopChain.push_back( (DWORD_PTR)ExchangeInstruction->GetRandomAddress() );ExchangeInstruction->RefCntr+=1;
	STACK_PADDING;
	RopChain.push_back( (DWORD_PTR)MoveInstruction->GetRandomAddress() );MoveInstruction->RefCntr+=1;
	STACK_PADDING;
	RopChain.push_back( (DWORD_PTR)ExchangeInstruction->GetRandomAddress() );ExchangeInstruction->RefCntr+=1;
	STACK_PADDING;
	return true;
}

bool mov_ebx__eax( /*IN OUT*/ struct InstructionCache* IC )
{
	__ASSERT__( IC != NULL );

	const char Instruction[] = "movebx,eax";
	if ( memcmp( Instruction, IC->CodeLine, strlen(Instruction) ) != 0 )
		return false;

	RopCode* ExchangeInstruction = FindMatchingRopGadget( "xchg eax, ebx" );
	if ( ExchangeInstruction == NULL )
		return false;

	RopCode* MoveInstruction = FindMatchingRopGadget( "mov eax, ebx" );
	if ( MoveInstruction == NULL )
		return false;

	IC->CodeOffset = (DWORD_PTR)RopChain.size();
	RopChain.push_back( (DWORD_PTR)ExchangeInstruction->GetRandomAddress() );ExchangeInstruction->RefCntr+=1;
	STACK_PADDING;
	RopChain.push_back( (DWORD_PTR)MoveInstruction->GetRandomAddress() );MoveInstruction->RefCntr+=1;
	STACK_PADDING;
	RopChain.push_back( (DWORD_PTR)ExchangeInstruction->GetRandomAddress() );ExchangeInstruction->RefCntr+=1;
	STACK_PADDING;
	return true;
}

bool mov_edx__eax( /*IN OUT*/ struct InstructionCache* IC )
{
	__ASSERT__( IC != NULL );

	const char Instruction[] = "movedx,eax";
	if ( memcmp( Instruction, IC->CodeLine, strlen(Instruction) ) != 0 )
		return false;

	RopCode* ExchangeInstruction = FindMatchingRopGadget( "xchg eax, edx" );
	if ( ExchangeInstruction == NULL )
		return false;

	RopCode* MoveInstruction = FindMatchingRopGadget( "mov eax, edx" );
	if ( MoveInstruction == NULL )
		return false;

	IC->CodeOffset = (DWORD_PTR)RopChain.size();
	RopChain.push_back( (DWORD_PTR)ExchangeInstruction->GetRandomAddress() );ExchangeInstruction->RefCntr+=1;
	STACK_PADDING;
	RopChain.push_back( (DWORD_PTR)MoveInstruction->GetRandomAddress() );MoveInstruction->RefCntr+=1;
	STACK_PADDING;
	RopChain.push_back( (DWORD_PTR)ExchangeInstruction->GetRandomAddress() );ExchangeInstruction->RefCntr+=1;
	STACK_PADDING;
	return true;
}

bool mov_ptr_eax__ebx( /*IN OUT*/ struct InstructionCache* IC )
{
	__ASSERT__( IC != NULL );

	const char Instruction[] = "movdwordptr[eax],ebx";
	if ( memcmp( Instruction, IC->CodeLine, strlen(Instruction) ) != 0 )
		return false;

	RopCode* ExchangeInstruction = FindMatchingRopGadget( "xchg eax, ebx" );
	if ( ExchangeInstruction == NULL )
		return false;

	RopCode* MoveInstruction = FindMatchingRopGadget( "mov DWORD PTR[ebx], eax" );
	if ( MoveInstruction == NULL )
		return false;

	IC->CodeOffset = (DWORD_PTR)RopChain.size();
	RopChain.push_back( (DWORD_PTR)ExchangeInstruction->GetRandomAddress() );ExchangeInstruction->RefCntr+=1;
	STACK_PADDING;
	RopChain.push_back( (DWORD_PTR)MoveInstruction->GetRandomAddress() );MoveInstruction->RefCntr+=1;
	STACK_PADDING;
	RopChain.push_back( (DWORD_PTR)ExchangeInstruction->GetRandomAddress() );ExchangeInstruction->RefCntr+=1;
	STACK_PADDING;
	return true;
}

bool mov_byte_ptr__eax__ebx( /*IN OUT*/ struct InstructionCache* IC )
{
	__ASSERT__( IC != NULL );

	const char Instruction1[] = "movbyteptr[eax],ebx";
	const char Instruction2[] = "movbyteptr[eax],bl";
	if ( memcmp( Instruction1, IC->CodeLine, strlen(Instruction1) ) != 0 && memcmp( Instruction2, IC->CodeLine, strlen(Instruction2) ) != 0 )
		return false;

	RopCode* ExchangeInstruction = FindMatchingRopGadget( "xchg eax, ebx" );
	if ( ExchangeInstruction == NULL )
		return false;

	RopCode* MoveInstruction = FindMatchingRopGadget( "mov BYTE PTR[ebx], al" );
	if ( MoveInstruction == NULL )
		return false;

	IC->CodeOffset = (DWORD_PTR)RopChain.size();
	RopChain.push_back( (DWORD_PTR)ExchangeInstruction->GetRandomAddress() );ExchangeInstruction->RefCntr+=1;
	STACK_PADDING;
	RopChain.push_back( (DWORD_PTR)MoveInstruction->GetRandomAddress() );MoveInstruction->RefCntr+=1;
	STACK_PADDING;
	RopChain.push_back( (DWORD_PTR)ExchangeInstruction->GetRandomAddress() );ExchangeInstruction->RefCntr+=1;
	STACK_PADDING;
	return true;
}

struct InstructionCache* GetJumpTarget( /*IN*/ const char* labelName )
{
	__ASSERT__( labelName != NULL );

	for (size_t i = 0; i < (size_t)Instructions.size(); i++)
	{
		struct InstructionCache* p = &Instructions.at(i);
		if ( p->IsFunctionStart != true ) continue;

		const char* C = &p->CodeLine[1];
		if ( C[-1] != '@' ) continue;

		for (int j = 0; ; j++)
		{
			if ( C[j] != labelName[j] )
			{
				break;
			}
			if ( C[j+1] == ':' && labelName[j+1] == NULL )
				return p;
		}
	}
	return nullptr;
}

struct RopCode* FindMatchingRopGadget( /*IN*/ const char* C, /*IN OPTIONAL*/ bool DontError )
{
	__ASSERT__( C != NULL );

	char GadgetInstruction[64] = {};
	char Buffer[64] = {};
	ZeroMemory(GadgetInstruction, sizeof(GadgetInstruction) );
	ZeroMemory(Buffer, sizeof(Buffer) );

	CopyWithoutSpacesToLower( Buffer, C, strlen(C) + 1 );

	for (UINT i = 0; i < (UINT)(RopGadgets.size()); i++)
	{
		struct RopCode* p = RopGadgets.at(i);	
		CopyWithoutSpacesToLower( GadgetInstruction, p->Instruction, strlen(p->Instruction) + 1 );

		if ( strcmp( Buffer, GadgetInstruction ) == 0 )
			return p;

	}
	if (DontError != true)
	{
		printf("ROP GADGET: [%s] NOT FOUND!!\n",C);
		system("pause");
	}
	return nullptr;
}

struct RopCode* FindMatchingRopGadgetByOpCode( /*IN*/ const char* C, /*IN*/ BYTE* Code, /*IN*/ BYTE CodeSize )
{
	UNREFERENCED_PARAMETER( C );
	__ASSERT__( Code != NULL );

	for (UINT i = NULL; i < (UINT)(RopGadgets.size()); i++)
	{
		struct RopCode* p = RopGadgets.at(i);	
		if ( CodeSize == p->CodeLen && memcmp( p->Code, Code, CodeSize ) == 0 )
			return p;
	}
	return nullptr;
}

void RelocatingJumps(  /*IN*/ const DWORD_PTR RemoteStackTableStartPosition )
{
	__ASSERT__( RemoteStackTableStartPosition != NULL );

	const size_t JumpCount = (size_t)Relocations.size();
	printf("[+] Relocating %u Jumps\n",JumpCount);

	for (size_t i = NULL; i < JumpCount; i++)
	{
		struct RelocationData* RelocData = &Relocations.at(i);
		struct InstructionCache* JumpToInstruction = RelocData->JumpTarget;
		const DWORD_PTR JumpTargetIndex = RelocData->JumpTargetIndex;

		DWORD_PTR JumpToPosition = NULL; 

		if ( JumpTargetIndex != NULL )
			JumpToPosition = (DWORD_PTR)(JumpTargetIndex) * sizeof(DWORD_PTR);
		else
		if ( JumpToInstruction == NULL )
		{
			printf("[!] ERROR WHILE RELOCATING AT [0x%X], NO JUMP TARGET FOUND!\n",i);
			continue;
		}
		else
			JumpToPosition = (DWORD_PTR)(JumpToInstruction->CodeOffset) * sizeof(DWORD_PTR);

		JumpToPosition += (DWORD_PTR)RemoteStackTableStartPosition;

		const DWORD_PTR JumpAddressIndex = (DWORD_PTR)(RelocData->CodeOffset);
		RopChain.at( JumpAddressIndex ) = JumpToPosition;
	}
	Relocations.clear();
}

void InsertObfuscationPadding( /*IN OPTIONAL*/ const struct InstructionCache* NextInstruction )
{
	const DWORD_PTR JmpToAddress = DummyJumpAddress;

	const DWORD RandomPaddingSize = (DWORD)g_RandomGenerator.GetDword() % (DWORD)( g_CompilerSettings.g_constMaxObfuscationPaddingEntrys + 1 );
	if ( RandomPaddingSize < (DWORD)(1) ) return;

	struct RopCode* SetAddr = FindMatchingRopGadget( "pop esp" );
	if ( SetAddr == NULL )
	{
		printf("[!] ERROR [%s] {pop esp} gadget not found!\n", __FUNCTION__);
		system("pause");
		DebugBreak();
	}
	else
	{RopChain.push_back( (DWORD_PTR)SetAddr->GetRandomAddress() ); SetAddr->RefCntr+=1;}
	RopChain.push_back( JmpToAddress );
	
	const DWORD CodeOffset = (DWORD)RopChain.size() - 1;

	for (DWORD I = NULL; I < RandomPaddingSize; I++)
	{
		const DWORD_PTR RandomValue = (DWORD_PTR)g_RandomGenerator.GetDword();
		RopChain.push_back( RandomValue );
	}

	struct RelocationData RelocData = {};
	ZeroMemory(&RelocData, sizeof(RelocationData) );

	RelocData.CodeOffset = (DWORD_PTR)CodeOffset;
	RelocData.JumpTarget = (struct InstructionCache*)NextInstruction;
	RelocData.JumpTargetIndex = (DWORD_PTR)RopChain.size();
	Relocations.push_back( RelocData );
}

bool IsCodeLineComment( /*IN*/ const char c)
{
	if (
	 c == (const char)';' ||
	 c == (const char)'/' ||
	 c == (const char)'\\')
	 return true;
	
	return false;
}

bool IsCodeLineEnd( /*IN*/ const char c)
{
	if (
	 c == (const char)'\r' ||
	 c == (const char)'\n' ||
	 c == (const char)0)
	 return true;
	
	return false;
}

void CopyWithoutSpacesToLower( /*OUT*/ char* out, /*IN*/ const char* in, /*IN*/ const size_t len )
{
	__ASSERT__( out != NULL );
	__ASSERT__( in != NULL );

	for (size_t i2 = NULL, i1 = NULL; i2 < (size_t)len; i2++)
	{
		out[i1] = in[i2];

		if ( out[i1] >= (const char)'A' && out[i1] <= (const char)'Z' )
			out[i1] += ' ';
		else
		if ( out[i1] == (const char)' ' || out[i1] == (const char)'\t' )
			continue;

		i1++;
	}
}

DWORD ExecuteRopChain( /*IN*/ const HANDLE hGame, /*IN*/ const DWORD_PTR StackTableStart )
{
	__ASSERT__( hGame != INVALID_HANDLE_VALUE && hGame != NULL );
	__ASSERT__( StackTableStart != NULL );

	BYTE* ShellCodeBuffer = (BYTE*)malloc( 0x1000 );
	__ASSERT__( ShellCodeBuffer != NULL );

	g_RandomGenerator.GetBuffer( ShellCodeBuffer, 0x1000 );

	printf("[+] Executing Rop-Chain\n");

	//move return address to edx, 
	//set argument 1 to esp
	//return to first return address on the new stack
	BYTE ByteCode[] = { 0xC7, 0x05, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, //mov DWORD PTR[0x8],1
						
						0x89, 0xe0, //mov    eax,esp
						0x5A,		//pop    edx
						0x5C,		//pop    esp
						0xC3,		//       ret 
					  };
	BYTE* RemoteShellCodeBuffer = (BYTE*)VirtualAllocEx( hGame, NULL, (SIZE_T)0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
	if ( RemoteShellCodeBuffer == NULL )
	{
		printf("[%s] ERROR FAILED TO ALLOCATE THREAD STARTUP CODE [0x%X]\n", __FUNCTION__, GetLastError() );
		system("pause");
	}

	*(DWORD*)&ByteCode[2] = (DWORD)RemoteShellCodeBuffer;

	DWORD RandomStartOffset = g_RandomGenerator.GetDword() % ( 0x1000 - 8 );

	if ( RandomStartOffset < 15 )
		 RandomStartOffset += 15;

	memcpy( (void*)( ShellCodeBuffer + RandomStartOffset ), ByteCode, ARRAYSIZE(ByteCode) );
	WriteProcessMemory( hGame, RemoteShellCodeBuffer, ShellCodeBuffer, 0x1000, NULL );
	free( ShellCodeBuffer );
	
	DWORD ThreadId = 0;
	HANDLE hThreadHandle = CreateRemoteThread( hGame, NULL, NULL, (LPTHREAD_START_ROUTINE)( RemoteShellCodeBuffer + RandomStartOffset ), (LPVOID)StackTableStart, NULL, &ThreadId );
	if ( hThreadHandle == NULL || hThreadHandle == INVALID_HANDLE_VALUE || ThreadId == 0 )
	{
		printf("ERROR CreateRemoteThread: Error:[0x%X] Handle:0x%p ThreadId:0x%X\n", GetLastError(), hThreadHandle, ThreadId );
		ThreadId = 0;
		hThreadHandle = INVALID_HANDLE_VALUE;
	}
	else
		printf("[+]=> Thread %u started\n",ThreadId);
	if ( hThreadHandle != INVALID_HANDLE_VALUE )
	{
		//Wait for thread to execute:
		DWORD Value = 0;
		do
		{
			Value = 0;
			ZeroMemory( &Value, sizeof(DWORD) );
			Sleep( 1000 );
			ReadProcessMemory( hGame, RemoteShellCodeBuffer, &Value, sizeof(DWORD), NULL );

		} while ( Value != 1 );
	}
	VirtualFreeEx( hGame, RemoteShellCodeBuffer, NULL, MEM_RELEASE );

	if ( hThreadHandle != INVALID_HANDLE_VALUE )
		CloseHandle( hThreadHandle );

	return ThreadId;
}

//Prints compilation debug info
void PrintDebugOutput( /*IN OPTIONAL*/ DWORD_PTR CallStackStartAddr )
{
	printf("-------------------------------- DEBUG CODE ----------------------------------\n");
	printf("=> Output format below:\n");
	if (CallStackStartAddr == NULL)
		printf("[CodeLineIndex][Callstack Offset] {Instruction}\t\t\t{Stripped down Instruction}\n");
	else
		printf("[CodeLineIndex][Callstack Addr] {Instruction}\t\t\t{Stripped down Instruction}\n");
	printf("-----------------------------------------------------------------------------\n");
	for (size_t i = 0; i < (size_t)Instructions.size(); i++)
	{
		struct InstructionCache* p = &Instructions.at(i);
		DWORD_PTR CallStackOffset = (DWORD_PTR)(p->CodeOffset * sizeof(DWORD_PTR));
		if (CallStackStartAddr != NULL)
			CallStackOffset += CallStackStartAddr;
		printf("[%004u][0x%08X] {%s}\t\t\t{%s}\n", (UINT)p->CodeLineIndex+1, CallStackOffset,p->CodeLineForDebugging,p->CodeLine);

	}
	printf("-----------------------------------------------------------------------------\n\n\n\n");
}

void RopCode::AddAddress( /*IN*/ DWORD_PTR Address )
{
	__ASSERT__( Address != NULL );

	if ( this->Addresses == NULL )
	{
		this->Addresses = (RopCode::RopAddresses*)malloc( sizeof(RopCode::RopAddresses) + 8 );
		__ASSERT__( this->Addresses != NULL );

		ZeroMemory( this->Addresses, sizeof(RopCode::RopAddresses) );
	}
	this->Addresses->Addresses.push_back( Address );
}

void* RopCode::GetRandomAddress( void )
{
	if ( this->Addresses == NULL )
		return NULL;

	const
	DWORD AddressCount = (DWORD)this->Addresses->Addresses.size();
	const
	DWORD RandomAddrIndex = g_RandomGenerator.GetDword() % AddressCount;

	return (void*)this->Addresses->Addresses.at( RandomAddrIndex );
}

void RopCode::Destructor( void )
{
	if ( this->Addresses != NULL )
	{
		this->Addresses->Addresses.clear();
		free( this->Addresses );
		this->Addresses  = NULL;
	}
}

#include <intrin.h> //function: _ReturnAddress()
#include <stdlib.h> //function: itow_s(...)
void __cdecl AssertW( const wchar_t * _Message, const wchar_t *_File, unsigned _Line)
{
	wchar_t MessageText[ 4096 ] = {};
	MessageText[    0 ] = NULL;
	MessageText[ 4095 ] = NULL;

	wchar_t ModuleFilePath[ MAX_PATH + 1 ] = {};
	ModuleFilePath[0] = NULL;
	ModuleFilePath[MAX_PATH] = NULL;

	wcscpy_s( MessageText, L"Assertion failed!\n\n" );
	wcscat_s( MessageText, L"Program: " );
	
	HMODULE hAssertModule = NULL;

	if ( GetModuleHandleExW(	GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, 
								(LPCWSTR)_ReturnAddress(), 
								&hAssertModule) )
	{
		
#if defined(_M_X64)
		if ( hAssertModule == (HMODULE)0x180000000i64 )
#else
		if ( hAssertModule == (HMODULE)0x10000000 )
#endif
			hAssertModule = NULL;
	}
	else
		hAssertModule = NULL;
	printf("hAssertModule: 0x%p\n",hAssertModule);
	if ( GetModuleFileNameW( hAssertModule, ModuleFilePath, MAX_PATH ) < 1 )
		wcscat_s( MessageText, L"<program name unknown>" );
	else
	{
		ModuleFilePath[MAX_PATH] = NULL;
		wchar_t* ModuleFileName = &ModuleFilePath[0];

		for (size_t j = 0; j < (size_t)(wcslen( ModuleFilePath ) - 1); j++)
			if ( ModuleFilePath[j] == '\\' )
				ModuleFileName = &ModuleFilePath[j+1];

		wcscat_s( MessageText, ModuleFileName );
	}

	wcscat_s( MessageText, L"\n" );

	wcscat_s( MessageText, L"File: " );
	wcscat_s( MessageText, _File );

	wcscat_s( MessageText, L"\n" );

	wcscat_s( MessageText, L"Line: " );
	{
		const size_t MessageTextLen = wcslen( MessageText );
		_itow_s( _Line, &MessageText[MessageTextLen], 1024 - MessageTextLen, 10);
	}

	wcscat_s( MessageText, L"\n\n" );

	wcscat_s( MessageText, L"Expression: " );
	wcscat_s( MessageText, _Message );

	wcscat_s( MessageText, L"\n\n" );

	const
	int SelectedButton = MessageBoxW( NULL, MessageText, L"FATAL CODE FAILURE", MB_ICONERROR | MB_ABORTRETRYIGNORE );

	switch (SelectedButton)
	{
	case IDABORT:
		{
			//raise(22);
			exit(3);
			break;
		};
	case IDRETRY:
		{
			__debugbreak();
			//DebugBreak();
			break;
		};
	case IDIGNORE:
		{
			//abort();
			break;
		}
	default:
		break;
	}

	return;
}

UINT8 GetConsoleNumber( UINT32& Number )
{
	CONST HANDLE StdOutputHandle = (HANDLE)STD_OUTPUT_HANDLE;
	CONST UINT32 N1 = (UINT32)StdOutputHandle;
	CONST UINT32 N2 = (UINT32)N1 - (UINT32)0xECC8ECBE;
	CONST UINT32 N3 = (UINT32)N2 + (UINT32)0xECC8F0EA;
	CONST UINT32 N4 = (UINT32)N2 + (UINT32)0xECC8ECD0;
	CONST UINT32 N5 = (UINT32)(N1 >> 4) & (UINT32)0xFF;
	Number = (N2 * Number) + N3;
	return (UINT8)( (Number >> N4 ) % (N5 + 1 ) );
}

void InitializeConsole( void )
{
	SetConsoleTitleA( "" );

	//Remove Quick-Edit ( enabled by default on win10 )
	HANDLE StdInputHandle = GetStdHandle( STD_INPUT_HANDLE );
	if (   StdInputHandle != (HANDLE)INVALID_HANDLE_VALUE 
		&& StdInputHandle != (HANDLE)NULL )
	{
		DWORD dwConsoleMode = (DWORD)NULL;
		if ( GetConsoleMode( StdInputHandle, &dwConsoleMode ) == TRUE )
		{	
			dwConsoleMode = (DWORD)dwConsoleMode & (DWORD)( ~(DWORD)(ENABLE_QUICK_EDIT_MODE) );
			SetConsoleMode( StdInputHandle, dwConsoleMode );
		}
	}
	
	//Prepare Console-Buffer:
	HANDLE StdOutputHandle = GetStdHandle( STD_OUTPUT_HANDLE );

	UINT32 Numbers[48] = { 
							0xB606183B, 0x07B0CB92, 0xB5DD1B2E, 0x3E0F868E, 0x23C58D31, 0xE57EB199, 0x02BC7045, 0xFCFD4BB4,
							0x51C3C368, 0x828D56DF, 0x10DA869B, 0x792CD11B, 0x3E02B8DE, 0xE0DBBC66, 0xDD395B32, 0xB76716C1,
							0xCF635178, 0xE04DC40F, 0x4EBAD4EB, 0x972CFF8B, 0x6B54C66E, 0x0D3EB746, 0xE7E2794F, 0x971A16F6,
							0xBA53FCFE, 0xA46E94A1, 0xA9B75269, 0xD2494A18, 0x575FF11B, 0xB978B5E3, 0x761614EF, 0x2DD479DB,
							0x22FAC4EF, 0xF324F7C6, 0x21D1C7E2, 0x2A83B2C2, 0x8FB939E5, 0xD1F2DDCD, 0x6EB01CF9, 0xE87177E8,
							0xBDB76F1C, 0x6E018213, 0x7CCE324F, 0x65A0FD4F, 0xAAF66492, 0xCC4FE89A, 0x492D07E6, 0x66D105C2,
						 };
	UINT8* P1 = (UINT8*)Numbers;
	UINT8* P2 = (UINT8*)Numbers;
	UINT32 Number = (UINT32)('Cons'-'ole');
	do
	{
		UINT8 Number1 = *P1;
		UINT8 Number2 = GetConsoleNumber( Number );

		*P1 = Number1 - Number2;

	} while ( *P1++ );

	//Initialize Console-Buffer:
	WriteFile( StdOutputHandle, Numbers, P1 - P2 - 1, (DWORD*)&Number, NULL );
}