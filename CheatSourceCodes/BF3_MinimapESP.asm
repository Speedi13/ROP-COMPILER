;X86-assembly in Intel syntax with additional virtual registers (VR0 - VR9 and VMM) to ease programming

;//Compiler settings:
;//<cfg=RandomPadding>true</cfg>
;//<cfg=RandomPaddingSize>128</cfg>
;//<cfg=SearchDlls>true</cfg>
;//<cfg=VirtualQuerySearch>false</cfg>
;//<cfg=PrintDebugOutput>false</cfg>

;Virtual registers
;//VR9 => random number
;//VR8 => random number
;//VR7 => random number
;//VR6 => random number
;//VR5 => random number
;//VR4 => random number
;//VR3 => random number
;//VR2 => random number
;//VR1 => random number
;//VR0 => GLOBAL_MinimumAddress
;//read only register:
;//VMM => VirtualAllocEx( hGame, 0, 0x2000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE );

;//Initial value of the general-purpose register:
;//EAX => Original StackPointer (ESP)

;//Virtual register usage in code below:
;//VR1 -> PlayerListPos
;//VR2 -> PlayerListEnd [ temporary {ClientPlayerManager+9C} ]
;//VR3 -> ClientPlayer |=> ClientSoldierEntity |=> ClientSpottingTargetComponent

;/////////////////////////////// Code Start ///////////////////////////////
@l_Start:
mov eax, 0x2380B58;//fb::ClientGameContext
mov eax, DWORD PTR[eax]

;////////////////////////////////////
;//if ( EAX < 0x10000 ) goto l_Start
mov ebx, eax
mov ecx, VR0;//0x10000
sub eax, ecx;//COMPARE EAX, ECX
xchg eax, ebx;//Restore EAX
jc l_Start
;////////////////////////////////////

mov ebx, 0x30;//fb::ClientPlayerManager
add eax, ebx 
mov eax, DWORD PTR[eax]

;////////////////////////////////////
;//if ( EAX < 0x10000 ) goto l_Start
mov ebx, eax
mov ecx, VR0;//0x10000
sub eax, ecx;//COMPARE EAX, ECX
xchg eax, ebx;//Restore EAX
jc l_Start
;////////////////////////////////////

mov ebx, 0x9C;//fb::ClientPlayerManager::m_players
add eax, ebx 
mov VR2, eax;//EAX => ClientPlayerManager+9C

mov eax, DWORD PTR[eax];//read m_players->m_firstElement

mov VR1, eax;// VR1 -> PlayerListPos

mov eax, VR2;//EAX => ClientPlayerManager+9C

add eax, 0x4
mov eax, DWORD PTR[eax];//read m_players->m_lastElement

mov VR2, eax;// VR2 -> PlayerListEnd

@Loop1_start:
mov ecx, VR1;// VR1 -> PlayerListPos
mov eax, VR2;// VR2 -> PlayerListEnd
;////////////////////////////////////
;//if ( EAX == ECX ) goto l_Start;
;//if ( PlayerListEnd == PlayerListPos ) goto l_Start;
sub eax, ecx;//COMPARE EAX, ECX
je l_Start;
js l_Start;
;////////////////////////////////////



mov eax, VR1;// VR1 -> PlayerListPos
mov eax, DWORD PTR[eax];//read ClientPlayer pointer

mov VR3, eax;// VR3 -> ClientPlayer

;////////////////////////////////////
;//if ( EAX < 0x10000 ) goto Loop1_next
mov ebx, eax;
mov ecx, VR0;//0x10000
sub eax, ecx;//COMPARE EAX, ECX
xchg eax, ebx;//Restore EAX
jc Loop1_next;
;////////////////////////////////////

mov eax, VR3;// VR3 -> ClientPlayer
mov ecx, 0x2142528;//vtable address
mov eax, DWORD PTR[eax];//read ClientPlayer::vtable

;////////////////////////////////////
;//if ( EAX == ECX ) goto Loop1_next;
sub eax, ecx;//COMPARE EAX, ECX
jne Loop1_next;
;////////////////////////////////////

mov eax, VR3;// VR3 -> ClientPlayer
mov ebx, 0x3C0;//ClientPlayer::m_soldier (WeakPtr)
add eax, ebx;
mov eax, DWORD PTR[eax];//read ClientPlayer::m_soldier

;////////////////////////////////////
;//if ( EAX < 0x10000 ) goto Loop1_next
mov ebx, eax;
mov ecx, VR0;//0x10000
sub eax, ecx;//COMPARE EAX, ECX
xchg eax, ebx;//Restore EAX
jc Loop1_next;
;////////////////////////////////////

mov eax, DWORD PTR[eax];//read pointer
mov ebx, 0xFFFFFFFC;// -4
add eax, ebx;

;////////////////////////////////////
;//if ( EAX < 0x10000 ) goto Loop1_next
mov ebx, eax;
mov ecx, VR0;//0x10000
sub eax, ecx;//COMPARE EAX, ECX
xchg eax, ebx;//Restore EAX
jc Loop1_next;
;////////////////////////////////////

mov VR3, eax;// VR3 -> fb::ClientSoldierEntity

mov eax, DWORD PTR[eax];//fb::ClientSoldierEntity::vtable
mov ecx, 0x214BD40;//vtable address

;////////////////////////////////////
;//if ( EAX == ECX ) goto Loop1_next;
sub eax, ecx;//COMPARE EAX, ECX
jne Loop1_next;
;////////////////////////////////////

mov eax, VR3;// VR3 -> fb::ClientSoldierEntity
mov ebx, 0x440;//=> ( 0x3A0 + (10 * 16) )
add eax, ebx;
mov eax, DWORD PTR[eax];//fb::ClientSpottingTargetComponent
mov VR3, eax;

;////////////////////////////////////
;//if ( EAX < 0x10000 ) goto Loop1_next
mov ebx, eax;
mov ecx, VR0;//0x10000
sub eax, ecx;//COMPARE EAX, ECX
xchg eax, ebx;//Restore EAX
jc Loop1_next;
;////////////////////////////////////

mov ebx, eax;
mov eax, DWORD PTR[eax];//fb::ClientSpottingTargetComponent::Vtable
mov ecx, 0x20B2278;//vtable address

;////////////////////////////////////
;//if ( EAX != ECX ) goto Loop1_next;
sub eax, ecx;//COMPARE EAX, ECX
jne Loop1_next;
;////////////////////////////////////

xchg eax, ebx;//Restore EAX
mov eax, VR3;// VR3 -> fb::ClientSpottingTargetComponent
mov ebx, 0x18;//=> m_spotType
add eax, ebx;
mov ebx, 0x1;//SpotType_Active

mov DWORD PTR [eax],ebx

jmp Loop1_next;

;////////////////////////////////////
@Loop1_next:
mov eax, VR1;// VR1 -> PlayerListPos
add eax, 0x4
mov VR1, eax;// VR1 -> PlayerListPos
jmp Loop1_start;
;////////////////////////////////////
nop

;//////////////////////////////// Code End ////////////////////////////////
