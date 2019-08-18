;X86-assembly in Intel syntax with additional virtual registers (VR0 - VR9 and VMM) to ease programming

;//Compiler settings:
;//<cfg=RandomPadding>true</cfg>
;//<cfg=RandomPaddingSize>128</cfg>
;//<cfg=SearchDlls>false</cfg>
;//<cfg=VirtualQuerySearch>true</cfg>
;//<cfg=PrintDebugOutput>false</cfg>

;Virtual registers
;//VR9 => OFFSET_GlowObjectManager
;//VR8 => OFFSET_LocalPlayer
;//VR7 => OFFSET_EntityList
;//VR6 => OFFSET_FORCE_ATTACK
;//VR5 => OFFSET_CrosshairId
;//VR4 => OFFSET_TeamNum
;//VR3 => OFFSET_bSpotted
;//VR2 => random number
;//VR1 => random number
;//VR0 => GLOBAL_MinimumAddress
;//read only register:
;//VMM => VirtualAllocEx( hGame, 0, 0x2000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE );

;//Initial value of the general-purpose register:
;//EAX => Original StackPointer (ESP)

;//Virtual register usage in code below:
;//VR1 -> PlayerEntity
;//VR2 -> Loop counter
;//VR6 -> Local Team Id
;//VR9 -> PlayerEntity offset

;/////////////////////////////// Code Start ///////////////////////////////

@l_Start:
mov eax, VR8;//OFFSET_LocalPlayer
mov eax, DWORD PTR[eax]

;//if ( EAX < 0x10000 ) goto l_Start
mov ebx, eax
mov ecx, VR0;//0x10000
sub eax, ecx;//COMPARE EAX, ECX
xchg eax, ebx;//Restore EAX
jc l_Start

mov ebx, VR4;//OFFSET_TeamNum 
add eax, ebx 
mov eax, DWORD PTR[eax]
mov VR6, eax;//<-- VR6 -> Local TeamId

;//if ( EAX > 64 ) goto l_Start
xchg eax, ecx
mov eax, 64
sub eax, ecx;//COMPARE EAX, ECX
js l_Start

mov eax, 64
mov VR2, eax;//LoopCounter = 64

mov eax, VR7;//VR7 => OFFSET_EntityList
mov VR9, eax;//VR9 => PlayerEntity offset


@l_Loop:
mov eax, VR9;//VR9 => PlayerEntity offset
mov eax, DWORD PTR[eax];
mov VR1, eax;//VR1 -> Entity

;//if ( EAX < 0x10000 ) goto l_skip
mov ebx, eax
mov ecx, VR0;//0x10000
sub eax, ecx;//COMPARE EAX, ECX
xchg eax, ebx;//Restore EAX
jc l_skip

jmp GetClassID
@GetClassID_Ret:

;//if ( ECX != 0x28 ) goto l_skip
mov eax, 0x28
sub eax, ecx;//COMPARE EAX, ECX
jne l_skip

mov eax, VR1;//VR1 -> Entity
mov ebx, VR4;//VR4 -> OFFSET_TeamNum
add eax, ebx 
mov eax, DWORD PTR[eax];//eax = Entity->m_iTeamNum
mov ecx, eax

mov eax, VR6;//VR6 = Local iTeamNum

;//skip players of same team
;//if ( EAX == ECX ) goto l_skip;
mov ebx, ecx
mov edx, eax
sub eax, ecx;//COMPARE EAX, ECX
xchg eax, edx;//Restore EAX
je l_skip

mov eax, VR1;//VR1 -> Entity
mov ebx, VR3;//VR3 -> m_bSpotted
add eax, ebx 
mov ebx,1
mov BYTE PTR [eax],bl

;//m_clrRender = 0x70;
;//uncomment code below to color enemy players red

mov eax, VR1;//VR1 -> Entity
mov ebx, 0x70;//m_clrRender
add eax, ebx 
mov ebx,0xFF0000FF;//RR GG BB AA
mov DWORD PTR [eax],ebx


@l_skip:
mov eax, VR9;//VR9 => PlayerEntity offset
add eax, 0x4
add eax, 0x4
add eax, 0x4
add eax, 0x4
mov VR9, eax

mov eax, VR2
dec eax
mov VR2, eax
;//if ( EAX == ECX ) goto l_skip;
mov ecx, 0
sub eax, ecx;//COMPARE EAX, ECX
jne l_Loop

jmp l_Start


;//////////////////////////////////////////// GetClassId ////////////////////////////////////////////
;//Function GetClassId
;//EAX => Entity
@GetClassID:
mov ecx, eax

add eax, 0x4
add eax, 0x4

mov eax, DWORD PTR[eax]

;//if ( EAX < 0x10000 ) goto l_Fail
mov ebx, eax
mov ecx, VR6;//0x10000
sub eax, ecx;//COMPARE EAX, ECX
xchg eax, ebx;//Restore EAX

jc l_Fail

add eax, 0x4
add eax, 0x4

mov eax, DWORD PTR[eax]

;//if ( EAX < 0x10000 ) goto l_Fail
mov ebx, eax
mov ecx, VR6;//0x10000
sub eax, ecx;//COMPARE EAX, ECX
xchg eax, ebx;//Restore EAX
jc l_Fail

inc eax
mov eax, DWORD PTR[eax]

;//if ( EAX < 0x10000 ) goto l_Fail
mov ebx, eax
mov ecx, VR6;//0x10000
sub eax, ecx;//COMPARE EAX, ECX
xchg eax, ebx;//Restore EAX
jc l_Fail


add eax, 0x4
add eax, 0x4
add eax, 0x4
add eax, 0x4
add eax, 0x4


mov eax, DWORD PTR[eax]
mov ecx, eax

jmp GetClassID_Ret

@l_Fail:
mov ecx, 0x0
jmp GetClassID_Ret
;//////////////////////////////// Code End ////////////////////////////////
