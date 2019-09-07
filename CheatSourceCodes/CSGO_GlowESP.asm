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
;//VR0 -> Local Team Id
;//VR1 -> Object Count
;//VR2 -> GlowObject / temporary GlowObjectManager
;//VR3 -> Entity
;//VR6 -> GLOBAL_MinimumAddress


;/////////////////////////////// Code Start ///////////////////////////////
;//VR6 => VR0
mov eax, VR0
mov VR6, eax;//OFFSET_FORCE_ATTACK is not needed and gets overwritten!

@l_Start:
mov eax, VR8;//OFFSET_LocalPlayer
mov eax, DWORD PTR[eax]

;//if ( EBX < 0x10000 ) goto l_Start
mov ebx, eax
mov ecx, VR6;//0x10000
sub eax, ecx;//COMPARE EAX, ECX
xchg eax, ebx;//Restore EAX
jc l_Start

mov ebx, VR4;//OFFSET_TeamNum 
add eax, ebx 
mov eax, DWORD PTR[eax]
mov VR0, eax;//<-- VR0 -> Local TeamId

;//if ( EAX > 64 ) goto l_Start
xchg eax, ecx
mov eax, 64
sub eax, ecx;//COMPARE EAX, ECX
js l_Start


mov eax, VR9;//OFFSET_GlowObjectManager
mov VR2, eax;//VR2 = GlowObjectManager

add eax, 0x4
add eax, 0x4
add eax, 0x4

mov eax, DWORD PTR[eax]
mov VR1, eax;//VR1 = Object Count
mov eax, VR2;//VR2 = GlowObjectManager
mov eax, DWORD PTR[eax]
mov VR2, eax;//VR2 = GlowObject

@l_Loop1:
mov eax, VR2;//VR2 = GlowObject
mov eax, DWORD PTR[eax] ;//eax = GlowObject->m_pEntity
mov VR3, eax;//VR3 -> Entity

;//if ( EAX < 0x10000 ) goto l_skip
mov ebx, eax
mov ecx, VR6;//0x10000
sub eax, ecx;//COMPARE EAX, ECX
xchg eax, ebx;//Restore EAX
jc l_skip


mov eax, VR3;//VR3 -> Entity
jmp GetClassID
@GetClassID_Ret:

;//if ( ECX != 0x28 ) goto l_skip
mov eax, 0x28
sub eax, ecx;//COMPARE EAX, ECX
jne l_skip

mov eax, VR3;//VR3 -> Entity
mov ebx, VR4;//VR4 -> OFFSET_TeamNum
add eax, ebx 
mov eax, DWORD PTR[eax];//eax = Entity->m_iTeamNum
mov ecx, eax

mov eax, VR0;//VR0 = Local iTeamNum

;//skip players of same team
;//if ( EAX == ECX ) goto l_skip;
mov ebx, eax
sub eax, ecx;//COMPARE EAX, ECX
xchg eax, ebx;//Restore EAX
je l_skip


mov eax, VR2;//VR2 = GlowObject
add eax, 0x4
mov ebx, 0x3F800000
mov DWORD PTR[eax], ebx;//GlowObject->m_flRed = 1.0f [1.0f => 0x3F800000]
add eax, 0x4
mov ebx, 0x0
mov DWORD PTR[eax], ebx;//GlowObject->m_flGreen = 0.0f
add eax, 0x4
mov DWORD PTR[eax], ebx;//GlowObject->m_flBlue = 0.0f
add eax, 0x4
mov ebx, 0x3F800000
mov DWORD PTR[eax], ebx;//GlowObject->m_flAlpha = 1.0f [1.0f => 0x3F800000]

add eax, 4
add eax, 4
add eax, 4
add eax, 4
add eax, 4
;GlowObject->m_bRenderWhenOccluded = 1
;GlowObject->m_bRenderWhenUnoccluded = 0
;GlowObject->m_bFullBloom = 0
;=> 0x00000101
mov ebx, 0x00000001
mov DWORD PTR[eax], ebx

@l_skip:

mov eax, VR2;//VR2 = GlowObject
mov ebx, 0x38
add eax, ebx ;//GlowObject = GlowObject+0x38
mov VR2, eax;//VR2 = GlowObject

mov eax, VR1;//VR1 = Object Count
dec eax
mov VR1, eax;//VR1 = VR-1

;//if ( EAX != 0 ) goto l_Loop1
mov ecx, 0x00
sub eax, ecx;//COMPARE EAX, ECX
jne l_Loop1

jmp l_Start;//=> Jump back to start

;//////////////////////////////////////////// GetClassId ////////////////////////////////////////////
;//Function GetClassId
;//EAX => Entity
@GetClassID:
mov ecx, eax

add eax, 0x4
add eax, 0x4

mov eax, DWORD PTR[eax]

;//if ( EBX < 0x10000 ) goto l_Fail
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
