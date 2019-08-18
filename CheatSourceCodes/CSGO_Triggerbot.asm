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
;//VR1 -> Local Team Id
;//VR2 -> AttackState
;//VR3 -> Original Stack Pointer
;//VR9 -> Crosshair id / temporary localplayer / temporary TriggerbotKey

;/////////////////////////////// Code Start ///////////////////////////////
mov VR3, eax;//VR3 => Original Stack Pointer

mov eax, 0x0
mov VR2, eax;//VR2 => 0

@l_MainLoop:;//EAX => Triggerbot key:
mov eax,0x6;//-> VK_XBUTTON2
;//https://docs.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes
mov VR9, eax;

mov ecx, 0x0
mov eax, VR3;//=> Original Stack Pointer
mov ebx, !kernel32.Sleep
mov DWORD PTR[eax], ebx
add eax, 0x4
mov ebx, #xchg esp,ebx;//return-rop-address will be stored on ebx
mov DWORD PTR[eax], ebx
add eax, 0x4
mov ebx, 13;//13 milli-sec
mov DWORD PTR[eax], ebx
mov eax, VR3;//=> Original Stack Pointer
mov ebx, @l_ReturnFromSleep
;//----------------------------------------------------
xchg eax, esp;//=> Jump to [EAX] -> Sleep
;//----------------------------------------------------
@l_ReturnFromSleep:
mov eax, VR3;//=> Original Stack Pointer
mov ebx, !user32.GetAsyncKeyState
mov DWORD PTR[eax], ebx
add eax, 0x4
mov ebx, #xchg esp,ebx;//return-rop-address will be stored on ebx
mov DWORD PTR[eax], ebx
add eax, 0x4
mov ebx, VR9
mov DWORD PTR[eax], ebx
mov eax, VR3;//=> Original Stack Pointer
mov ebx, @l_ReturnFromGetAsyncKeyState
;//----------------------------------------------------
xchg eax, esp;//=> Jump to [EAX] -> GetAsyncKeyState
;//----------------------------------------------------
@l_ReturnFromGetAsyncKeyState:
mov ecx, 0x0
sub eax, ecx;//COMPARE EAX, ECX
jne l_KeyDown
@l_KeyUp:
;//Below if key is not down:
;//if (AttackState)
;//{
;//	*(bool*)dwForceAttack = false;
;//	AttackState = FALSE;
;//}

;//if ( AttackState == 0 ) goto l_MainLoop;
mov ecx, VR2;//VR2 -> AttackState
mov eax, 0x0
sub eax, ecx;//COMPARE EAX, ECX
je l_MainLoop

;//*(BOOL*)dwForceAttack = false;
mov eax, VR6;//VR6 => OFFSET_FORCE_ATTACK
mov ebx, 0x0
mov DWORD PTR[eax], ebx
mov eax, 0x0
mov VR2, eax;//VR2 -> AttackState
jmp l_MainLoop


@l_KeyDown:
mov eax, VR8;//OFFSET_LocalPlayer
mov eax, DWORD PTR[eax]

mov VR9, eax;//VR9 -> Local PlayerEntity


;//if ( EAX < 0x10000 ) goto l_MainLoop
mov ebx, eax
mov ecx, VR0;//0x10000
sub eax, ecx;//COMPARE EAX, ECX
xchg eax, ebx;//Restore EAX
jc l_MainLoop

mov ebx, VR4;//OFFSET_TeamNum 
add eax, ebx 
mov eax, DWORD PTR[eax]
mov VR1, eax;//VR1 -> Local TeamId

mov eax, VR9;//VR9 -> Local PlayerEntity
mov ebx, VR5;//OFFSET_CrosshairId

add eax, ebx
mov eax, DWORD PTR[eax]

mov VR9, eax;//VR9 -> CrosshairId

;//if ( CrosshairId > 64 ) goto l_KeyUp;
xchg eax, ecx
mov eax, 0x40
sub eax, ecx;//COMPARE EAX, ECX
xchg eax, ecx;//Restore EAX
js l_KeyUp

;//if ( CrosshairId == 0 ) goto l_KeyUp;
mov ecx, 0x0
mov ebx, eax
sub eax, ecx;//COMPARE EAX, ECX
je l_KeyUp


mov ecx, VR9;//VR9 -> CrosshairId
mov eax, 0x0

;//TargetPlayer = *(DWORD_PTR*)( (DWORD_PTR)OFFSET_EntityList + ( CrosshairId * 0x10 ) );


@l_CrosshairIdLoop:
add eax, 0x4
add eax, 0x4
add eax, 0x4
add eax, 0x4

;//dec ecx
xchg eax, ecx;//Swap EAX with ECX
dec eax
xchg eax, ecx;//Swap EAX with ECX

xchg eax, ebx
mov eax, 0x0
sub eax, ecx;//COMPARE EAX, ECX
xchg eax, ebx;//Restore EAX
jne l_CrosshairIdLoop

;//EAX = ( CrosshairId * 0x10 )

mov ebx, VR7;//VR7 => OFFSET_EntityList
add eax, ebx ;// eax = OFFSET_EntityList + ( CrosshairId * 0x10 )

mov eax, DWORD PTR[eax]

;//if ( EAX < 0x10000 ) goto l_KeyUp
mov ebx, eax
mov ecx, VR0;//0x10000
sub eax, ecx;//COMPARE EAX, ECX
xchg eax, ebx;//Restore EAX
jc l_KeyUp

mov ebx, VR4;//OFFSET_TeamNum 
add eax, ebx 
mov eax, DWORD PTR[eax];//EAX = Entity->m_iTeamNum
mov ebx, eax
mov ecx, VR1;//VR1 -> Local TeamId

;//if ( EAX == ECX ) goto l_KeyUp
;//if ( Entity->m_iTeamNum == LocalTeamId ) goto l_KeyUp
sub eax, ecx;//COMPARE EAX, ECX
xchg eax, ebx;//Restore EAX
je l_KeyUp

;//Toggle AttackState below:
mov ecx, 0x0
mov eax, VR2;//VR2 -> AttackState
sub eax, ecx;//COMPARE EAX, ECX
je l_SetToTrue

mov ebx, 0x0
mov eax, VR6;//VR6 => OFFSET_FORCE_ATTACK
mov DWORD PTR[eax],ebx;//*(BOOL*)dwForceAttack = FALSE;
mov eax, 0x0
mov VR2, eax;//VR2 -> AttackState = 0
jmp l_MainLoop

@l_SetToTrue:
mov ebx, 0x1
mov eax, VR6;//VR6 => OFFSET_FORCE_ATTACK
mov DWORD PTR[eax],ebx;//*(BOOL*)dwForceAttack = TRUE;
mov eax, 0x1
mov VR2, eax;//VR2 -> AttackState = 1
jmp l_MainLoop
;//////////////////////////////// Code End ////////////////////////////////
