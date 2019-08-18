//C++ interpretation of the CSGO_Triggerbot.asm to help understanding how it works

BOOL AttackState = FALSE;
DWORD TargetPlayer = 0;
while (true)
{
l_MainLoop:	
	Sleep( 20 );
	SHORT KeyState = GetAsyncKeyState( VK_XBUTTON1 );
	if ( KeyState != 0 )
	{
l_KeyDown:		
		DWORD p = *(DWORD*)OFFSET_LocalPlayer;
		if ( p > 0x10000 )
		{
			DWORD LocalTeamId = *(DWORD*)( p + OFFSET_TeamNum );

			DWORD CrosshairId = *(DWORD*)( p + OFFSET_CrosshairId );
			if ( CrosshairId > 0 && CrosshairId < 64 )
			{
				TargetPlayer = *(DWORD*)( (DWORD)OFFSET_EntityList + ( CrosshairId * 0x10 ) );
				if ( TargetPlayer > 0x10000 )
				{
					DWORD TargetTeamId = *(DWORD*)( TargetPlayer + OFFSET_TeamNum );
					if ( LocalTeamId != TargetTeamId )
					{
						if ( AttackState == 0 )
						{
							AttackState = 1;
							*(BOOL*)dwForceAttack = AttackState;
							continue;//goto l_MainLoop
						}
						else
						{
							AttackState = 0;
							*(BOOL*)dwForceAttack = AttackState;
							continue;//goto l_MainLoop
						}
					}
				}
			}
		}
	}
l_KeyUp:	
	if (AttackState != 0)
	{
		*(BOOL*)dwForceAttack = false;
		AttackState = FALSE;
	}
	continue;//goto l_MainLoop;
}
return;