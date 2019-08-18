//C++ interpretation of the BF3_MinimapESP.asm to help understanding how it works

for ( ; ; )
{
	DWORD CGC = *(DWORD*)0x2380B58;
	if ( CGC > 0x10000 )
	{
		DWORD PlayerMgr = *(DWORD*)( CGC + 0x30 );
		if ( PlayerMgr > 0x10000 )
		{
			DWORD PlayerListPos = *(DWORD*)( PlayerMgr + 0x9C + 0 );
			DWORD PlayerListEnd = *(DWORD*)( PlayerMgr + 0x9C + 4 );

			while( PlayerListPos != PlayerListEnd )
			{
				DWORD ClientPlayer = *(DWORD*)(PlayerListPos);
				if ( ClientPlayer > 0x10000 )
				{
					if ( *(DWORD*)ClientPlayer == 0x02142528 )
					{
						

						DWORD WeakPtr = *(DWORD*)( ClientPlayer + 0x3C0 );
						if ( WeakPtr > 0x10000 )
						{
							DWORD ClientSoldierEntity = *(DWORD*)WeakPtr - 4;
							if ( ClientSoldierEntity > 0x10000 )
							{
								if ( *(DWORD*)ClientSoldierEntity == 0x214BD40 )
								{

									DWORD ClientSpottingTargetComponent = *(DWORD*)( ClientSoldierEntity + 0x3A0ui32 + (10ui32 * 16ui32) );
									if ( ClientSpottingTargetComponent > 0x10000 )
									{
										if ( *(DWORD*)ClientSpottingTargetComponent == 0x20B2278 )
										{
											*(DWORD*)( ClientSpottingTargetComponent + 0x18 ) = 1;
										}
									}
								}
							}
						}
					}
				}
				PlayerListPos += 4;
			}
		}
	}
}