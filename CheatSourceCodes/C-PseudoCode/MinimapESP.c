//C++ interpretation of the CSGO_MinimapESP.asm to help understanding how it works

DWORD VR5 = 0x93D;//m_bSpotted

while(true)
{
	DWORD LocalPlayer = *(DWORD*)OFFSET_LocalPlayer;
	if ( LocalPlayer < 0x10000 ) continue;

	DWORD LocalTeamId = *(DWORD*)( LocalPlayer + OFFSET_TeamNum );
	if ( LocalTeamId > 64 ) continue;
	
	DWORD VR2 = 64;
	DWORD VR9 = OFFSET_EntityList;
	while(true)
	{
		DWORD Entity = *(DWORD*)VR9;
		if (  Entity < 0x10000 ) goto l_skip;
		
		DWORD TeamId = *(DWORD*)( Entity + OFFSET_TeamNum );
		if ( TeamId == LocalPlayer ) goto l_skip;
		
		//*(DWORD*)( Entity + 0x70 ) = 0xFF0000FF;// [RR GG BB AA] m_clrRender
		
		Entity += VR5;
		*(BYTE*)Entity = 1;
		
l_skip:		
		VR9 = VR9 + 0x4 + 0x4 + 0x4 + 0x4;
		
		VR2 = VR2 - 1;
		if ( VR2 == 0 ) break;
	}
}
return;

DWORD GetClassID( DWORD Entity )
{
	DWORD IClientNetworkableVtable = *(DWORD*)(Entity + 0x8);
	if ( IClientNetworkableVtable >= 0x10000 )
	{
		DWORD GetClientClassFunction = *(DWORD*)(IClientNetworkableVtable + 0x8);
		if ( GetClientClassFunction >= 0x10000 )
		{
			DWORD ClientClass = *(DWORD*)(GetClientClassFunction + 0x1);
			if ( ClientClass >= 0x10000 )
			{
				return *(DWORD*)( ClientClass + 0x14 );
			}
		}
	}
	return 0;
}