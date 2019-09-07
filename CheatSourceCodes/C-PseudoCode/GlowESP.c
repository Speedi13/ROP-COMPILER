//C++ interpretation of the CSGO_GlowESP.asm to help understanding how it works

while(true)
{
l_Start:	
	DWORD LocalPlayer = *(DWORD*)OFFSET_LocalPlayer;
	if ( LocalPlayer < 0x10000 ) continue;
	
	DWORD LocalTeamId = *(DWORD*)( LocalPlayer + OFFSET_TeamNum );
	if ( LocalTeamId > 64 ) continue;
	
	DWORD GlowObjectManager = OFFSET_GlowObjectManager;
	
	DWORD ObjectCount = *(DWORD*)( GlowObjectManager + 0x4 + 0x4 + 0x4 );
	DWORD GlowObject = *(DWORD*)GlowObjectManager;
	while(true)
	{
		DWORD Entity = *(DWORD*)( GlowObject + 0 );
		if ( Entity > 0x10000 )
		{
			DWORD ClassId = GetClassID( Entity );
			if ( ClassId == 0x28 )
			{
				DWORD TeamId = *(DWORD*)( Entity + OFFSET_TeamNum );
				if ( TeamId != LocalTeamId )
				{
					*(DWORD*)( GlowObject + 0x04 ) = 0x3F800000;//GlowObject->m_flRed = 1.0f [1.0f => 0x3F800000]
					*(DWORD*)( GlowObject + 0x08 ) = 0x0;//GlowObject->m_flGreen = 0.0f
					*(DWORD*)( GlowObject + 0x0C ) = 0x0;//GlowObject->m_flBlue = 0.0f
					*(DWORD*)( GlowObject + 0x10 ) = 0x3F800000;//GlowObject->m_flAlpha = 1.0f [1.0f => 0x3F800000]
					*(DWORD*)( GlowObject + 0x24 ) = 0x00000001;
				}
			}
		}
l_skip:	
		GlowObject += 0x38;
		ObjectCount -= 1;
		if ( ObjectCount == 0 ) break;
	}
	continue;
};
return;

//class GlowObject 
//{
//public:
//       BaseEntity* m_pEntity; //0x0000 
//       float m_flRed; //0x0004 
//       float m_flGreen; //0x0008 
//       float m_flBlue; //0x000C 
//       float m_flAlpha; //0x0010 
//       char _0x0014[16];
//       BYTE m_bRenderWhenOccluded; //0x0024 
//       BYTE m_bRenderWhenUnoccluded; //0x0025 
//       BYTE m_bFullBloom; //0x0026 
//       uint8_t pad_0027[5];               //0x0027
//       int32_t m_nGlowStyle;              //0x002C
//       int32_t m_nSplitScreenSlot;        //0x0030
//       int32_t m_nNextFreeSlot; //0x0034
//};//Size=0x0038

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