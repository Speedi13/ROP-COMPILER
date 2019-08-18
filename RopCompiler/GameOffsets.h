#pragma once
extern DWORD_PTR OFFSET_GlowObjectManager;// -> VR9
extern DWORD_PTR OFFSET_LocalPlayer;// -> VR8
extern DWORD_PTR OFFSET_EntityList;// -> VR7
extern DWORD_PTR OFFSET_FORCE_ATTACK;// -> VR6

extern DWORD_PTR OFFSET_CrosshairId;// -> VR5
extern DWORD_PTR OFFSET_TeamNum;// -> VR4
extern DWORD_PTR OFFSET_bSpotted;// -> VR3

extern DWORD_PTR GLOBAL_MinimumAddress;// -> VR0

bool ClientDllSearchForOffsets( /*IN*/ const struct RemoteProcessModuleInfo* ClientDllInfo );