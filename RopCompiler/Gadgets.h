#pragma once
//https://defuse.ca/online-x86-assembler.htm

RopCode g_RopGadgets[] = {
	{"mov eax, ecx",				(unsigned __int8*)"\x8B\xC1\xC3", 3,		(0), 0},
	{"mov eax, edx",				(unsigned __int8*)"\x89\xD0\xC3", 3,		(0), 0},
	{"mov eax, ebx",				(unsigned __int8*)"\x89\xD8\xC3", 3,		(0), 0},
	
	//The following instructions are implemented by using other instructions [via the AdvancedInstructionHandler callbacks] so they can be used:
	//{"mov ecx, eax",				(unsigned __int8*)"\x89\xC1\xC3", 3,		(0), 0},//
	//{"mov ebx, ecx",				(unsigned __int8*)"\x89\xCB\xC3", 3,		(0), 0},//
	//{"mov ebx, eax",				(unsigned __int8*)"\x8B\xD8\xC3", 3,		(0), 0},//
	//{"mov edx, eax",				(unsigned __int8*)"\x89\xC2\xC3", 3,		(0), 0},//
	//{"mov DWORD PTR[eax], ebx",	(unsigned __int8*)"\x89\x18\xC3", 3,		(0), 0},//
	//{"mov BYTE PTR [eax],bl",		(unsigned __int8*)"\x88\x18\xC3", 3,		(0), 0},//
	//{"mov BYTE PTR [eax],ebx",	(unsigned __int8*)"\x88\x18\xC3", 3,		(0), 0},//

	{"sub eax, ecx",				(unsigned __int8*)"\x29\xC8\xC3", 3,		(0), 0},
	//{"sub ebx, edx",				(unsigned __int8*)"\x29\xD3\xC3", 3,		(0), 0},//REMOVED: NO GADGET FOUND

	{"lea eax,[ecx+4]",				(unsigned __int8*)"\x8D\x41\x04\xC3", 4,	(0), 0},

	{"lea eax,[eax+4]",				(unsigned __int8*)"\x83\xC0\x04\xC3", 4,	(0), 0},
	{"add eax, 4",					(unsigned __int8*)"\x83\xC0\x04\xC3", 4,	(0), 0},
	{"add eax, 0x4",				(unsigned __int8*)"\x83\xC0\x04\xC3", 4,	(0), 0},

	{"inc eax",						(unsigned __int8*)"\x40\xC3", 2,			(0), 0},
	{"dec eax",						(unsigned __int8*)"\x48\xC3", 2,			(0), 0},


	{"inc edx",						(unsigned __int8*)"\x42\xC3", 2,			(0), 0},
	{"dec edx",						(unsigned __int8*)"\x4A\xC3", 2,			(0), 0},

	
	{"add eax, ebx",				(unsigned __int8*)"\x01\xD8\xC3", 3,		(0), 0},

	{"mov DWORD PTR[ebx], eax",		(unsigned __int8*)"\x89\x03\xC3", 3,		(0), 0},
	
	
	{"mov BYTE PTR [ebx],eax",		(unsigned __int8*)"\x88\x03\xC3", 3,		(0), 0},
	{"mov BYTE PTR [ebx],al",		(unsigned __int8*)"\x88\x03\xC3", 3,		(0), 0},

	{"pop eax",						(unsigned __int8*)"\x58\xC3", 2,			(0), 0},
	{"pop ecx",						(unsigned __int8*)"\x59\xC3", 2,			(0), 0},
	{"pop edx",						(unsigned __int8*)"\x5A\xC3", 2,			(0), 0},
	{"pop ebx",						(unsigned __int8*)"\x5B\xC3", 2,			(0), 0},
	{"pop esp",						(unsigned __int8*)"\x5C\xC3", 2,			(0), 0},
	{"pop ebp",						(unsigned __int8*)"\x5D\xC3", 2,			(0), 0},
	{"pop esi",						(unsigned __int8*)"\x5E\xC3", 2,			(0), 0},
	{"pop edi",						(unsigned __int8*)"\x5F\xC3", 2,			(0), 0},
	{"pusha",						(unsigned __int8*)"\x60\xC3", 2,			(0), 0},
	{"popa",						(unsigned __int8*)"\x61\xC3", 2,			(0), 0},

	//USED BY VM TO READ FROM Virtual Registers
	{"mov eax, DWORD PTR[eax]",		(unsigned __int8*)"\x8B\x00\xC3", 3,		(0), 0},
	/*
	{"mov ecx, DWORD PTR[ecx]",		(unsigned __int8*)"\x8B\x09\xC3", 3,		(0), 0},//REMOVED: NO GADGET FOUND
	{"mov edx, DWORD PTR[edx]",		(unsigned __int8*)"\x8B\x12\xC3", 3,		(0), 0},//REMOVED: NO GADGET FOUND
	{"mov ebx, DWORD PTR[ebx]",		(unsigned __int8*)"\x8B\x1B\xC3", 3,		(0), 0},//REMOVED: NO GADGET FOUND
	{"mov esp, DWORD PTR[esp]",		(unsigned __int8*)"\x8B\x24\x24\xC3", 4,	(0), 0},//REMOVED: NO GADGET FOUND
	{"mov ebp, DWORD PTR[ebp]",		(unsigned __int8*)"\x8B\x6D\x00\xC3", 4,	(0), 0},//REMOVED: NO GADGET FOUND
	{"mov esi, DWORD PTR[esi]",		(unsigned __int8*)"\x8B\x36\xC3", 3,		(0), 0},
	{"mov edi, DWORD PTR[edi]",		(unsigned __int8*)"\x8B\x3F\xC3", 3,		(0), 0},//REMOVED: NO GADGET FOUND
	*/
	{"cmovs eax,ecx",				(unsigned __int8*)"\x0F\x48\xC1\xC3", 4,	(0), 0},

	{"cmovc eax,ecx",				(unsigned __int8*)"\x0F\x42\xC1\xC3", 4,	(0), 0},

	/*
	{"cmovs esp,eax",				(unsigned __int8*)"\x0F\x48\xE0\xC3", 4,	(0), 0},//REMOVED: NO GADGET FOUND
	{"cmovs esp,eax",				(unsigned __int8*)"\x0F\x48\xE0\xC3", 4,	(0), 0},//REMOVED: NO GADGET FOUND
	{"cmovs esp,ecx",				(unsigned __int8*)"\x0F\x48\xE1\xC3", 4,	(0), 0},//REMOVED: NO GADGET FOUND
	{"cmovs esp,edx",				(unsigned __int8*)"\x0F\x48\xE2\xC3", 4,	(0), 0},//REMOVED: NO GADGET FOUND
	{"cmovs esp,ebx",				(unsigned __int8*)"\x0F\x48\xE3\xC3", 4,	(0), 0},//REMOVED: NO GADGET FOUND
	{"cmovs esp,ebp",				(unsigned __int8*)"\x0F\x48\xE5\xC3", 4,	(0), 0},//REMOVED: NO GADGET FOUND
	*/
	//{"cmovns eax,ecx",				(unsigned __int8*)"\x0F\x49\xC1\xC3", 4,	(0), 0},//REMOVED: NO GADGET FOUND
	/*
	{"cmovns esp,eax",				(unsigned __int8*)"\x0F\x49\xE0\xC3", 4,	(0), 0},//REMOVED: NO GADGET FOUND
	{"cmovns esp,ecx",				(unsigned __int8*)"\x0F\x49\xE1\xC3", 4,	(0), 0},//REMOVED: NO GADGET FOUND
	{"cmovns esp,edx",				(unsigned __int8*)"\x0F\x49\xE2\xC3", 4,	(0), 0},//REMOVED: NO GADGET FOUND
	{"cmovns esp,ebx",				(unsigned __int8*)"\x0F\x49\xE3\xC3", 4,	(0), 0},//REMOVED: NO GADGET FOUND
	{"cmovns esp,ebp",				(unsigned __int8*)"\x0F\x49\xE5\xC3", 4,	(0), 0},//REMOVED: NO GADGET FOUND
	{"cmovne esp,ebx",				(unsigned __int8*)"\x0F\x45\xE3\xC3", 4,	(0), 0},//REMOVED: NO GADGET FOUND
	{"cmove esp,ebx",				(unsigned __int8*)"\x0F\x44\xE3\xC3", 4,	(0), 0},//REMOVED: NO GADGET FOUND
	*/

	{"cmove eax,ecx",				(unsigned __int8*)"\x0F\x44\xC1\xC3", 4,	(0), 0},

	{"cmovne eax,ecx",				(unsigned __int8*)"\x0F\x45\xC1\xC3", 4,	(0), 0},

	
	/*
	{"cmovs ebp,ebx",				(unsigned __int8*)"\x0F\x48\xEB\xC3", 4,	(0), 0},//REMOVED: NO GADGET FOUND
	{"cmovs esi,ebx",				(unsigned __int8*)"\x0F\x48\xF3\xC3", 4,	(0), 0},//REMOVED: NO GADGET FOUND
	{"cmovs edi,ebx",				(unsigned __int8*)"\x0F\x48\xFB\xC3", 4,	(0), 0},//REMOVED: NO GADGET FOUND
	*/

	

	{"xchg eax,ecx",				(unsigned __int8*)"\x91\xC3", 2,			(0), 0},
	{"xchg ecx,eax",				(unsigned __int8*)"\x91\xC3", 2,			(0), 0},

	//{"xchg ebx,ecx",				(unsigned __int8*)"\x87\xCB\xC3", 3,		(0), 0},//REMOVED: NO GADGET FOUND
	//{"xchg ecx,ebx",				(unsigned __int8*)"\x87\xCB\xC3", 3,		(0), 0},//REMOVED: NO GADGET FOUND

	{"xchg edx,eax",				(unsigned __int8*)"\x92\xC3", 2,			(0), 0},
	{"xchg eax,edx",				(unsigned __int8*)"\x92\xC3", 2,			(0), 0},

	{"xchg ebx,eax",				(unsigned __int8*)"\x93\xC3", 2,			(0), 0},
	{"xchg eax,ebx",				(unsigned __int8*)"\x93\xC3", 2,			(0), 0},

	{"xchg esp,eax",				(unsigned __int8*)"\x94\xC3", 2,			(0), 0},
	{"xchg eax,esp",				(unsigned __int8*)"\x94\xC3", 2,			(0), 0},

	{"xchg ebp,eax",				(unsigned __int8*)"\x95\xC3", 2,			(0), 0},
	{"xchg eax,ebp",				(unsigned __int8*)"\x95\xC3", 2,			(0), 0},

	{"xchg esi,eax",				(unsigned __int8*)"\x96\xC3", 2,			(0), 0},
	{"xchg eax,esi",				(unsigned __int8*)"\x96\xC3", 2,			(0), 0},

	{"xchg edi,eax",				(unsigned __int8*)"\x97\xC3", 2,			(0), 0},
	{"xchg eax,edi",				(unsigned __int8*)"\x97\xC3", 2,			(0), 0},

	{"xchg esp,ebp",				(unsigned __int8*)"\x87\xEC\xC3", 3,		(0), 0},
	{"xchg ebp,esp",				(unsigned __int8*)"\x87\xEC\xC3", 3,		(0), 0},

	{"xchg esp,ebx",				(unsigned __int8*)"\x87\xDC\xC3", 3,		(0), 0},//REMOVED: NO GADGET FOUND
	//{"xchg ebx,esp",				(unsigned __int8*)"\x87\xDC\xC3", 3,		(0), 0},//REMOVED: NO GADGET FOUND
	
	//{"xchg esp,edx",				(unsigned __int8*)"\x87\xD4\xC3", 3,		(0), 0},//REMOVED: NO GADGET FOUND
	//{"xchg edx,esp",				(unsigned __int8*)"\x87\xD4\xC3", 3,		(0), 0},//REMOVED: NO GADGET FOUND
	
	//Breakpoint:
	{"int3",						(unsigned __int8*)"\xCC\xC3", 2,			(0), 0},

	//No-Operation:
	{"nop",							(unsigned __int8*)"\x90\xC3", 2,			(0), 0},
};

