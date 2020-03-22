#pragma once

struct RandomGenerator
{
	void Initialize( void );
	void release( void );
	unsigned int GenerateRandomSeed( void );

	BYTE    GetByte ( void );
	WORD    GetWord ( void );
	DWORD   GetDword( void );
	DWORD64 GetQword( void );
	CHAR*   GetString( /*IN OUT*/CHAR*  Buffer, /*IN*/DWORD Size );

	void GetBuffer( /*IN OUT*/ void* Address, /*IN*/ DWORD Size );

	///////////////////// Linear congruential generator /////////////////////
	unsigned int LCGGeneratorIndex;
	unsigned int LCGState[10];

	unsigned int LCG_ThreadId;
	
	int LCG_rand( void );
	void LCG_randBuffer( /*IN OUT*/ void* Address, /*IN*/ DWORD Size );
	/////////////////////////////////////////////////////////////////////////

	bool checkHardwareRNG( void );
};
extern RandomGenerator g_RandomGenerator;


/////////////////////////////////////////// Linear congruential generator ///////////////////////////////////////////
struct LinearCongruentialGenerator
{
	__int32 modulus; //m

	unsigned __int32 multiplier; //a
	unsigned __int32 increment; //c
	
	unsigned __int32 Shift;
	unsigned __int32 Mask; 
};
	
const LinearCongruentialGenerator GeneratorValues[10] = {
	//https://en.wikipedia.org/wiki/Linear_congruential_generator#Parameters_in_common_use
	
	//Numerical Recipes
	{ -1i32, 1664525ui32, 1013904223ui32, 16, 0x7FFF },

	//Borland C/C++
	{ -1i32, 22695477ui32, 1ui32, 16, 0x7FFF },

	//glibc (used by GCC)
	{ -1i32, 1103515245ui32, 12345ui32, 0, 0x7FFFFFFF },

	//ANSI C: Watcom, Digital Mars, CodeWarrior, IBM VisualAge C/C++
	{ -1i32, 1103515245ui32, 12345ui32, 16, 0x7FFF },

	//Borland Delphi, Virtual Pascal and Turbo Pascal
	//but using on 32bit
	{ -1i32, 134775813ui32, 1ui32, 0, 0xFFFFFFFF },
	
	//Microsoft Visual/Quick C/C++
	{ -1i32, 214013ui32, 2531011ui32, 16, 0x7FFF },

	//Microsoft Visual Basic (6 and earlier)
	{ 16777216i32, 214013ui32, 2531011ui32, 16, 0x7FFF },

	//RtlUniform from Native API
	{ 2147483647i32, 0x7FFFFFEDui32, 0x7FFFFFC3ui32, 0, 0x7FFFFFFF },

	//cc65 [0]
	{ 8388608i32, 0x10101ui32, 0x415927ui32, 8, 0x7FFF },

	//cc65 [1]
	{ -1i32, 0x10101ui32, 826366247ui32, 16, 0x7FFF },
};
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
