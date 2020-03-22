#include <Windows.h>
#include "ASSERT.h"

#include <bcrypt.h>

#include "Compiler.h"
#include "Util.h"
#include "RandomGenerator.h"

#include <Psapi.h>

#include <immintrin.h> //RDRAND and RDSEED instructions

RandomGenerator g_RandomGenerator = {};

struct WinApiCryptGenRandom
{
    HMODULE ADVAPI32;
    HCRYPTPROV hCryptProv;

    ///////////////////////////// API Functions /////////////////////////////
    BOOL (WINAPI* _CryptAcquireContextA)(
    _Out_       HCRYPTPROV  *phProv,
    _In_opt_    LPCSTR    szContainer,
    _In_opt_    LPCSTR    szProvider,
    _In_        DWORD       dwProvType,
    _In_        DWORD       dwFlags
    );

    BOOL (WINAPI* _CryptReleaseContext)(
    _In_    HCRYPTPROV  hProv,
    _In_    DWORD       dwFlags
    );

    BOOL (WINAPI* _CryptGenRandom)(
    _In_                            HCRYPTPROV  hProv,
    _In_                            DWORD   dwLen,
    _Inout_updates_bytes_(dwLen)    BYTE    *pbBuffer
    );
    /////////////////////////////////////////////////////////////////////////

    BOOL WinApiCryptGenRandom::Initialize( void )
    {
        this->hCryptProv = NULL;

        this->ADVAPI32 = LoadLibraryW( L"ADVAPI32.dll" );
        if ( this->ADVAPI32 == NULL )
            return FALSE;

        this->_CryptAcquireContextA = ( decltype(this->_CryptAcquireContextA) ) GetProcAddress( ADVAPI32, "CryptAcquireContextA" );
        this->_CryptReleaseContext  = ( decltype(this->_CryptReleaseContext) )  GetProcAddress( ADVAPI32, "CryptReleaseContext" );
        this->_CryptGenRandom       = ( decltype(this->_CryptGenRandom) )       GetProcAddress( ADVAPI32, "CryptGenRandom" );

        if (    this->_CryptAcquireContextA == NULL
            ||  this->_CryptReleaseContext == NULL 
            ||  this->_CryptGenRandom == NULL)
        {
            this->ADVAPI32 = NULL;
            return FALSE;
        }

        return this->_CryptAcquireContextA( &this->hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT ); 
    }
    BOOL WinApiCryptGenRandom::release( void )
    {
        if ( this->ADVAPI32 == NULL || this->hCryptProv == NULL )
            return TRUE;
        return this->_CryptReleaseContext( this->hCryptProv, 0 ); 
    }

    //https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptgenrandom
    bool WinApiCryptGenRandom::Random( /*OUT*/ BYTE *pbBuffer, /*IN*/ DWORD dwLen)
    {
        if (this->hCryptProv == NULL || this->ADVAPI32 == NULL)
            return false;

        __ASSERT__( pbBuffer != NULL );
        __ASSERT__( dwLen > 0 );

        return this->_CryptGenRandom( this->hCryptProv, dwLen, (BYTE*)pbBuffer ) == TRUE;
    }
};


//https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom
struct WinApiCryptGenRandomV2
{
    BCRYPT_ALG_HANDLE hAlgorithm;
    HMODULE BCRYPT;

    ///////////////////////////// API Functions /////////////////////////////
    NTSTATUS (WINAPI* _BCryptOpenAlgorithmProvider)(
    _Out_       BCRYPT_ALG_HANDLE   *phAlgorithm,
    _In_        LPCWSTR pszAlgId,
    _In_opt_    LPCWSTR pszImplementation,
    _In_        ULONG   dwFlags
    );

    NTSTATUS (WINAPI* _BCryptCloseAlgorithmProvider)(
    _Inout_ BCRYPT_ALG_HANDLE   hAlgorithm,
    _In_    ULONG   dwFlags
    );

    NTSTATUS (WINAPI* _BCryptGenRandom)(
    _In_opt_                        BCRYPT_ALG_HANDLE   hAlgorithm,
    _Inout_updates_bytes_all_(cbBuffer)   PUCHAR  pbBuffer,
    _In_                            ULONG   cbBuffer,
    _In_                            ULONG   dwFlags
    );
    /////////////////////////////////////////////////////////////////////////

    BOOL WinApiCryptGenRandomV2::Initialize( /*IN*/ bool UseDualEllipticCurve /*NSA backdoored RNG*/ )
    {
        this->hAlgorithm = NULL;

        this->BCRYPT = LoadLibraryW( L"bcrypt.dll" );
        if ( this->BCRYPT == NULL )
            return FALSE;

        this->_BCryptOpenAlgorithmProvider  = ( decltype(this->_BCryptOpenAlgorithmProvider) )  GetProcAddress( BCRYPT, "BCryptOpenAlgorithmProvider" );
        this->_BCryptCloseAlgorithmProvider = ( decltype(this->_BCryptCloseAlgorithmProvider) ) GetProcAddress( BCRYPT, "BCryptCloseAlgorithmProvider" );
        this->_BCryptGenRandom              = ( decltype(this->_BCryptGenRandom) )              GetProcAddress( BCRYPT, "BCryptGenRandom" );


        LPCWSTR AlogName = UseDualEllipticCurve ? BCRYPT_RNG_DUAL_EC_ALGORITHM : BCRYPT_RNG_FIPS186_DSA_ALGORITHM;

        return this->_BCryptOpenAlgorithmProvider( &this->hAlgorithm, AlogName ,0 ,0 ) == 0;
    }

    BOOL WinApiCryptGenRandomV2::release( void )
    {
        if ( this->BCRYPT == NULL )
            return TRUE;

        BOOL Result = FALSE;

        if ( this->hAlgorithm != NULL )
            Result = this->_BCryptCloseAlgorithmProvider( &this->hAlgorithm, 0 ) == 0;

        FreeLibrary( this->BCRYPT ); this->BCRYPT = NULL;
        return Result == TRUE;
    }

    //https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptgenrandom
    bool WinApiCryptGenRandomV2::Random( /*OUT*/ BYTE *pbBuffer, /*IN*/ DWORD dwLen)
    {
        if ( this->BCRYPT == NULL )
            return false;

        DWORD Flags;
        if ( this->hAlgorithm == NULL )
            Flags = BCRYPT_USE_SYSTEM_PREFERRED_RNG;
        else
            Flags = 0;

        __ASSERT__( pbBuffer != NULL );
        __ASSERT__( dwLen > 0 );

        return this->_BCryptGenRandom( this->hAlgorithm, pbBuffer, dwLen, 0) == (NTSTATUS)(0x00000000l);
    }
};

WinApiCryptGenRandom   g_OldCryptApi;
WinApiCryptGenRandomV2 g_DualEllipticCurveRNG; //don't use it, its way to slow anyway
WinApiCryptGenRandomV2 g_FIPS186DSARNG;

void RandomGenerator::Initialize( void )
{
    g_OldCryptApi.Initialize();

    //don't use it, its way to slow on non-win10 systems anyway
    //g_DualEllipticCurveRNG.Initialize( true );
    /*===>*/g_DualEllipticCurveRNG.BCRYPT = NULL;
    /*===>*/g_DualEllipticCurveRNG.hAlgorithm = NULL;

    g_FIPS186DSARNG.Initialize( false );

    unsigned __int64 Seed = GenerateRandomSeed();

    unsigned __int64 PrimeNumber = 836663ui64;

    for (int i = 0; i < 10; i++)
    {
        this->LCGState[i] = (unsigned __int32)( Seed & 0xFFFFFFFFui64 );

        //https://prime-numbers.info/list/safe-primes
        Seed *= PrimeNumber;
        Seed += 1ui64;
        PrimeNumber = (2ui64 * PrimeNumber) + 1ui64;
    }
    this->LCG_ThreadId = GetCurrentThreadId();
}

void RandomGenerator::release( void )
{
    g_OldCryptApi.release( );
    g_DualEllipticCurveRNG.release( );
    g_FIPS186DSARNG.release( );
    for (int i = 0; i < 10; i++)
        this->LCGState[i] = NULL;
}

template< typename T >
T RandomOperator( /*IN*/ T Input1, /*IN*/ T Input2, /*IN*/ BYTE OperatorId )
{
    switch (OperatorId)
    {
    case 0: //XOR
        return (T)( (T)Input1 ^ (T)Input2 );
    case 1: //SUB1
        return (T)( (T)Input1 - (T)Input2 );
    case 2: //SUB2
        return (T)( (T)Input2 - (T)Input1 );
    case 3://ADD
        return (T)( (T)Input1 + (T)Input2 );
    }
    return (T)NULL;
}

template< typename T >
T RandomCombineData( /*IN*/ BYTE* RandomArray, /*IN*/ DWORD ArraySize, /*IN*/ BYTE ActionId )
{
    switch (ActionId)
    {
    case 0:
        {
        T Value = (T)0;
        T Mask = (T)1;
        for (DWORD i = 0; i < ArraySize; i+= 2 * sizeof( T ) )
        {
            Value |= (RandomArray[i] & Mask);
            Mask = Mask << sizeof( T );
        }
        return Value;
        }
    case 1: //XOR
        {
        T Value = 0;
        for (DWORD i = 0; i < ArraySize; i += 1 * sizeof( T ) )
            Value ^= RandomArray[i];
        return Value;
        }
    case 2: //SUB
        {
        T Value = 0;
        for (DWORD i = 0; i < ArraySize; i += 1 * sizeof( T ) )
            Value -= RandomArray[i];
        return Value;
        }
    case 3://ADD
        {
        T Value = 0;
        for (DWORD i = 0; i < ArraySize; i += 1 * sizeof( T ) )
            Value += RandomArray[i];
        return Value;
        }
    }
    return (T)NULL;
}


BYTE RandomGenerator::GetByte( void )
{
    //https://en.wikipedia.org/wiki/RdRand  
    if ( g_HardwareRngSupported_RDRND == true )
    {
        //https://software.intel.com/en-us/cpp-compiler-developer-guide-and-reference-rdrand16-step-rdrand32-step-rdrand64-step
        unsigned short HardwareGeneratedRandomNumber = NULL;
        const int Success = _rdrand16_step( &HardwareGeneratedRandomNumber );
        HardwareGeneratedRandomNumber = HardwareGeneratedRandomNumber % 256;
        if ( Success == TRUE ) 
            return (BYTE)( HardwareGeneratedRandomNumber & 0xFF );
		else
			 printf("[%s] _rdrand16_step failed!\n", __FUNCTION__);
    }

    BYTE RandomValue = (BYTE)( (int)( this->LCG_rand() % 256 ) & 0xFF );

    const BYTE ArraySize = 16 * sizeof( BYTE ); 
    BYTE RandomArray[ ArraySize ] = {};
    ZeroMemory( RandomArray, sizeof(RandomArray) );

    for (int r = 0; r < 3; r++)
    {
        if ( r == 0 && g_OldCryptApi.Random( RandomArray, ArraySize )           != true ) 
            continue;
        if ( r == 1 && g_DualEllipticCurveRNG.Random( RandomArray, ArraySize )  != true  ) 
            continue;
        if ( r == 2 && g_FIPS186DSARNG.Random( RandomArray, ArraySize )         != true  ) 
            continue;

        BYTE Value  = RandomCombineData<BYTE>(  RandomArray,    ArraySize,  RandomArray[ ArraySize - 2 ] % 4 );
        RandomValue = RandomOperator<BYTE>(     RandomValue,    Value,      RandomArray[ ArraySize - 1 ] % 4 );
        continue;
    }
    return RandomValue;
}

WORD RandomGenerator::GetWord( void )
{
    //https://en.wikipedia.org/wiki/RdRand
    if ( g_HardwareRngSupported_RDRND == true )
    {
        //https://software.intel.com/en-us/cpp-compiler-developer-guide-and-reference-rdrand16-step-rdrand32-step-rdrand64-step
        unsigned short HardwareGeneratedRandomNumber = NULL;
        const int Success = _rdrand16_step( &HardwareGeneratedRandomNumber );
        if ( Success == TRUE ) 
            return HardwareGeneratedRandomNumber;
		else
			printf("[%s] _rdrand16_step failed!\n", __FUNCTION__);
    }

    WORD RandomValue = NULL;
    for (WORD i = 0; i < sizeof(WORD); i++)
        RandomValue |= (WORD)( (WORD)( this->LCG_rand() % 256 ) << (8 * i) );

    const BYTE ArraySize = 16 * sizeof( WORD ); 
    BYTE RandomArray[ ArraySize ] = {};
    ZeroMemory( RandomArray, sizeof(RandomArray) );

    for (int r = 0; r < 3; r++)
    {
        if ( r == 0 && g_OldCryptApi.Random( RandomArray, ArraySize )           != true ) 
            continue;
        if ( r == 1 && g_DualEllipticCurveRNG.Random( RandomArray, ArraySize )  != true  ) 
            continue;
        if ( r == 2 && g_FIPS186DSARNG.Random( RandomArray, ArraySize )         != true  ) 
            continue;

        WORD Value  = RandomCombineData<WORD>(  RandomArray,    ArraySize,  RandomArray[ ArraySize - 2 ] % 4 );
        RandomValue = RandomOperator<WORD>(     RandomValue,    Value,      RandomArray[ ArraySize - 1 ] % 4 );
        continue;
    }
    return RandomValue;
}

DWORD RandomGenerator::GetDword( void )
{
    //https://en.wikipedia.org/wiki/RdRand  
    if ( g_HardwareRngSupported_RDRND == true )
    {
        //https://software.intel.com/en-us/cpp-compiler-developer-guide-and-reference-rdrand16-step-rdrand32-step-rdrand64-step
        unsigned int HardwareGeneratedRandomNumber = NULL;
        const int Success = _rdrand32_step( &HardwareGeneratedRandomNumber );
        if ( Success == TRUE ) 
            return HardwareGeneratedRandomNumber;
		else
			printf("[%s] _rdrand32_step failed!\n", __FUNCTION__);
    }

    
    DWORD RandomValue = 0;

    for (DWORD i = 0; i < sizeof(DWORD); i++)
        RandomValue |= (DWORD)( (DWORD)( this->LCG_rand() % 256 ) << (8 * i) );

    const BYTE ArraySize = 16 * sizeof( DWORD ); 
    BYTE RandomArray[ ArraySize ] = {};
    ZeroMemory( RandomArray, sizeof(RandomArray) );

    for (int r = 0; r < 3; r++)
    {
        if ( r == 0 && g_OldCryptApi.Random( RandomArray, ArraySize )           != true ) 
            continue;

        if ( r == 1 && g_DualEllipticCurveRNG.Random( RandomArray, ArraySize )  != true  ) 
            continue;

        if ( r == 2 && g_FIPS186DSARNG.Random( RandomArray, ArraySize )         != true  ) 
            continue;

        DWORD Value = RandomCombineData<DWORD>( RandomArray,    ArraySize,  RandomArray[ ArraySize - 2 ] % 4 );
        RandomValue = RandomOperator<DWORD>(    RandomValue,    Value,      RandomArray[ ArraySize - 1 ] % 4 );
        continue;
    }
    return RandomValue;
}

DWORD64 RandomGenerator::GetQword( void )
{
#if defined(_M_X64)
    //https://en.wikipedia.org/wiki/RdRand
    if ( g_HardwareRngSupported_RDRND == true )
    {
        //https://software.intel.com/en-us/cpp-compiler-developer-guide-and-reference-rdrand16-step-rdrand32-step-rdrand64-step
        unsigned __int64 HardwareGeneratedRandomNumber = 0;
        const int Success = _rdrand64_step( &HardwareGeneratedRandomNumber );
        if ( Success == TRUE ) 
            return HardwareGeneratedRandomNumber;
		else
			printf("[%s] _rdrand64_step failed!\n", __FUNCTION__);
    }
#else
    if ( g_HardwareRngSupported_RDRND == true )
    {
        unsigned int Dwords[2] = { (unsigned int)(0), (unsigned int)(0) };
        int Success = FALSE;
        for (DWORD j = 0; j < 2; j++)
            Success += _rdrand32_step( &Dwords[j] );

        if ( Success == (int)( (int)TRUE + (int)TRUE ) )
            return (DWORD64)( Dwords[0] ) | (DWORD64)( (DWORD64)( Dwords[1] ) << 32 );
		else
			printf("[%s] _rdrand32_step failed!\n", __FUNCTION__);
    }
#endif

    DWORD64 RandomValue = NULL;
    for (DWORD64 i = 0; i < sizeof(DWORD64); i++)
        RandomValue |= (DWORD64)( (DWORD64)( this->LCG_rand() % 256 ) << (DWORD64)(8ui64 * i) );

    const BYTE ArraySize = 16 * sizeof( DWORD64 ); 
    BYTE RandomArray[ ArraySize ] = {};
    ZeroMemory( RandomArray, sizeof(RandomArray) );

    for (int r = 0; r < 3; r++)
    {
        if ( r == 0 && g_OldCryptApi.Random( RandomArray, ArraySize )           != true ) 
            continue;
        if ( r == 1 && g_DualEllipticCurveRNG.Random( RandomArray, ArraySize )  != true  ) 
            continue;
        if ( r == 2 && g_FIPS186DSARNG.Random( RandomArray, ArraySize )         != true  ) 
            continue;

        DWORD64 Value = RandomCombineData<DWORD64>( RandomArray,    ArraySize,  RandomArray[ ArraySize - 2 ] % 4 );
        RandomValue =   RandomOperator<DWORD64>(    RandomValue,    Value,      RandomArray[ ArraySize - 1 ] % 4 );
        continue;
    }
    return RandomValue;
}

CHAR* RandomGenerator::GetString( /*IN OUT*/CHAR* Buffer, /*IN*/DWORD Size )
{
    __ASSERT__( Buffer != NULL );
    __ASSERT__( Size > 0 );

    this->GetBuffer( Buffer, Size );

    const UINT8 PrintableFirst = (UINT8)' ';
    const UINT8 PrintableLast  = (UINT8)'~';

    const UINT8 PrintableChars = ( PrintableLast + 1 ) - PrintableFirst;

    for (DWORD i = 0; i < Size; i++)
    {
        const UINT8 NewChar = (UINT8)Buffer[ i ] % ( PrintableChars );
        Buffer[ i ] = (CHAR)( (UINT8)NewChar + (UINT8)PrintableFirst );
    }

    Buffer[ Size - 1 ] = (CHAR)NULL;
    return Buffer;
}

void RandomGenerator::GetBuffer( /*IN OUT*/ void* Address, /*IN*/ DWORD Size )
{
    __ASSERT__( Address != NULL );
    __ASSERT__( Size > 0 );

    //https://en.wikipedia.org/wiki/RdRand  
    if ( g_HardwareRngSupported_RDRND == true )
    {
        bool HWRNGSuccess = true;

        const DWORD NotAlignedSize = (DWORD)( (DWORD)Size % (DWORD)4ui32 );
        const DWORD Aligned_4Byte  = (DWORD)( (DWORD)Size / (DWORD)4ui32 );
        
        unsigned __int32 RandomNbr32 = 0ui32;

        for (DWORD i = 0ui32; i < Aligned_4Byte; i++)
        {
            if ( _rdrand32_step( &RandomNbr32 ) != TRUE )
            {
				printf("[%s] _rdrand32_step [1] failed!\n", __FUNCTION__);
                HWRNGSuccess = false;
                break;
            }
            *(DWORD*)( (DWORD_PTR)Address + (i * 4ui32) ) = (DWORD)(RandomNbr32);
        }

        if ( HWRNGSuccess == true && NotAlignedSize > 0ui32 )
        {
            for (DWORD i = 0ui32; i < NotAlignedSize; i++)
            {
                if ( _rdrand32_step( &RandomNbr32 ) != TRUE )
                {
					printf("[%s] _rdrand32_step [2] failed!\n", __FUNCTION__);
                    HWRNGSuccess = false;
                    break;
                }
                RandomNbr32 %= 256ui32;
                *(BYTE*)( (DWORD_PTR)Address + (Aligned_4Byte * 4ui32) + i ) = (BYTE)(RandomNbr32);
            }
        }
        if ( HWRNGSuccess == true ) 
                return;
    }
    
    bool MallocUsed = false;

    BYTE* Buffer = (BYTE*)0;
    if ( Size > 0x1000ui32 )
    {
        Buffer = (BYTE*)malloc( Size );
        MallocUsed = true;
    }
    else
    {
        Buffer = (BYTE*)alloca( Size );
        if ( Buffer == NULL )
        {
            Buffer = (BYTE*)malloc( Size );
            MallocUsed = true;
        }
    }
    __ASSERT__( Buffer != NULL );

    BYTE* p = (BYTE*)Address;
    BYTE RandomOp = NULL;

    this->LCG_randBuffer( p, Size );

    for (int r = 0; r < 3; r++)
    {
        p = (BYTE*)Address;
        RandomOp = *(BYTE*)p % 4;

        if ( r == 0 && g_OldCryptApi.Random( (BYTE*)Buffer, Size )      != true ) 
            continue;
        if ( r == 1 && g_DualEllipticCurveRNG.Random( Buffer, Size )    != true  ) 
            continue;
        if ( r == 2 && g_FIPS186DSARNG.Random( Buffer, Size )           != true  ) 
            continue;

        for (DWORD i = NULL; i < Size; i++, p++)
            { *(BYTE*)p = RandomOperator( *(BYTE*)p, Buffer[i], RandomOp); };

        continue;
    }
    

    if ( MallocUsed == true )
        free( Buffer );
}

unsigned int RandomGenerator::GenerateRandomSeed( void )
{
    UINT cookie = 0;
    FILETIME SystemTimeAsFileTime = {};
    LARGE_INTEGER PerformanceCounter = {};
    LARGE_INTEGER InterruptCounter = {};
    LARGE_INTEGER TickCount64 = {};
    LARGE_INTEGER AuxiliaryCounterValue = {};
    LARGE_INTEGER ConversionErrorValue = {};
    LARGE_INTEGER ProcessorIdleCycleTime = {};
    
    __int32 cpuInfo[ 4 ] = {}; //{ EAX, EBX, ECX, EDX }

    ZeroMemory( &SystemTimeAsFileTime, sizeof(FILETIME) );
    ZeroMemory( &PerformanceCounter, sizeof(LARGE_INTEGER) );
    ZeroMemory( &InterruptCounter, sizeof(LARGE_INTEGER) );
    ZeroMemory( &TickCount64, sizeof(LARGE_INTEGER) );
    ZeroMemory( &AuxiliaryCounterValue, sizeof(LARGE_INTEGER) );
    ZeroMemory( &ConversionErrorValue, sizeof(LARGE_INTEGER) );

    const HMODULE Kernel32  = GetModuleHandleW(L"kernel32.dll");
    const HMODULE KernelBase= GetModuleHandleW(L"kernelbase.dll");

    __ASSERT__( Kernel32 != NULL );
    __ASSERT__( KernelBase != NULL );

    ////////////////////////////////////// CPUID Based Start Value //////////////////////////////////////
    ZeroMemory( cpuInfo, sizeof(cpuInfo) );
    __cpuidex( (int*)cpuInfo, 0 /*EAX*/, 0 /*ECX*/ );

    QueryPerformanceCounter( (LARGE_INTEGER*)&PerformanceCounter );
    BYTE RandomOperatorId = (BYTE)( (DWORD)( (DWORD)( PerformanceCounter.LowPart >> 3 ) % 4) );

    const UINT HighestFunctionParameter = cpuInfo[/*EAX*/0];
    __ASSERT__( HighestFunctionParameter > 0 );

    for (UINT i = 0; i < HighestFunctionParameter; i++)
    {
        ZeroMemory( cpuInfo, sizeof(cpuInfo) );
        __cpuidex( (int*)cpuInfo, HighestFunctionParameter /*EAX*/, 0 /*ECX*/ );

        for (int j = 0; j < 4; j++)
            cookie = (UINT)RandomOperator<UINT>( (UINT)(cookie), (UINT)(cpuInfo[j]), RandomOperatorId );
    }

    ZeroMemory( cpuInfo, sizeof(cpuInfo) );
    __cpuidex( (int*)cpuInfo, /*Highest Extended Function Parameter => */ 0x80000000 /*EAX*/, 0 /*ECX*/ );

    QueryPerformanceCounter( (LARGE_INTEGER*)&PerformanceCounter );
    RandomOperatorId = (BYTE)( (DWORD)( (DWORD)( PerformanceCounter.LowPart >> 7 ) % 4 ) );

    const UINT HighestExtendedFunctionParameter = cpuInfo[/*EAX*/0];
    __ASSERT__( HighestExtendedFunctionParameter > 0x80000000 );

    for (UINT i = 0x80000000; i < HighestExtendedFunctionParameter; i++)
    {
        ZeroMemory( cpuInfo, sizeof(cpuInfo) );
        __cpuidex( (int*)cpuInfo, i /*EAX*/, 0 /*ECX*/ );

        for (UINT j = 0; j < 4; j++)
            cookie = (UINT)RandomOperator<UINT>( (UINT)(cookie), (UINT)(cpuInfo[j]), RandomOperatorId );
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////////

    BOOL (__stdcall* FncGetPerformanceInfo)(PERFORMANCE_INFORMATION* pPerformanceInformation, DWORD cb) = NULL;
    FncGetPerformanceInfo = ( decltype(FncGetPerformanceInfo) )GetProcAddress( Kernel32, "GetPerformanceInfo" );
    if ( FncGetPerformanceInfo != NULL )
    {
        PERFORMANCE_INFORMATION PerformanceInformation = {};
        ZeroMemory( &PerformanceInformation, sizeof(PERFORMANCE_INFORMATION) );
        if ( FncGetPerformanceInfo( &PerformanceInformation, sizeof(PERFORMANCE_INFORMATION) ) == TRUE )
        {
            cookie ^= PerformanceInformation.ThreadCount;
            cookie ^= PerformanceInformation.HandleCount;
            cookie ^= PerformanceInformation.ProcessCount;
        }
    }

    BOOL (__stdcall* fncGlobalMemoryStatusEx)(LPMEMORYSTATUSEX lpBuffer) = NULL;
    fncGlobalMemoryStatusEx = ( decltype(fncGlobalMemoryStatusEx) )GetProcAddress( Kernel32, "GlobalMemoryStatusEx" );
    if ( fncGlobalMemoryStatusEx != NULL )
    {
        MEMORYSTATUSEX MemoryStatusEx = {};
        ZeroMemory( &MemoryStatusEx, sizeof(MEMORYSTATUSEX) );
        if ( fncGlobalMemoryStatusEx( &MemoryStatusEx ) == TRUE )
        {
            const UINT64 XorValue = (UINT64)( (UINT64)( (UINT64)(MemoryStatusEx.dwMemoryLoad) * (UINT64)(cookie) ) * (UINT64)2096687ui64 ) >> 7;
            cookie ^= (UINT)( XorValue & 0xFFFFFFFF );
        }
    }

    //https://docs.microsoft.com/en-us/windows/win32/api/realtimeapiset/nf-realtimeapiset-queryidleprocessorcycletime
    BOOL (WINAPI* fncQueryIdleProcessorCycleTime)( PULONG BufferLength, PULONG64 ProcessorIdleCycleTime ) = NULL;
    fncQueryIdleProcessorCycleTime = ( decltype(fncQueryIdleProcessorCycleTime) )GetProcAddress( Kernel32, "QueryIdleProcessorCycleTime" );
    if ( fncQueryIdleProcessorCycleTime != NULL )
    {
        ULONG BufferLength = sizeof(LARGE_INTEGER);
        if ( fncQueryIdleProcessorCycleTime( &BufferLength, (ULONG64*)&ProcessorIdleCycleTime.QuadPart ) == TRUE )
        {
            cookie ^= ProcessorIdleCycleTime.LowPart;
            cookie ^= ProcessorIdleCycleTime.HighPart;
        }
    }

    GetSystemTimeAsFileTime( (LPFILETIME)&SystemTimeAsFileTime );

    cookie ^= SystemTimeAsFileTime.dwLowDateTime;
    cookie ^= SystemTimeAsFileTime.dwHighDateTime;
    cookie ^= GetCurrentProcessId( );
    cookie ^= GetCurrentThreadId( );

    TickCount64.QuadPart = GetTickCount64( );

    cookie ^= TickCount64.LowPart;
    cookie ^= TickCount64.HighPart;

    //https://docs.microsoft.com/en-us/windows/win32/api/realtimeapiset/nf-realtimeapiset-queryunbiasedinterrupttime
    BOOL (WINAPI*fncQueryUnbiasedInterruptTime)( PULONGLONG UnbiasedTime ) = NULL;
    fncQueryUnbiasedInterruptTime = ( decltype(fncQueryUnbiasedInterruptTime) )GetProcAddress( Kernel32, "QueryUnbiasedInterruptTime" );

    //https://docs.microsoft.com/en-us/windows/win32/api/realtimeapiset/nf-realtimeapiset-queryinterrupttime
    void (WINAPI*fncQueryInterruptTime)( PULONGLONG Time ) = NULL;
    fncQueryInterruptTime = ( decltype(fncQueryInterruptTime) )GetProcAddress( KernelBase, "QueryInterruptTime" );

    if ( fncQueryInterruptTime != NULL )
    {
        fncQueryInterruptTime( (PULONGLONG)&InterruptCounter.QuadPart );
        cookie ^= InterruptCounter.LowPart;
        cookie ^= InterruptCounter.HighPart;
    }
    else
    if ( fncQueryUnbiasedInterruptTime != NULL && 
         fncQueryUnbiasedInterruptTime( (PULONGLONG)&InterruptCounter.QuadPart ) == TRUE )
    {
        cookie ^= InterruptCounter.LowPart;
        cookie ^= InterruptCounter.HighPart;
    }

    this->LCGGeneratorIndex = cookie % 10;
    printf("[+] LCG start index: %u\n",this->LCGGeneratorIndex);

    //https://docs.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancecounter
    if ( QueryPerformanceCounter( (LARGE_INTEGER*)&PerformanceCounter ) == TRUE )
    {
        cookie ^= PerformanceCounter.LowPart;
        cookie ^= PerformanceCounter.HighPart;
    }

    //https://docs.microsoft.com/en-us/windows/win32/api/realtimeapiset/nf-realtimeapiset-convertperformancecountertoauxiliarycounter
    HRESULT (WINAPI* fncConvertPerformanceCounterToAuxiliaryCounter)(   ULONGLONG ullPerformanceCounterValue, 
                                                                        PULONGLONG lpAuxiliaryCounterValue, 
                                                                        PULONGLONG lpConversionError 
                                                                    ) = NULL;
    fncConvertPerformanceCounterToAuxiliaryCounter = ( decltype(fncConvertPerformanceCounterToAuxiliaryCounter) )GetProcAddress( KernelBase, "ConvertPerformanceCounterToAuxiliaryCounter");
    if ( fncConvertPerformanceCounterToAuxiliaryCounter != NULL &&
         QueryPerformanceCounter( (LARGE_INTEGER*)&PerformanceCounter ) == TRUE)
    {
        const HRESULT 
                hResult = fncConvertPerformanceCounterToAuxiliaryCounter(   (ULONGLONG)PerformanceCounter.QuadPart, 
                                                                            (PULONGLONG)&AuxiliaryCounterValue.QuadPart, 
                                                                            (PULONGLONG)&ConversionErrorValue.QuadPart );
        if ( hResult == S_OK )
        {
            if ( AuxiliaryCounterValue.LowPart  != PerformanceCounter.LowPart &&
                 AuxiliaryCounterValue.HighPart != PerformanceCounter.HighPart)
            {       
                cookie ^= AuxiliaryCounterValue.LowPart;
                cookie ^= AuxiliaryCounterValue.HighPart;
            }
        }
    }
    
    //https://en.wikipedia.org/wiki/RdRand
    if ( g_HardwareRngSupported_RDSEED == true )
    {
#if _MSC_VER >= 1910
        //https://software.intel.com/en-us/cpp-compiler-developer-guide-and-reference-rdseed16-step-rdseed32-step-rdseed64-step
        unsigned __int32 HardwareGeneratedSeed = NULL;
        const int Success = _rdseed32_step( &HardwareGeneratedSeed );
        if ( Success == TRUE ) 
            cookie ^= HardwareGeneratedSeed;
		else
			printf("[%s] _rdseed32_step failed!\n", __FUNCTION__);
#endif
    }
    else
    if ( g_HardwareRngSupported_RDRND == true )
    {
        //https://software.intel.com/en-us/cpp-compiler-developer-guide-and-reference-rdrand16-step-rdrand32-step-rdrand64-step
        unsigned int HardwareGeneratedRandomNumber = NULL;
        const int Success = _rdrand32_step( &HardwareGeneratedRandomNumber );
        if ( Success == TRUE ) 
            cookie ^= HardwareGeneratedRandomNumber;
		else
			printf("[%s] _rdrand32_step failed!\n", __FUNCTION__);
    }

    return cookie;
};

//Linear congruential generator
int RandomGenerator::LCG_rand( void )
{
    const DWORD CurrentThreadId = GetCurrentThreadId();
    if ( CurrentThreadId != this->LCG_ThreadId )
        printf("FATAL ERROR: %s can not be used multithreaded!\n", __FUNCTION__);

    LCGGeneratorIndex = ( LCGGeneratorIndex + 1 ) % 10;

    
    const LinearCongruentialGenerator Generator = GeneratorValues[ LCGGeneratorIndex ];

    unsigned int Number = Generator.multiplier * this->LCGState[ LCGGeneratorIndex ] + Generator.increment;

    const __int32 modulus = (__int32)(Generator.modulus);
    if ( modulus != (__int32)(-1i32) )
        Number = (unsigned int)( Number % ((unsigned int)(modulus)) );

    this->LCGState[ LCGGeneratorIndex ] = Number;

    Number = (unsigned int)( Number >> Generator.Shift ) & Generator.Mask;
    return Number;
}

void RandomGenerator::LCG_randBuffer( /*IN OUT*/ void* Address, /*IN*/ DWORD Size)
{
    __ASSERT__( Address != NULL );
    __ASSERT__( Size > 0 );

    BYTE* Pointer = (BYTE*)( (DWORD_PTR)Address + (DWORD_PTR)0 );

    LinearCongruentialGenerator LocalGeneratorValues[10] = {};
    unsigned int Local_LCGState[10] = {};

    for (int c1 = 0; c1 < 10; c1++)
    {
        Local_LCGState[c1] = this->LCGState[c1];
        LocalGeneratorValues[c1] = GeneratorValues[c1];
    }

    unsigned int Index = this->LCGGeneratorIndex;
    
    for (DWORD i = 0; i < Size; i++, Pointer++)
    {
        Index = ( Index + 1 ) % 10;
        
        unsigned int Number = Local_LCGState[ Index ];

        Number *= LocalGeneratorValues[Index].multiplier;
        Number += LocalGeneratorValues[Index].increment;

        const signed __int32 modulus = (signed __int32)( LocalGeneratorValues[Index].modulus );
        if ( modulus != (signed __int32)(-1i32) )
            Number %= (unsigned int)( modulus );

        Local_LCGState[ Index ] = Number;

        Number >>= LocalGeneratorValues[Index].Shift;
        *(BYTE*)Pointer = (BYTE)( Number );
    }

    for (int c1 = 0; c1 < 10; c1++)
        this->LCGState[c1] = Local_LCGState[c1];
    this->LCGGeneratorIndex = Index;
}

bool RandomGenerator::checkHardwareRNG( void )
{
	unsigned __int32 RdSeed32Cntr = 0;
	unsigned __int32 RdSeed32Value = 0;

	unsigned __int32 RdRand32Cntr = 0;
	unsigned __int32 RdRand32Value = 0;
	
	//check if hardware random number generator is bugged.
	//Some CPUs always return the same for some reason.

	for (unsigned int i = 0; i < 32; i++)
	{
		if ( g_HardwareRngSupported_RDSEED == true )
		{
	#if _MSC_VER >= 1910
			//https://software.intel.com/en-us/cpp-compiler-developer-guide-and-reference-rdseed16-step-rdseed32-step-rdseed64-step
			unsigned int HardwareGeneratedRandomNumber = NULL;
			const int Success = _rdseed32_step( &HardwareGeneratedRandomNumber );
			if ( Success == TRUE )
			{
				if ( i == 0 )
					RdSeed32Value = HardwareGeneratedRandomNumber;
				else
				{
					if ( RdSeed32Value == HardwareGeneratedRandomNumber )
						RdSeed32Cntr += 1;
				}
			}
	#endif
		}

		if ( g_HardwareRngSupported_RDRND == true )
		{
			//https://software.intel.com/en-us/cpp-compiler-developer-guide-and-reference-rdrand16-step-rdrand32-step-rdrand64-step
			unsigned int HardwareGeneratedRandomNumber = NULL;
			const int Success = _rdrand32_step( &HardwareGeneratedRandomNumber );
			if ( Success == TRUE )
			{
				if ( i == 0 )
					RdRand32Value = HardwareGeneratedRandomNumber;
				else
				{
					if ( RdRand32Value == HardwareGeneratedRandomNumber )
						RdRand32Cntr += 1;
				}
			}

		}
	}
	//if more than half of the values are the same, its bugged.
	if ( RdRand32Cntr > 16 || RdSeed32Cntr > 16 )
		return false;

	return true;
}
