//https://github.com/Speedi13/CPUID

#pragma once
//https://docs.microsoft.com/en-us/cpp/intrinsics/cpuid-cpuidex
#include <intrin.h>

#if     ( _MSC_VER >= 800 )
#pragma warning(disable:4514)
#ifndef __WINDOWS_DONT_DISABLE_PRAGMA_PACK_WARNING__
#pragma warning(disable:4103)
#endif
#if _MSC_VER >= 1200
#pragma warning(push)
#endif
#pragma warning(disable:4001)
#pragma warning(disable:4201)
#pragma warning(disable:4214)
#endif

struct CpuInfo
{
    int HighestFunctionParameter;
    int HighestExtendedFunctionParameter;

    char ManufacturerID[12 + 1];//12 bytes + 1 byte for null-terminator
    //=> "GenuineIntel"

    char ProcessorNameStringIdentifier[48 + 1];//48 bytes + 1 byte for null-terminator
    //=> "        Intel(R) Core(TM) i5-2500 CPU @ 3.30GHz"

    //////////////////////////////// Processor Version Information ////////////////////////////////
    struct
    {
        //on intel only use if FamilyID == 0x0F
        //value to display in that case: Extended_Family_ID + Family_ID;
        int ExtendedFamilyID;

        //INTEL only
        int ExtendedModelID;
    
        int ProcessorType;
        //=> [0] -> Original OEM Processor
        //=> [1] -> Intel OverDrive Processor
        //=> [2] -> Dual processor (not applicable to Intel486 processors)
        //=> [3] -> Intel reserved

        int FamilyID;
        int Model;
        int SteppingID;

    } ProcessorVersionInformation;
    ///////////////////////////////////////////////////////////////////////////////////////////////

    /////////////////////////////////// Additional Information ////////////////////////////////////
    struct
    {
        int BrandIndex;
        int CLFLUSH;

        //AMD only
        int LogicalProcessorCount;

        int LocalApicId;

    } AdditionalInformation;
    ///////////////////////////////////////////////////////////////////////////////////////////////

    //////////////////////////////////// Feature Information //////////////////////////////////////
    struct
    {
        //https://en.wikipedia.org/w/index.php?title=CPUID#EAX=1:_Processor_Info_and_Feature_Bits

        //EDX-Register:
        union
        {
            struct
            {
                bool FPU;           //Onboard x87 FPU
                bool VME;           //Virtual 8086 mode extensions (such as VIF, VIP, PIV)
                bool DE;            //Debugging extensions (CR4 bit 3)
                bool PSE;           //Page Size Extension
                bool TSC;           //Time Stamp Counter
                bool MSR;           //Model-specific registers
                bool PAE;           //Physical Address Extension
                bool MCE;           //Machine Check Exception
                bool CX8;           //CMPXCHG8 (compare-and-swap) instruction
                bool APIC;          //Onboard Advanced Programmable Interrupt Controller
                bool EDX_BIT10;
                bool SEP;           //SYSENTER and SYSEXIT instructions
                bool MTRR;          //Memory Type Range Registers
                bool PGE;           //Page Global Enable bit in CR4
                bool MCA;           //Machine check architecture
                bool CMOV;          //Conditional move and FCMOV instructions
                bool PAT;           //Page Attribute Table
                bool PSE_36;        //36-bit page size extension
                bool PSN;           //Processor Serial Number
                bool CLFSH;         //CLFLUSH instruction (SSE2)
                bool EDX_BIT20;
                bool DS;            //Debug store: save trace of executed jumps
                bool ACPI;          //Onboard thermal control MSRs for ACPI
                bool MMX;           //MMX instructions
                bool FXSR;          //FXSAVE, FXRESTOR instructions, CR4 bit 9
                bool SSE;           //SSE instructions (a.k.a. Katmai New Instructions)
                bool SSE2;          //SSE2 instructions
                bool SS;            //CPU cache implements self-snoop
                bool HTT;           //Hyper-threading
                bool TM;            //Thermal monitor automatically limits temperature
                bool IA64;          //IA64 processor emulating x86
                bool PBE;           //Pending Break Enable (PBE# pin) wakeup capability
            } DUMMYSTRUCTNAME;

            bool EDX[32];

        } DUMMYUNIONNAME;

        //ECX-Register:
        union
        {
            struct
            {
                bool SSE3;          //Prescott New Instructions-SSE3 (PNI)
                bool PCLMULQDQ;     //PCLMULQDQ
                bool DTES64;        //64-bit debug store (edx bit 21) 
                bool MONITOR;       //MONITOR and MWAIT instructions (SSE3) 
                bool DS_CPL;        //CPL qualified debug store 
                bool VMX;           //Virtual Machine eXtensions
                bool SMX;           //Safer Mode Extensions (LaGrande) 
                bool EST;           //Enhanced SpeedStep
                bool TM2;           //Thermal Monitor 2
                bool SSSE3;         //Supplemental SSE3 instructions 
                bool CNXT_ID;       //L1 Context ID 
                bool SDBG;          //Silicon Debug interface 
                bool FMA;           //Fused multiply-add (FMA3)
                bool CX16;          //CMPXCHG16B instruction 
                bool XTPR;          //Can disable sending task priority messages 
                bool PDCM;          //Perfmon & debug capability 
                bool ECX_BIT16;
                bool PCID;          //Process context identifiers (CR4 bit 17)
                bool DCA;           //Direct cache access for DMA writes
                bool SSE41;         //SSE4.1 instructions
                bool SSE42;         //SSE4.2 instructions 
                bool X2APIC;        //x2APIC
                bool MOVBE;         //MOVBE instruction (big-endian) 
                bool POPCNT;        //POPCNT instruction 
                bool TSC_DEADLINE;  //APIC implements one-shot operation using a TSC deadline value
                bool AES;           //AES instruction set
                bool XSAVE;         //XSAVE, XRESTOR, XSETBV, XGETBV 
                bool OSXSAVE;       //XSAVE enabled by OS 
                bool AVX;           //Advanced Vector Extensions
                bool F16C;          //F16C (half-precision) FP feature 
                bool RDRND;         //RDRAND (intel on-chip random number generator) feature 
                bool HYPERVISOR;    //Hypervisor present (always zero on physical CPUs)
            } DUMMYSTRUCTNAME;

            bool ECX[32];
        } DUMMYUNIONNAME2;

    } FeatureInformation;
    ///////////////////////////////////////////////////////////////////////////////////////////////

    //////////////////////////////////// Feature Extended Information //////////////////////////////////////
    struct
    {
        //https://en.wikipedia.org/w/index.php?title=CPUID#EAX=7,_ECX=0:_Extended_Features
        //not used on AMD except for BMI1

        //EBX-Register:
        union
        {
            struct
            {
                bool FSGSBASE;              //Access to base of %fs and %gs
                bool IA32_TSC_ADJUST;
                bool SGX;                   //Software Guard Extensions
                bool BMI1;                  //Bit Manipulation Instruction Set 1
                bool HLE;                   //Transactional Synchronization Extensions
                bool AVX2;                  //Advanced Vector Extensions 2
                bool FDP_EXCPTN_ONLY;       //x87 FPU Data Pointer updated only on x87 exceptions if 1.
                bool SMEP;                  //Supervisor Mode Execution Prevention
                bool BMI2;                  //Bit Manipulation Instruction Set 2
                bool ERMS;                  //Enhanced REP MOVSB/STOSB
                bool INVPCID;               //INVPCID instruction
                bool RTM;                   //Transactional Synchronization Extensions
                bool PQM;                   //Platform Quality of Service Monitoring
                bool CS_DS_DEPRECATED;      //FPU CS and FPU DS deprecated
                bool MPX;                   //Intel MPX (Memory Protection Extensions)
                bool PQE;                   //Platform Quality of Service Enforcement
                bool AVX512F;               //AVX-512 Foundation
                bool AVX512DQ;              //AVX-512 Doubleword and Quadword Instructions
                bool RDSEED;                //RDSEED instruction 
                bool ADX;                   //Intel ADX (Multi-Precision Add-Carry Instruction Extensions)
                bool SMAP;                  //Supervisor Mode Access Prevention
                bool AVX512IFMA;            //AVX-512 Integer Fused Multiply-Add Instructions 
                bool PCOMMIT;               //PCOMMIT instruction
                bool CLFLUSHOPT;            //CLFLUSHOPT instruction
                bool CLWB;                  //CLWB instruction
                bool INTEL_PT;              //Intel Processor Trace
                bool AVX512PF;              //AVX-512 Prefetch Instructions
                bool AVX512ER;              //AVX-512 Exponential and Reciprocal Instructions
                bool AVX512CD;              //AVX-512 Conflict Detection Instructions
                bool SHA;                   //Intel SHA extensions
                bool AVX512BW;              //AVX-512 Byte and Word Instructions
                bool AVX512VL;              //AVX-512 Vector Length Extensions

            } DUMMYSTRUCTNAME;

            bool EBX[32];

        } DUMMYUNIONNAME;

        //ECX-Register:
        union
        {
            struct
            {
                bool PREFETCHWT1;           //PREFETCHWT1 instruction 
                bool AVX512VBMI;            //AVX-512 Vector Bit Manipulation Instructions 
                bool UMIP;                  //User-mode Instruction Prevention 
                bool PKU;                   //Memory Protection Keys for User-mode pages 
                bool OSPKE;                 //PKU enabled by OS 
                bool ECX_BIT5;
                bool AVX512VBMI2;           //AVX-512 Vector Bit Manipulation Instructions 2 
                bool ECX_BIT7;      
                bool GFNI;                  //Galois Field instructions
                bool VAES;                  //Vector AES instruction set (VEX-256/EVEX) 
                bool VPCLMULQDQ;            //CLMUL instruction set (VEX-256/EVEX) 
                bool AVX512VNNI;            //AVX-512 Vector Neural Network Instructions 
                bool AVX512BITALG;          //AVX-512 BITALG instructions 
                bool ECX_BIT13;
                bool AVX512VPOPCNTDQ;       //AVX-512 Vector Population Count Double and Quad-word 
                bool ECX_BIT15;
                bool ECX_BIT16;
                bool MAWAU_0;               //The value of userspace MPX Address-Width Adjust used by the BNDLDX and BNDSTX Intel MPX instructions in 64-bit mode 
                bool MAWAU_1;
                bool MAWAU_2;
                bool MAWAU_3;
                bool MAWAU_4;
                bool RDPID;                 //Read Processor ID Instruction
                bool ECX_BIT23;
                bool ECX_BIT24;
                bool ECX_BIT25;
                bool ECX_BIT26;
                bool ECX_BIT27;
                bool ECX_BIT28;
                bool ECX_BIT29;
                bool SGX_LC;                //SGX Launch Configuration 
                bool ECX_BIT31;
            } DUMMYSTRUCTNAME;

            bool ECX[32];

        } DUMMYUNIONNAME2;

        //EDX-Register:
        union
        {
            struct
            {
                bool EDX_BIT0;
                bool EDX_BIT1;
                bool AVX512_4VNNIW;     //AVX-512 4-register Neural Network Instructions 
                bool AVX512_4FMAPS;     //AVX-512 4-register Multiply Accumulation Single precision 
                bool EDX_BIT4;
                bool EDX_BIT5;
                bool EDX_BIT6;
                bool EDX_BIT7;
                bool EDX_BIT8;
                bool EDX_BIT9;
                bool EDX_BIT10;
                bool EDX_BIT11;
                bool EDX_BIT12;
                bool EDX_BIT13;
                bool EDX_BIT14;
                bool EDX_BIT15;
                bool EDX_BIT16;
                bool EDX_BIT17;
                bool PCONFIG;           //Platform configuration (Memory Encryption Technologies Instructions)
                bool EDX_BIT19;
                bool EDX_BIT20;
                bool EDX_BIT21;
                bool EDX_BIT22;
                bool EDX_BIT23;
                bool EDX_BIT24;
                bool EDX_BIT25;

                //https://software.intel.com/security-software-guidance/api-app/sites/default/files/336996-Speculative-Execution-Side-Channel-Mitigations.pdf
                bool IBRS_and_IBPB; //Speculation Control:
                                    //Indirect Branch Restricted Speculation (IBRS) and
                                    //Indirect Branch Prediction Barrier (IBPB)
                bool SingleThreadIndirectBranchPredictor; //Single Thread Indirect Branch Predictor (STIBP)
                bool L1D_FLUSH;
                bool IA32_ARCH_CAPABILITIES;
                bool EDX_BIT30;
                bool SpeculativeStoreBypassDisable; //as mitigation for Speculative Store Bypass
            } DUMMYSTRUCTNAME;

            bool EDX[32];

        } DUMMYUNIONNAME3;

    } FeatureExtendedInformation;
    ///////////////////////////////////////////////////////////////////////////////////////////////

    ///////////////////////////// AMD Feature Extended Information ////////////////////////////////
    struct
    {
        //https://en.wikipedia.org/w/index.php?title=CPUID#EAX=80000001h:_Extended_Processor_Info_and_Feature_Bits
        //not used on Intel

        //ECX-Register:
        union
        {
            struct
            {
                bool LAHF_LM;       //LAHF/SAHF in long mode 
                bool CMP_LEGACY;    //Hyperthreading not valid 
                bool SVM;           //Secure Virtual Machine
                bool EXTAPIC;       //Extended APIC space           
                bool CR8_LEGACY;    //CR8 in 32-bit mode 
                bool ABM;           //Advanced bit manipulation (lzcnt and popcnt)
                bool SSE4A;         //SSE4a
                bool MISALIGNSSE;   //Misaligned SSE mode 
                bool _3DNOWPREFETCH;//PREFETCH and PREFETCHW instructions 
                bool OSVW;          //OS Visible Workaround 
                bool IBS;           //Instruction Based Sampling
                bool XOP;           //XOP instruction set
                bool SKINIT;        //SKINIT/STGI instructions 
                bool WDT;           //Watchdog timer
                bool ECX_BIT14;     
                bool LWP;           //Light Weight Profiling
                bool FMA4;          //4 operands fused multiply-add
                bool TCE;           //Translation Cache Extension
                bool ECX_BIT18;
                bool NODEID_MSR;    //NodeID MSR 
                bool ECX_BIT20;
                bool TBM;           //Trailing Bit Manipulation
                bool TOPOEXT;       //Topology Extensions 
                bool PERFCTR_CORE;  //Core performance counter extensions 
                bool PERFCTR_NB;    //NB performance counter extensions 
                bool ECX_BIT25;
                bool DBX;           //Data breakpoint extensions 
                bool PERFTSC;       //Performance TSC 
                bool PCX_L2I;       //L2I perf counter extensions 
                bool ECX_BIT29;
                bool ECX_BIT30;             
                bool ECX_BIT31;
            } DUMMYSTRUCTNAME;

            bool ECX[32];

        } DUMMYUNIONNAME;

        //EDX-Register:
        union
        {
            struct
            {
                bool FPU;       //Onboard x87 FPU
                bool VME;       //Virtual mode extensions (VIF)
                bool DE;        //Debugging extensions (CR4 bit 3)
                bool PSE;       //Page Size Extension
                bool TSC;       //Time Stamp Counter
                bool MSR;       //Model-specific registers
                bool PAE;       //Physical Address Extension
                bool MCE;       //Machine Check Exception
                bool CX8;       //CMPXCHG8 (compare-and-swap) instruction
                bool APIC;      //Onboard Advanced Programmable Interrupt Controller
                bool EDX_BIT10;
                bool SYSCALL;   //SYSCALL and SYSRET instructions
                bool MTRR;      //Memory Type Range Registers
                bool PGE;       //Page Global Enable bit in CR4
                bool MCA;       //Machine check architecture
                bool CMOV;      //Conditional move and FCMOV instructions
                bool PAT;       //Page Attribute Table
                bool PSE36;     //36-bit page size extension
                bool EDX_BIT18;
                bool MP;        //Multiprocessor Capable
                bool NX;        //NX bit
                bool EDX_BIT21;
                bool MMXEXT;    //Extended MMX
                bool MMX;       //MMX instructions
                bool FXSR;      //FXSAVE, FXRSTOR instructions, CR4 bit 9
                bool FXSR_OPT;  //FXSAVE/FXRSTOR optimizations
                bool PDPE1GB;   //Gibibyte pages
                bool RDTSCP;    //RDTSCP instruction
                bool EDX_BIT28;
                bool LM;        //Long mode
                bool _3DNOWEXT; //Extended 3DNow!
                bool _3DNOW;    //3DNow!
            } DUMMYSTRUCTNAME;

            bool EDX[32];

        } DUMMYUNIONNAME2;

    } AMDFeatureExtendedInformation;
    ///////////////////////////////////////////////////////////////////////////////////////////////


    CpuInfo( void )
    {
        //https://docs.microsoft.com/en-us/cpp/intrinsics/cpuid-cpuidex?view=vs-2019

        //3.2 - CPUID—CPU Identification
        //https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf
        //AMD CPUID Documentation:
        //https://www.amd.com/system/files/TechDocs/25481.pdf

        __int32 cpuInfo[4] = {}; //{ EAX, EBX, ECX, EDX }

        __int32* EAX = (__int32*)&cpuInfo[0];
        __int32* EBX = (__int32*)&cpuInfo[1];
        __int32* ECX = (__int32*)&cpuInfo[2];
        __int32* EDX = (__int32*)&cpuInfo[3];

        /////////////////// Highest Function Parameter and Manufacturer ID ///////////////////
        ZeroMemory( cpuInfo, sizeof(cpuInfo) );
        
        //https://docs.microsoft.com/en-us/cpp/intrinsics/cpuid-cpuidex
        __cpuidex( (int*)cpuInfo, 0 /*EAX*/, 0 /*ECX*/ );
        HighestFunctionParameter = *EAX;
        

        *(__int32*)&this->ManufacturerID[0] = *(__int32*)EBX;
        *(__int32*)&this->ManufacturerID[4] = *(__int32*)EDX;
        *(__int32*)&this->ManufacturerID[8] = *(__int32*)ECX ;
        this->ManufacturerID[12] = NULL;
        //////////////////////////////////////////////////////////////////////////////////////



        //////////////////////// Highest Extended Function Parameter ///////////////////////
        ZeroMemory( cpuInfo, sizeof(cpuInfo) );

        //https://docs.microsoft.com/en-us/cpp/intrinsics/cpuid-cpuidex
        __cpuidex( (int*)cpuInfo, /*Highest Extended Function Parameter => */ 0x80000000 /*EAX*/, 0 /*ECX*/ );

        HighestExtendedFunctionParameter = *EAX;
        //////////////////////////////////////////////////////////////////////////////////////


        /////////////////////////// Processor Info and Feature Bits //////////////////////////
        ZeroMemory( cpuInfo, sizeof(cpuInfo) );

        //https://docs.microsoft.com/en-us/cpp/intrinsics/cpuid-cpuidex
        __cpuidex( (int*)cpuInfo, 1 /*EAX*/, 0/*ECX*/ );


        //Processor Version Information: EAX
        this->ProcessorVersionInformation.SteppingID        = (*EAX >>  0 ) & 0x0F;
        this->ProcessorVersionInformation.Model             = (*EAX >>  4 ) & 0x8F;
        this->ProcessorVersionInformation.FamilyID          = (*EAX >>  8 ) & 0x0F;
        this->ProcessorVersionInformation.ProcessorType     = (*EAX >> 12 ) & 0x03;
        this->ProcessorVersionInformation.ExtendedModelID   = (*EAX >> 16 ) & 0x0F;
        this->ProcessorVersionInformation.ExtendedFamilyID  = (*EAX >> 20 ) & 0xFF;

        //Additional Information: EBX
        this->AdditionalInformation.BrandIndex              = (*EBX >>  0 ) & 0x0F;
        this->AdditionalInformation.CLFLUSH                 = (*EBX >>  8 ) & 0x0F;
        this->AdditionalInformation.LogicalProcessorCount   = (*EBX >> 16 ) & 0x0F;
        this->AdditionalInformation.LocalApicId             = (*EBX >> 24 ) & 0x0F;

        //Feature Information: EDX
        for (int i = 0; i < 32; i++)
            this->FeatureInformation.EDX[i] = ( (*EDX >> i ) & 1 ) == 1;
        

        //Feature Information: ECX
        for (int i = 0; i < 32; i++)
            this->FeatureInformation.ECX[i] = ( (*ECX >> i ) & 1 ) == 1;
        //////////////////////////////////////////////////////////////////////////////////////
        
        /////////////////////////// Processor Extended Feature Bits //////////////////////////
        ZeroMemory( cpuInfo, sizeof(cpuInfo) );

        //https://docs.microsoft.com/en-us/cpp/intrinsics/cpuid-cpuidex
        __cpuidex( (int*)cpuInfo, /*Extended Feature Bits => */ 7 /*EAX*/, 0 /*ECX*/ );

        //Feature Extended Information: EBX
        for (int i = 0; i < 32; i++)
            this->FeatureExtendedInformation.EBX[i] = ( (*EBX >> i ) & 1 ) == 1;

        //Feature Extended Information: ECX
        for (int i = 0; i < 32; i++)
            this->FeatureExtendedInformation.ECX[i] = ( (*ECX >> i ) & 1 ) == 1;

        //Feature Extended Information: EDX
        for (int i = 0; i < 32; i++)
            this->FeatureExtendedInformation.EDX[i] = ( (*EDX >> i ) & 1 ) == 1;
        //////////////////////////////////////////////////////////////////////////////////////

        ///////////////////////// AMD Processor Extended Feature Bits ////////////////////////
        ZeroMemory( cpuInfo, sizeof(cpuInfo) );

        __cpuidex( (int*)cpuInfo, /*AMD Extended Feature Bits => */ 0x80000001ui32 /*EAX*/, 0 /*ECX*/ );

        //AMD Feature Extended Information: ECX
        for (int i = 0; i < 32; i++)
            this->AMDFeatureExtendedInformation.ECX[i] = ( (*ECX >> i ) & 1 ) == 1;

        //AMD Feature Extended Information: EDX
        for (int i = 0; i < 32; i++)
            this->AMDFeatureExtendedInformation.EDX[i] = ( (*EDX >> i ) & 1 ) == 1;
        //////////////////////////////////////////////////////////////////////////////////////

        /////////////////////////////// Processor Brand String //////////////////////////////
        if ( (unsigned __int32)this->HighestExtendedFunctionParameter >= (unsigned __int32)0x80000004ui32 )
        {
            for (int i = 0; i < 3; i++)
            {
                ZeroMemory( cpuInfo, sizeof(cpuInfo) );
                unsigned __int32 ArgEAX = (unsigned __int32)(0x80000002ui32) + (unsigned __int32)(i);

                //https://docs.microsoft.com/en-us/cpp/intrinsics/cpuid-cpuidex
                __cpuidex( (int*)cpuInfo, ArgEAX/*EAX*/, 0 /*ECX*/ );

                *(__int32*)&this->ProcessorNameStringIdentifier[ (i * 16) + (0 * 4) ] = *(__int32*)EAX;
                *(__int32*)&this->ProcessorNameStringIdentifier[ (i * 16) + (1 * 4) ] = *(__int32*)EBX;
                *(__int32*)&this->ProcessorNameStringIdentifier[ (i * 16) + (2 * 4) ] = *(__int32*)ECX;
                *(__int32*)&this->ProcessorNameStringIdentifier[ (i * 16) + (3 * 4) ] = *(__int32*)EDX;
            }
            this->ProcessorNameStringIdentifier[48] = '\0';
        }
        else
            ZeroMemory( this->ProcessorNameStringIdentifier, sizeof(this->ProcessorNameStringIdentifier) );
        //////////////////////////////////////////////////////////////////////////////////////
        ZeroMemory( cpuInfo, sizeof(cpuInfo) );
    }
};

#if     ( _MSC_VER >= 800 )
#if _MSC_VER >= 1200
#pragma warning(pop)
#else
#pragma warning(default:4001)
#pragma warning(default:4201)
#pragma warning(default:4214)
/* Leave 4514 disabled.  It's an unneeded warning anyway. */
#endif
#endif