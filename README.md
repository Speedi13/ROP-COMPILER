# ROP-COMPILER
ROP based CSGO, BF3, BF4 cheat

# What is ROP
The Wikipedia article about it describes it best:
> Return-oriented programming (ROP) is a computer security exploit technique that allows an attacker to execute code in the presence of security defenses such as executable space protection and code signing.[1]
>
> In this technique, an attacker gains control of the call stack to hijack program control flow and then executes carefully chosen machine instruction sequences that are already present in the machine's memory, called "gadgets".[2] Each gadget typically ends in a return instruction and is located in a subroutine within the existing program and/or shared library code. Chained together, these gadgets allow an attacker to perform arbitrary operations on a machine employing defenses that thwart simpler attacks.

https://en.wikipedia.org/wiki/Return-oriented_programming

The TL;DR is that return-oriented programming (ROP) is a commonly used technique in exploitation to gain code execution<br />

look below at [Compiler output](https://github.com/Speedi13/ROP-COMPILER/blob/master/README.md#compiler-output)

# Why ROP
CSGO is protected by Valve Anti-Cheat (short VAC)<br />
BF3 and BF4 are protected by PunkBuster (short PB)<br />
ROP should be very difficult to detect for these Anti-Cheats for the following reasons<br />
- The cheats program code consists of a list of volatile memory addresses that change with each game and computer restart
- Afaik VAC prefers to analyze memory pages that are marked as executable but for ROP the list of return-addresses doesn't require to be on an executable memory page. 
- Additionally the ROP-Compiler supports the option of inserting random padding into the ROP-chain.
<br />
So hopefully this cheat will be VAC / PB undetected for ever :wink:<br />

# ROP-Code
- [BF3_MinimapESP.asm](https://github.com/Speedi13/ROP-COMPILER/blob/master/CheatSourceCodes/BF3_MinimapESP.asm)
- [BF4_x86_MinimapESP.asm](https://github.com/Speedi13/ROP-COMPILER/blob/master/CheatSourceCodes/BF4_x86_MinimapESP.asm)
- [CSGO_GlowESP.asm](https://github.com/Speedi13/ROP-COMPILER/blob/master/CheatSourceCodes/CSGO_GlowESP.asm)
- [CSGO_MinimapESP.asm](https://github.com/Speedi13/ROP-COMPILER/blob/master/CheatSourceCodes/CSGO_MinimapESP.asm)
- [CSGO_Triggerbot.asm](https://github.com/Speedi13/ROP-COMPILER/blob/master/CheatSourceCodes/CSGO_Triggerbot.asm)

You can download a compiled binary of the Rop-Compiler from here:<br />
[![DOWNLOAD BUTTON](https://www.unknowncheats.me/forum/ambience/buttons/download_file.gif)](https://www.unknowncheats.me/forum/downloads.php?do=file&id=27687)

For a look into the compiled code look below at [Compiler output](https://github.com/Speedi13/ROP-COMPILER/blob/master/README.md#compiler-output)

# Compiler
## Data-types
In computer science a [Word](https://en.wikipedia.org/wiki/Word_(computer_architecture))s size is determined by the maximal number of bits the processor can process <br />
But Intel and Microsoft define a word as a 16bit number: <br />

| Bits | Bytes | Datatype name |
|---|---|---|
| 16 | 2 | WORD |
| 32 | 4 | DWORD |
| 64 | 8 | QWORD |
| 64 | 8 | DWORD64 |

For all data-types check microsofts documentation:<br />
https://docs.microsoft.com/en-us/windows/win32/winprog/windows-data-types <br />
## Accessible registers
### Native x86 registers
* EAX => ( Initialized to `GLOBAL_MinimumAddress` )
* ECX
* EDX
* EBX ( is also used by the compiler for jumps and writing to virtual registers )

### added virtual registers
* VR0 => ( Initialized to `GLOBAL_MinimumAddress` )
* VR1 => ( Initialized to random number )
* VR2 => ( Initialized to random number )
* VR3 => ( Initialized to `OFFSET_bSpotted` )
* VR4 => ( Initialized to `OFFSET_TeamNum` )
* VR5 => ( Initialized to `OFFSET_CrosshairId` )
* VR6 => ( Initialized to `OFFSET_FORCE_ATTACK` )
* VR7 => ( Initialized to `OFFSET_EntityList` )
* VR8 => ( Initialized to `OFFSET_LocalPlayer` )
* VR9 => ( Initialized to `OFFSET_GlowObjectManager` )

#### Read only register
* VMM => ( Initialized to the address of a 8192 Byte Read/Write memory page )

## Usable instructions
The instruction set is very limited and can be found in the [>>Gadgets.h<<](https://github.com/Speedi13/ROP-COMPILER/blob/master/RopCompiler/Gadgets.h) header <br />

### Compare two values
it's very rare to find a comparison instruction followed by a return, so I am using a trick:
```asm
;//if ( ECX != 0x28 ) goto l_skip
mov eax, 0x28
sub eax, ecx;//COMPARE EAX, ECX
jne l_skip
```
a substraction in x86 also effects the flags.<br />
so for example:
```asm
mov eax, 0x1
mov ecx, 0x1
sub eax, ecx
```
the ZeroFlag will be set to 1 by the substraction instruction.<br />

## Special instructions
#### Jump labels 
```asm
@l_LabelName:
```

#### Get address of jump label
```asm
mov ebx, @l_LabelName
```
#### Get address of Gadget
```asm
mov ebx, #xchg esp,ebx
```

#### Get address of API function
```asm
mov ebx, !user32.GetAsyncKeyState
```

#### Reading from Virtual Registers
```asm
mov ecx, VR8
```
<sub>the compiler will translate it to (each line a single gadget)</sub><br/>

```asm
xchg eax, ecx
pop eax ;//load virtual register address from stack
mov eax, DWORD PTR[eax]
xchg eax, ecx
```

#### Writing to Virtual Registers
```asm
mov VR8, ecx
```
<sub>note that ebx can't be written directly to a virtual register</sub><br/><br/>
<sub>the compiler will translate it to (each line a single gadget)</sub><br/>

```asm
xchg eax, ecx
pop ebx ;//load virtual register address from stack
mov DWORD PTR[ebx], eax
xchg eax, ecx
```

### Jumps
```asm
jne l_Start
```
note that a jump overwrites the ebx register!<br/>
look at the function `addJumpToRopChain` but basically its using a conditional move
```asm
mov ebx, @l_Start
cmovne esp,ebx
```
only that a conditional move directly to esp is very rare so it's utilizing exchange instructions to be able to use a more commonly used instruction like this: 
```asm
mov ebx, @l_Start
xchg ecx, ebx
mov eax, @l_continue543
cmovne eax,ecx
xchg ecx, ebx
xchg eax, ebp
@l_continue543:
```

## Compiler functions
| Execution order |         Function          | Description |
|---|---------------|---|
|1. | LoadFileToMemory | loads the raw assembly source-code file into memory |
|2. | GetCompilerSettings | searches for the compiler settings |
|3. | InitializeRopGadgets | depending on the compiler settings gadgets specified in the "Gadgets.h" header get searched |
|4. | BringYourOwnGadgets | the gadgets that didn't get found get placed into a with random data-filled buffer |
|5. | CompileCode | calls the four functions below |
|6. | => ReadInCode | the instructions get extracted from the source-code file and stored in the `InstructionCache` struct |
|7. | => ConvertToROP | builds the ROP-chain by retrieving the address of each instruction and adding it to the RopChain vector |
|8. | => HijackThreadStack | creates a new thread with `CreateRemoteThread` and overwrites the threads stack with the Rop-chain at a random position in the stack |
|9. | ==> RelocatingJumps | relocates all jump addresses to the address of the rop-chain in memory |
|10.| RemoveUnusedGadgets | removes not used gadgets from the gadget buffer created by the BringYourOwnGadgets function |
|11.| ResumeThread | starts the execution of the rop-chain |

## Compiler output
using the tool ReClass you can look inspect memory and look at the generated rop-chain<br />
### Raw thread stack
This is how the generated thread-stack (ROP-Chain) looks like:<br /><br />
![Image of rop-chain](https://github.com/Speedi13/ROP-COMPILER/blob/master/pictures/ROP_STACK_1.png)
### Thread stack with gadget code
Now on the right I added the assembler code that is at each address:<br /><br />
![Image of rop-chain](https://github.com/Speedi13/ROP-COMPILER/blob/master/pictures/ROP_STACK_2.png)
### Reclass
For a Tutorial on ReClass look at UC<br />
https://www.unknowncheats.me/forum/general-programming-and-reversing/120805-reclass-usuage-reclass-and-its-content.html

### ret instruction
the return instruction is essential for ROP.<br />
The CPU jumps ( by setting the InstructionPointer [on x86 EIP] ) to an address it reads from the stack<br />
to help understanding the instruction this how the CPU processes the `ret` instruction: 
```cpp
void Ret( )
{
	Eip = *(DWORD*)( Esp + 0x000000 );
	Esp = Esp + 4;
}
```

### pop instruction
gadgets for pop instructions are easy to find and can be used to set a register to a certain value <br />
to help understanding the instruction this how the CPU processes the `pop eax` instruction: <br />
```cpp
void PopEAX( )
{
	Eax = *(DWORD*)( Esp + 0x000000 );
	Esp = Esp + 4;
	Eip = Eip + 1;
}
```

### jumps in ROP
in ROP the stack pointer ESP becomes the instruction pointer so by changing it follwed by a return instruction a jump happens <br />
to do conditional jumps a conditional move instruction can be used:
```cpp
//Unsigned Conditional Jump
//  JE - JZ   - Equal/zero                  - ZF = 1
if ( memcmp( C, "je", 2 ) == 0 || memcmp( C, "jz", 2 ) == 0 )
{
	//"cmove esp,ebx"
	addJumpToRopChain( p, C, 2, "cmove" );
	continue;	
}
```
for unconditional jumps a `pop esp` or a `xchg esp, ebx` can be used<br />

Conditional jump instructions: [page: 184]<br />
https://software.intel.com/sites/default/files/managed/39/c5/325462-sdm-vol-1-2abcd-3abcd.pdf#G9.1746

Conditional Move Instructions: [page: 172]<br />
https://software.intel.com/sites/default/files/managed/39/c5/325462-sdm-vol-1-2abcd-3abcd.pdf#G9.17648
