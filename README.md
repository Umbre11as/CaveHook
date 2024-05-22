# CaveHook
Small library for hooking functions in same process

## Getting started
1. Download and unpack zip from [releases](https://github.com/Umbre11as/CaveHook/releases)
2. Include and link using your build system
3. See the examples

## Quick example
```c++
QWORD original;

void HOOKCALLBACK Detour(int arg1, int arg2) {
    printf("hooked\n");
    return reinterpet_cast<decltype(&Detour)>(original)(arg1, arg2);
}

bool status = CaveHook(0x123, &Detour, reinterpret_cast<LPVOID*>(&original));
if (!status) {
    fprintf(stderr, "%d\n", CaveLastError());
}
```

## Enhanced example
```c++
QWORD original;

void HOOKCALLBACK Detour(int arg1, int arg2) {
    printf("hooked\n");
    return reinterpet_cast<decltype(&Detour)>(original)(arg1, arg2);
}

HOOK_DATA data{};
bool status = CaveHookEx(0x123, &Detour, reinterpret_cast<LPVOID*>(&original), &data);
if (!status) {
    fprintf(stderr, "%d\n", CaveLastError());
} else {
    printf("Hook placed at address=%p,detour=%p,trampoline=%p,prologue:", data.Target, data.Detour, data.Trampoline);
    for (SIZE_T i = 0; i < data.Prologue.Length; i++)
        printf("%02X ", data.Prologue.Buffer[i]);
    printf("\n");
}
```

## How it works?
*From my blog*
### Introduction
Who knows, what we need in this life.
Personally, I usually use hooks in my projects, but up to this point, I was using someone else’s library. That’s why I wanted to make my own library and share my experience to other people
Let's go!

### Theory
Hooks - A technology for intercepting someone else's function in same process. They can be used for fixing bugs in old games or substitute information from calls.

Let's imagine there is a function that we want to hook:

![](https://i.ibb.co/r4qzSN5/Target1.png)

In order, to hook it, we just need to place jmp at the beginnning of it. It's recommended that the hook be 5 bytes long.
<details>
  <summary>Spoiler</summary>
  But why? Based on my experience, after hooking the DX11 Present, Discord overlay calls from Present+5, which is brokes my old hook with 14 bytes long.
</details>

A jmp of 5 bytes in length is calculated relative to target function. It adds to destination address current rip + instruction size (5). Okay, adding it:
```c++
*reinterpret_cast<BYTE*>(target) = 0xE9;
*reinterpret_cast<DWORD*>(target + 1) = detour - target - 5;
```

![](https://i.ibb.co/HDspb1D/Target4-1.png)

Done. The theory ends there. If no kidding, then this is really, in a sense, the end. And then I want to call the original function and that's the start of shit.
Let's figure out in order what our jmp has ruined:

#### 1. Prologue / Copy original bytes

![](https://i.ibb.co/s1Mgv3Y/Frame-3-1.png)

As you can see, the prologue (first 5 bytes) have been removed. It breaks the function logic and we need to save the prologue. We can't copy exactly 5 bytes, because next instruction can be bigger than 5 bytes.
If you don't understand, see the pictures:

![](https://i.ibb.co/jWfXZqg/Frame-3-3.png)

Explanation of 2 picture: We copied 2 instructions and piece of 3 instruction. Is it possible to copy just a piece? We will just have 1 byte lying around in memory, which will cause an error (access violation).

Therefore downloading a disassembler library (I do not recommend Zydis, because after disassembling my function it saw fit to clean uo the fuck knows that and give me an access violation) and disassembling the target function while prologue length is bigger whan 5 bytes of jmp.

*(omg, I worded the sentence too badly, just see the code)*
```c++
BYTE* FindPrologue(QWORD target, SIZE_T jmpLength, SIZE_T* resultLength) {
	SIZE_T prologueLength = 0;
	for (SIZE_T i = 0; i < count; i++) {
		if (prologueLength > jmpLength)
			break; // "while prologue length is bigger whan 5 bytes of jmp"
		
		prologueLength += instructions[i].size;
	}
	
	*resultLength = prologueLength;
	BYTE* prologue = new BYTE[prologueLength];
	memcpy(prologue, reinterpret_cast<LPCVOID>(address), prologueLength);
	
	return prologue;
}
```

#### 2. Where insert original bytes?
Good question is, where do we insert these bytes? The answer to it is the name of this hook - Trampoline. We need to allocate the buffer, which is named Trampoline with size of copied bytes + size for jmp (hehehe, in trampoline I will use big jmp (14 bytes)). Do it!
```c++
LPVOID CreateTrampoline(QWORD jmpTo, BYTE* prologue, SIZE_T prologueLength) {
	LPVOID buffer = VirtualAlloc(nullptr, prologueLength + 14, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy(buffer, prologue, prologueLength);
	BYTE directJmp[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	memcpy(directJmp + 6, &jmpTo, sizeof(jmpTo));
	memcpy(reinterpret_cast<LPVOID>(reinterpret_cast<QWORD>(buffer) + prologueLength), directJmp, 14);
	
	return buffer;
}
```

![](https://i.ibb.co/34srfHb/Trampoline.png)

#### 3. The end? No AHAHAHHAHAH
*I think this is the best chapter*
But what is still wrong, why are you still getting access violation? I think if I hadn't told you, you wouldn't have guessed. And yes, until I downloaded the disassembler library and looked at what is actually hidden behind the beautiful code in x64dbg... JMP, MOV and etc IS NOT DIRECTIONAL
*(Think I'm weird, but I didn't know that)*

Explanation: In x64dbg you see `jmp 0x123` or `mov rax, 0x456` but it encodes absolutally in a different way. `jmp [rip+0x10]` `mov rax, rip + size + imm`
And yes, you understand me correctly, they were calculated once and remained in place after copying them into the trampoline.
LET'S GOOOOOOOOOOOOO

```c++
void RelocateInstructions(QWORD target, LPVOID trampoline, SIZE_T prologueLength) {
	// disassemble trampoline with size of prologue
	
	for (SIZE_T i = 0; i < count; i++) {
		cs_insn instruction = instructions[i];
		QWORD old = target + (reinterpret_cast<QWORD>(trampoline) - instruction.address);
		for (BYTE j = 0; j < instruction.detail->x86.op_count; j++) {
			cs_x86_op operand = instruction.detail->x86.operands[i];
			if (operand.type == X86_OP_MEM && operand.mem.base == X86_REG_RIP) { // Rip relative addressing
				LONGLONG displacement = operand.mem.disp;
				QWORD calculatedValue = old + displacement + instruction.size;
				
				DWORD result = static_cast<DWORD>(calculatedValue - instruction.address - instruction.size);
				memcpy(reinterpret_cast<LPVOID>(instruction.address + 2), &result, sizeof(result));
			} else if ((instruction.bytes[0] & 0xFD) == 0xE9) {
				QWORD destination = old + instruction.size + instruction.detail->x86.operands[0].imm; // destination stoles in operand with index 0
				DWORD result = destination - (instruction.address + instruction.size * 2);
				
				memcpy(reinterpret_cast<LPVOID>(instruction.address + 1), &result, sizeof(result));
			}
		}
	}
}
```

#### 4. Happy end
