#include "CaveHook.h"

#include "Allocator.h"
#include <capstone/capstone.h>

int lastError = 0;

BYTE* CreateDirectJmp(QWORD target) {
	BYTE* buffer = new BYTE[14];
	buffer[0] = 0xFF;
	buffer[1] = 0x25;
	buffer[2] = 0x00;
	buffer[3] = 0x00;
	buffer[4] = 0x00;
	buffer[5] = 0x00;
	memcpy(buffer + 6, &target, sizeof(target));

	return buffer;
}

bool PlaceDetourJmp(QWORD target, LPVOID detour) {
	DWORD oldProtect;
	VirtualProtect(reinterpret_cast<LPVOID>(target), 6, PAGE_EXECUTE_READWRITE, &oldProtect);

	// Sometimes the distance between detour and target is too large, so I allocate the buffer in the right place
	LPVOID readdress = VirtualAlloc(FindFreeRegion(reinterpret_cast<LPVOID>(target)), 15, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!readdress) {
		lastError = BUFFER_NOT_ALLOCATED;
		return false;
	}
	memcpy(readdress, CreateDirectJmp(reinterpret_cast<QWORD>(detour)), 14);

	// Placing 5 byte relative jmp to detour
	*reinterpret_cast<BYTE*>(target) = 0xE9;
	*reinterpret_cast<DWORD*>(target + 1) = reinterpret_cast<DWORD>(readdress) - static_cast<DWORD>(target) - 5;

	VirtualProtect(reinterpret_cast<LPVOID>(target), 6, oldProtect, &oldProtect);
	return true;
}

ByteBuffer FindPrologue(QWORD address, SIZE_T jmpLength) {
	csh handle;
	cs_insn* instructions;

	BYTE* data = new BYTE[jmpLength + 10];
	memcpy(data, reinterpret_cast<LPCVOID>(address), jmpLength + 10);

	cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
	SIZE_T count = cs_disasm(handle, data, jmpLength + 10, 0, 0, &instructions);

	SIZE_T prologueLength = 0;
	for (SIZE_T i = 0; i < count; i++) {
		if (prologueLength > jmpLength)
			break; // While prologue length is bigger whan 5 bytes of jmp

		prologueLength += instructions[i].size;
	}

	cs_free(instructions, count);
	cs_close(&handle);

	ByteBuffer buffer{};

	buffer.Buffer = new BYTE[prologueLength];
	memcpy(buffer.Buffer, reinterpret_cast<LPCVOID>(address), prologueLength);
	buffer.Length = prologueLength;

	return buffer;
}

void RelocateInstructions(QWORD oldAddress, LPVOID trampoline, SIZE_T prologueLength) {
	// Not all instructions are direct
	csh handle;
	cs_insn* instructions;

	BYTE* data = new BYTE[prologueLength];
	memcpy(data, trampoline, prologueLength);

	cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	SIZE_T count = cs_disasm(handle, data, prologueLength, 0, 0, &instructions);

	SIZE_T offset = 0; // It's more convenient for me
	for (SIZE_T i = 0; i < count; i++) {
		cs_insn instruction = instructions[i];

		for (BYTE i = 0; i < instruction.detail->x86.op_count; i++) {
			cs_x86_op operand = instruction.detail->x86.operands[i];
			if (operand.type == X86_OP_MEM && operand.mem.base == X86_REG_RIP) { // Rip relative addressing
				QWORD currentRip = reinterpret_cast<QWORD>(trampoline) + offset;
				QWORD oldRip = oldAddress + offset;
				LONGLONG displacement = operand.mem.disp;

				QWORD calculatedValue = oldRip + displacement + instruction.size;
				DWORD result = static_cast<DWORD>(calculatedValue - currentRip - instruction.size);
				memcpy(reinterpret_cast<LPVOID>(reinterpret_cast<QWORD>(trampoline) + offset + 2), &result, sizeof(result));

				break;
			} else if ((instruction.bytes[0] & 0xFD) == 0xE9) { // JMP
				ULONGLONG destination = oldAddress + offset + instruction.size + instruction.detail->x86.operands[0].imm;
				DWORD result = destination - (reinterpret_cast<QWORD>(trampoline) + offset + instruction.size * 2);

				memcpy(reinterpret_cast<LPVOID>(reinterpret_cast<QWORD>(trampoline) + offset + 1), &result, sizeof(result));
			}
		}

		offset += instruction.size;
	}

	cs_free(instructions, count);
	cs_close(&handle);

	delete[] data;
}

bool CreateTrampoline(QWORD target, ByteBuffer prologue, LPVOID* lpTrampoline) {
	// Creating trampoline for inserting original bytes + jmp to original function to continue execution
	LPVOID trampoline = VirtualAlloc(FindFreeRegion(reinterpret_cast<LPVOID>(target)), prologue.Length + 14, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!trampoline) {
		lastError = BUFFER_NOT_ALLOCATED;
		return false;
	}

	memcpy(trampoline, prologue.Buffer, prologue.Length);
	memcpy(reinterpret_cast<LPVOID>(reinterpret_cast<QWORD>(trampoline) + prologue.Length), CreateDirectJmp(target + prologue.Length), 14);
	*lpTrampoline = trampoline;

	return true;
}

bool CaveHookEx(QWORD target, LPVOID detour, LPVOID* original, HOOK_DATA* hookData) {
	ByteBuffer prologue = FindPrologue(target, 5);
	if (!PlaceDetourJmp(target, detour))
		return false;

	LPVOID trampoline;
	if (!CreateTrampoline(target, prologue, &trampoline))
		return false;

	RelocateInstructions(target, trampoline, prologue.Length);

	if (original)
		*original = trampoline;
	
	hookData->Target = target;
	hookData->Detour = detour;
	hookData->Trampoline = trampoline;
	hookData->Prologue = prologue;

	return true;
}

bool CaveHook(QWORD target, LPVOID detour, LPVOID* original) {
	HOOK_DATA ignored{};
	return CaveHookEx(target, detour, original, &ignored);
}

int CaveLastError() {
	return lastError;
}
