#pragma once

#include <Windows.h>
#include <libloaderapi.h>
#include <stdio.h>
#include <cstdint>

// Borrowed macros
#define InRange(x,a,b)  (x >= a && x <= b) 
#define Bits( x )		(InRange((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xa) : (InRange(x,'0','9') ? x - '0' : 0))
#define Byte( x )		(Bits(x[0]) << 4 | Bits(x[1]))

namespace Signature {
	uintptr_t FindPattern(uintptr_t Start, uintptr_t End, const char* Pattern) {
		const char* PatternCopy = Pattern;
		uintptr_t Match = NULL;

		for (uintptr_t Current = Start; Current < End; Current++) {
			if (!*PatternCopy) return Match;
			if (*(unsigned char*)PatternCopy == '\?' || *(unsigned char*)Current == Byte(PatternCopy))
			{
				Match = !Match ? Current : Match;
				if (!PatternCopy[2]) return Match;
				PatternCopy += (*(unsigned short*)PatternCopy == '\?\?' || *(unsigned char*)PatternCopy != '\?') ? 3 : 2;
			}
			else
			{
				PatternCopy = Pattern;
				Match = 0;
			}
		}

		return 0; // Should never happen
	}

	template <class T>
	T FindPatternInModule(HMODULE Module, const char* Pattern) {
		PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)Module;
		PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)(((ULONG_PTR)Module) + pDOSHeader->e_lfanew);
		return (T)FindPattern((ULONG_PTR)Module, ((ULONG_PTR)Module) + pNTHeaders->OptionalHeader.SizeOfImage, Pattern);
	}
}