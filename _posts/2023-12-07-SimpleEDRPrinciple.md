---
layout: post
title: Simple EDR Principle
subtitle: There's lots to learn!
tags: [CyberSec]
comments: true
---

## How EDR works ? 

*EDR* (Endpoint detection and response) usually detects the malicious call from the program using Hooking techniques :
* **UserLand Hooking**
* **Kernel Mode Hooking**

Before the introduction of *Kernel Patch Protection* (KPP), it was possible for antivirus products to implement their hooks in the Windows kernel, e.g. using SSDT (System Service Descriptor Table) hooking. With Patch Guard, this was prevented by Microsoft for reasons of operating system stability.

Most of the EDRs rely primarily on *inline API hooking*.

So, when we are trying to execute any functions using high level WinAPI, functions from *ntdll.dll* are indirectly triggered. The EDR applies hooks over them to detect for malicious calls.

You can see the chain of calls below for the *CreateFileW()* function.

![Alt text](https://rfc6592.github.io/assets/img/notepad_transition_syscall.png)

You can see below the principle of EDR user mode API-Hooking on a high level :

![Alt text](https://rfc6592.github.io/assets/img/Usermode_hooking_principle.png)
Technically, an inline hook is a 5-byte assembly instruction (also called a *jump* or **trampoline**) that causes a redirection to the EDR's `Hooking.dll` before the system call is executed in the context of the respective native API. The redirection from the `Hooking.dll` back to the system call in the `ntdll.dll` only occurs if the executed code analysed by the Hooking.dll was found to be harmless. Otherwise, the execution of the corresponding system call is prevented by the Endpoint Protection (EPP) component of an EPP/EDR combination.

## Implementing a simple EDR

### Inline Hooking

So we are going to use Detours to implement our simple EDR on `NtAllocateVirtualMemory`. So, Detours intercepts Win32 functions on x86 machines. Indeed, detours intercepts Win32 functions by re-writing target function images.


![Alt text](https://rfc6592.github.io/assets/img/Pasted image 20231202192741.png)

### How the trampoline works ?

#NtAllocateVirtualMemory
![Alt text](https://rfc6592.github.io/assets/img/Pasted image 20231202193824.png)


### NtAllocateVirtualMemory

Whe are going to target `NtAllocateVirtualMemory`. The *HookMessageAllocateVirtualMemory()* will take over of the `NtAllocateVirtualMemory`. 

Any hooking in Detours is done by using transactions, when we want to set a hook we need to create a new transaction.

```c++
DetourRestoreAfterWith();
DetourTransactionBegin();
DetourUpdateThread(GetCurrentThread());
DetourAttach(&(PVOID&)myNtAllocateVirtualMemory, HookMessageAllocateVirtualMemory);
err = DetourTransactionCommit();
```

*DetourRestoreAfterWith()* will restore the IAT.

*DetourAttach()* will set the hook so we provide the address of the function we want to hook and the function that will take over.

*DetourUpdateThread()* make sure that any threads listed here in *GetCurrentThread()* will have a consistence code.

#### Syntax

So the **NtAllocateVirtualMemory** routine reserves, commits, or both, a region of pages within the user-mode virtual address space of a specified process.

```c++
__kernel_entry NTSYSCALLAPI NTSTATUS NtAllocateVirtualMemory(
  [in]      HANDLE    ProcessHandle,
  [in, out] PVOID     *BaseAddress,
  [in]      ULONG_PTR ZeroBits,
  [in, out] PSIZE_T   RegionSize,
  [in]      ULONG     AllocationType,
  [in]      ULONG     Protect
);
```

To use the `NtAllocateVirtualMemory` function, we have to define its definition in our code.


```c++
typedef NTSTATUS (NTAPI* _NtAllocateVirtualMemoryPtr)(
    HANDLE    hProcess,
    PVOID     *pBaseAddress,
    ULONG_PTR dwZeroBits,
    PSIZE_T   pRegionSize,
    ULONG     dwAllocationType,
    ULONG     dwProtect
);
```

#### Hooking DLL - Using Detours 
```c++

...


...

// Hooking function
int HookMessageAllocateVirtualMemory(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType) {
    printf("[EDR] NtAllocateVirtualMemory() called !\n");
    return IDOK;

}

  

// Set hooks on NtAllocateVirtualMemory
BOOL HookNtAllocateVirtualMemory(void) {
  
    LONG err;
  

    pNtAllocateVirtualMemory myNtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtAllocateVirtualMemory"); // Invoking GetProcAddress function to return the starting address of the NtAllocateVirtualMemory function.

    DetourRestoreAfterWith();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)myNtAllocateVirtualMemory, HookMessageAllocateVirtualMemory);

    err = DetourTransactionCommit();

  

    printf("[EDR] NtAllocateVirtualMemory() hooked! (res = %d)\n", err);

    return TRUE;

}

...
  
...

```

Now we have to create a simple malware program that will use inject our shellcode to remote process, but this malware program should also take the **NAVMEdr.dll** file. W are going to use the concept of remote process injection for injecting the shellcode in the remote process memory (ProcessHacker).


```c++

typedef LPVOID(WINAPI* VirtualAlloc_t)(LPVOID lpAddress, SIZE_T dwSize,
	DWORD flAllocationType, DWORD flProtect);



int main(void)
{

	VirtualAlloc_t pVirtualAlloc = (VirtualAlloc_t)GetProcAddress(GetModuleHandle(L"KERNEL32.DLL"), "VirtualAlloc");


	
	unsigned char calc_payload[] = { 0x42, 0x24, 0x1a, 0x21, 0x56, 0x22, 0x21, 0x1b, 0x1c, 0x24, 0x38, 0x2c, 0x20, 0x36, 0x23, 0x31, 0x23, 0x33, 0x36, 0x38, 0x30, 0x2f, 0x37, 0x28, 0x3e, 0x1, 0x29, 0x1e, 0x36, 0x3d, 0x1f, 0x36, 0x20, 0x28, 0x8, 0x3f, 0x30, 0xb, 0x1a, 0x2c, 0x1d, 0x5a, 0x2c, 0x1e, 0x3e, 0x28, 0x7, 0x1c, 0x36, 0x37, 0x2, 0x24,
0x1f, 0x55, 0x9, 0x26, 0x35, 0x27, 0x2d, 0x29, 0x21, 0x21, 0x3c, 0x2a, 0x17, 0x3d, 0x15, 0x9, 0x15, 0x24, 0x2a, 0x1, 0x2c, 0x31, 0x23, 0x27, 0x0, 0x3c, 0x50, 0x31, 0x24, 0x0, 0x3a, 0xc, 0x43, 0x3d, 0x2f, 0x3b, 0x38, 0x34, 0x1a, 0x29, 0x36, 0x1b, 0x26, 0x38, 0x3a, 0xf, 0x1, 0x24, 0x20, 0x17, 0x26, 0x2f, 0x15, 0x2c, 0x13, 0x2a, 0x24, 0x38, 0x2f, 0x28, 0x1b, 0x6, 0x21, 0x42, 0x3f, 0x44, 0xc, 0x27, 0x49, 0x2b, 0x22, 0x3f, 0x36, 0x21, 0x1a, 0x20, 0x1d, 0x5b, 0x24, 0x1e, 0x3e, 0x30, 0x3b, 0x34, 0x57, 0x43, 0x3f, 0x3d, 0x44, 0x5d, 0x15, 0x2f, 0x8, 0x9, 0x36, 0x2a, 0x21, 0x24, 0x3c, 0x3c, 0x31, 0x2d, 0x25, 0x2b, 0x20,
0x21, 0x2b, 0x33, 0x17, 0x31, 0x23, 0x27, 0x0, 0x3c, 0x50, 0x31, 0x24, 0x0, 0x37, 0x51, 0x40, 0x23, 0x3d, 0x1, 0x39, 0x20, 0x3d, 0x28, 0x29, 0x33, 0xd, 0x32, 0x24, 0x1, 0x3f, 0x5c, 0x53, 0x35, 0xd, 0x26, 0x1b, 0x55, 0x35, 0x0, 0x36, 0x28, 0x25, 0x30, 0x29, 0xe, 0x24, 0x3e, 0x21, 0x31, 0x3, 0x20, 0x10, 0x5d,
0x20, 0x10, 0x36, 0x32, 0x3a, 0x34, 0x25, 0x32, 0x16, 0x3c, 0x4, 0x24, 0x14, 0x27, 0x53, 0x37, 0x23, 0x2d, 0x3a, 0x33, 0x11, 0x8, 0x36, 0x25, 0x15, 0x21, 0x25, 0x20, 0x32, 0x31, 0x34, 0x2f, 0x1d, 0x28, 0x14, 0x4e, 0x14, 0x15, 0x34, 0x22, 0x27, 0x4a, 0x4d, 0x2b, 0x9, 0x31, 0x32, 0x35, 0x2, 0x2c, 0x1d, 0x13, 0x29, 0x9, 0x3b, 0x4e, 0x5c, 0x4a, 0x4c, 0x43, 0x54, 0x3d, 0x1e, 0x2, 0x3c, 0x2c, 0x20, 0x32, 0x24, 0x22, 0x33, 0x24, 0x35, 0x2a, 0x36, 0x30, 0x5f, 0x2f, 0x32, 0x34, 0x26, 0x33, 0x24, 0x31, 0x2c, 0x53, 0x34, 0x34, 0x15, 0x5, 0xd, 0x4c, 0x5d, 0x33, 0x1, 0x44, 0x26, 0x48, 0x2, 0xd, 0x29, 0x27, 0x16, 0x3, 0x4, 0x22, 0x1d, 0x3f, 0x4a, 0x42, 0x50, 0x26, 0xc, 0x27, 0xa, 0x26, 0x13, 0x53, 0x27, 0x17, 0x1a, 0x2a, 0x14, 0x35, 0x15, 0x15, 0x1, 0x25, 0x3c, 0x52, 0x2b, 0x15, 0x2f, 0xa, 0x7, 0x51, 0x1d, 0x24, 0x23, 0x3e, 0x22, 0x33, 0x5f, 0x17, 0x5c, 0x33, 0x3a, 0x40, 0x23, 0x7, 0x32, 0x1c, 0x4c, 0x1, 0x4, 0x34, 0x30, 0x22 };
	unsigned int calc_len = sizeof(calc_payload);
	char key[] = "masecretkey";


	printf("\nHit me 1nd - Before VirtualAlloc!\n");
	getchar();
	
	exec_mem = pVirtualAlloc(0, calc_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	

	printf("\nHit me 2st - After VirtualAlloc!\n");
	getchar();

	...


	...
	
	printf("Bye !\n");
	return 0;
}
```

We can compile *NAVMhookme.cpp* w/ Visual Studio 2022 and *NAVMEdr.cpp* using this :

```
@ECHO OFF
  
cl.exe /nologo /W0 NAVMEdr.cpp /D UNICODE /MT /link /DLL /DLL detours\lib.X64\detours.lib /OUT:NAVMEdr.dll

del *.obj *.lib *.exp
```

## Files 
![Alt text](https://rfc6592.github.io/assets/img/Pasted image 20231203181224.png)

---

## Demontration 

1) Launch MalwareDemonstration.exe
2) Inject the DLL w/ Process Hacker

![Alt text](https://rfc6592.github.io/assets/img/ProcessHackerInjectDLLEDR.png)


The *hook* on `NtAllocateVirtualMemory()` has been set : 

![Alt text](https://rfc6592.github.io/assets/img/NtAllocateVirtualMemoryHookedCMD 1.png)

**Detected** the *NtAllocateVirtualMemory()*

![Alt text](https://rfc6592.github.io/assets/img/Pasted image 20231203194030.png)

---

## WinDbg

If we want to check our own EDR to see which APIs are redirected to the EDR's own `NAVMEdr.dll` by *inline hooking*, we can use a debugger such as WinDbg. 

The following command extracts the memory address of the desired API, in this case the address of the native API `NtAllocateVirtualMemory`, which is located in `ntdll.dll`.

```md
x ntdll!NtAllocateVirtualMemory
```
#### Not hooked Native API
The original *NtAllocateVirtualMemory()* before the *hook* :
![Alt text](https://rfc6592.github.io/assets/img/noEDR 1.png)
#### Inline Hooking
The *NtAllocateVirtualMemory()* after the *hook*:
![Alt text](https://rfc6592.github.io/assets/img/withEDR.png)

---
## x64Dbg

![Alt text](https://rfc6592.github.io/assets/img/x64dbgNtAllocateVirtualMemoryInNtdll.png)

#### Not hooked Native API
The original *NtAllocateVirtualMemory()* before the *hook* :
![Alt text](https://rfc6592.github.io/assets/img/noEDRWithNtAllocateVirtualMemory.png)
#### Inline Hooking
The *NtAllocateVirtualMemory()* after the *hook*:
![Alt text](https://rfc6592.github.io/assets/img/withEDRWithNtAllocateVirtualMemory.png)

## Detours Detection 


**Detection** – Detours can be spotted by examining the first few
bytes of each imported function. If they contain an uncondi-
tional jump, then Detours has been installed. However, the jump-
instruction can also be placed a little later in the function, making
detection more difficult. The major drawback of Debugger aided
Hooking is its need for a separate debugger process. While Single
Instruction Hooking can overcome this drawback, it still leaves
the path of trusted execution and jumps to an arbitrary code area. While Detours works in kernel-mode as well, the properties of Debugger aided Hooking and SIH (Single Instruction Hooking ) make them inappropriate for
being useful within the kernel.



## Sources
* (2023 - jstage) https://www.jstage.jst.go.jp/article/ipsjjip/25/0/25_866/_pdf
* (2023 - Medium) https://securitytimes.medium.com/path-to-process-injection-bypass-userland-api-hooking-a8a49ae5def6
* (2023 - Sektor7) https://institute.sektor7.net/red-team-operator-malware-development-essentials
* (2023 - Sektor7) https://institute.sektor7.net/rto-maldev-intermediate