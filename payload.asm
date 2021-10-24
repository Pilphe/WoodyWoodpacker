.const

    PayloadSize                  dd PayloadEnd - PayloadStart
    ExecutableSectionOffset      dd (ExecutableSectionOffsetPlaceholder - PayloadStart) + 1
    ExecutableSectionSizeOffset  dd (ExecutableSectionSizeOffsetPlaceholder - PayloadStart) + 2
    OriginalEntryPointJumpOffset dd (OriginalEntryPointJumpOffsetPlaceholder - PayloadStart) + 1

.code

; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

PUBLIC PayloadStart
PUBLIC PayloadSize
PUBLIC ExecutableSectionOffset
PUBLIC ExecutableSectionSizeOffset
PUBLIC OriginalEntryPointJumpOffset

; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

; Payload
;
; Description:
; - Decrypts executable section
; - Retrieves KERNEL32.dll base address in memory from the PEB
; - Parses KERNEL32.dll to find the address of LoadLibraryA function
; - Calls LoadLibraryA to load user32.dll and get its memory base address
; - Parses user32.dll to find the address of MessageBoxA function
; - Calls MessageBoxA to print the string "....WOODY...." as requested by the subject
; - The "jmp PayloadStart" instruction at the end of the function is a placeholder for the real
;   entry point offset of the packed PE which will be calculated and replaced during the packing
;    process
; - PEB: https://www.geoffchappell.com/studies/windows/win32/ntdll/structs/peb/index.htm
;
; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

PayloadStart::
EncryptionKey byte 16 DUP(0)
Payload PROC
    LOCAL NumberOfFunctions:DWORD
    LOCAL AddressOfFunctions:DWORD
    LOCAL AddressOfNames:DWORD
    LOCAL AddressOfNameOrdinals:DWORD
    LOCAL StackStr[16]:BYTE
    LOCAL SavedRsi:QWORD
    LOCAL SavedRdi:QWORD
    LOCAL ShadowSpace[32]:BYTE

    mov SavedRsi, rsi
    mov SavedRdi, rdi

    jmp GetKernel32DllAddress

FindFunctionAddress:

    ;Get PE Header address
    mov eax, DWORD PTR [r8+3Ch]
    add rax, r8

    ;Get export table address
    mov eax, DWORD PTR [rax+88h]
    add rax, r8

    ;Get export table number of functions
    mov edx, DWORD PTR [rax+14h]
    mov NumberOfFunctions, edx

    ;Get function adresses table
    mov edx, DWORD PTR [rax+1Ch]
    mov AddressOfFunctions, edx

    ;Get function names table
    mov edx, DWORD PTR [rax+20h]
    mov AddressOfNames, edx

    ;Get function name ordinals table
    mov edx, DWORD PTR [rax+24h]
    mov AddressOfNameOrdinals, edx

    ;Initializing variables before looping through function names table
    xor rdx, rdx
    mov eax, AddressOfNames
    add rax, r8
    cld

StrnEqu:
    ;Index is in rdx
    mov edi, DWORD PTR [rax+rdx*4]
    add rdi, r8
    lea rsi, StackStr
    mov ecx, r10d
    repe cmpsb
    jz FunctionNameOrdinalToAddress
    cmp edx, NumberOfFunctions
    je PayloadEpilogue
    inc edx
    jmp StrnEqu


FunctionNameOrdinalToAddress:
    mov eax, AddressOfNameOrdinals
    add rax, r8
    movzx rdx, WORD PTR [rax+rdx*2]
    mov eax, AddressOfFunctions
    add rax, r8
    mov eax, DWORD PTR [rax+rdx*4]
    add rax, r8
    jmp r9

GetKernel32DllAddress:
    mov r8, gs:[60h]                ;Get PEB address
    mov rdx, [r8+10h]                ;Save PE memory base address

XorCipher:
    xor rax, rax
ExecutableSectionOffsetPlaceholder::
    mov ecx, 12345678h
ExecutableSectionSizeOffsetPlaceholder::
    mov r11d, 12345678h

    add rcx, rdx
    lea rdx, [EncryptionKey]

XorLoop:
    mov r9, rax
    and r9, 0Fh
    mov r10b, BYTE PTR [rcx+rax]
    xor r10b, BYTE PTR [rdx+r9]
    mov BYTE PTR [rax+rcx], r10b
    inc rax
    cmp rax, r11
    jb XorLoop

    mov rax, [r8+18h]                ;Get PEB_LDR_DATA address
    mov rax, [rax+20h]                ;LIST_ENTRY InMemoryOrderModuleList (1st module: the exe itself)

    mov rax, [rax]                    ;LIST_ENTRY InMemoryOrderModuleList.Flink (2nd module: ntdll.dll)
    mov rax, [rax]                    ;LIST_ENTRY InMemoryOrderModuleList.Flink (3rd module: kernel32.dll)
    mov r8, [rax+20h]                ;Save KERNEL32.dll base address into r8 which will be our base register

    ;Store "LoadLibraryA" string into stack
    mov rdx, 7262694C64616F4Ch
    mov QWORD PTR StackStr, rdx
    mov edx, 41797261h
    mov QWORD PTR StackStr+8, rdx
    lea r9, [LoadUser32Dll]
    mov r10d, 0Dh
    jmp FindFunctionAddress

LoadUser32Dll:
    ;Store "user32.dll" string into stack
    mov rdx, 642E323372657375h
    mov QWORD PTR StackStr, rdx
    mov edx, 6C6Ch
    mov DWORD PTR StackStr+8, edx

    ;LoadLibraryA("user32.dll")
    lea rcx, StackStr
    call rax

    test rax, rax
    jz PayloadEpilogue
    mov r8, rax
    
    ;Store "MessageBoxA" string into stack
    mov rdx, 426567617373654Dh
    mov QWORD PTR StackStr, rdx
    mov edx, 41786Fh
    mov DWORD PTR StackStr+8, edx
    lea r9, [DisplayMessageBox]
    mov r10d, 0Ch
    jmp FindFunctionAddress


DisplayMessageBox:
    ;Store "....WOODY...." string into stack
    mov rdx, 444F4F572E2E2E2Eh
    mov QWORD PTR StackStr, rdx
    mov rdx, 2E2E2E2E59h
    mov QWORD PTR StackStr+8, rdx

    ;MessageBoxA(NULL, "....WOODY....", "....WOODY....", MB_OK)
    xor rcx, rcx
    xor r9, r9
    lea rdx, StackStr
    mov r8, rdx
    call rax


PayloadEpilogue:
    mov rsi, SavedRsi
    mov rdi, SavedRdi

    leave
OriginalEntryPointJumpOffsetPlaceholder::
    jmp PayloadStart

Payload ENDP
PayloadEnd::

; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

END
