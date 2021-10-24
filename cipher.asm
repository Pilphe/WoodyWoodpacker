.code

; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

PUBLIC XorCipher

; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

; XorCipher function
;
; Args:
;  - Pointer to a data buffer (rcx)
;  - Data buffer size (rdx)
;  - Pointer to the xoring key (r8)
;
; Description: 
;  - Loops through the whole data buffer and applies a simple xor with key algorithm on it

; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

XorCipher PROC

    xor rax, rax

XorLoop:
    mov r9, rax
    and r9, 0Fh
    mov r10b, BYTE PTR [rcx+rax]
    xor r10b, BYTE PTR [r8+r9]
    mov BYTE PTR [rax+rcx], r10b
    inc rax
    cmp rax, rdx
    jb XorLoop
    ret

XorCipher ENDP

; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

END
