IFDEF RAX

.code

executeSyscall PROC
    add rsp, 8
    mov rax, rcx
    mov rcx, rdx
    mov rdx, r8
    mov r8, r9
    mov r9, [rsp + 20h]
    mov r10, rcx
    syscall
    sub rsp, 8
    ret
executeSyscall ENDP

ELSE
ENDIF
END