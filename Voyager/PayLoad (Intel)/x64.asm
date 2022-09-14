
.CONST

VMX_OK                      EQU     0
VMX_ERROR_WITH_STATUS       EQU     1
VMX_ERROR_WITHOUT_STATUS    EQU     2

.CODE
; unsigned char __stdcall AsmInvept(
;     _In_ InvEptType invept_type,
;     _In_ const InvEptDescriptor *invept_descriptor);
AsmInvept PROC
    ; invept  ecx, oword ptr [rdx]
    db  66h, 0fh, 38h, 80h, 0ah
    jz errorWithCode        ; if (ZF) jmp
    jc errorWithoutCode     ; if (CF) jmp
    xor rax, rax            ; return VMX_OK
    ret

errorWithoutCode:
    mov rax, VMX_ERROR_WITHOUT_STATUS
    ret

errorWithCode:
    mov rax, VMX_ERROR_WITH_STATUS
    ret
AsmInvept ENDP

END
