.686p
.model flat, stdcall
.MMX
.XMM


EXTERN g_kitrap0e: DWORD
EXTERN g_target_eprocess: DWORD

EXTERN g_SwapContextBack: DWORD
EXTERN g_MmCreateTebBack: DWORD
EXTERN g_PspAllocateThreadBack: DWORD
EXTERN MySwapContextHandler@12 : PROC
EXTERN MyMmCreateTebHandler@4 : PROC

EXTERN EmuKiFastCallEntryHandler@4 : PROC
EXTERN g_TrampoKiFastCallEntry: DWORD
EXTERN EmuKiServiceExitHandler@4 : PROC
EXTERN g_TrampoKiServiceExit: DWORD
EXTERN EmuKei386HelperExitHandler@4 : PROC
EXTERN g_TrampoKei386HelperExit: DWORD
EXTERN EmuKiCallUserModeExitHandler@4 : PROC
EXTERN g_TrampoKiCallUserModeExit: DWORD

EXTERN TargetPageFault@8 : PROC

.CONST

.CODE

AsmStopSMEP PROC
    mov eax, cr4
	and eax, 0FFEFFFFFh
	mov cr4, eax
	ret
AsmStopSMEP ENDP

AsmDisableInterrupt PROC
    cli
    ret
AsmDisableInterrupt ENDP

AsmEnableInterrupt PROC
    sti
    ret
AsmEnableInterrupt ENDP

MySwapContext PROC
	mov   eax, [esi + 150h]  ; process
	cmp   eax, g_target_eprocess
	jz    TARGET_PROCESS
	mov   eax, [esi + 440h]
	mov   [ecx + 62h], ax
	jmp   dword ptr [g_SwapContextBack]

TARGET_PROCESS:
	mov  word ptr [ecx+38h], 0ffffh ; 
	;push  ecx  ; 
	;push  edx
	;push  ecx  ; gdt
	;push  esi  ; ETHREAD
	;push  ebx  ; KPCR
	;call  MySwapContextHandler@12
	;pop   edx
	;pop   ecx
	mov   eax, [esi + 440h]
	mov   [ecx + 62h], ax
	jmp   dword ptr [g_SwapContextBack]

MySwapContext ENDP

MyMmCreateTeb PROC
	push  ebx
	call  MyMmCreateTebHandler@4
	cmp   eax, 0
	jnz   TARGET_PROCESS

	lea   eax, [ebp - 38h]
	push  eax
	push  1000h
	xor   edx, edx
    jmp   dword ptr [g_MmCreateTebBack]

TARGET_PROCESS:
    lea   eax, [ebp - 38h]
	push  eax
	push  2000h
	xor   edx, edx
    jmp   dword ptr [g_MmCreateTebBack]

MyMmCreateTeb ENDP

MyPspAllocateThread PROC
    mov   eax, dword ptr [ebp - 6Ch]
    cmp   eax, g_target_eprocess
	jz    TARGET_PROCESS
	push  4
	push  1000h
	push  dword ptr [ebp - 68h]
	jmp   dword ptr [g_PspAllocateThreadBack]

TARGET_PROCESS:
    int   3
    push  4
	push  2000h
	push  dword ptr [ebp - 68h]
	jmp   dword ptr [g_PspAllocateThreadBack]

MyPspAllocateThread ENDP

KiFastCallEntry PROC
    pushfd                            ; saveeflags
	push ebp              
	push ebx 
	push esi
	push edi
	push eax
	push ecx
	push edx
	push fs

	push esp                         ; KTRAP_FRAME3
	call EmuKiFastCallEntryHandler@4

	pop fs      
	pop edx
	pop ecx
	pop eax
	pop edi
	pop esi
	pop ebx
	pop ebp
	popfd
	jmp dword ptr [g_TrampoKiFastCallEntry]
KiFastCallEntry ENDP

KiServiceExit PROC
    push ebp
	push eax
	push ecx
	push edx
	pushfd

	push ebp                         ;ktrap_frame
    call EmuKiServiceExitHandler@4

	popfd
	pop  edx
	pop  ecx
	pop  eax
	pop  ebp
	jmp  dword ptr [g_TrampoKiServiceExit]
KiServiceExit ENDP

Kei386HelperExit PROC
    push ebp
	push edx
	push ecx
	push eax
	pushfd

	push ebp     ;ktrap_frame
    call EmuKei386HelperExitHandler@4

	popfd
	pop  eax
	pop  ecx
	pop  edx
	pop  ebp
	jmp  dword ptr [g_TrampoKei386HelperExit]
Kei386HelperExit ENDP


KiCallUserModeExit PROC
	push ebp
	push edx
	push ecx
	push eax
	pushfd

	push eax
	call EmuKiCallUserModeExitHandler@4

	popfd
	pop  eax
	pop  ecx
	pop  edx
	pop  ebp
	jmp  dword ptr [g_TrampoKiCallUserModeExit]
KiCallUserModeExit ENDP

KiTrapPageFault PROC
   assume fs:nothing

   push  fs
   push  eax
   mov   ax, fs
   cmp   ax, 30h 
   jz    R0_MODE

R3_MODE:
   mov   ax, 30h
   mov   fs, ax
   mov   eax, fs:[124h]              ;_KTHREAD/_ETHREAD
   mov   eax, dword ptr [eax + 150h] ; KPROCESS
   cmp   eax, g_target_eprocess  
   jnz   DEFAULT                     ; Not target process thread

TARGET_THREAD:
   push  ecx  
   push  edx
   push  edi
   push  esp             ; PAGE_FAULT_FRAME
   mov   eax, cr2
   push  eax             ; fault_address
   cld
   call  TargetPageFault@8
   cmp   eax, 0
   pop   edi
   jz    NORMAL_EXIT
   pop   edx
   pop   ecx
   pop   eax
   pop   fs
   add   esp, 4          ; skip error code
   iretd                 ; interrupt returns

R0_MODE:
   mov   eax, fs:[124h]              ;_KTHREAD/_ETHREAD
   mov   eax, dword ptr [eax + 150h] ; KPROCESS
   cmp   eax, g_target_eprocess      ; R0 & TARGET_THREAD
   jnz   DEFAULT
                    
TARGET_THREAD2:
   mov   eax, dword ptr [esp + 20]   ; Maybe from ud_decode()
   test  eax, 200h                  
   jne   DEFAULT                     ; if IF != 1, then set IF = 1
   or    eax, 200h                  
   mov   dword ptr [esp+20], eax
DEFAULT:
   pop  eax
   pop  fs
   jmp  dword ptr [g_kitrap0e]

NORMAL_EXIT:
   pop  edx
   pop  ecx
   pop  eax
   pop  fs
   jmp  dword ptr [g_kitrap0e]

KiTrapPageFault ENDP

AsmUserWaitFunction PROC
   assume fs:nothing

   mov   fs:[88h], esp
   mov   esp, fs:[84h]
   push  ebp
   lea   ebp, [esp + 4]  ; ebp -> s_fault_addr
   pushfd
   push  eax
   push  ecx
   push  edx
          
   mov   dword ptr [ebp + 12], 0 ; &Undesired = 0
   cmp   dword ptr [ebp + 24], 0 ; wb_state
   jne   SIGNALED
   mov   edx, [ebp + 8]          ; s_function
WAIT_FUNC:
   push  0
   push  4
   lea   eax, [ebp + 12]     ; &Undesired
   push  eax
   lea   eax, [ebp + 24]     ; &wb_state
   push  eax
   add   esp, 16                   
   ;call  edx
   mov   eax, dword ptr [ebp + 24]  ; Captured = [wb_state]
   cmp   eax, [ebp + 12]         ; Captured == Undesired?
   je    WAIT_FUNC
SIGNALED:
   tzcnt eax, dword ptr [ebp + 24] ; eax = freeIndex
   mov   dword ptr [ebp + 16], eax ; w_index = freeIndex
   mov   ecx, [ebp + eax*4 + 28]   ; wb_list[freeIndex]
   mov   dword ptr [ebp + 20], ecx ; w_buffer = wb_list[freeIndex];
   mov   ecx, eax                 
   mov   eax, 1
   shl   eax, cl
   not   eax
   lock and  dword ptr [ebp + 24], eax ; InterlockedAnd(wb_state, ~(1 << freeIndex));

   mov  eax, dword ptr [ebp]      ; original_addr
   mov  fs:[68h], eax
   pop  edx
   pop  ecx
   pop  eax
   mov  ecx, dword ptr [ebp + 20] ; Ecx = w_buffer - offset;
   sub  ecx, dword ptr [ebp + 4]
   popfd
   pop  ebp

   mov  esp, fs:[88h]
   jmp  dword ptr fs:[68h]

AsmUserWaitFunction ENDP

AsmUserWaitFunctionEnd PROC
   xor  eax, eax
   ret
AsmUserWaitFunctionEnd ENDP


AsmEnterIntoAnalysisCode PROC StartAddr, WorkBuffer, AuxBuffer, ThreadData
	assume fs:nothing

	pushfd
	push ebx
	push ebp
	push esi
	push edi
	mov  eax, ThreadData
	push eax
	mov  ecx, WorkBuffer
	mov  edx, AuxBuffer
	mov  eax, StartAddr
	call eax             ; ...| ThreadData | RETURN_ADDR |
RETURN_ADDR:
    add  esp, 4
	pop  edi
	pop  esi
	pop  ebp
	pop  ebx
	popfd
	ret

AsmEnterIntoAnalysisCode ENDP

AsmEnterIntoAnalysisCode2 PROC StartAddr, WorkBuffer, LogPtr, ThreadData
	assume fs:nothing

	pushfd
	push ebx
	push ebp
	push esi
	push edi
	mov  eax, ThreadData
	push eax
	mov  ecx, WorkBuffer
	mov  edx, LogPtr
CHECK_R:
    mov  ebx, [edx]      ; start wait
    cmp  ecx, ebx
    jz   CHECK_R
	mov  eax, [ecx]
	; mov  eax, StartAddr
	call eax             ; ...| ThreadData | RETURN_ADDR |
RETURN_ADDR:
    add  esp, 4
	pop  edi
	pop  esi
	pop  ebp
	pop  ebx
	popfd
	ret

AsmEnterIntoAnalysisCode2 ENDP

AsmFlushGlobalTlb PROC
    assume fs:nothing
	
	mov   eax, cr4
	mov   ecx, eax
	and   eax, 0FFFFFF7Fh ; global TLB£¬bit7 PGE
	mov   cr4, eax
	mov   cr4, ecx

	ret
AsmFlushGlobalTlb ENDP

AsmFlushAllTlb PROC
    assume fs:nothing
	
	mov   eax, cr3        
	mov   cr3, eax
	mov   eax, cr4
	mov   ecx, eax
	and   eax, 0FFFFFF7Fh ;global TLB£¬bit7 PGE
	mov   cr4, eax
	mov   cr4, ecx

	ret
AsmFlushAllTlb ENDP


END
