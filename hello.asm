%define DIRENT_SIZE 1024
struc	linux_dirent
	.d_ino			resq	1
	.d_off			resq	1
	.d_reclen		resw	1
  .d_type     resb  1
	.d_name			resb	1
endstruc

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
  jge .end

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
      mov rax, rdi
      call ft_write
      lea r15, [rbp - 0x2710]
      .stat:
        mov rax, 4 ; stat syscall
        ; rdi already has d_name
        mov rsi, r15 ; statbuf struct
        syscall

    .next_file
      mov rbx, [rbp - 0x41c]
      cmp rbx, [rbp - 0x424] ; compare num with res
      jl .while

  .end:
    mov ebx, 0 ; exitcode 0
    mov eax, 1 ; exit syscall
    int 0x80 ; execute syscall
