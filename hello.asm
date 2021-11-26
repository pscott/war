%define DIRENT_SIZE 1024
struc	linux_dirent
	.d_ino			resq	1
	.d_off			resq	1
	.d_reclen		resw	1
	.d_name			resb	1
  .pad        resb  1
  .d_type     resb  1
endstruc

section .text
  global _start

section .data
msg db 'Hello, world!',0xa
msg_len equ $ - msg
dot db '.',0x0
dot_len equ $ - dot

section .text

hello:
  mov edx, msg_len ; move length of msg
  mov ecx, msg ; move pointer to msg
  mov ebx, 1 ; STDOUT
  mov eax, 4 ; write syscall
  int 0x80 ; execute syscall
  ret

_start:
  push rbp
  mov rbp, rsp

  sub rsp, 0x430 ; char buf[1024]
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
  while:
    mov rax, [rbp - 0x41c] ; rax = num
    lea rdx, [rbp - 0x400] ; rdx = (address) buf

    add rax, rdx ; p = buf + num

    ; num += p->d_reclen
    mov rbx, [rbp - 0x41c] ; rbx = num
    mov cx, [rax + linux_dirent.d_reclen] ; rcx = p->d_reclen
    add bx, cx ; rbx += rcx
    mov [rbp - 0x41c], rbx ; store rbx in num

    call hello
    mov rbx, [rbp - 0x41c]
    cmp rbx, [rbp - 0x424] ; compare num with res
    jl while
  end:
  call hello

  mov ebx, 0 ; exitcode 0
  mov eax, 1 ; exit syscall
  int 0x80 ; execute syscall
