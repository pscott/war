ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 44 43 42 41 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Shared object file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0xc000000
  Start of program headers:          64 (bytes into file)
  Start of section headers:          14976 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         13
  Size of section headers:           64 (bytes)
  Number of section headers:         31
  Section header string table index: 30

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .interp           PROGBITS         0000000000000318  00000318
       000000000000001c  0000000000000000   A       0     0     1
  [ 2] .note.gnu.propert NOTE             0000000000000338  00000338
       0000000000000020  0000000000000000   A       0     0     8
  [ 3] .note.gnu.build-i NOTE             0000000000000358  00000358
       0000000000000024  0000000000000000   A       0     0     4
  [ 4] .note.ABI-tag     NOTE             000000000000037c  0000037c
       0000000000000020  0000000000000000   A       0     0     4
  [ 5] .gnu.hash         GNU_HASH         00000000000003a0  000003a0
       0000000000000024  0000000000000000   A       6     0     8
  [ 6] .dynsym           DYNSYM           00000000000003c8  000003c8
       0000000000000120  0000000000000018   A       7     1     8
  [ 7] .dynstr           STRTAB           00000000000004e8  000004e8
       00000000000000b6  0000000000000000   A       0     0     1
  [ 8] .gnu.version      VERSYM           000000000000059e  0000059e
       0000000000000018  0000000000000002   A       6     0     2
  [ 9] .gnu.version_r    VERNEED          00000000000005b8  000005b8
       0000000000000030  0000000000000000   A       7     1     8
  [10] .rela.dyn         RELA             00000000000005e8  000005e8
       00000000000000c0  0000000000000018   A       6     0     8
  [11] .rela.plt         RELA             00000000000006a8  000006a8
       0000000000000090  0000000000000018  AI       6    24     8
  [12] .init             PROGBITS         0000000000001000  00001000
       000000000000001b  0000000000000000  AX       0     0     4
  [13] .plt              PROGBITS         0000000000001020  00001020
       0000000000000070  0000000000000010  AX       0     0     16
  [14] .plt.got          PROGBITS         0000000000001090  00001090
       0000000000000010  0000000000000010  AX       0     0     16
  [15] .plt.sec          PROGBITS         00000000000010a0  000010a0
       0000000000000060  0000000000000010  AX       0     0     16
  [16] .text             PROGBITS         0000000000001100  00001100
       00000000000003f5  0000000000000000  AX       0     0     16
  [17] .fini             PROGBITS         00000000000014f8  000014f8
       000000000000000d  0000000000000000  AX       0     0     4
  [18] .rodata           PROGBITS         0000000000002000  00002000
       0000000000000078  0000000000000000   A       0     0     4
  [19] .eh_frame_hdr     PROGBITS         0000000000002078  00002078
       000000000000004c  0000000000000000   A       0     0     4
  [20] .eh_frame         PROGBITS         00000000000020c8  000020c8
       0000000000000128  0000000000000000   A       0     0     8
  [21] .init_array       INIT_ARRAY       0000000000003d90  00002d90
       0000000000000008  0000000000000008  WA       0     0     8
  [22] .fini_array       FINI_ARRAY       0000000000003d98  00002d98
       0000000000000008  0000000000000008  WA       0     0     8
  [23] .dynamic          DYNAMIC          0000000000003da0  00002da0
       00000000000001f0  0000000000000010  WA       7     0     8
  [24] .got              PROGBITS         0000000000003f90  00002f90
       0000000000000070  0000000000000008  WA       0     0     8
  [25] .data             PROGBITS         0000000000004000  00003000
       0000000000000010  0000000000000000  WA       0     0     8
  [26] .bss              NOBITS           0000000000004010  00003010
       0000000000000008  0000000000000000  WA       0     0     1
  [27] .comment          PROGBITS         0000000000000000  00003010
       000000000000002a  0000000000000001  MS       0     0     1
  [28] .symtab           SYMTAB           0000000000000000  00003040
       00000000000006a8  0000000000000018          29    46     8
  [29] .strtab           STRTAB           0000000000000000  000036e8
       0000000000000278  0000000000000000           0     0     1
  [30] .shstrtab         STRTAB           0000000000000000  00003960
       000000000000011a  0000000000000000           0     0     1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  l (large), p (processor specific)

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  PHDR           0x0000000000000040 0x0000000000000040 0x0000000000000040
                 0x00000000000002d8 0x00000000000002d8  R      0x8
  INTERP         0x0000000000000318 0x0000000000000318 0x0000000000000318
                 0x000000000000001c 0x000000000000001c  R      0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000738 0x0000000000000738  R      0x1000
  LOAD           0x0000000000001000 0x0000000000001000 0x0000000000001000
                 0x0000000000000505 0x0000000000000505  R E    0x1000
  LOAD           0x0000000000002000 0x0000000000002000 0x0000000000002000
                 0x00000000000001f0 0x00000000000001f0  R      0x1000
  LOAD           0x0000000000002d90 0x0000000000003d90 0x0000000000003d90
                 0x0000000000000280 0x0000000000000288  RW     0x1000
  DYNAMIC        0x0000000000002da0 0x0000000000003da0 0x0000000000003da0
                 0x00000000000001f0 0x00000000000001f0  RW     0x8
  LOAD           0x0000000000004240 0x000000000c000000 0x0000000000000338
                 0x0000000000000311 0x0000000000000311  R E    0x200000
  NOTE           0x0000000000000358 0x0000000000000358 0x0000000000000358
                 0x0000000000000044 0x0000000000000044  R      0x4
  GNU_PROPERTY   0x0000000000000338 0x0000000000000338 0x0000000000000338
                 0x0000000000000020 0x0000000000000020  R      0x8
  GNU_EH_FRAME   0x0000000000002078 0x0000000000002078 0x0000000000002078
                 0x000000000000004c 0x000000000000004c  R      0x4
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     0x10
  GNU_RELRO      0x0000000000002d90 0x0000000000003d90 0x0000000000003d90
                 0x0000000000000270 0x0000000000000270  R      0x1

 Section to Segment mapping:
  Segment Sections...
   00     
   01     .interp 
   02     .interp .note.gnu.property .note.gnu.build-id .note.ABI-tag .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt 
   03     .init .plt .plt.got .plt.sec .text .fini 
   04     .rodata .eh_frame_hdr .eh_frame 
   05     .init_array .fini_array .dynamic .got .data .bss 
   06     .dynamic 
   07     
   08     .note.gnu.build-id .note.ABI-tag 
   09     .note.gnu.property 
   10     .eh_frame_hdr 
   11     
   12     .init_array .fini_array .dynamic .got 
