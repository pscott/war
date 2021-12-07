#include <stdio.h>
#include <elf.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#define _GNU_SOURCE
#include <dirent.h>
#include <stdlib.h>

void print_bytes(char *b, size_t size)
{
	size_t i = 0;
	while (i < size)
	{
		printf("%.2hhx ", b[i]);
		i++;
	}
	printf("\n");
}

int main(int ac, char **av)
{
	char buf[2048];

	if (ac < 2)
	{
		printf("Missing arg\n");
		return (1);
	}
	int fd = open(av[1], O_RDONLY);
	read(fd, buf, 2048);
	Elf64_Ehdr *hdr = (Elf64_Ehdr *)buf;

	printf("sizeof: %lu\n", sizeof(Elf64_Ehdr));
	printf("Mag:\t\t");
	print_bytes((char *)hdr->e_ident, 4);
	printf("class:\t\t");
	print_bytes((char *)hdr->e_ident + EI_CLASS, 1);
	printf("data:\t\t");
	print_bytes((char *)hdr->e_ident + EI_DATA, 1);
	printf("version:\t");
	print_bytes((char *)hdr->e_ident + EI_VERSION, 1);
	printf("OSABI:\t\t");
	print_bytes((char *)hdr->e_ident + EI_OSABI, 1);
	printf("EI_ABIVERSION:\t");
	print_bytes((char *)hdr->e_ident + EI_ABIVERSION, 1);
	printf("pad:\t\t");
	print_bytes((char *)hdr->e_ident + EI_PAD, EI_NIDENT - 1 - EI_PAD);

	printf("type:\t\t");
	print_bytes((char *)&hdr->e_type, sizeof(hdr->e_type));

	printf("entry:\t\t");
	print_bytes((char *)&hdr->e_entry, sizeof(hdr->e_entry));

	return (0);
}
