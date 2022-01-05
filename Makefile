BIN_NAME=pestillence

all:
	nasm -f elf64 pestillence.asm && ld -s -o ${BIN_NAME} pestillence.o

clean:
	rm -rf pestillence.o

fclean: clean
	rm -rf ${BIN_NAME}


re: fclean all
