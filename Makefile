BIN_NAME=war

all:
	nasm -f elf64 war.asm && ld -s -o ${BIN_NAME} war.o

clean:
	rm -rf war.o

fclean: clean
	rm -rf ${BIN_NAME}


re: fclean all
