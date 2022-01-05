BIN_NAME=famine

all:
	nasm -f elf64 famine.asm && ld -s -o ${BIN_NAME} famine.o

clean:
	rm -rf famine.o

fclean: clean
	rm -rf ${BIN_NAME}


re: fclean all
