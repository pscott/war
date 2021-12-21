BIN_NAME=woody_woodpacker

all: $(BIN_NAME)
	nasm -f elf64 woody_woodpacker.asm && ld -s -o ${BIN_NAME} woody_woodpacker.o

clean:
	rm -rf woody_woodpacker.o

fclean: clean
	rm -rf ${BIN_NAME}


re: fclean all
