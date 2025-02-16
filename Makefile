CC = gcc
CFLAGS = -W -Wall -pedantic -ansi
LDFLAGS = -lreadline -lm -lSDL -lSDL_ttf
EXEC = solver
SRC = $(wildcard src/*.c)
OBJ = $(SRC: *.c = *.o)

all : $(EXEC)

help :
	@echo ""
	@echo "Makefile utilisation :"
	@echo "make all -> compile everything"
	@echo "make solver -> compile everything"
	@echo "make help -> give help with makefile"
	@echo "make clean -> remove all object files"
	@echo "make mrproper -> remove all executable files"
	@echo ""

solver : $(OBJ)
	@$(CC) $^ -o $@ $(LDFLAGS)

*.o : *.c
	@$(CC) -o $@ -c $< $(CFLAGS)

.PHONY : clean

.PHONY : mrproper

clean :
	@rm -f src/*.o

mrproper : clean
	@rm -f $(EXEC)
