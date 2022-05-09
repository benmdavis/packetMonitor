# Usage:
# make        # compile all binary
# make clean  # remove ALL binaries and objects
.PHONY = all clean

CC = gcc                        # compiler to use

LINKERFLAG = `pkg-config gtk4 --cflags --libs`

SRC := packetCatchGui.c
BIN := packetCatchGui

all: packetCatchGui

build:
		echo "Compiling..."
		${CC} ${LINKERFLAG} ${SRC} -o ${BIN}

clean:
	@echo "Cleaning up..."
		rm -rvf *.o ${BIN}
