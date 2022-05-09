# Usage:
# make        # compile all binary
# make clean  # remove ALL binaries and objects
.PHONY = all clean

CC = gcc                        # compiler to use

LINKERFLAG = -lpcap `pkg-config gtk4 --cflags --libs`

SRC_CLI := packetCatch.c
BIN_CLI := packetCatch

SRC_GUI := packetCatchGui.c
BIN_GUI := packetCatchGui

all: packetCatchGui

cli:
		echo "Compiling CLI app..."
		${CC} ${LINKERFLAG} ${SRC_CLI} -o ${BIN_CLI}

gui:
		echo "Compiling..."
		${CC} ${LINKERFLAG} ${SRC_GUI} -o ${BIN_GUI}

clean:
	@echo "Cleaning up..."
		rm -rvf *.o ${BIN}
