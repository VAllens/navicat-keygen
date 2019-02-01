INCLUDES = inc

# flags
CC = g++
CXXFLAGS = -Wall -std=c++11 -O3 -DNDEBUG -I${INCLUDES}

ifeq (${OS}, Windows_NT)
	CXXFLAGS += -Wl,--subsystem,windows
	LFLAGS += -llibui -llibeay32 -lcapstone
	LIBS = lib/amd64
	OUTPUT = bin
else
	CXXFLAGS += -rpath @executable_path
	LFLAGS += -lui -lcrypto -lcapstone
	LIBS = keygen.app/Contents/MacOS
	OUTPUT = ${LIBS}
endif

SRCS = \
src/keygen.cpp \
src/activate.cpp \
src/patch.cpp \
src/patch2.cpp \
src/patch3.cpp

.PHONY: keygen

keygen:
	$(CC) ${CXXFLAGS} ${SRCS} -L${LIBS} $(LFLAGS) -o ${OUTPUT}/$@
