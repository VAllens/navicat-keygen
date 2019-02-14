INCLUDES = inc

# flags
CC = g++
CXXFLAGS = -Wall -std=c++11 -O3 -DNDEBUG -I${INCLUDES}
SRCS = \
src/keygen.cpp \
src/activate.cpp \
src/patch.cpp \
src/patch2.cpp \
src/patch3.cpp

ifeq (${OS}, Windows_NT)
	CXXFLAGS += -Wl,--subsystem,windows
	LFLAGS += -Llib/amd64 -llibui -llibeay32 -lcapstone
	SRCS += src/helper.cpp
	OUTPUT = bin
else
	CXXFLAGS += -rpath @executable_path
	LFLAGS += -Lkeygen.app/Contents/MacOS -lui -lcrypto -lcapstone -framework Foundation
	SRCS += src/helper.mm
	OUTPUT = keygen.app/Contents/MacOS
endif

.PHONY: keygen

keygen:
	$(CC) ${CXXFLAGS} ${SRCS} $(LFLAGS) -o ${OUTPUT}/$@
