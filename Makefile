# /**
#  *  @file       Makefile
#  *  @author     Andrej Nano (xnanoa00)
#  *  @date       2018-10-01
#  *  @version    0.1
#  * 
#  *  @brief ISA 2018, Export DNS informací pomocí protokolu Syslog
#  *  
#  *  @desc Cílem projektu je vytvořit aplikaci, která bude umět zpracovávat data protokolu DNS (Domain Name System) a vybrané statistiky exportovat pomocí protokolu Syslog na centrální logovací server. 
#  */

# Distribution archive name
TARNAME = xnanoa00

# Executable file name
EXEC = dns-export

# Source c++ files
SRC_FILES := $(wildcard src/*.cc)

# Optimization level
OPTIMIZE = -O2

# Compiling flags
CXXFLAGS = -std=c++11 -g -Wall -Wextra -lpcap -lpthread

# -----------------------------

all: build

.PHONY: clean run pack test

build: src/$(EXEC).cc
	$(CXX) $(CXXFLAGS) $(SRC_FILES) -o $(EXEC)

clean:
	rm $(TARNAME).tar

# TODO: add all required files
pack:
	tar $(TARNAME).tar $(SRC_FILES) Makefile

run:
	make -B && ./$(EXEC)

test:
	make -B && python3 ./tests/run.py
