# ---------------------------------------------------------------------------
#  Rainbow attack -- build file
#
#  Targets:
#     make            build everything (gen-table, attack, gen-passwd, check-passwd)
#     make gen-table  preprocessing program (build a rainbow table)
#     make attack     attack program (crack hashes using rainbow tables)
#     make tools      the teacher-provided gen-passwd and check-passwd
#     make clean      remove the built binaries
#
#  Requires g++ with C++17 (Ubuntu 24.04 ships a suitable g++).
# ---------------------------------------------------------------------------

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O3 -march=native -pthread -Wall -Wextra
SRC      := src

SHA_OBJ  := $(SRC)/sha256.cpp

.PHONY: all tools clean

all: gen-table attack tools

gen-table: $(SRC)/gen-table.cpp $(SRC)/rainbow.hpp $(SRC)/sha256.h $(SRC)/staticstring.hpp $(SRC)/misc/threadpool.hpp $(SHA_OBJ)
	$(CXX) $(CXXFLAGS) -I$(SRC) -o $@ $(SRC)/gen-table.cpp $(SHA_OBJ)

attack: $(SRC)/attack.cpp $(SRC)/rainbow.hpp $(SRC)/sha256.h $(SRC)/staticstring.hpp $(SRC)/misc/threadpool.hpp $(SHA_OBJ)
	$(CXX) $(CXXFLAGS) -I$(SRC) -o $@ $(SRC)/attack.cpp $(SHA_OBJ)

tools: gen-passwd check-passwd

gen-passwd: $(SRC)/gen-passwd.cpp $(SRC)/passwd-utils.hpp $(SRC)/random.hpp $(SRC)/sha256.h $(SRC)/staticstring.hpp $(SHA_OBJ)
	$(CXX) $(CXXFLAGS) -I$(SRC) -o $@ $(SRC)/gen-passwd.cpp $(SHA_OBJ)

check-passwd: $(SRC)/check-passwd.cpp $(SRC)/passwd-utils.hpp $(SRC)/random.hpp $(SRC)/sha256.h $(SRC)/staticstring.hpp $(SHA_OBJ)
	$(CXX) $(CXXFLAGS) -I$(SRC) -o $@ $(SRC)/check-passwd.cpp $(SHA_OBJ)

clean:
	rm -f gen-table attack gen-passwd check-passwd
