SRC=src/main.cpp
OBJ=$(SRC:.cpp=.o)
CXXFLAGS=-I../LIEF/output/include -L../LIEF/output/lib -std=c++17 -g
LDFLAGS=-lLIEF -lboost_system -lboost_filesystem

all: binmerge

binmerge: $(OBJ)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^

test_c: binmerge
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):/home/nurelin/repo/LIEF/output/lib:tests/c ./binmerge tests/c/main

.PHONY: all test_c
