all: main

run: main
	LD_LIBRARY_PATH=. ./main

clean:
	$(RM) main
	$(RM) main.o
	$(RM) libfoo.so
	$(RM) libfoo.o

main: main.o | libfoo.so
	$(CXX) -L. -lfoo -o $@ $<

libfoo.so: libfoo.o
	$(CXX) -shared -o $@ $<

.PHONY: run all clean
