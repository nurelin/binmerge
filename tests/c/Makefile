all: main

run: main
	LD_LIBRARY_PATH=. ./main

clean:
	$(RM) main
	$(RM) main.o
	$(RM) libfoo.so
	$(RM) libfoo.o

main: main.o | libfoo.so
	$(CC) -L. -lfoo -o $@ $<

libfoo.so: libfoo.o
	$(CC) -shared -o $@ $<

.PHONY: run all clean
