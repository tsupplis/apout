# Makefile for Apout PDP-11 application emulator
#
# $Revision: 1.31 $
# $Date: 2008/05/19 13:42:39 $
#
# You will need gcc if you choose the optimised compile below
CC?=gcc

# Set the CFLAGS, LDFLAGS for speed or debugging. If you don't want 2.11BSD
# emulation, then remove the -DEMU211 flag.
# Set up the LIBS if required for your system
#
# These flags for doing debugging
APOUT_OPTIONS?= -DEMU211 -DEMUV1 -DNATIVES -DRUN_V1_RAW \
	-DDEBUG -DZERO_MEMORY -DWRITEBASE
# These flags should be fine for most cases
#APOUT_OPTIONS?= -DEMU211 -DEMUv1 -DNATIVES

# These flags for speed
#CFLAGS+= -DEMU211 -DNATIVES -DINLINE=inline -O2 -Winline -Wall \
#	-finline-functions -fomit-frame-pointer
#LDFLAGS?=

# Assemble CFLAGS
CFLAGS?= -O2 -DINLINE=inline -finline-functions -fomit-frame-pointer
CFLAGS+=-Winline -Wunused-result # silence warnings
CFLAGS+= $(APOUT_OPTIONS)

# Any extra libraries required
LIBS= -lm

# Install destinations
PREFIX?=/usr/local
MANDIR=$(PREFIX)/share/man/man1
BINDIR=$(PREFIX)/bin

VERSION= apout2.4.0
SRCS=	cpu.c aout.c aout.h branch.c double.c ea.c itab.c main.c ke11a.c \
	single.c fp.c v7trap.c bsdtrap.c defines.h v7trap.h debug.c \
	bsdtrap.h bsd_ioctl.c bsd_signal.c magic.c v1trap.c v1trap.h
OBJS=	aout.o branch.o bsd_ioctl.o bsd_signal.o bsdtrap.o cpu.o debug.o \
	double.o ea.o fp.o itab.o ke11a.o magic.o main.o single.o v1trap.o \
	v7trap.o

all: apout

TEST_CFLAGS?= -O1 -g
TEST_OPTIONS= -DEMU211 -DEMUV1 -DNATIVES -DRUN_V1_RAW -DWRITEBASE
CORE_SRCS= cpu.c branch.c double.c single.c ea.c fp.c ke11a.c itab.c
SYSCALL_SRCS= $(CORE_SRCS) aout.c bsdtrap.c bsd_ioctl.c bsd_signal.c magic.c v1trap.c
LOADER_SRCS= $(filter-out aout.c,$(SYSCALL_SRCS)) v7trap.c
BSD_TEST_SRCS= $(filter-out bsdtrap.c,$(SYSCALL_SRCS)) v7trap.c
TERMINAL_TEST_SRCS= $(filter-out bsd_ioctl.c,$(SYSCALL_SRCS)) v7trap.c
TEST_HEADERS= defines.h aout.h v7trap.h bsdtrap.h v1trap.h
PDP11_FIXTURES?= $(HOME)/Emulation/PDP11

.PHONY: all test test-sanitize test-smoke

tests/core: tests/core.c $(CORE_SRCS) defines.h Makefile
	$(CC) $(TEST_CFLAGS) $(TEST_OPTIONS) $(CORE_SRCS) tests/core.c -o $@ $(LIBS)

tests/main.o: main.c defines.h Makefile
	$(CC) $(TEST_CFLAGS) $(TEST_OPTIONS) -Dmain=apout_main -c main.c -o $@

tests/syscalls: tests/syscalls.c tests/main.o $(SYSCALL_SRCS) v7trap.c $(TEST_HEADERS) Makefile
	$(CC) $(TEST_CFLAGS) $(TEST_OPTIONS) $(SYSCALL_SRCS) tests/main.o tests/syscalls.c -o $@ $(LIBS)

tests/loader: tests/loader.c tests/main.o $(LOADER_SRCS) aout.c $(TEST_HEADERS) Makefile
	$(CC) $(TEST_CFLAGS) $(TEST_OPTIONS) $(LOADER_SRCS) tests/main.o tests/loader.c -o $@ $(LIBS)

tests/bsd: tests/bsd.c tests/main.o $(BSD_TEST_SRCS) bsdtrap.c $(TEST_HEADERS) Makefile
	$(CC) $(TEST_CFLAGS) $(TEST_OPTIONS) $(BSD_TEST_SRCS) tests/main.o tests/bsd.c -o $@ $(LIBS)

tests/signals: tests/signals.c tests/main.o $(BSD_TEST_SRCS) bsdtrap.c $(TEST_HEADERS) Makefile
	$(CC) $(TEST_CFLAGS) $(TEST_OPTIONS) $(BSD_TEST_SRCS) tests/main.o tests/signals.c -o $@ $(LIBS)

tests/terminal: tests/terminal.c tests/main.o $(TERMINAL_TEST_SRCS) bsd_ioctl.c $(TEST_HEADERS) Makefile
	$(CC) $(TEST_CFLAGS) $(TEST_OPTIONS) $(TERMINAL_TEST_SRCS) tests/main.o tests/terminal.c -o $@ $(LIBS)

test: tests/core tests/syscalls tests/loader tests/bsd tests/signals tests/terminal
	./tests/core
	./tests/syscalls
	./tests/loader
	./tests/bsd
	./tests/signals
	./tests/terminal

test-sanitize:
	$(CC) $(TEST_CFLAGS) $(TEST_OPTIONS) -fsanitize=address,undefined \
		-fno-sanitize-recover=all $(CORE_SRCS) tests/core.c -o tests/core-sanitize $(LIBS)
	./tests/core-sanitize
	$(CC) $(TEST_CFLAGS) $(TEST_OPTIONS) -fsanitize=address,undefined \
		-fno-sanitize-recover=all -Dmain=apout_main -c main.c -o tests/main-sanitize.o
	$(CC) $(TEST_CFLAGS) $(TEST_OPTIONS) -fsanitize=address,undefined \
		-fno-sanitize-recover=all $(SYSCALL_SRCS) tests/main-sanitize.o \
		tests/syscalls.c -o tests/syscalls-sanitize $(LIBS)
	./tests/syscalls-sanitize
	$(CC) $(TEST_CFLAGS) $(TEST_OPTIONS) -fsanitize=address,undefined \
		-fno-sanitize-recover=all $(LOADER_SRCS) tests/main-sanitize.o \
		tests/loader.c -o tests/loader-sanitize $(LIBS)
	./tests/loader-sanitize
	$(CC) $(TEST_CFLAGS) $(TEST_OPTIONS) -fsanitize=address,undefined \
		-fno-sanitize-recover=all $(BSD_TEST_SRCS) tests/main-sanitize.o \
		tests/bsd.c -o tests/bsd-sanitize $(LIBS)
	./tests/bsd-sanitize
	$(CC) $(TEST_CFLAGS) $(TEST_OPTIONS) -fsanitize=address,undefined \
		-fno-sanitize-recover=all $(BSD_TEST_SRCS) tests/main-sanitize.o \
		tests/signals.c -o tests/signals-sanitize $(LIBS)
	./tests/signals-sanitize
	$(CC) $(TEST_CFLAGS) $(TEST_OPTIONS) -fsanitize=address,undefined \
		-fno-sanitize-recover=all $(TERMINAL_TEST_SRCS) tests/main-sanitize.o \
		tests/terminal.c -o tests/terminal-sanitize $(LIBS)
	./tests/terminal-sanitize

test-smoke: apout
	sh tests/smoke.sh "$(CURDIR)/apout" "$(PDP11_FIXTURES)"

apout: $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o apout $(LIBS)

install: apout apout.1
	cp apout $(BINDIR)
	chmod 755 $(BINDIR)/apout
	cp apout.1 $(MANDIR)
	chmod 644 $(MANDIR)/apout.1

clean:
	rm -f tests/core tests/core-sanitize tests/syscalls tests/syscalls-sanitize \
		tests/loader tests/loader-sanitize tests/main.o tests/main-sanitize.o
	rm -f tests/bsd tests/bsd-sanitize
	rm -f tests/signals tests/signals-sanitize tests/terminal tests/terminal-sanitize
	rm -rf apout *core $(OBJS) *.dbg $(VERSION) $(VERSION).tar.gz apout.0

apout.0: apout.1
	nroff -man apout.1 > apout.0

indent: $(SRCS)
	astyle --style=kr $(SRCS)

disttar: clean apout.0
	- mkdir $(VERSION)
	cp $(SRCS) $(VERSION)
	chmod -R go+rX $(VERSION)
	chmod -R u+w $(VERSION)
	chown -R wkt $(VERSION)
	tar vzcf $(VERSION).tar.gz $(VERSION)

# Dependencies for object files
aout.o: aout.c defines.h aout.h Makefile
branch.o: branch.c defines.h Makefile
bsd_ioctl.o: bsd_ioctl.c defines.h Makefile
bsd_signal.o: bsd_signal.c defines.h bsdtrap.h Makefile
bsdtrap.o: bsdtrap.c bsdtrap.h defines.h Makefile
cpu.o: cpu.c defines.h Makefile
debug.o: debug.c defines.h Makefile
double.o: double.c defines.h Makefile
ea.o: ea.c defines.h Makefile
fp.o: fp.c defines.h Makefile
itab.o: itab.c defines.h Makefile
ke11a.o: ke11a.c defines.h Makefile
magic.o: magic.c defines.h Makefile
main.o: main.c defines.h Makefile
single.o: single.c defines.h Makefile
v1trap.o: v1trap.c v1trap.h defines.h Makefile
v7trap.o: v7trap.c v7trap.h defines.h Makefile
