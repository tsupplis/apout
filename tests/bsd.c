#include "../bsdtrap.c"

static u_int16_t imem[PDP_MEM_SIZE / 2], dmem[PDP_MEM_SIZE / 2];
static unsigned checks, failures;

static void check(const char *name, long actual, long expected)
{
    checks++;
    if (actual != expected) {
        fprintf(stderr, "FAIL %s: got %ld, expected %ld\n", name, actual, expected);
        failures++;
    }
}

static void require(int success, const char *name)
{
    if (!success) {
        perror(name);
        exit(EXIT_FAILURE);
    }
}

static void put32(unsigned address, int32_t value)
{
    u_int32_t bits = (u_int32_t) value;
    dspace[address] = bits >> 16;
    dspace[address + 1] = bits >> 24;
    dspace[address + 2] = bits;
    dspace[address + 3] = bits >> 8;
}

static int32_t get32(unsigned address)
{
    return (int32_t) (((u_int32_t) dspace[address + 1] << 24) |
                     ((u_int32_t) dspace[address] << 16) |
                     ((u_int32_t) dspace[address + 3] << 8) | dspace[address + 2]);
}

static void syscall_test(unsigned number, u_int16_t a, u_int16_t b,
                         u_int16_t c, u_int16_t d)
{
    u_int16_t arguments[6] = {a, b, c, d, 0, 0};
    sim_init();
    regs[SP] = 0100;
    memcpy(&dspace[0102], arguments, sizeof(arguments));
    ir = 0104400 | number;
    bsdtrap();
}

static void time_tests(void)
{
    struct itimerval original, disabled = {{0, 0}, {0, 0}};
    struct stat st;
    unsigned char saved[16];
    char filename[] = "/tmp/apout-bsd-tests.XXXXXX";
    int fd;

    memset(&dspace[0], 0x55, 16);
    syscall_test(S_GETTIMEOFDAY, 01002, 0, 0, 0);
    check("GETTIMEOFDAY succeeds with NULL timezone", CC_C, 0);
    check("GETTIMEOFDAY seconds", get32(01002) > 0, 1);
    check("GETTIMEOFDAY microseconds", get32(01006) >= 0 && get32(01006) < 1000000, 1);
    check("GETTIMEOFDAY leaves NULL output untouched", dspace[0], 0x55);
    syscall_test(S_GETTIMEOFDAY, 0, 0, 0, 0);
    check("GETTIMEOFDAY permits both NULL outputs", CC_C, 0);
    check("GETTIMEOFDAY NULL preserves memory", dspace[0], 0x55);
    syscall_test(S_GETTIMEOFDAY, 65532, 0, 0, 0);
    check("GETTIMEOFDAY rejects buffer overrun", CC_C ? regs[0] : 0, EFAULT);

    require(getitimer(ITIMER_VIRTUAL, &original) == 0, "getitimer");
    require(setitimer(ITIMER_VIRTUAL, &disabled, NULL) == 0, "disable timer");
    memset(&dspace[02002], 0, 16);
    put32(02012, 60);
    memcpy(saved, &dspace[02002], sizeof(saved));
    memset(&dspace[03002], 0x55, 16);
    syscall_test(S_SETITIMER, ITIMER_VIRTUAL, 02002, 03002, 0);
    check("SETITIMER succeeds", CC_C, 0);
    check("SETITIMER does not overwrite input", memcmp(saved, &dspace[02002], sizeof(saved)), 0);
    check("SETITIMER returns old timer in third argument", get32(03012), 0);
    syscall_test(S_SETITIMER, ITIMER_VIRTUAL, 02002, 0, 0);
    check("SETITIMER permits NULL old timer", CC_C, 0);
    syscall_test(S_GETITIMER, ITIMER_VIRTUAL, 03002, 0, 0);
    check("GETITIMER succeeds", CC_C, 0);
    check("GETITIMER decodes installed timer", get32(03012) >= 59 && get32(03012) <= 60, 1);
    memset(&dspace[03002], 0x55, 16);
    syscall_test(S_GETITIMER, 0177777, 03002, 0, 0);
    check("GETITIMER propagates invalid selector", CC_C ? regs[0] : 0, EINVAL);
    check("GETITIMER preserves output on failure", dspace[03002], 0x55);
    require(setitimer(ITIMER_VIRTUAL, &original, NULL) == 0, "restore timer");

    fd = mkstemp(filename);
    require(fd != -1, "mkstemp");
    strcpy((char *) &dspace[04000], filename);
    put32(02002, 1700000000);
    put32(02006, 0);
    put32(02012, 1700000001);
    put32(02016, 0);
    memcpy(saved, &dspace[02002], sizeof(saved));
    syscall_test(S_UTIMES, 04000, 02002, 0, 0);
    check("UTIMES succeeds", CC_C, 0);
    require(fstat(fd, &st) == 0, "fstat");
    check("UTIMES sets access time", st.st_atime, 1700000000);
    check("UTIMES sets modification time", st.st_mtime, 1700000001);
    check("UTIMES preserves input", memcmp(saved, &dspace[02002], sizeof(saved)), 0);
    put32(02002, -1);
    put32(02012, -2);
    syscall_test(S_UTIMES, 04000, 02002, 0, 0);
    check("UTIMES accepts signed seconds", CC_C, 0);
    require(fstat(fd, &st) == 0, "fstat signed times");
    check("UTIMES sign-extends access time", st.st_atime, -1);
    check("UTIMES sign-extends modification time", st.st_mtime, -2);
    syscall_test(S_UTIMES, 04000, 0, 0, 0);
    check("UTIMES NULL sets current time", CC_C, 0);
    require(close(fd) == 0, "close");
    require(unlink(filename) == 0, "unlink");

    memset(&dspace[02002], 0x55, sizeof(struct tr_rusage));
    syscall_test(S_GETRUSAGE, RUSAGE_SELF, 02002, 0, 0);
    check("GETRUSAGE succeeds", CC_C, 0);
    check("GETRUSAGE user time initialized", get32(02002) >= 0, 1);
    check("GETRUSAGE user microseconds valid", get32(02006) >= 0 && get32(02006) < 1000000, 1);
    check("GETRUSAGE system microseconds valid", get32(02016) >= 0 && get32(02016) < 1000000, 1);
}

static void io_tests(void)
{
    int pipes[2], fd1, fd2;
    u_int16_t vector[4] = {02000, 2, 02002, 3};
    char output[6] = {0};

    require(pipe(pipes) == 0, "pipe");
    memcpy(&dspace[02000], "hello", 5);
    syscall_test(S_WRITE, pipes[1], 02000, 5, 0);
    check("WRITE transfers bytes", CC_C ? -1 : regs[0], 5);
    syscall_test(S_READ, pipes[0], 03000, 5, 0);
    check("READ transfers bytes", CC_C ? -1 : regs[0], 5);
    check("READ byte content", memcmp(&dspace[03000], "hello", 5), 0);
    syscall_test(S_WRITE, pipes[1], 65534, 4, 0);
    check("WRITE rejects guest buffer overrun", CC_C ? regs[0] : 0, EFAULT);
    syscall_test(S_READ, pipes[0], 65534, 4, 0);
    check("READ rejects guest buffer overrun before blocking", CC_C ? regs[0] : 0, EFAULT);
    memcpy(&dspace[01000], vector, sizeof(vector));
    syscall_test(S_WRITEV, pipes[1], 01000, 2, 0);
    check("WRITEV transfers both vectors", CC_C ? -1 : regs[0], 5);
    require(read(pipes[0], output, 5) == 5, "read vector output");
    check("WRITEV byte content", memcmp(output, "hello", 5), 0);
    require(write(pipes[1], "hello", 5) == 5, "write readv input");
    vector[0] = 03000;
    vector[2] = 03002;
    memcpy(&dspace[01000], vector, sizeof(vector));
    syscall_test(S_READV, pipes[0], 01000, 2, 0);
    check("READV transfers both vectors", CC_C ? -1 : regs[0], 5);
    check("READV byte content", memcmp(&dspace[03000], "hello", 5), 0);
    syscall_test(S_READV, pipes[0], 01000, 0177777, 0);
    check("READV rejects negative vector count", CC_C ? regs[0] : 0, EINVAL);
    vector[0] = 65534;
    vector[1] = 4;
    memcpy(&dspace[01000], vector, sizeof(vector));
    syscall_test(S_WRITEV, pipes[1], 01000, 1, 0);
    check("WRITEV rejects vector buffer overrun", CC_C ? regs[0] : 0, EFAULT);
    syscall_test(S_WRITEV, pipes[1], 65534, 2, 0);
    check("WRITEV rejects vector-array overrun", CC_C ? regs[0] : 0, EFAULT);
    syscall_test(S_WRITEV, pipes[1], 0, 0, 0);
    check("WRITEV permits zero vectors", CC_C ? -1 : regs[0], 0);
    syscall_test(S_WRITEV, pipes[0], 0, 0, 0);
    check("WRITEV zero vectors checks descriptor mode", CC_C ? regs[0] : 0, EBADF);
    syscall_test(S_WRITEV, 0177777, 0, 0, 0);
    check("WRITEV zero vectors checks descriptor validity", CC_C ? regs[0] : 0, EBADF);
    syscall_test(S_WRITEV, pipes[1], 01000, 17, 0);
    check("WRITEV enforces BSD vector limit", CC_C ? regs[0] : 0, EINVAL);
    vector[0] = 02000;
    vector[1] = 40000;
    vector[2] = 02000;
    vector[3] = 40000;
    memcpy(&dspace[01000], vector, sizeof(vector));
    syscall_test(S_WRITEV, pipes[1], 01000, 2, 0);
    check("WRITEV rejects 16-bit transfer overflow", CC_C ? regs[0] : 0, EINVAL);
    syscall_test(S_SOCKETPAIR, AF_UNIX, SOCK_STREAM, 0, 65534);
    check("SOCKETPAIR rejects output overrun", CC_C ? regs[0] : 0, EFAULT);
    require(close(pipes[0]) == 0 && close(pipes[1]) == 0, "close pipes");

    memset(&dspace[01002], 0x55, 6);
    syscall_test(S_SOCKETPAIR, AF_UNIX, SOCK_STREAM, 0, 01002);
    check("SOCKETPAIR succeeds", CC_C, 0);
    fd1 = dspace[01002] | (dspace[01003] << 8);
    fd2 = dspace[01004] | (dspace[01005] << 8);
    check("SOCKETPAIR returns first descriptor", fcntl(fd1, F_GETFD) != -1, 1);
    check("SOCKETPAIR returns second descriptor", fcntl(fd2, F_GETFD) != -1, 1);
    check("SOCKETPAIR writes exactly two words", dspace[01006], 0x55);
    if (fd1 != 0x5555 && fd2 != 0x5555 && fd1 != fd2) {
        memcpy(&dspace[02000], "ok", 2);
        syscall_test(S_SEND, fd1, 02000, 2, 0);
        check("SEND transfers bytes", CC_C ? -1 : regs[0], 2);
        syscall_test(S_RECV, fd2, 03000, 2, 0);
        check("RECV transfers bytes", CC_C ? -1 : regs[0], 2);
        check("SOCKETPAIR endpoints communicate", memcmp(&dspace[03000], "ok", 2), 0);
        syscall_test(S_SEND, fd1, 65534, 4, 0);
        check("SEND rejects buffer overrun", CC_C ? regs[0] : 0, EFAULT);
        syscall_test(S_RECV, fd2, 65534, 4, 0);
        check("RECV rejects buffer overrun before blocking", CC_C ? regs[0] : 0, EFAULT);
        syscall_test(S_SEND, fd1, 02000, 0177777, 0);
        check("SEND rejects negative count", CC_C ? regs[0] : 0, EINVAL);
        require(close(fd1) == 0 && close(fd2) == 0, "close sockets");
    }
}

int main(int argc, char **argv)
{
    (void) argc;
    (void) argv;
    alarm(15);
    ispace = (u_int8_t *) imem;
    dspace = (u_int8_t *) dmem;
    dwrite_base = 0;
    Binary = IS_211BSD;
    set_apout_root("/");
    time_tests();
    io_tests();
    printf("BSD: %u checks, %u failures\n", checks, failures);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
