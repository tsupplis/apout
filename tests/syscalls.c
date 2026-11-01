#include "../v7trap.c"
#include <assert.h>

static u_int16_t imem[PDP_MEM_SIZE / 2], dmem[PDP_MEM_SIZE / 2];
static unsigned checks, failures;

static void check(const char *name, long actual, long expected)
{
    checks++;
    if (actual != expected) {
        fprintf(stderr, "FAIL %s: got %ld, expected %ld\n",
                name, actual, expected);
        failures++;
    }
}

static void io_tests(void)
{
    int pipes[2], edition;
    u_int16_t arguments[2];

    for (edition = 0; edition < 2; edition++) {
        if (pipe(pipes) == -1) {
            perror("test pipe");
            exit(EXIT_FAILURE);
        }
        Binary = edition ? IS_V1 : IS_V7;
        memcpy(&dspace[03000], "ok", 2);
        arguments[0] = 03000;
        arguments[1] = 2;
        memcpy(&ispace[0200], arguments, sizeof(arguments));
        memcpy(&dspace[0200], arguments, sizeof(arguments));
        regs[PC] = 0200;
        regs[0] = pipes[1];
        ir = 0104400 | S_WRITE;
        if (edition)
            v1trap();
        else
            v7trap();
        check("V1/V7 WRITE transfers bytes", CC_C ? -1 : regs[0], 2);
        arguments[0] = 04000;
        memcpy(&ispace[0200], arguments, sizeof(arguments));
        memcpy(&dspace[0200], arguments, sizeof(arguments));
        regs[PC] = 0200;
        regs[0] = pipes[0];
        ir = 0104400 | S_READ;
        if (edition)
            v1trap();
        else
            v7trap();
        check("V1/V7 READ transfers bytes", CC_C ? -1 : regs[0], 2);
        check("V1/V7 READ preserves content", memcmp(&dspace[04000], "ok", 2), 0);
        arguments[0] = 65534;
        arguments[1] = 4;
        memcpy(&ispace[0200], arguments, sizeof(arguments));
        memcpy(&dspace[0200], arguments, sizeof(arguments));
        regs[PC] = 0200;
        regs[0] = pipes[1];
        ir = 0104400 | S_WRITE;
        if (edition)
            v1trap();
        else
            v7trap();
        check("V1/V7 WRITE rejects buffer overrun", CC_C, 1);
        check("V1/V7 WRITE reports EFAULT", errno, EFAULT);
        regs[PC] = 0200;
        regs[0] = pipes[0];
        ir = 0104400 | S_READ;
        if (edition)
            v1trap();
        else
            v7trap();
        check("V1/V7 READ rejects buffer overrun before blocking", CC_C, 1);
        check("V1/V7 READ reports EFAULT", errno, EFAULT);
        if (edition) {
            arguments[1] = 0177777;
            memcpy(&dspace[0200], arguments, sizeof(arguments));
            regs[PC] = 0200;
            regs[0] = pipes[1];
            ir = 0104400 | S_WRITE;
            v1trap();
            check("V1 WRITE rejects negative count", CC_C, 1);
            check("V1 WRITE reports EINVAL", errno, EINVAL);
        }
        if (close(pipes[0]) == -1 || close(pipes[1]) == -1) {
            perror("test close");
            exit(EXIT_FAILURE);
        }
    }
}

int main(int argc, char **argv)
{
    int master, slave;
    char *name;
    struct termios before, after;
    struct tr_sgttyb sg;
    void (*previous)(int);

    (void) argc;
    (void) argv;
    alarm(15);
    ispace = (u_int8_t *) imem;
    dspace = (u_int8_t *) dmem;
    dwrite_base = 0;
    Binary = IS_V7;
    master = posix_openpt(O_RDWR | O_NOCTTY);
    if (master == -1 || grantpt(master) == -1 || unlockpt(master) == -1) {
        perror("test pseudoterminal");
        return EXIT_FAILURE;
    }
    name = ptsname(master);
    if (name == NULL || (slave = open(name, O_RDWR | O_NOCTTY)) == -1) {
        perror("test pseudoterminal slave");
        close(master);
        return EXIT_FAILURE;
    }
    assert(tcgetattr(slave, &before) == 0);
    assert(cfsetispeed(&before, B9600) == 0);
    assert(cfsetospeed(&before, B9600) == 0);
    before.c_lflag |= ECHO | ICANON | ISIG;
    before.c_oflag |= ONLCR;
    assert(tcsetattr(slave, TCSANOW, &before) == 0);
    check("GTTY succeeds", trap_gtty(slave, 01000), 0);
    memcpy(&sg, &dspace[01000], sizeof(sg));
    check("GTTY maps input baud code", sg.sg_ispeed, 13);
    check("GTTY maps output baud code", sg.sg_ospeed, 13);
    sg.sg_flags = TR_RAW | TR_ANYP;
    sg.sg_erase = 0177;
    sg.sg_kill = 025;
    memcpy(&dspace[01000], &sg, sizeof(sg));
    check("STTY raw succeeds", trap_stty(slave, 01000), 0);
    assert(tcgetattr(slave, &after) == 0);
    check("STTY raw clears canonical", !!(after.c_lflag & ICANON), 0);
    check("STTY raw clears echo", !!(after.c_lflag & ECHO), 0);
    check("STTY raw clears signals", !!(after.c_lflag & ISIG), 0);
    check("STTY raw clears newline conversion", !!(after.c_oflag & ONLCR), 0);
    check("STTY preserves speed", cfgetospeed(&after), B9600);
    check("STTY raw minimum read", after.c_cc[VMIN], 1);
    check("GTTY raw succeeds", trap_gtty(slave, 01000), 0);
    memcpy(&sg, &dspace[01000], sizeof(sg));
    check("GTTY reports RAW", !!(sg.sg_flags & TR_RAW), 1);
    sg.sg_flags = TR_CBREAK | TR_ECHO | TR_CRMOD | TR_ANYP;
    memcpy(&dspace[01000], &sg, sizeof(sg));
    check("STTY cbreak succeeds", trap_stty(slave, 01000), 0);
    assert(tcgetattr(slave, &after) == 0);
    check("STTY cbreak enables signals", !!(after.c_lflag & ISIG), 1);
    check("STTY cbreak enables echo", !!(after.c_lflag & ECHO), 1);
    check("GTTY cbreak succeeds", trap_gtty(slave, 01000), 0);
    memcpy(&sg, &dspace[01000], sizeof(sg));
    check("GTTY reports CBREAK", !!(sg.sg_flags & TR_CBREAK), 1);
    sg.sg_flags = TR_ECHO | TR_CRMOD | TR_ANYP;
    memcpy(&dspace[01000], &sg, sizeof(sg));
    check("STTY cooked succeeds", trap_stty(slave, 01000), 0);
    assert(tcgetattr(slave, &after) == 0);
    check("STTY cooked restores canonical", !!(after.c_lflag & ICANON), 1);
    check("STTY preserves erase", after.c_cc[VERASE], 0177);
    check("STTY preserves kill", after.c_cc[VKILL], 025);
    check("STTY rejects NULL", trap_stty(slave, 0), -1);
    check("STTY NULL errno", errno, EFAULT);
    check("GTTY rejects overrun", trap_gtty(slave, 65535), -1);
    check("GTTY overrun errno", errno, EFAULT);
    sg.sg_ispeed = 16;
    memcpy(&dspace[01000], &sg, sizeof(sg));
    check("STTY rejects invalid speed", trap_stty(slave, 01000), -1);
    check("STTY invalid speed errno", errno, EINVAL);
    assert(tcsetattr(slave, TCSANOW, &before) == 0);
    close(slave);
    close(master);

    check("signal rejects negative number", v7signal(-1, V7_SIG_IGN), -1);
    check("signal rejects zero", v7signal(0, V7_SIG_IGN), -1);
    check("signal rejects out of range", v7signal(V7_NSIG + 1, V7_SIG_IGN), -1);
    previous = signal(SIGTERM, SIG_DFL);
    assert(previous != SIG_ERR);
    check("signal returns guest default", v7signal(V7_SIGTERM, V7_SIG_IGN), V7_SIG_DFL);
    check("signal returns guest ignore", v7signal(V7_SIGTERM, V7_SIG_DFL), V7_SIG_IGN);
    regs[PC] = 01000;
    imem[01000 / 2] = V7_SIGTERM;
    imem[01002 / 2] = V7_SIG_IGN;
    dmem[01000 / 2] = V7_SIGKILL;
    dmem[01002 / 2] = V7_SIG_IGN;
    ir = 0104400 | S_SIGNAL;
    v7trap();
    check("Direct syscall reads instruction-space arguments", CC_C, 0);
    check("Direct syscall advances PC past arguments", regs[PC], 01004);
    regs[PC] = 01000;
    imem[01000 / 2] = 02000;
    dmem[02000 / 2] = 0104400 | S_SIGNAL;
    dmem[02002 / 2] = V7_SIGTERM;
    dmem[02004 / 2] = V7_SIG_DFL;
    ir = 0104400 | S_INDIR;
    v7trap();
    check("Indirect syscall reads data-space arguments", CC_C, 0);
    check("Indirect syscall returns previous guest handler", regs[0], V7_SIG_IGN);
    assert(signal(SIGTERM, previous) != SIG_ERR);
    check("signal propagates host failure", v7signal(V7_SIGKILL, V7_SIG_IGN), -1);
    io_tests();
    printf("Syscalls: %u checks, %u failures\n", checks, failures);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
