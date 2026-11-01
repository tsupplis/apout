#include "../bsd_ioctl.c"
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>

static unsigned checks, failures;
static u_int16_t memory[PDP_MEM_SIZE / 2];

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

static void conversion_tests(void)
{
    struct termios native;
    struct tr_sgttyb guest;
    struct tr_ltchars local;
    unsigned n;
    static const unsigned parity[] = {TR_ODDP, TR_EVENP, TR_ANYP, 0};

    for (n = 0; n < 4; n++) {
        memset(&native, 0, sizeof(native));
        memset(&guest, 0, sizeof(guest));
        guest.sg_flags = parity[n];
        guest.sg_ispeed = TR_B9600;
        guest.sg_ospeed = TR_B9600;
        to_termios(&guest, &native);
        check("Parity enable", !!(native.c_cflag & PARENB), n < 2);
        check("Odd parity flag", !!(native.c_cflag & PARODD), n == 0);
        check("Cooked mode enables canonical input", !!(native.c_lflag & ICANON), 1);
        check("Cooked mode enables signals", !!(native.c_lflag & ISIG), 1);
        check("Cooked mode enables output processing", !!(native.c_oflag & OPOST), 1);
    }
    memset(&native, 0, sizeof(native));
    native.c_lflag = ISIG | IEXTEN | ECHO;
    native.c_oflag = OPOST;
    to_sgttyb(&guest, &native);
    check("Echoing noncanonical mode is CBREAK", !!(guest.sg_flags & TR_CBREAK), 1);
    check("Echoing noncanonical mode is not RAW", !!(guest.sg_flags & TR_RAW), 0);
    native.c_lflag = 0;
    native.c_oflag = 0;
    to_sgttyb(&guest, &native);
    check("Non-echoing raw mode is RAW", !!(guest.sg_flags & TR_RAW), 1);
    check("Non-echoing raw mode is not CBREAK", !!(guest.sg_flags & TR_CBREAK), 0);
    memset(&native, 0, sizeof(native));
    native.c_iflag = BRKINT | ICRNL | INPCK | ISTRIP | IXON | PARMRK | INLCR | IGNCR;
    native.c_lflag = ICANON | ISIG | IEXTEN;
    native.c_oflag = OPOST;
    memset(&guest, 0, sizeof(guest));
    guest.sg_flags = TR_RAW;
    guest.sg_ispeed = guest.sg_ospeed = TR_B9600;
    to_termios(&guest, &native);
    check("RAW clears input-processing flags",
          native.c_iflag & (BRKINT | ICRNL | INPCK | ISTRIP | IXON | PARMRK | INLCR | IGNCR), 0);
    check("RAW clears canonical and signal flags", native.c_lflag & (ICANON | ISIG | IEXTEN), 0);
    check("RAW disables output processing", native.c_oflag & OPOST, 0);
    guest.sg_flags = TR_CBREAK | TR_ECHO | TR_CRMOD | TR_TANDEM;
    to_termios(&guest, &native);
    check("CBREAK retains requested echo", !!(native.c_lflag & ECHO), 1);
    check("CBREAK restores signal processing", !!(native.c_lflag & ISIG), 1);
    check("CBREAK restores output processing", !!(native.c_oflag & OPOST), 1);
    check("CRMOD maps input carriage return", !!(native.c_iflag & ICRNL), 1);
    check("CRMOD maps output newline", !!(native.c_oflag & ONLCR), 1);
    check("TANDEM enables input flow control", !!(native.c_iflag & IXOFF), 1);
    to_sgttyb(&guest, &native);
    check("TANDEM roundtrip", !!(guest.sg_flags & TR_TANDEM), 1);
    guest.sg_flags = 0;
    to_termios(&guest, &native);
    check("Cooked mode restored after CBREAK", !!(native.c_lflag & ICANON), 1);
    check("Clearing CRMOD removes input mapping", native.c_iflag & ICRNL, 0);
    memset(&local, 0xff, sizeof(local));
    local.t_werasc = 027;
    native.c_cc[VERASE] = 010;
    tc_to_tchars(NULL, &local, &native);
    check("Word erase maps to VWERASE", native.c_cc[VWERASE], 027);
    check("Word erase does not overwrite erase", native.c_cc[VERASE], 010);
    to_tchars(NULL, &local, &native);
    check("Word erase readback uses VWERASE", (u_int8_t) local.t_werasc, 027);
    native.c_cc[VINTR] = _POSIX_VDISABLE;
    {
        struct tr_tchars characters;
        to_tchars(&characters, NULL, &native);
        check("Disabled native control character becomes BSD 0xff",
              (u_int8_t) characters.t_intrc, 0xff);
        characters.t_intrc = -1;
        tc_to_tchars(&characters, NULL, &native);
        check("Disabled BSD control character becomes native disabled",
              native.c_cc[VINTR], _POSIX_VDISABLE);
    }
}

static void pty_tests(void)
{
    struct termios native;
    struct tr_sgttyb guest;
    struct pollfd ready;
    unsigned char ch;
    int slave, master = posix_openpt(O_RDWR | O_NOCTTY);

    require(master != -1 && grantpt(master) == 0 && unlockpt(master) == 0, "private terminal");
    slave = open(ptsname(master), O_RDWR | O_NOCTTY);
    require(slave != -1, "open private terminal");
    require(tcgetattr(slave, &native) == 0, "terminal attributes");
    to_sgttyb(&guest, &native);
    guest.sg_flags = TR_CBREAK | TR_ANYP;
    guest.sg_ispeed = guest.sg_ospeed = TR_B9600;
    memcpy(&dspace[03001], &guest, 6);
    require(trap_settermios(slave, TR_TIOCSETN, 03001) == 0, "set private CBREAK");
    require(tcgetattr(slave, &native) == 0, "CBREAK attributes");
    check("PTY uses native input speed", cfgetispeed(&native), B9600);
    check("PTY uses native output speed", cfgetospeed(&native), B9600);
    require(write(master, "q", 1) == 1, "queue private input");
    ready.fd = slave;
    ready.events = POLLIN;
    require(poll(&ready, 1, 1000) == 1, "private input readiness");
    require(trap_settermios(slave, TR_TIOCSETN, 03001) == 0, "SETN preserves input");
    ready.revents = 0;
    check("SETN preserves queued input", poll(&ready, 1, 0), 1);
    require(read(slave, &ch, 1) == 1 && ch == 'q', "consume private input");
    require(write(master, "q", 1) == 1, "queue input for flush");
    require(poll(&ready, 1, 1000) == 1, "flush input readiness");
    require(trap_settermios(slave, TR_TIOCSETP, 03001) == 0, "SETP flush");
    ready.revents = 0;
    check("SETP flushes queued input", poll(&ready, 1, 0), 0);
    guest.sg_ispeed = 16;
    memcpy(&dspace[03001], &guest, 6);
    check("Unsupported speed fails instead of hanging up",
          trap_settermios(slave, TR_TIOCSETN, 03001), -1);
    check("Unsupported speed errno", errno, EINVAL);
    require(tcgetattr(slave, &native) == 0, "unchanged speed");
    check("Invalid speed preserves native terminal", cfgetispeed(&native), B9600);
    require(close(slave) == 0 && close(master) == 0, "close private terminal");
}

int main(int argc, char **argv)
{
    (void) argc;
    (void) argv;
    alarm(15);
    dspace = (u_int8_t *) memory;
    conversion_tests();
    pty_tests();
    printf("Terminal: %u checks, %u failures\n", checks, failures);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
