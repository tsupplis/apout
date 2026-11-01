#include <sys/types.h>
#include <unistd.h>
#include <signal.h>

static int test_kill(pid_t pid, int sig);
static int test_killpg(pid_t pid, int sig);
#define kill test_kill
#define killpg test_killpg
#include "../bsdtrap.c"
#undef kill
#undef killpg

static u_int16_t imem[PDP_MEM_SIZE / 2], dmem[PDP_MEM_SIZE / 2];
static unsigned checks, failures, kill_calls;
static pid_t killed_pid;
static int killed_signal, killed_group;

static int test_kill(pid_t pid, int sig)
{
    kill_calls++;
    killed_pid = pid;
    killed_signal = sig;
    killed_group = 0;
    return 0;
}

static int test_killpg(pid_t pid, int sig)
{
    test_kill(pid, sig);
    killed_group = 1;
    return 0;
}

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

static void call(unsigned number, u_int16_t a, u_int16_t b, u_int16_t c, u_int16_t d)
{
    u_int16_t args[] = {a, b, c, d, 0, 0};
    sim_init();
    regs[SP] = 0100;
    memcpy(&dspace[0102], args, sizeof(args));
    ir = 0104400 | number;
    bsdtrap();
}

static void action(unsigned addr, u_int16_t handler, u_int32_t mask, u_int16_t flags)
{
    memcpy(&dspace[addr], &handler, 2);
    bsd_store_long(addr + 2, mask);
    memcpy(&dspace[addr + 6], &flags, 2);
}

static u_int16_t word(unsigned addr)
{
    u_int16_t result;
    memcpy(&result, &dspace[addr], 2);
    return result;
}

static void action_tests(void)
{
    struct sigaction native;
    unsigned n;
    const unsigned invalid[] = {0, 9, 17, 29, 32, 65535};

    memset(&native, 0, sizeof(native));
    sigemptyset(&native.sa_mask);
    native.sa_handler = SIG_DFL;
    require(sigaction(SIGUSR1, &native, NULL) == 0, "initialize private signal");
    action(03001, 1, 1UL << 30, 2);
    memset(&dspace[04000], 0x55, 10);
    call(S_SIGACTION, 01234, 30, 03001, 04001);
    check("SIGACTION accepts real trampoline-first ABI", CC_C, 0);
    require(sigaction(SIGUSR1, NULL, &native) == 0, "query native action");
    check("SIGACTION installs ignored disposition", native.sa_handler == SIG_IGN, 1);
    check("SIGACTION translates mask signal 31", sigismember(&native.sa_mask, SIGUSR2), 1);
    check("SIGACTION translates restart flag", !!(native.sa_flags & SA_RESTART), 1);
    check("SIGACTION returns old disposition", word(04001), 0);
    check("SIGACTION old mask has guest layout", bsd_load_long(04003), 0);
    check("SIGACTION leading canary", dspace[04000], 0x55);
    check("SIGACTION trailing canary", dspace[04011], 0x55);
    call(S_SIGACTION, 01234, 30, 0, 65528);
    check("SIGACTION query accepts exact end", CC_C, 0);
    check("SIGACTION query returns ignored disposition", word(65528), 1);
    check("SIGACTION query returns translated mask", bsd_load_long(65530), 1UL << 30);
    check("SIGACTION query returns guest flags", word(65534), 2);
    call(S_SIGACTION, 0, 9, 0, 04001);
    check("SIGACTION permits querying SIGKILL", CC_C, 0);
    check("SIGACTION reports SIGKILL default", word(04001), 0);
    call(S_SIGACTION, 0, 17, 0, 0);
    check("SIGACTION permits no-op SIGSTOP query", CC_C, 0);
    call(S_SIGACTION, 0, 30, 03001, 03001);
    check("SIGACTION supports aliased old and new actions", CC_C, 0);
    check("SIGACTION aliased output", word(03001), 1);
    action(03001, 0, 0, 0);
    call(S_SIGACTION, 0, 30, 65529, 0);
    check("SIGACTION rejects input overrun", CC_C ? regs[0] : 0, EFAULT);
    call(S_SIGACTION, 0, 30, 03001, 65529);
    check("SIGACTION rejects output overrun before setting", CC_C ? regs[0] : 0, EFAULT);
    require(sigaction(SIGUSR1, NULL, &native) == 0, "action after invalid pointers");
    check("SIGACTION invalid buffers preserve disposition", native.sa_handler == SIG_IGN, 1);
    for (n = 0; n < sizeof(invalid) / sizeof(invalid[0]); n++) {
        call(S_SIGACTION, 0, invalid[n], 03001, 04001);
        check("SIGACTION rejects invalid or uncatchable signal", CC_C ? regs[0] : 0, EINVAL);
    }
    memset(&dspace[04001], 0x55, 8);
    action(03001, 02000, 0, 0);
    call(S_SIGACTION, 01234, 30, 03001, 04001);
    check("SIGACTION explicitly rejects unsupported guest handlers", CC_C ? regs[0] : 0, ENOSYS);
    check("SIGACTION unsupported handler preserves output", word(04001), 0x5555);
    action(03001, 1, 0, 0x8000);
    call(S_SIGACTION, 0, 30, 03001, 0);
    check("SIGACTION rejects unknown flags", CC_C ? regs[0] : 0, EINVAL);
    action(03001, 1, 0, 0);
    call(S_SIGACTION, 0, 20, 03001, 0);
    check("SIGACTION rejects host SIGCHLD ignore semantic mismatch", CC_C ? regs[0] : 0, ENOSYS);
}

static void mask_tests(void)
{
    sigset_t empty, native, old;
    u_int32_t bits = (1UL << 29) | (1UL << 30);
    unsigned n;

    sigemptyset(&empty);
    require(sigprocmask(SIG_SETMASK, &empty, &old) == 0, "initialize private mask");
    bsd_store_long(03001, bits);
    memset(&dspace[04000], 0x55, 6);
    call(S_SIGPROCMASK, 1, 03001, 04001, 0);
    check("SIGPROCMASK blocks guest mask", CC_C, 0);
    check("SIGPROCMASK returns previous mask", bsd_load_long(04001), 0);
    check("SIGPROCMASK leading canary", dspace[04000], 0x55);
    check("SIGPROCMASK trailing canary", dspace[04005], 0x55);
    require(sigprocmask(SIG_SETMASK, NULL, &native) == 0, "query native mask");
    check("SIGPROCMASK maps guest USR1", sigismember(&native, SIGUSR1), 1);
    check("SIGPROCMASK maps guest USR2", sigismember(&native, SIGUSR2), 1);
    call(S_SIGPROCMASK, 999, 0, 65532, 0);
    check("SIGPROCMASK query ignores how with NULL input", CC_C, 0);
    check("SIGPROCMASK exact-end output", (u_int32_t) bsd_load_long(65532), bits);
    bsd_store_long(03001, 1UL << 29);
    call(S_SIGPROCMASK, 2, 03001, 03001, 0);
    check("SIGPROCMASK accepts aliased masks", CC_C, 0);
    check("SIGPROCMASK aliased output is old mask", (u_int32_t) bsd_load_long(03001), bits);
    require(sigprocmask(SIG_SETMASK, NULL, &native) == 0, "query unblocked mask");
    check("SIGPROCMASK unblocks translated signal", sigismember(&native, SIGUSR1), 0);
    check("SIGPROCMASK preserves other blocked signal", sigismember(&native, SIGUSR2), 1);
    bsd_store_long(03001, 0);
    call(S_SIGPROCMASK, 3, 03001, 65533, 0);
    check("SIGPROCMASK rejects output before unblocking", CC_C ? regs[0] : 0, EFAULT);
    call(S_SIGPROCMASK, 3, 65533, 04001, 0);
    check("SIGPROCMASK rejects input overrun", CC_C ? regs[0] : 0, EFAULT);
    call(S_SIGPROCMASK, 4, 03001, 04001, 0);
    check("SIGPROCMASK rejects invalid operation", CC_C ? regs[0] : 0, EINVAL);
    require(sigprocmask(SIG_SETMASK, NULL, &native) == 0, "mask after bad calls");
    check("SIGPROCMASK failures preserve native mask", sigismember(&native, SIGUSR2), 1);
    bsd_store_long(03001, (1UL << 8) | (1UL << 16));
    call(S_SIGPROCMASK, 1, 03001, 0, 0);
    require(sigprocmask(SIG_SETMASK, NULL, &native) == 0, "unmaskable signals");
    check("SIGPROCMASK cannot block SIGKILL", sigismember(&native, SIGKILL), 0);
    check("SIGPROCMASK cannot block SIGSTOP", sigismember(&native, SIGSTOP), 0);

    require(raise(SIGUSR2) == 0, "queue blocked private signal");
    memset(&dspace[04000], 0x55, 6);
    call(S_SIGPENDING, 04001, 0, 0, 0);
    check("SIGPENDING returns success", CC_C, 0);
    check("SIGPENDING uses guest USR2 bit", (u_int32_t) bsd_load_long(04001), 1UL << 30);
    check("SIGPENDING leading canary", dspace[04000], 0x55);
    check("SIGPENDING trailing canary", dspace[04005], 0x55);
    call(S_SIGPENDING, 0, 0, 0, 0);
    check("SIGPENDING NULL pointer matches BSD", CC_C ? regs[0] : 0, EINVAL);
    call(S_SIGPENDING, 65533, 0, 0, 0);
    check("SIGPENDING rejects overrun", CC_C ? regs[0] : 0, EFAULT);
    require(signal(SIGUSR2, SIG_IGN) != SIG_ERR, "discard private pending signal");
    require(sigprocmask(SIG_SETMASK, &old, NULL) == 0, "restore mask");
    for (n = 0; n < 9; n++) {
        static const unsigned unsupported[] = {
            S_SIGRETURN, S_SIGALTSTACK, S_SIGSUSPEND, S_SIGVEC, S_SIGBLOCK,
            S_SIGSETMASK, S_SIGPAUSE, S_SIGSTACK, S_SIGRETURN
        };
        call(unsupported[n], 0, 0, 0, 0);
        check("Unsupported signal APIs fail explicitly", CC_C ? regs[0] : 0, ENOSYS);
    }
}

static void private_handler(int sig)
{
    (void) sig;
}

static void exec_tests(void)
{
    struct sigaction action;
    sigset_t mask, oldmask;
    char directory[] = "/tmp/apout-signals.XXXXXX";

    require(mkdtemp(directory) != NULL, "signal exec directory");
    snprintf((char *) &dspace[02000], 100, "%s/missing", directory);
    call(S_EXECVE, 02000, 0, 0, 0);
    check("Failed exec reports missing file", CC_C ? regs[0] : 0, ENOENT);
    require(sigaction(SIGUSR1, NULL, &action) == 0, "signal after failed exec");
    check("Failed exec preserves ignored disposition", action.sa_handler == SIG_IGN, 1);
    require(rmdir(directory) == 0, "remove signal exec directory");
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR2);
    require(sigprocmask(SIG_BLOCK, &mask, &oldmask) == 0, "mask across exec");
    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);
    action.sa_handler = private_handler;
    require(sigaction(SIGUSR2, &action, NULL) == 0, "private caught disposition");
    call(S_SIGACTION, 0, 31, 0, 04001);
    check("SIGACTION rejects unrepresentable native handler", CC_C ? regs[0] : 0, ENOSYS);
    require(bsd_signal_exec() == 0, "emulated exec signal transition");
    require(sigaction(SIGUSR1, NULL, &action) == 0, "ignored signal across exec");
    check("Exec preserves ignored disposition", action.sa_handler == SIG_IGN, 1);
    require(sigaction(SIGUSR2, NULL, &action) == 0, "caught signal across exec");
    check("Exec resets caught disposition", action.sa_handler == SIG_DFL, 1);
    require(sigprocmask(SIG_SETMASK, NULL, &mask) == 0, "query exec mask");
    check("Exec preserves native mask", sigismember(&mask, SIGUSR2), 1);
    require(sigprocmask(SIG_SETMASK, &oldmask, NULL) == 0, "restore exec mask");
}

static void kill_tests(void)
{
    unsigned n;
    static const unsigned invalid[] = {29, 32, 65535};
    call(S_KILL, 1234, 30, 0, 0);
    check("KILL translates SIGUSR1", killed_signal, SIGUSR1);
    check("KILL preserves target PID", killed_pid, 1234);
    call(S_KILLPG, 1234, 17, 0, 0);
    check("KILLPG translates SIGSTOP", killed_signal, SIGSTOP);
    check("KILLPG preserves group dispatch", killed_group, 1);
    call(S_KILL, 1234, 0, 0, 0);
    check("KILL supports signal-zero probe", killed_signal, 0);
    kill_calls = 0;
    for (n = 0; n < sizeof(invalid) / sizeof(invalid[0]); n++) {
        call(S_KILL, 1234, invalid[n], 0, 0);
        check("KILL rejects unmapped guest signals", CC_C ? regs[0] : 0, EINVAL);
    }
    check("Invalid KILL never reaches native syscall", kill_calls, 0);
}

int main(int argc, char **argv)
{
    pid_t child = fork();
    int status;
    (void) argc;
    (void) argv;
    require(child != -1, "fork isolated signal tests");
    if (child) {
        require(waitpid(child, &status, 0) == child, "wait signal tests");
        if (WIFSIGNALED(status))
            fprintf(stderr, "FAIL signal test process terminated by native signal %d\n",
                    WTERMSIG(status));
        return WIFEXITED(status) ? WEXITSTATUS(status) : EXIT_FAILURE;
    }
    alarm(15);
    ispace = (u_int8_t *) imem;
    dspace = (u_int8_t *) dmem;
    Binary = IS_211BSD;
    action_tests();
    kill_tests();
    /* Do not raise a default-fatal signal if the mask APIs failed. */
    if (!failures) {
        exec_tests();
        mask_tests();
    }
    printf("Signals: %u checks, %u failures\n", checks, failures);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
