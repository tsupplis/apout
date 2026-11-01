#include "../aout.c"
#include <sys/wait.h>

static u_int16_t imem[PDP_MEM_SIZE / 2], dmem[PDP_MEM_SIZE / 2];
static unsigned checks, failures;
static char oversized[PDP_MEM_SIZE + 1];
static unsigned char saved_memory[PDP_MEM_SIZE];
int apout_main(int argc, char **argv);

static void check(const char *name, long actual, long expected)
{
    checks++;
    if (actual != expected) {
        fprintf(stderr, "FAIL %s: got %ld, expected %ld\n", name, actual, expected);
        failures++;
    }
}

static void oversized_stack_test(void)
{
    pid_t child;
    int status;

    memset(oversized, 'x', sizeof(oversized) - 1);
    oversized[sizeof(oversized) - 1] = 0;
    child = fork();
    if (child == -1) {
        perror("fork stack test");
        exit(EXIT_FAILURE);
    }
    if (child == 0) {
        Binary = IS_V7;
        Argc = 1;
        Argv[0] = oversized;
        Envc = 0;
        Envp[0] = NULL;
        regs[SP] = 01234;
        memset(dmem, 0x55, sizeof(dmem));
        errno = 0;
        set_arg_env(0, 0);
        _exit(errno == E2BIG && regs[SP] == 01234 && dmem[0] == 0x5555 ? 0 : 1);
    }
    if (waitpid(child, &status, 0) != child) {
        perror("wait stack test");
        exit(EXIT_FAILURE);
    }
    check("Oversized stack fails cleanly before writes",
          WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
}

static void reject_stack(int mode, unsigned floor, int error)
{
    int envc = Envc;
    char *env0 = Envp[0];
    memset(dmem, 0x55, sizeof(dmem));
    memcpy(saved_memory, dmem, sizeof(dmem));
    regs[SP] = 01234;
    errno = 0;
    check("Invalid stack returns failure", set_arg_env(mode, floor), -1);
    check("Invalid stack errno", errno, error);
    check("Invalid stack preserves SP", regs[SP], 01234);
    check("Invalid stack preserves all guest bytes", memcmp(dmem, saved_memory, sizeof(dmem)), 0);
    check("Invalid stack preserves environment count", Envc, envc);
    check("Invalid stack preserves environment pointer", Envp[0] == env0, 1);
}

static void stack_bounds_tests(void)
{
    static const int editions[] = {IS_V1, IS_V2, IS_V6, IS_V7, IS_211BSD};
    unsigned n, top, floor, bytes;
    int mode, i, start;
    u_int16_t pointer, count;

    ispace = (u_int8_t *) imem;
    dspace = (u_int8_t *) dmem;
    dwrite_base = 0;
    for (n = 0; n < sizeof(editions) / sizeof(editions[0]); n++) {
        Binary = editions[n];
        top = (Binary == IS_V1 || Binary == IS_V2) ? KE11LO - 2 : PDP_MEM_SIZE - 2;
        for (mode = 0; mode <= 1; mode++) {
            Argc = Envc = 1;
            Argv[0] = oversized;
            Envp[0] = "X=y";
            floor = 02000;
            bytes = top - floor - (mode ? 10 + 4 : 6);
            memset(oversized, 'x', bytes - 1);
            oversized[bytes - 1] = 0;
            memset(dmem, 0x55, sizeof(dmem));
            check("Exact-fit argument stack succeeds", set_arg_env(mode, floor), 0);
            check("Exact-fit SP reaches image boundary", regs[SP], floor);
            ll_word(floor, count);
            check("Exact-fit argc", count, 1);
            ll_word(floor + 2, pointer);
            check("Exact-fit argument starts after vectors", pointer, floor + (mode ? 10 : 6));
            check("Exact-fit argument payload", dspace[pointer], 'x');
            check("Exact-fit argument terminator", dspace[pointer + bytes - 1], 0);
            check("Exact-fit preserves image canary", dspace[floor - 1], 0x55);
            if (Binary == IS_V1 || Binary == IS_V2)
                check("Stack preserves KE11A window", dspace[KE11LO], 0x55);
            memset(oversized, 'x', bytes);
            oversized[bytes] = 0;
            reject_stack(mode, floor, E2BIG);

            memset(oversized, 'x', bytes - 1);
            oversized[bytes - 1] = 0;
            reject_stack(mode, floor + 1, E2BIG);
            check("Stack plan accounts for odd-floor alignment",
                  arg_env_start(mode, floor - 1, Binary), floor);
        }
    }

    Binary = IS_V7;
    Argc = 2;
    Argv[0] = Argv[1] = oversized;
    Envc = 1;
    Envp[0] = "X=y";
    memset(oversized, 'x', 40000);
    oversized[40000] = 0;
    reject_stack(0, 0, E2BIG);
    Argc = 1;
    Argv[0] = "a";
    Envc = 2;
    Envp[0] = Envp[1] = oversized;
    reject_stack(1, 0, E2BIG);
    check("Ignored environment does not consume stack", set_arg_env(0, 0), 0);

    Envc = 0;
    Envp[0] = NULL;
    start = PDP_MEM_SIZE - 2 - 2;
    for (i = 0; i < default_envc; i++)
        start -= strlen(default_envp[i]) + 1;
    start = (start & ~1) - 2 * (1 + default_envc + 3);
    reject_stack(1, start + 2, E2BIG);
    check("Exact-fit default environment succeeds", set_arg_env(1, start), 0);
    check("Default environment count preserved", Envc, default_envc);
    check("Default environment stack boundary", regs[SP], start);

    Argc = MAX_ARGS + 1;
    reject_stack(0, 0, E2BIG);
    Argc = -1;
    reject_stack(0, 0, EINVAL);
    Argc = 1;
    Argv[0] = NULL;
    reject_stack(0, 0, EFAULT);
    Argv[0] = "a";
    Envc = MAX_ARGS + 1;
    Envp[0] = "X=y";
    reject_stack(1, 0, E2BIG);
    Envc = -1;
    reject_stack(1, 0, EINVAL);
    Envc = 2;
    Envp[1] = NULL;
    reject_stack(1, 0, EFAULT);
    Envc = 1;
    reject_stack(2, 0, EINVAL);
    reject_stack(0, PDP_MEM_SIZE, E2BIG);
    dwrite_base = PDP_MEM_SIZE - 6;
    reject_stack(0, 0, E2BIG);
    dwrite_base = 0;
}

static void cli_stack_test(char *filename)
{
    char output[512], *arguments[] = {"apout", filename, oversized, NULL};
    int descriptors[2], status;
    ssize_t length;
    pid_t child;

    memset(oversized, 'x', PDP_MEM_SIZE);
    oversized[PDP_MEM_SIZE] = 0;
    if (pipe(descriptors) == -1 || (child = fork()) == -1) {
        perror("CLI stack test");
        exit(EXIT_FAILURE);
    }
    if (child == 0) {
        close(descriptors[0]);
        if (dup2(descriptors[1], STDERR_FILENO) == -1 ||
            unsetenv("APOUT_ROOT") == -1)
            _exit(254);
        close(descriptors[1]);
        apout_main(3, arguments);
        _exit(255);
    }
    close(descriptors[1]);
    if (waitpid(child, &status, 0) != child ||
        (length = read(descriptors[0], output, sizeof(output) - 1)) < 0) {
        perror("CLI stack result");
        exit(EXIT_FAILURE);
    }
    output[length] = 0;
    check("CLI rejects oversized argument stack",
          WIFEXITED(status) ? WEXITSTATUS(status) : -1, EXIT_FAILURE);
    check("CLI reports argument-size error", strstr(output, strerror(E2BIG)) != NULL, 1);
    if (close(descriptors[0]) == -1) {
        perror("close CLI test pipe");
        exit(EXIT_FAILURE);
    }
}

static void loader_preflight_tests(void)
{
    static const struct {
        unsigned magic, magic2, text, bss, overlay, floor;
        int binary;
    } images[] = {
        {ANY_NORMAL, V7_M2, 2, 1024, 0, 1028, IS_V7},
        {ANY_NORMAL, V2_M2, 2, 1024, 0, 16384 + 1028, IS_V2},
        {ANY_ROTEXT, V7_M2, 2, 1024, 0, 8192 + 1026, IS_V7},
        {ANY_SPLITID, BSD_M2, 2, 1024, 0, 1026, IS_211BSD},
        {V1_NORMAL, 0, 32, 1024, 0, 16384 + 32, IS_V1},
        {BSD_OVERLAY, 0, 2, 1024, 8192, 16384 + 1026, IS_211BSD},
        {BSD_ROVERLAY, 0, 2, 1024, 8192, 1026, IS_211BSD}
    };
    struct exec header;
    unsigned char padding[64] = {0};
    char filename[] = "/tmp/apout-loader.XXXXXX";
    FILE *file;
    int fd = mkstemp(filename);
    unsigned n, top, bytes;

    if (fd == -1 || (file = fdopen(fd, "w+b")) == NULL) {
        perror("loader fixture");
        exit(EXIT_FAILURE);
    }
    for (n = 0; n < sizeof(images) / sizeof(images[0]); n++) {
        memset(&header, 0, sizeof(header));
        header.a_magic = images[n].magic;
        header.a_magic2 = images[n].magic2;
        header.a_text = images[n].text;
        header.a_data = 2;
        header.a_bss = images[n].bss;
        if (images[n].magic == V1_NORMAL)
            header.a_syms = images[n].bss;
        if (images[n].overlay)
            header.max_ovl = images[n].overlay;
        rewind(file);
        if (fwrite(&header, sizeof(header), 1, file) != 1 ||
            fwrite(padding, sizeof(padding), 1, file) != 1 || fflush(file) != 0) {
            perror("write loader fixture");
            exit(EXIT_FAILURE);
        }
        ispace = (u_int8_t *) imem;
        dspace = (u_int8_t *) dmem;
        Binary = IS_V6;
        dwrite_base = 012;
        regs[SP] = 01234;
        Argc = 1;
        Argv[0] = oversized;
        Envc = 0;
        Envp[0] = NULL;
        memset(oversized, 'x', PDP_MEM_SIZE);
        oversized[PDP_MEM_SIZE] = 0;
        memset(darray, 0x55, sizeof(darray));
        memset(iarray, 0x66, sizeof(iarray));
        memcpy(saved_memory, darray, sizeof(darray));
        check("Loader rejects oversized stack", load_a_out(filename, NULL, 0), -1);
        check("Loader stack error is E2BIG", errno, E2BIG);
        check("Rejected load preserves data mapping", dspace == (u_int8_t *) dmem, 1);
        check("Rejected load preserves instruction mapping", ispace == (u_int8_t *) imem, 1);
        check("Rejected load preserves binary type", Binary, IS_V6);
        check("Rejected load preserves write protection", dwrite_base, 012);
        check("Rejected load preserves registers", regs[SP], 01234);
        check("Rejected load precedes data/image writes",
              memcmp(darray, saved_memory, sizeof(darray)), 0);
        check("Rejected load precedes instruction writes", iarray[0], 0x66);
        Argv[0] = "a";
        Envc = 2;
        Envp[0] = Envp[1] = oversized;
        memset(oversized, 'x', 40000);
        oversized[40000] = 0;
        check("Loader rejects combined oversized environment", load_a_out(filename, NULL, 1), -1);
        check("Loader environment error is E2BIG", errno, E2BIG);
        check("Environment rejection precedes guest writes",
              memcmp(darray, saved_memory, sizeof(darray)), 0);
        check("Environment rejection preserves mapping", dspace == (u_int8_t *) dmem, 1);
        check("Environment rejection preserves registers", regs[SP], 01234);
        Envc = 0;
        Envp[0] = NULL;
        Argv[0] = oversized;
        top = (images[n].binary == IS_V1 || images[n].binary == IS_V2) ?
              KE11LO - 2 : PDP_MEM_SIZE - 2;
        bytes = top - images[n].floor - 6;
        memset(oversized, 'x', bytes - 1);
        oversized[bytes - 1] = 0;
        check("Loader accepts exact-fit stack above image", load_a_out(filename, NULL, 0), 0);
        check("Loader exact-fit SP protects code/data/BSS", regs[SP], images[n].floor);
        check("Loader commits expected binary type", Binary, images[n].binary);
    }
    cli_stack_test(filename);
    for (n = 0; n < 8; n++) {
        memset(&header, 0, sizeof(header));
        header.a_magic = ANY_NORMAL;
        header.a_magic2 = V7_M2;
        header.a_text = 2;
        switch (n) {
        case 0:
            header.a_text = 40000;
            header.a_data = 30000;
            break;
        case 1:
            header.a_magic = ANY_SPLITID;
            header.a_magic2 = BSD_M2;
            header.a_data = 65530;
            header.a_bss = 10;
            break;
        case 2:
            header.a_magic = ANY_ROTEXT;
            header.a_text = 65535;
            header.a_data = 1;
            break;
        case 3:
            header.a_magic = BSD_OVERLAY;
            header.max_ovl = -1;
            header.ov_siz[0] = 0;
            break;
        case 4:
            header.a_magic = BSD_OVERLAY;
            header.max_ovl = 2;
            header.ov_siz[0] = 4;
            break;
        case 5:
            header.a_magic = BSD_ROVERLAY;
            header.a_text = 65535;
            header.max_ovl = 8192;
            header.ov_siz[0] = 0;
            break;
        case 6:
            header.a_magic = BSD_OVERLAY;
            header.a_text = 24576;
            header.max_ovl = 24576;
            header.a_data = 20000;
            header.ov_siz[0] = 0;
            break;
        case 7:
            header.a_magic2 = V2_M2;
            header.a_text = 65500;
            break;
        }
        rewind(file);
        if (fwrite(&header, sizeof(header), 1, file) != 1 || fflush(file) != 0) {
            perror("write invalid loader fixture");
            exit(EXIT_FAILURE);
        }
        ispace = (u_int8_t *) imem;
        dspace = (u_int8_t *) dmem;
        Binary = IS_V7;
        Argc = 1;
        Argv[0] = "a";
        Envc = 0;
        Envp[0] = NULL;
        regs[SP] = 01234;
        memset(darray, 0x55, sizeof(darray));
        memcpy(saved_memory, darray, sizeof(darray));
        check("Loader rejects overflowing image layout", load_a_out(filename, NULL, 0), -1);
        check("Invalid image layout errno", errno, ENOEXEC);
        check("Invalid image preserves guest memory",
              memcmp(darray, saved_memory, sizeof(darray)), 0);
        check("Invalid image preserves mapping", dspace == (u_int8_t *) dmem, 1);
        check("Invalid image preserves registers", regs[SP], 01234);
    }
    if (fclose(file) != 0 || unlink(filename) != 0) {
        perror("cleanup loader fixture");
        exit(EXIT_FAILURE);
    }
    ispace = (u_int8_t *) imem;
    dspace = (u_int8_t *) dmem;
    dwrite_base = 0;
}

int main(int argc, char **argv)
{
    int want_env, arg_length, env_length, edition;
    u_int16_t pointer, value;

    (void) argc;
    (void) argv;
    alarm(15);
    ispace = (u_int8_t *) imem;
    dspace = (u_int8_t *) dmem;
    dwrite_base = 0;
    Argc = 2;
    Envc = 1;
    Argv[1] = "bc";
    for (edition = 0; edition < 2; edition++) {
        Binary = edition ? IS_V1 : IS_V7;
        for (want_env = 0; want_env < 2; want_env++) {
            for (arg_length = 0; arg_length < 2; arg_length++) {
                for (env_length = 0; env_length < 2; env_length++) {
                    memset(dmem, 0, sizeof(dmem));
                    Argv[0] = arg_length ? "aa" : "a";
                    Envp[0] = env_length ? "X=yy" : "X=y";
                    check("Loader accepts normal stack", set_arg_env(want_env, 0), 0);
                    check("Loader aligns stack for every string parity", regs[SP] & 1, 0);
                    ll_word(regs[SP], value);
                    check("Loader saves argc", value, 2);
                    ll_word(regs[SP] + 2, pointer);
                    check("Loader aligns argv[0] for V7 crt0", pointer & 1, 0);
                    check("Loader preserves argv[0]", strcmp((char *) &dspace[pointer], Argv[0]), 0);
                    ll_word(regs[SP] + 4, pointer);
                    check("Loader preserves argv[1]", strcmp((char *) &dspace[pointer], Argv[1]), 0);
                    ll_word(regs[SP] + 6, value);
                    check("Loader terminates argv", value, want_env ? 0 : 0177777);
                    if (want_env) {
                        ll_word(regs[SP] + 8, pointer);
                        check("Loader preserves environment", strcmp((char *) &dspace[pointer], Envp[0]), 0);
                    }
                }
            }
        }
    }
    Binary = IS_V7;
    Argc = Envc = MAX_ARGS;
    for (edition = 0; edition < MAX_ARGS; edition++) {
        Argv[edition] = "arg";
        Envp[edition] = "X=y";
    }
    Argv[MAX_ARGS] = Envp[MAX_ARGS] = NULL;
    check("Loader accepts maximum vector counts", set_arg_env(1, 0), 0);
    ll_word(regs[SP], value);
    check("Loader supports full MAX_ARGS count", value, MAX_ARGS);
    ll_word(regs[SP] + 2 * (MAX_ARGS + 1), value);
    check("Loader terminates maximum argument vector", value, 0);
    ll_word(regs[SP] + 2 * (2 * MAX_ARGS + 2), value);
    check("Loader terminates maximum environment vector", value, 0);
    oversized_stack_test();
    stack_bounds_tests();
    loader_preflight_tests();
    printf("Loader: %u checks, %u failures\n", checks, failures);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
