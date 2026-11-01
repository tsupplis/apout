#include "../aout.c"

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
                    set_arg_env(want_env);
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
    printf("Loader: %u checks, %u failures\n", checks, failures);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
