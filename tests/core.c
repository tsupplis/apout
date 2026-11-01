#include "../defines.h"
#include <math.h>
#include <sys/wait.h>
#include <unistd.h>

int Binary = IS_V7;
static u_int16_t imem[PDP_MEM_SIZE / 2], dmem[PDP_MEM_SIZE / 2];
static unsigned checks, failures;

static void reset(void)
{
    sim_init();
    memset(imem, 0, sizeof(imem));
    memset(dmem, 0, sizeof(dmem));
    ispace = (u_int8_t *) imem;
    dspace = (u_int8_t *) dmem;
    dwrite_base = 0;
    memset(fregs, 0, sizeof(FLOAT) * 8);
    FPN = FPZ = FPV = FPC = FPMODE = INTMODE = 0;
    Binary = IS_V7;
}

static void check(const char *name, long actual, long expected)
{
    checks++;
    if (actual != expected) {
        fprintf(stderr, "FAIL %s: got %ld, expected %ld\n",
                name, actual, expected);
        failures++;
    }
}

static void execute(unsigned instruction)
{
    ir = instruction;
    itab[ir >> 6]();
}

static void integer_tests(void)
{
    reset();
    CC_N = CC_Z = CC_V = CC_C = 1;
    execute(0106400);
    check("MTPS clears NZVC", CC_N + CC_Z + CC_V + CC_C, 0);
    reset(); regs[0] = 0100000; execute(0005600);
    check("SBC without carry has no overflow", CC_V, 0);
    reset(); regs[0] = 0200; CC_C = 1; execute(0105600);
    check("SBCB signed overflow", CC_V, 1);
    reset(); regs[0] = 0201; CC_C = 1; execute(0105600);
    check("SBCB result at minimum is not overflow", CC_V, 0);
    reset(); regs[0] = 300; regs[2] = 300; execute(0070002);
    check("MUL carry for wide product", CC_C, 1);
    check("MUL high word", regs[0], 1);
    check("MUL low word", regs[1], 24464);
    reset(); regs[0] = 3; regs[2] = 4; execute(0070002);
    check("MUL carry for narrow product", CC_C, 0);
    reset(); regs[0] = 1; regs[1] = 0; regs[2] = 1; execute(0071002);
    check("DIV overflow flag", CC_V, 1);
    check("DIV overflow preserves high word", regs[0], 1);
    check("DIV overflow preserves low word", regs[1], 0);
    reset(); regs[0] = 0100000; regs[2] = 0177777; execute(0071002);
    check("DIV INT32_MIN/-1 overflow", CC_V, 1);
    check("DIV INT32_MIN/-1 preserves dividend", regs[0], 0100000);
    reset(); regs[0] = 0; regs[1] = 10; regs[2] = 3; execute(0071002);
    check("DIV quotient", regs[0], 3);
    check("DIV remainder", regs[1], 1);
    reset(); regs[0] = 1; regs[1] = 2; execute(0071002);
    check("DIV zero flags", CC_C + CC_V, 2);
    check("DIV zero preserves dividend", regs[0], 1);
    reset(); regs[0] = 040000; regs[2] = 2; execute(0072002);
    check("ASH tracks intermediate sign change", CC_V, 1);
    reset(); regs[0] = 040000; regs[2] = 2; execute(0073002);
    check("ASHC tracks intermediate sign change", CC_V, 1);
    reset(); regs[0] = 0100000; regs[2] = 077; execute(0072002);
    check("ASH right shift sign extension", regs[0], 0140000);
    check("ASH right shift no overflow", CC_V, 0);
    reset(); regs[0] = 01000; dmem[01000 / 2] = 1;
    CC_C = CC_V = CC_N = 1; regs[SP] = 02000; execute(0006510);
    check("MFPI clears overflow", CC_V, 0);
    check("MFPI result sign", CC_N, 0);
    check("MFPI preserves carry", CC_C, 1);
    check("MFPI pushed value", dmem[01776 / 2], 1);
    CC_V = CC_N = 1; regs[0] = 03000; execute(0006610);
    check("MTPI stored value", dmem[03000 / 2], 1);
    check("MTPI clears overflow", CC_V, 0);
    check("MTPI result sign", CC_N, 0);
}

static void addressing_tests(void)
{
    reset(); regs[0] = 01000;
    dmem[01000 / 2] = 02000; imem[01000 / 2] = 03000;
    execute(0000130);
    check("JMP deferred reads data pointer", regs[PC], 02000);
    reset(); regs[0] = 01002;
    dmem[01000 / 2] = 02000; imem[01000 / 2] = 03000;
    execute(0000150);
    check("JMP autodecrement deferred reads data pointer", regs[PC], 02000);
    reset(); regs[0] = 012345; regs[PC] = 01000;
    imem[01000 / 2] = 02000; dmem[01000 / 2] = 03000;
    execute(0010037);
    check("MOV absolute destination uses instruction pointer", dmem[02000 / 2], 012345);
    check("MOV absolute destination advances PC", regs[PC], 01002);
    reset(); regs[0] = 0377; regs[PC] = 01000;
    imem[01000 / 2] = 02000; dmem[01000 / 2] = 03000;
    execute(0110037);
    check("MOVB absolute destination uses instruction pointer", dspace[02000], 0377);
}

static void floating_tests(void)
{
    reset(); regs[2] = 01000; dmem[01000 / 2] = 0177777;
    execute(0177022);
    check("LDCIF signed memory operand", (long) fregs[0], -1);
    check("LDCIF advances correct operand", regs[2], 01002);
    reset(); regs[2] = 0177777; execute(0177002);
    check("LDCIF signed register operand", (long) fregs[0], -1);
    reset(); fregs[0] = 1.0f; execute(0170700);
    check("NEGF register", (long) fregs[0], -1);
    check("NEGF negative flag", FPN, 1);
    execute(0170600);
    check("ABSF register", (long) fregs[0], 1);
    reset(); regs[0] = 01000; dmem[01000 / 2] = 040200;
    execute(0170710);
    check("NEGF positive memory sign", dmem[01000 / 2], 0140200);
    check("NEGF memory negative flag", FPN, 1);
    execute(0170710);
    check("NEGF negative memory sign", dmem[01000 / 2], 040200);
    reset(); regs[0] = 01000; dmem[01000 / 2] = 02000;
    dmem[02000 / 2] = 040200; execute(0172430);
    check("LDF deferred pointer stride", regs[0], 01002);
    check("LDF deferred value", (long) fregs[0], 1);
    regs[0] = 01002; execute(0172450);
    check("LDF deferred decrement stride", regs[0], 01000);
    reset(); fregs[0] = 1.0f; regs[0] = 01000; dmem[01000 / 2] = 02000;
    FPMODE = 1; execute(0174030);
    check("STF deferred double pointer stride", regs[0], 01002);
    check("STF deferred double value", dmem[02000 / 2], 040200);
    reset(); regs[PC] = 01000;
    imem[01000 / 2] = 02000; dmem[01000 / 2] = 03000;
    dmem[02000 / 2] = 040200; execute(0172437);
    check("LDF absolute reads data float", (long) fregs[0], 1);
    check("LDF absolute advances PC", regs[PC], 01002);
    reset(); regs[0] = 0200 | 040 | CC_NBIT; CC_Z = 1; execute(0170100);
    check("LDFPS FP negative", FPN, 1);
    check("LDFPS double mode", FPMODE, 1);
    check("LDFPS long mode", INTMODE, 1);
    check("LDFPS preserves CPU flags", CC_N + CC_Z, 1);
    dstword = 012345; execute(0170201);
    check("STFPS returns FP status", regs[1], 0200 | 040 | CC_NBIT);
    reset(); FPN = 1; execute(0170400);
    check("CLRF clears negative", FPN, 0);
    check("CLRF sets zero", FPZ, 1);
    reset(); fregs[0] = 1.0f; regs[2] = 3; execute(0176402);
    check("LDEXP correct operand", (long) fregs[0], 4);
    reset(); INTMODE = 1; regs[2] = 01000; dmem[01000 / 2] = 02000;
    dmem[02000 / 2] = 0; dmem[02002 / 2] = 7; execute(0177032);
    check("LDCLF deferred stride", regs[2], 01002);
    check("LDCLF long word order", (long) fregs[0], 7);
    reset(); fregs[0] = 1.0f; regs[2] = 01000; execute(0177422);
    check("LDCDF alternate width stride", regs[2], 01010);
    check("LDCDF restores mode", FPMODE, 0);
    reset(); regs[0] = 01000; dmem[01000 / 2] = 0200; execute(0172410);
    check("LDF minimum exponent is nonzero", fregs[0] > 0.0f, 1);
    reset(); regs[0] = 01002; dmem[01002 / 2] = 040200; execute(0172410);
    check("LDF supports word-aligned float", (long) fregs[0], 1);
    fregs[0] = 2.0f; execute(0174010);
    check("STF supports word-aligned float", dmem[01002 / 2], 040400);
}

static void ke11_tests(void)
{
    reset(); Binary = IS_V1;
    kesl_word(0177304, 1); kesl_word(0177306, 0177777);
    check("KE11 signed MUL high", (u_int16_t) kell_word(0177302), 0177777);
    check("KE11 signed MUL low", (u_int16_t) kell_word(0177304), 0177777);
    kesl_word(0177304, 0177777); kesl_word(0177302, 0177777); kesl_word(0177314, 077);
    check("KE11 logical right zero fill", (u_int16_t) kell_word(0177302), 077777);
    kesl_word(0177304, 0177775); kesl_word(0177302, 0177777); kesl_word(0177316, 077);
    check("KE11 arithmetic right rounds down", (u_int16_t) kell_word(0177304), 0177776);
    kesl_word(0177304, 3); kesl_word(0177314, 0);
    check("KE11 logical zero shift", (u_int16_t) kell_word(0177304), 3);
    kesl_word(0177316, 0);
    check("KE11 arithmetic zero shift", (u_int16_t) kell_word(0177304), 3);
    kesl_word(0177304, 0177777); kesl_word(0177314, 040);
    check("KE11 logical shift by 32", (u_int16_t) kell_word(0177304), 0);
    kesl_word(0177304, 0177777); kesl_word(0177316, 040);
    check("KE11 arithmetic shift by 32", (u_int16_t) kell_word(0177304), 0177777);
    kesl_word(0177304, 9); kesl_word(0177300, 2);
    check("KE11 DIV quotient", (u_int16_t) kell_word(0177304), 4);
    check("KE11 DIV remainder", (u_int16_t) kell_word(0177302), 1);
    kesl_word(0177304, 0); kesl_word(0177302, 0100000); kesl_word(0177300, 0177777);
    check("KE11 DIV INT32_MIN/-1 overflow", !!(kell_word(0177310) & 0140000), 1);
    kesl_word(0177304, 1); kesl_word(0177312, 0);
    check("KE11 normalize low word", (u_int16_t) kell_word(0177304), 0);
    check("KE11 normalize high word", (u_int16_t) kell_word(0177302), 040000);
}

static void failure_tests(void)
{
    static const char *names[] = {
        "Non-finite store exits rather than hanging",
        "KE11 zero division reports failure rather than host fault",
        "Odd word load reports bus error",
        "Odd word store reports bus error",
        "Odd instruction fetch reports bus error",
        "Out-of-range word address reports bus error"
    };
    pid_t child;
    int status, scenario;

    for (scenario = 0; scenario < 6; scenario++) {
        fflush(NULL);
        child = fork();
        if (child == -1) {
            perror("test fork");
            exit(EXIT_FAILURE);
        }
        if (child == 0) {
            alarm(2);
            reset();
            if (scenario == 0) {
                fregs[0] = INFINITY;
                regs[0] = 01000;
                execute(0174010);
            } else if (scenario == 1) {
                Binary = IS_V1;
                kesl_word(0177300, 0);
            } else if (scenario == 2) {
                ll_word(1, dstword);
            } else if (scenario == 3) {
                sl_word(1, 1);
            } else if (scenario == 4) {
                lli_word(1, dstword);
            } else {
                ll_word(PDP_MEM_SIZE, dstword);
            }
            _exit(EXIT_SUCCESS);
        }
        if (waitpid(child, &status, 0) != child) {
            perror("test waitpid");
            exit(EXIT_FAILURE);
        }
        check(names[scenario],
              WIFEXITED(status) && WEXITSTATUS(status) == EXIT_FAILURE, 1);
    }
}

int main(int argc, char **argv)
{
    (void) argc;
    (void) argv;
    alarm(15);
    integer_tests();
    addressing_tests();
    floating_tests();
    ke11_tests();
    failure_tests();
    printf("Core: %u checks, %u failures\n", checks, failures);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
