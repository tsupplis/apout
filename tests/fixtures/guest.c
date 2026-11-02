/* Original, generated PDP-11 programs; no historical binaries or toolchain needed. */
#include "../../defines.h"
#include "../../aout.h"
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/wait.h>
#include <time.h>

#define IMAGE_SIZE 4096
#define ENTRY 0100
#define PAYLOAD 02000
#define READBACK 02200
#define PATHNAME 03000
#define VECTOR 03400

struct operand {
    unsigned value;
    int reg;
};

struct image {
    unsigned char bytes[IMAGE_SIZE];
    unsigned pc, branches[32], count;
    int bsd;
};

static const char message[] = "fixture output\n";
static const char *editions[] = {"v6", "v7", "bsd"};
static const unsigned magics[] = {V6_M2, V7_M2, BSD_M2};
static const char *flows[] = {"write", "files", "arithmetic", "exec"};
static char work[PATH_MAX];

static void fail(const char *what)
{
    perror(what);
    exit(EXIT_FAILURE);
}

static void require(int success, const char *what)
{
    if (!success)
        fail(what);
}

static void path(char *output, const char *name)
{
    int n = snprintf(output, PATH_MAX, "%s/%s", work, name);
    if (n < 0 || n >= PATH_MAX) {
        errno = ENAMETOOLONG;
        fail("fixture path");
    }
}

static void cleanup(void)
{
    struct dirent *entry;
    DIR *directory;
    char filename[PATH_MAX];
    if (!work[0])
        return;
    directory = opendir(work);
    require(directory != NULL, "open fixture cleanup directory");
    while ((entry = readdir(directory)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        path(filename, entry->d_name);
        require(unlink(filename) == 0, "remove generated fixture");
    }
    require(closedir(directory) == 0 && rmdir(work) == 0, "remove fixture directory");
    work[0] = 0;
}

static void store(struct image *image, unsigned address, unsigned value)
{
    require(address + 1 < IMAGE_SIZE, "fixture image capacity");
    image->bytes[address] = value;
    image->bytes[address + 1] = value >> 8;
}

static void emit(struct image *image, unsigned value)
{
    require(image->pc + 2 <= PAYLOAD, "fixture code capacity");
    store(image, image->pc, value);
    image->pc += 2;
}

static struct operand literal(unsigned value)
{
    struct operand result = {value, 0};
    return result;
}

static struct operand reg(unsigned number)
{
    struct operand result = {number, 1};
    return result;
}

static void move(struct image *image, struct operand value, unsigned destination)
{
    emit(image, 010000 | ((value.reg ? value.value : 027) << 6) | destination);
    if (!value.reg)
        emit(image, value.value);
}

static void branch_on_error(struct image *image, unsigned opcode)
{
    require(image->count < sizeof(image->branches) / sizeof(image->branches[0]),
            "fixture branch capacity");
    image->branches[image->count++] = image->pc;
    emit(image, opcode);
}

static void call(struct image *image, unsigned number, int r0_argument,
                 unsigned count, const struct operand *arguments)
{
    unsigned i;
    if (image->bsd) {
        for (i = count; i > 0; i--)
            move(image, arguments[i - 1], 046); /* -(sp) */
        emit(image, 005046); /* dummy return address */
    } else if (r0_argument) {
        move(image, arguments[0], 0);
    }
    emit(image, 0104400 | number);
    if (!image->bsd)
        for (i = r0_argument ? 1 : 0; i < count; i++) {
            require(!arguments[i].reg, "literal inline syscall argument");
            emit(image, arguments[i].value);
        }
    branch_on_error(image, 0103400); /* bcs */
    if (image->bsd) {
        emit(image, 062706); /* add $argument bytes,sp */
        emit(image, 2 * (count + 1));
    }
}

static void exit_program(struct image *image, struct operand status)
{
    if (image->bsd) {
        move(image, status, 046);
        emit(image, 005046);
    } else {
        move(image, status, 0);
    }
    emit(image, 0104401);
    emit(image, 0); /* must not return from exit */
}

static void check_count(struct image *image)
{
    emit(image, 022700); /* cmp $message length,r0 */
    emit(image, sizeof(message) - 1);
    branch_on_error(image, 001000); /* bne */
}

static void generate(unsigned edition, unsigned flow)
{
    struct image image;
    struct operand args[3];
    unsigned i, target;
    int distance;
    unsigned char header[16] = {0};
    char filename[PATH_MAX], name[64];
    FILE *file;

    memset(&image, 0, sizeof(image));
    image.bsd = edition == 2;
    image.pc = ENTRY;
    /* a_magic2 is the second word of the text, not part of the 16-byte header. */
    store(&image, 2, magics[edition]);
    memcpy(image.bytes + PAYLOAD, message, sizeof(message));
    memcpy(image.bytes + PATHNAME, "file.data", sizeof("file.data"));

    switch (flow) {
    case 0:
        args[0] = literal(1);
        args[1] = literal(PAYLOAD);
        args[2] = literal(sizeof(message) - 1);
        call(&image, 4, 1, 3, args);
        check_count(&image);
        exit_program(&image, literal(0));
        break;
    case 1:
        args[0] = literal(PATHNAME);
        args[1] = literal(0600);
        call(&image, 8, 0, 2, args); /* creat */
        move(&image, reg(0), 4);
        args[0] = reg(4);
        args[1] = literal(PAYLOAD);
        args[2] = literal(sizeof(message) - 1);
        call(&image, 4, 1, 3, args);
        check_count(&image);
        call(&image, 6, 1, 1, args);
        args[0] = literal(PATHNAME);
        args[1] = literal(0);
        call(&image, 5, 0, 2, args); /* open read-only */
        move(&image, reg(0), 4);
        args[0] = reg(4);
        args[1] = literal(READBACK);
        args[2] = literal(sizeof(message) - 1);
        call(&image, 3, 1, 3, args);
        check_count(&image);
        call(&image, 6, 1, 1, args);
        args[0] = literal(1);
        call(&image, 4, 1, 3, args);
        check_count(&image);
        exit_program(&image, literal(0));
        break;
    case 2:
        move(&image, literal(6), 0);
        move(&image, literal(7), 1);
        emit(&image, 070001); /* mul r1,r0 */
        move(&image, reg(1), 0);
        exit_program(&image, reg(0));
        break;
    case 3:
        snprintf(name, sizeof(name), "%s-arithmetic.aout", editions[edition]);
        memcpy(image.bytes + PATHNAME, name, strlen(name) + 1);
        store(&image, VECTOR, PATHNAME);
        store(&image, VECTOR + 2, 0);
        args[0] = literal(PATHNAME);
        args[1] = literal(VECTOR);
        args[2] = literal(0);
        call(&image, image.bsd ? 59 : 11, 0, image.bsd ? 3 : 2, args);
        exit_program(&image, literal(98)); /* successful exec must not return */
        break;
    }
    target = image.pc;
    exit_program(&image, literal(99));
    for (i = 0; i < image.count; i++) {
        unsigned address = image.branches[i];
        distance = ((int) target - (int) address - 2) / 2;
        require(distance >= -128 && distance <= 127, "fixture branch range");
        image.bytes[address] = (unsigned char) distance;
    }
    header[0] = ANY_NORMAL & 0xff;
    header[1] = ANY_NORMAL >> 8;
    header[2] = IMAGE_SIZE & 0xff;
    header[3] = IMAGE_SIZE >> 8;
    header[10] = ENTRY;
    header[14] = 1;
    snprintf(name, sizeof(name), "%s-%s.aout", editions[edition], flows[flow]);
    path(filename, name);
    file = fopen(filename, "wb");
    require(file != NULL, "create guest fixture");
    require(fwrite(header, 1, sizeof(header), file) == sizeof(header) &&
            fwrite(image.bytes, 1, sizeof(image.bytes), file) == sizeof(image.bytes) &&
            fclose(file) == 0, "write guest fixture");
}

static int matches(const char *name, const char *expected)
{
    char filename[PATH_MAX], content[128];
    size_t size;
    FILE *file;
    path(filename, name);
    file = fopen(filename, "rb");
    if (!file) {
        perror(filename);
        return 0;
    }
    size = fread(content, 1, sizeof(content), file);
    require(!ferror(file) && fclose(file) == 0, "read fixture result");
    return size == strlen(expected) && !memcmp(content, expected, size);
}

static int run_fixture(const char *apout, unsigned edition, unsigned flow)
{
    char filename[64], output[PATH_MAX], errors[PATH_MAX], data[PATH_MAX];
    int fd, status, timed_out = 0;
    struct timespec start, now, pause = {0, 10000000};
    pid_t pid, result;
    FILE *error_file;
    char line[256];
    unsigned lines = 0;

    snprintf(filename, sizeof(filename), "%s-%s.aout", editions[edition], flows[flow]);
    path(output, "stdout");
    path(errors, "stderr");
    path(data, "file.data");
    if (flow == 1 && unlink(data) == -1 && errno != ENOENT)
        fail("clear file fixture");
    require(clock_gettime(CLOCK_MONOTONIC, &start) == 0, "fixture clock");
    pid = fork();
    require(pid != -1, "fork guest fixture");
    if (pid == 0) {
        if (chdir(work) == -1 || setenv("APOUT_ROOT", work, 1) == -1 ||
            unsetenv("APOUT_UNIX_VERSION") == -1) {
            perror("guest fixture environment");
            _exit(127);
        }
        fd = open(output, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd == -1 || dup2(fd, STDOUT_FILENO) == -1) {
            perror("capture guest stdout");
            _exit(127);
        }
        close(fd);
        fd = open(errors, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd == -1 || dup2(fd, STDERR_FILENO) == -1) {
            perror("capture guest stderr");
            _exit(127);
        }
        close(fd);
        execl(apout, "apout", filename, (char *) NULL);
        perror("exec emulator");
        _exit(127);
    }
    for (;;) {
        result = waitpid(pid, &status, WNOHANG);
        if (result == pid)
            break;
        if (result == -1 && errno == EINTR)
            continue;
        require(result != -1, "wait guest fixture");
        require(clock_gettime(CLOCK_MONOTONIC, &now) == 0, "fixture timeout clock");
        if (now.tv_sec - start.tv_sec > 5 ||
            (now.tv_sec - start.tv_sec == 5 && now.tv_nsec >= start.tv_nsec)) {
            require(kill(pid, SIGKILL) == 0, "stop timed-out guest fixture");
            require(waitpid(pid, &status, 0) == pid, "reap timed-out guest fixture");
            timed_out = 1;
            break;
        }
        nanosleep(&pause, NULL);
    }
    if (!timed_out && WIFEXITED(status) &&
        WEXITSTATUS(status) == (flow >= 2 ? 42 : 0) &&
        matches("stdout", flow < 2 ? message : "") &&
        matches("stderr", "") && (flow != 1 || matches("file.data", message))) {
        printf("PASS %-4s %s\n", editions[edition], flows[flow]);
        return 1;
    }
    fprintf(stderr, "FAIL %s %s: %s %d\n", editions[edition], flows[flow],
            timed_out ? "timeout" : WIFEXITED(status) ? "exit" : "signal",
            WIFEXITED(status) ? WEXITSTATUS(status) : WTERMSIG(status));
    error_file = fopen(errors, "r");
    require(error_file != NULL, "read failed guest stderr");
    while (lines++ < 20 && fgets(line, sizeof(line), error_file))
        fputs(line, stderr);
    require(fclose(error_file) == 0, "close failed guest stderr");
    return 0;
}

int main(int argc, char **argv)
{
    char apout[PATH_MAX], directory[PATH_MAX];
    unsigned edition, flow, passed = 0, failed = 0;
    const char *selection;
    int n, selected;

    if (argc != 4) {
        fprintf(stderr, "Usage: %s apout fixture-directory all|smoke|write|files|arithmetic|exec\n", argv[0]);
        return EXIT_FAILURE;
    }
    require(realpath(argv[1], apout) != NULL && realpath(argv[2], directory) != NULL,
            "resolve project fixture paths");
    selection = argv[3];
    selected = !strcmp(selection, "all") || !strcmp(selection, "smoke");
    for (flow = 0; flow < 4; flow++)
        selected |= !strcmp(selection, flows[flow]);
    if (!selected) {
        fprintf(stderr, "Unknown fixture batch: %s\n", selection);
        return EXIT_FAILURE;
    }
    n = snprintf(work, sizeof(work), "%s/work.XXXXXX", directory);
    require(n > 0 && n < sizeof(work), "fixture directory capacity");
    require(mkdtemp(work) != NULL, "create project fixture directory");
    require(atexit(cleanup) == 0, "register fixture cleanup");
    for (edition = 0; edition < 3; edition++)
        for (flow = 0; flow < 4; flow++)
            generate(edition, flow);
    for (flow = 0; flow < 4; flow++) {
        if (strcmp(selection, "all") && strcmp(selection, flows[flow]) &&
            (strcmp(selection, "smoke") || (flow != 0 && flow != 2)))
            continue;
        for (edition = 0; edition < 3; edition++)
            if (run_fixture(apout, edition, flow))
                passed++;
            else
                failed++;
    }
    printf("Project fixtures: %u passed, %u failed\n", passed, failed);
    return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
