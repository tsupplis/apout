#include <sys/types.h>
#include <unistd.h>
#include <grp.h>

static int test_getgroups(int count, gid_t *groups);
static int test_setgroups(size_t count, const gid_t *groups);
#define getgroups test_getgroups
#define setgroups test_setgroups
#include "../bsdtrap.c"
#undef getgroups
#undef setgroups
#include <netinet/in.h>
#include <poll.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <termios.h>

static u_int16_t imem[PDP_MEM_SIZE / 2], dmem[PDP_MEM_SIZE / 2];
static unsigned checks, failures;
static int fake_groups, fail_setgroups, setgroups_calls;
static size_t supplied_group_count;
static gid_t supplied_groups[16];

static int test_getgroups(int count, gid_t *groups)
{
    if (!fake_groups)
        return getgroups(count, groups);
    if (fake_groups == 3)
        return 0;
    if (fake_groups == 4) {
        errno = EIO;
        return -1;
    }
    if (count == 0)
        return 2;
    if (count < 2) {
        errno = EINVAL;
        return -1;
    }
    groups[0] = 123;
    groups[1] = fake_groups == 2 ? 70000 : 60000;
    return 2;
}

static int test_setgroups(size_t count, const gid_t *groups)
{
    setgroups_calls++;
    supplied_group_count = count;
    if (count <= 16 && count)
        memcpy(supplied_groups, groups, count * sizeof(*groups));
    if (fail_setgroups) {
        errno = EPERM;
        return -1;
    }
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

static void syscall_test6(unsigned number, u_int16_t a, u_int16_t b,
                          u_int16_t c, u_int16_t d, u_int16_t e, u_int16_t f)
{
    u_int16_t arguments[6] = {a, b, c, d, e, f};
    sim_init();
    regs[SP] = 0100;
    memcpy(&dspace[0102], arguments, sizeof(arguments));
    ir = 0104400 | number;
    bsdtrap();
}

static void syscall_test(unsigned number, u_int16_t a, u_int16_t b,
                         u_int16_t c, u_int16_t d)
{
    syscall_test6(number, a, b, c, d, 0, 0);
}

static void put16(unsigned addr, u_int16_t value)
{
    memcpy(&dspace[addr], &value, 2);
}

static u_int16_t get16(unsigned addr)
{
    u_int16_t value;
    memcpy(&value, &dspace[addr], 2);
    return value;
}

static void socket_name_tests(void)
{
    struct sockaddr_in address;
    socklen_t length = sizeof(address);
    u_int16_t family = AF_INET, capacity;
    unsigned char expected[sizeof(address)];
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    unsigned n;

    require(fd != -1, "socket");
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    memcpy(&dspace[04000], &family, 2);
    memcpy(&dspace[04002], (unsigned char *) &address + 2, sizeof(address) - 2);
    syscall_test(S_BIND, fd, 04000, sizeof(address), 0);
    check("BIND IPv4 address", CC_C, 0);
    require(getsockname(fd, (struct sockaddr *) &address, &length) == 0, "getsockname");
    memcpy(expected, &family, 2);
    memcpy(expected + 2, (unsigned char *) &address + 2, sizeof(address) - 2);

    for (n = 0; n <= sizeof(address); n++) {
        memset(&dspace[03000], 0x55, 32);
        memset(&dspace[02000], 0x55, 4);
        capacity = n;
        memcpy(&dspace[02000], &capacity, 2);
        syscall_test(S_GETSOCKNAME, fd, 03000, 02000, 0);
        check("GETSOCKNAME succeeds for each capacity", CC_C, 0);
        memcpy(&capacity, &dspace[02000], 2);
        check("GETSOCKNAME BSD copied length", capacity, n);
        check("GETSOCKNAME translated prefix", memcmp(&dspace[03000], expected, n), 0);
        check("GETSOCKNAME address canary", dspace[03000 + n], 0x55);
        check("GETSOCKNAME length canary", dspace[02002], 0x55);
    }
    capacity = 16;
    memcpy(&dspace[02000], &capacity, 2);
    syscall_test(S_GETSOCKNAME, fd, 65530, 02000, 0);
    check("GETSOCKNAME rejects address overrun", CC_C ? regs[0] : 0, EFAULT);
    syscall_test(S_GETSOCKNAME, fd, 03000, 65535, 0);
    check("GETSOCKNAME rejects length-pointer overrun", CC_C ? regs[0] : 0, EFAULT);
    memset(&dspace[03000], 0x55, 32);
    syscall_test(S_GETPEERNAME, fd, 03000, 02000, 0);
    check("GETPEERNAME unconnected error", CC_C ? regs[0] : 0, ENOTCONN);
    check("GETPEERNAME failure preserves buffer", dspace[03000], 0x55);
    memcpy(&capacity, &dspace[02000], 2);
    check("GETPEERNAME failure preserves length", capacity, 16);
    require(close(fd) == 0, "close socket");
}

static void unix_socket_tests(void)
{
    char directory[] = "/tmp/apout-sockets.XXXXXX";
    char server_path[108], client_path[108];
    struct sockaddr_un peer;
    socklen_t peer_length = sizeof(peer);
    int server, client, client2, accepted, flags;

    require(mkdtemp(directory) != NULL, "mkdtemp sockets");
    require(snprintf(server_path, sizeof(server_path), "%s/server", directory) <
            sizeof(server_path), "server path");
    require(snprintf(client_path, sizeof(client_path), "%s/client", directory) <
            sizeof(client_path), "client path");
    server = socket(AF_UNIX, SOCK_STREAM, 0);
    client = socket(AF_UNIX, SOCK_STREAM, 0);
    client2 = socket(AF_UNIX, SOCK_STREAM, 0);
    require(server != -1 && client != -1 && client2 != -1, "Unix sockets");
    flags = fcntl(server, F_GETFL);
    require(flags != -1 && fcntl(server, F_SETFL, flags | O_NONBLOCK) == 0,
            "nonblocking listener");
    memset(&dspace[04000], 0, 110);
    put16(04000, AF_UNIX);
    strcpy((char *) &dspace[04002], server_path);
    syscall_test(S_BIND, server, 04000, 110, 0);
    check("BIND full-size guest Unix address", CC_C, 0);
    require(!CC_C, "guest Unix bind");
    memset(&dspace[05000], 0, 110);
    put16(05000, AF_UNIX);
    strcpy((char *) &dspace[05002], client_path);
    syscall_test(S_BIND, client, 05000, 110, 0);
    check("BIND Unix client", CC_C, 0);
    require(!CC_C, "guest Unix client bind");
    syscall_test(S_LISTEN, server, 4, 0, 0);
    check("LISTEN Unix socket", CC_C, 0);

    memset(&dspace[03000], 0x55, 128);
    put16(02000, 128);
    syscall_test(S_GETSOCKNAME, server, 03000, 02000, 0);
    check("GETSOCKNAME Unix succeeds", CC_C, 0);
    check("GETSOCKNAME Unix family", get16(03000), AF_UNIX);
    check("GETSOCKNAME Unix path", strcmp((char *) &dspace[03002], server_path), 0);
    check("GETSOCKNAME Unix canary", dspace[03000 + get16(02000)], 0x55);

    syscall_test(S_BIND, client2, 04000, 1, 0);
    check("BIND rejects short header", CC_C ? regs[0] : 0, EINVAL);
    syscall_test(S_BIND, client2, 04000, 0177777, 0);
    check("BIND rejects oversized length", CC_C ? regs[0] : 0, EINVAL);
    syscall_test(S_BIND, client2, 0, 16, 0);
    check("BIND rejects NULL address", CC_C ? regs[0] : 0, EFAULT);
    syscall_test(S_CONNECT, client2, 65530, 16, 0);
    check("CONNECT rejects address overrun", CC_C ? regs[0] : 0, EFAULT);
    syscall_test(S_CONNECT, client2, 04000, 111, 0);
    check("CONNECT rejects oversized Unix structure", CC_C ? regs[0] : 0, EINVAL);
#ifndef __linux__
    memset(&dspace[06000], 'x', 110);
    put16(06000, AF_UNIX);
    syscall_test(S_BIND, client2, 06000, 110, 0);
    check("BIND rejects path beyond native Unix limit", CC_C ? regs[0] : 0, ENAMETOOLONG);
#endif
    syscall_test(S_CONNECT, client, 04000, 2 + strlen(server_path), 0);
    check("CONNECT nonterminated length-delimited Unix path", CC_C, 0);
    require(!CC_C, "guest Unix connect");
    put16(02000, 128);
    syscall_test(S_ACCEPT, server, 65530, 02000, 0);
    check("ACCEPT validates address before consuming connection", CC_C ? regs[0] : 0, EFAULT);
    syscall_test(S_ACCEPT, server, 03000, 65535, 0);
    check("ACCEPT validates length pointer before consuming connection", CC_C ? regs[0] : 0, EFAULT);
    syscall_test(S_ACCEPT, server, 03000, 0, 0);
    check("ACCEPT rejects missing length pointer with address", CC_C ? regs[0] : 0, EFAULT);
    memset(&dspace[03000], 0x55, 128);
    syscall_test(S_ACCEPT, server, 03000, 02000, 0);
    check("ACCEPT returns queued connection", CC_C, 0);
    require(!CC_C, "guest accept");
    accepted = regs[0];
    check("ACCEPT Unix family", get16(03000), AF_UNIX);
    check("ACCEPT Unix client path", strcmp((char *) &dspace[03002], client_path), 0);
    require(getpeername(accepted, (struct sockaddr *) &peer, &peer_length) == 0,
            "native accepted peer");
    check("ACCEPT Unix copied length", get16(02000), peer_length);
    check("ACCEPT address canary", dspace[03000 + peer_length], 0x55);
    memcpy(&dspace[06000], "hello", 5);
    syscall_test(S_SEND, client, 06000, 5, 0);
    check("Unix connected SEND", CC_C ? -1 : regs[0], 5);
    syscall_test(S_RECV, accepted, 07000, 5, 0);
    check("Unix connected RECV", CC_C ? -1 : regs[0], 5);
    check("Unix connected payload", memcmp(&dspace[07000], "hello", 5), 0);
    put16(02000, 5);
    memset(&dspace[03000], 0x55, 128);
    syscall_test(S_GETPEERNAME, client, 03000, 02000, 0);
    check("GETPEERNAME Unix truncation succeeds", CC_C, 0);
    check("GETPEERNAME Unix copied length", get16(02000), 5);
    check("GETPEERNAME Unix family", get16(03000), AF_UNIX);
    check("GETPEERNAME Unix path prefix", memcmp(&dspace[03002], server_path, 3), 0);
    check("GETPEERNAME Unix truncation canary", dspace[03005], 0x55);
    require(close(accepted) == 0, "close accepted socket");
    syscall_test(S_CONNECT, client2, 04000, 110, 0);
    check("CONNECT full-size guest Unix address", CC_C, 0);
    require(!CC_C, "guest second connect");
    dspace[0] = 0x55;
    syscall_test(S_ACCEPT, server, 0, 65535, 0);
    check("ACCEPT NULL address ignores length pointer", CC_C, 0);
    require(!CC_C, "guest accept without address");
    check("ACCEPT NULL preserves guest address zero", dspace[0], 0x55);
    require(close(regs[0]) == 0, "close second accepted socket");
    require(close(server) == 0 && close(client) == 0 && close(client2) == 0,
            "close Unix sockets");
    require(unlink(server_path) == 0 && unlink(client_path) == 0, "unlink sockets");
    require(rmdir(directory) == 0, "rmdir sockets");
}

static void inet_stream_tests(void)
{
    struct sockaddr_in address, peer;
    socklen_t length = sizeof(address);
    int server = socket(AF_INET, SOCK_STREAM, 0);
    int client = socket(AF_INET, SOCK_STREAM, 0);
    int accepted;

    require(server != -1 && client != -1, "IPv4 stream sockets");
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    require(bind(server, (struct sockaddr *) &address, sizeof(address)) == 0,
            "IPv4 stream bind");
    require(getsockname(server, (struct sockaddr *) &address, &length) == 0,
            "IPv4 stream name");
    require(listen(server, 1) == 0, "IPv4 stream listen");
    put16(04001, AF_INET);
    memcpy(&dspace[04003], (unsigned char *) &address + 2, sizeof(address) - 2);
    syscall_test(S_CONNECT, client, 04001, 16, 0);
    check("CONNECT word-unaligned IPv4 address", CC_C, 0);
    require(!CC_C, "guest IPv4 connect");
    put16(02001, 16);
    memset(&dspace[03001], 0x55, 32);
    syscall_test(S_GETPEERNAME, client, 03001, 02001, 0);
    check("GETPEERNAME IPv4 succeeds", CC_C, 0);
    check("GETPEERNAME IPv4 family", get16(03001), AF_INET);
    check("GETPEERNAME IPv4 network bytes",
          memcmp(&dspace[03003], (unsigned char *) &address + 2, 14), 0);
    check("GETPEERNAME IPv4 copied length", get16(02001), 16);
    check("GETPEERNAME IPv4 canary", dspace[03001 + 16], 0x55);
    put16(02001, 3);
    memset(&dspace[03001], 0x55, 32);
    syscall_test(S_ACCEPT, server, 03001, 02001, 0);
    check("ACCEPT truncated IPv4 address succeeds", CC_C, 0);
    require(!CC_C, "guest IPv4 accept");
    accepted = regs[0];
    length = sizeof(peer);
    require(getpeername(accepted, (struct sockaddr *) &peer, &length) == 0,
            "native IPv4 peer");
    check("ACCEPT IPv4 family", get16(03001), AF_INET);
    check("ACCEPT IPv4 prefix preserves network order",
          dspace[03003], *((unsigned char *) &peer + 2));
    check("ACCEPT IPv4 BSD copied length", get16(02001), 3);
    check("ACCEPT IPv4 canary", dspace[03004], 0x55);
    put16(02001, 16);
    memset(&dspace[03001], 0x55, 32);
    syscall_test(S_ACCEPT, 0177777, 03001, 02001, 0);
    check("ACCEPT propagates bad descriptor", CC_C ? regs[0] : 0, EBADF);
    check("ACCEPT failure preserves output", dspace[03001], 0x55);
    check("ACCEPT failure preserves length", get16(02001), 16);
    syscall_test(S_GETSOCKNAME, server, 0, 02001, 0);
    check("GETSOCKNAME rejects NULL nonempty output", CC_C ? regs[0] : 0, EFAULT);
    put16(02001, 0);
    dspace[0] = 0x55;
    syscall_test(S_GETSOCKNAME, server, 0, 02001, 0);
    check("GETSOCKNAME permits zero-capacity NULL output", CC_C, 0);
    check("GETSOCKNAME NULL zero-capacity length", get16(02001), 0);
    check("GETSOCKNAME NULL zero-capacity preserves memory", dspace[0], 0x55);
    put16(02001, 16);
    syscall_test(S_GETSOCKNAME, server, 65520, 02001, 0);
    check("GETSOCKNAME accepts exact guest memory boundary", CC_C, 0);
    check("GETSOCKNAME boundary family", get16(65520), AF_INET);
    require(close(server) == 0 && close(client) == 0 && close(accepted) == 0,
            "close IPv4 streams");
}

static void udp_ready(int fd)
{
    struct pollfd event = {fd, POLLIN, 0};
    int result = poll(&event, 1, 1000);
    if (result == 0)
        errno = ETIMEDOUT;
    require(result == 1 && (event.revents & POLLIN), "UDP receiver readiness");
}

static void recvfrom_tests(void)
{
    struct sockaddr_in receiver, sender;
    socklen_t size = sizeof(receiver);
    unsigned char expected[sizeof(sender)];
    u_int16_t family = AF_INET;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    int source = socket(AF_INET, SOCK_DGRAM, 0);
    unsigned n;

    require(fd != -1 && source != -1, "UDP sockets");
    memset(&receiver, 0, sizeof(receiver));
    receiver.sin_family = AF_INET;
    receiver.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    require(bind(fd, (struct sockaddr *) &receiver, sizeof(receiver)) == 0, "UDP bind");
    require(bind(source, (struct sockaddr *) &receiver, sizeof(receiver)) == 0,
            "UDP source bind");
    require(getsockname(fd, (struct sockaddr *) &receiver, &size) == 0, "UDP name");
    require(fcntl(fd, F_SETFL, O_NONBLOCK) == 0, "nonblocking UDP");
    require(sendto(source, "hello", 5, 0, (struct sockaddr *) &receiver,
                   sizeof(receiver)) == 5, "send UDP");
    udp_ready(fd);
    put16(02000, 16);
    syscall_test6(S_RECVFROM, fd, 65534, 5, 0, 03000, 02000);
    check("RECVFROM rejects message overrun before consuming data", CC_C ? regs[0] : 0, EFAULT);
    syscall_test6(S_RECVFROM, fd, 06000, 0177777, 0, 03000, 02000);
    check("RECVFROM rejects negative count", CC_C ? regs[0] : 0, EINVAL);
    syscall_test6(S_RECVFROM, fd, 06000, 5, 0, 65530, 02000);
    check("RECVFROM rejects source overrun before consuming data", CC_C ? regs[0] : 0, EFAULT);
    syscall_test6(S_RECVFROM, fd, 06000, 5, 0, 03000, 65535);
    check("RECVFROM rejects length-pointer overrun", CC_C ? regs[0] : 0, EFAULT);
    syscall_test6(S_RECVFROM, fd, 06000, 5, 0, 03000, 0);
    check("RECVFROM rejects missing length pointer with source", CC_C ? regs[0] : 0, EFAULT);
    memset(&dspace[06000], 0x55, 6);
    memset(&dspace[03000], 0x55, 32);
    syscall_test6(S_RECVFROM, fd, 06000, 5, 0, 03000, 02000);
    check("RECVFROM receives preserved datagram", CC_C ? -(long) regs[0] : regs[0], 5);
    check("RECVFROM payload", memcmp(&dspace[06000], "hello", 5), 0);
    check("RECVFROM message canary", dspace[06005], 0x55);
    size = sizeof(sender);
    require(getsockname(source, (struct sockaddr *) &sender, &size) == 0, "UDP sender name");
    memcpy(expected, &family, 2);
    memcpy(expected + 2, (unsigned char *) &sender + 2, sizeof(sender) - 2);
    check("RECVFROM translated source", memcmp(&dspace[03000], expected, 16), 0);
    check("RECVFROM source length", get16(02000), 16);
    check("RECVFROM source canary", dspace[03020], 0x55);
    for (n = 0; n <= 4; n++) {
        require(sendto(source, "ok", 2, 0, (struct sockaddr *) &receiver,
                       sizeof(receiver)) == 2, "send truncated-source UDP");
        udp_ready(fd);
        put16(02001, n);
        memset(&dspace[03001], 0x55, 32);
        syscall_test6(S_RECVFROM, fd, 06001, 2, 0, 03001, 02001);
        check("RECVFROM word-unaligned outputs succeed", CC_C ? -(long) regs[0] : regs[0], 2);
        check("RECVFROM BSD truncated length", get16(02001), n);
        check("RECVFROM source prefix", memcmp(&dspace[03001], expected, n), 0);
        check("RECVFROM truncation canary", dspace[03001 + n], 0x55);
    }
    require(sendto(source, "ok", 2, 0, (struct sockaddr *) &receiver,
                   sizeof(receiver)) == 2, "send anonymous-source UDP");
    udp_ready(fd);
    dspace[0] = 0x55;
    syscall_test6(S_RECVFROM, fd, 06000, 2, 0, 0, 65535);
    check("RECVFROM NULL source ignores length pointer", CC_C ? -1 : regs[0], 2);
    check("RECVFROM NULL preserves guest address zero", dspace[0], 0x55);
    put16(02000, 16);
    memset(&dspace[03000], 0x55, 32);
    syscall_test6(S_RECVFROM, fd, 06000, 2, 0, 03000, 02000);
    check("RECVFROM propagates empty-queue error", CC_C, 1);
    check("RECVFROM empty-queue errno", regs[0] == EAGAIN || regs[0] == EWOULDBLOCK, 1);
    check("RECVFROM failure preserves address", dspace[03000], 0x55);
    check("RECVFROM failure preserves length", get16(02000), 16);
    require(close(fd) == 0 && close(source) == 0, "close UDP sockets");
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

static void pathname_tests(void)
{
    static const unsigned calls[] = {
        S_OPEN, S_CREAT, S_LINK, S_SYMLINK, S_RENAME, S_READLINK,
        S_ACCESS, S_MKDIR, S_RMDIR, S_ACCT, S_LSTAT, S_STAT, S_UTIMES,
        S_UNLINK, S_MKNOD, S_CHMOD, S_TRUNCATE, S_CHOWN, S_CHROOT,
        S_CHDIR, S_EXECV, S_EXECVE
#ifndef NO_CHFLAGS
        , S_CHFLAGS
#endif
    };
    static const unsigned pairs[] = {S_LINK, S_SYMLINK, S_RENAME};
    static char preserved[] = "preserved";
    char root[2 * MAXPATHLEN - 2];
    u_int16_t vector[MAX_ARGS + 2];
    void (*previous)(int);
    unsigned n;

    dspace[0] = 0;
    memset(&dspace[65534], 'x', 2);
    for (n = 0; n < sizeof(calls) / sizeof(calls[0]); n++) {
        if (calls[n] != S_ACCT) {
            syscall_test(calls[n], 0, 0, 0, 0);
            check("BSD pathname syscall rejects NULL", CC_C ? regs[0] : 0, EFAULT);
        }
        syscall_test(calls[n], 65534, 0, 0, 0);
        check("BSD pathname syscall rejects unterminated string", CC_C ? regs[0] : 0, EFAULT);
    }
    strcpy((char *) &dspace[04000], "apout-no-such-source");
    memset(&dspace[65000], 'x', PDP_MEM_SIZE - 65000);
    for (n = 0; n < sizeof(pairs) / sizeof(pairs[0]); n++) {
        syscall_test(pairs[n], 04000, 65000, 0, 0);
        check("BSD validates both pathnames before host call", CC_C ? regs[0] : 0, EFAULT);
    }
    dspace[65535] = 0;
    syscall_test(S_ACCESS, 65535, F_OK, 0, 0);
    check("BSD empty pathname compatibility at memory boundary", CC_C, 0);
    memset(root, 'r', sizeof(root) - 1);
    root[0] = '/';
    root[sizeof(root) - 1] = 0;
    require(set_apout_root(root) == 0, "long root");
    strcpy((char *) &dspace[04000], "/xx");
    syscall_test(S_CHDIR, 04000, 0, 0, 0);
    check("BSD propagates root-plus-path overflow", CC_C ? regs[0] : 0, ENAMETOOLONG);
    require(set_apout_root("/") == 0, "restore root");
    strcpy((char *) &dspace[04000], "apout-no-such-executable");
    strcpy((char *) &dspace[05000], "argument");
    Argc = Envc = 1;
    Argv[0] = Envp[0] = preserved;
    previous = signal(SIGTERM, SIG_IGN);
    require(previous != SIG_ERR, "set test signal");
    syscall_test(S_EXECVE, 04000, 65535, 0, 0);
    check("BSD EXEC rejects invalid vector", CC_C ? regs[0] : 0, EFAULT);
    check("BSD invalid EXEC preserves argc", Argc, 1);
    check("BSD invalid EXEC preserves argv", Argv[0] == preserved, 1);
    check("BSD invalid EXEC preserves environment", Envp[0] == preserved, 1);
    check("BSD invalid EXEC preserves signal disposition",
          signal(SIGTERM, previous) == SIG_IGN, 1);
    vector[0] = 05000;
    put16(65534, vector[0]);
    syscall_test(S_EXECV, 04000, 65534, 0, 0);
    check("BSD EXEC rejects wrapping vector", CC_C ? regs[0] : 0, EFAULT);
    vector[0] = 65534;
    vector[1] = 0;
    memcpy(&dspace[03000], vector, 4);
    memset(&dspace[65534], 'x', 2);
    syscall_test(S_EXECVE, 04000, 03000, 0, 0);
    check("BSD EXEC rejects unterminated argument", CC_C ? regs[0] : 0, EFAULT);
    syscall_test(S_EXECVE, 04000, 0, 65535, 0);
    check("BSD EXEC rejects invalid environment vector", CC_C ? regs[0] : 0, EFAULT);
    syscall_test(S_EXECVE, 04000, 0, 03000, 0);
    check("BSD EXEC rejects unterminated environment string", CC_C ? regs[0] : 0, EFAULT);
    for (n = 0; n <= MAX_ARGS; n++)
        vector[n] = 05000;
    vector[MAX_ARGS + 1] = 0;
    memcpy(&dspace[03000], vector, sizeof(vector));
    syscall_test(S_EXECVE, 04000, 03000, 0, 0);
    check("BSD EXEC rejects excess argument count", CC_C ? regs[0] : 0, E2BIG);
    syscall_test(S_EXECVE, 04000, 0, 03000, 0);
    check("BSD EXEC rejects excess environment count", CC_C ? regs[0] : 0, E2BIG);
    Argc = Envc = 0;
    Argv[0] = Envp[0] = NULL;
}

static void structure_tests(void)
{
    struct stat native;
    struct tr_stat guest;
    struct rlimit limit;
    char filename[] = "/tmp/apout-structures.XXXXXX";
    unsigned n;
    unsigned calls[] = {S_STAT, S_LSTAT, S_FSTAT};
    int fd = mkstemp(filename);
    unsigned pointer, k;
    unsigned invalid_pointers[] = {0, 65535, 65530};
    gid_t *native_groups;
    int group_count, unrepresentable = 0;

    require(fd != -1, "structure fixture");
    require(write(fd, "hello", 5) == 5 && fstat(fd, &native) == 0, "fixture stat");
    strcpy((char *) &dspace[04000], filename);
    check("BSD stat wire size", sizeof(guest), 52);
    for (n = 0; n < sizeof(calls) / sizeof(calls[0]); n++) {
        for (k = 0; k < sizeof(invalid_pointers) / sizeof(invalid_pointers[0]); k++) {
            syscall_test(calls[n], calls[n] == S_FSTAT ? fd : 04000,
                         invalid_pointers[k], 0, 0);
            check("BSD stat rejects invalid output", CC_C ? regs[0] : 0, EFAULT);
        }
        memset(&dspace[03000], 0x55, sizeof(guest) + 2);
        syscall_test(calls[n], calls[n] == S_FSTAT ? fd : 04000, 03001, 0, 0);
        check("BSD stat permits byte-aligned guest output", CC_C, 0);
        memcpy(&guest, &dspace[03001], sizeof(guest));
        check("BSD stat file size encoding", get32(03001 + offsetof(struct tr_stat, st_size)), 5);
        check("BSD stat mode", guest.st_mode, (u_int16_t) native.st_mode);
        check("BSD stat mtime encoding",
              get32(03001 + offsetof(struct tr_stat, st_mtim)), (int32_t) native.st_mtime);
        check("BSD stat clears spare1", guest.st_spare1, 0);
        check("BSD stat clears spare2", guest.st_spare2, 0);
        check("BSD stat clears spare3", guest.st_spare3, 0);
        check("BSD stat clears spare4", guest.st_spare4[0] | guest.st_spare4[1] | guest.st_spare4[2], 0);
        check("BSD stat leading canary", dspace[03000], 0x55);
        check("BSD stat trailing canary", dspace[03001 + sizeof(guest)], 0x55);
        pointer = PDP_MEM_SIZE - sizeof(guest);
        syscall_test(calls[n], calls[n] == S_FSTAT ? fd : 04000, pointer, 0, 0);
        check("BSD stat exact guest boundary", CC_C, 0);
        check("BSD stat boundary size", get32(pointer + offsetof(struct tr_stat, st_size)), 5);
    }
    memset(&dspace[03000], 0x55, sizeof(guest));
    syscall_test(S_FSTAT, 0177777, 03000, 0, 0);
    check("BSD FSTAT descriptor failure", CC_C ? regs[0] : 0, EBADF);
    check("BSD FSTAT failure preserves output", dspace[03000], 0x55);
    require(close(fd) == 0 && unlink(filename) == 0, "cleanup structure fixture");
    for (n = 0; n < 2; n++) {
        memset(&dspace[03000], 0x55, sizeof(guest));
        syscall_test(n ? S_STAT : S_LSTAT, 04000, 03000, 0, 0);
        check("BSD missing-path stat fails", CC_C ? regs[0] : 0, ENOENT);
        for (k = 0; k < sizeof(guest); k++)
            if (dspace[03000 + k] != 0x55)
                break;
        check("BSD missing-path stat preserves complete output", k, sizeof(guest));
    }
    for (n = 0; n < 2; n++) {
        for (k = 0; k < sizeof(invalid_pointers) / sizeof(invalid_pointers[0]); k++) {
            syscall_test(n ? S_SETRLIMIT : S_GETRLIMIT, 4, invalid_pointers[k], 0, 0);
            check("BSD resource limit rejects invalid buffer", CC_C ? regs[0] : 0, EFAULT);
        }
        syscall_test(n ? S_SETRLIMIT : S_GETRLIMIT, 6, 03000, 0, 0);
        check("BSD rejects non-guest resource", CC_C ? regs[0] : 0, EINVAL);
        syscall_test(n ? S_SETRLIMIT : S_GETRLIMIT, 0177777, 03000, 0, 0);
        check("BSD rejects negative resource", CC_C ? regs[0] : 0, EINVAL);
    }
    require(getrlimit(RLIMIT_CORE, &limit) == 0, "native core limit");
    memset(&dspace[03000], 0x55, 10);
    syscall_test(S_GETRLIMIT, 4, 03001, 0, 0);
    check("BSD GETRLIMIT byte-aligned output", CC_C, 0);
    check("BSD GETRLIMIT infinity/large value translation",
          get32(03001), limit.rlim_cur == RLIM_INFINITY || limit.rlim_cur > INT32_MAX ?
          INT32_MAX : (int32_t) limit.rlim_cur);
    check("BSD GETRLIMIT trailing canary", dspace[03011], 0x55);
    check("BSD infinity encodes as signed-long maximum", bsd_limit_value(RLIM_INFINITY), INT32_MAX);
    check("BSD wide native limit saturates", bsd_limit_value((rlim_t) INT32_MAX + 1), INT32_MAX);
    check("BSD resource RSS maps to native RSS", bsd_resource(5), RLIMIT_RSS);
    put32(03001, -1);
    put32(03005, INT32_MAX);
    syscall_test(S_SETRLIMIT, 4, 03001, 0, 0);
    check("BSD SETRLIMIT rejects negative current limit", CC_C ? regs[0] : 0, EINVAL);
    put32(03001, 0);
    put32(03005, -1);
    syscall_test(S_SETRLIMIT, 4, 03001, 0, 0);
    check("BSD SETRLIMIT rejects negative maximum limit", CC_C ? regs[0] : 0, EINVAL);
    memset(&dspace[03000], 0x55, 8);
    syscall_test(S_GETRLIMIT, 6, 03000, 0, 0);
    check("BSD GETRLIMIT failure preserves output", dspace[03000], 0x55);

    syscall_test(S_SETGROUPS, 17, 0, 0, 0);
    check("BSD SETGROUPS rejects excess count", CC_C ? regs[0] : 0, EINVAL);
    syscall_test(S_SETGROUPS, 0177777, 0, 0, 0);
    check("BSD SETGROUPS rejects negative count", CC_C ? regs[0] : 0, EINVAL);
    syscall_test(S_GETGROUPS, 0177777, 0, 0, 0);
    check("BSD GETGROUPS rejects negative count", CC_C ? regs[0] : 0, EINVAL);
    for (k = 0; k < sizeof(invalid_pointers) / sizeof(invalid_pointers[0]); k++) {
        syscall_test(S_SETGROUPS, 4, invalid_pointers[k], 0, 0);
        check("BSD SETGROUPS rejects invalid input", CC_C ? regs[0] : 0, EFAULT);
    }
    check("Invalid SETGROUPS never reaches native call", setgroups_calls, 0);
    put16(03001, 60000);
    put16(03003, 123);
    syscall_test(S_SETGROUPS, 2, 03001, 0, 0);
    check("BSD SETGROUPS byte-aligned input succeeds", CC_C, 0);
    check("BSD SETGROUPS preserves unsigned group ID", supplied_groups[0], 60000);
    check("BSD SETGROUPS second group", supplied_groups[1], 123);
    check("BSD SETGROUPS supplies count", supplied_group_count, 2);
    syscall_test(S_SETGROUPS, 0, 0, 0, 0);
    check("BSD SETGROUPS empty input succeeds", CC_C, 0);
    check("BSD SETGROUPS empty input count", supplied_group_count, 0);
    fail_setgroups = 1;
    syscall_test(S_SETGROUPS, 2, 03001, 0, 0);
    check("BSD SETGROUPS propagates host error", CC_C ? regs[0] : 0, EPERM);
    check("BSD SETGROUPS preserves input on failure", get16(03001), 60000);
    fail_setgroups = 0;
    fake_groups = 1;
    syscall_test(S_GETGROUPS, 0, 0, 0, 0);
    check("BSD GETGROUPS zero capacity is not native count query", CC_C ? regs[0] : 0, EINVAL);
    syscall_test(S_GETGROUPS, 1, 03000, 0, 0);
    check("BSD GETGROUPS insufficient capacity", CC_C ? regs[0] : 0, EINVAL);
    syscall_test(S_GETGROUPS, 2, 65534, 0, 0);
    check("BSD GETGROUPS rejects output overrun", CC_C ? regs[0] : 0, EFAULT);
    syscall_test(S_GETGROUPS, 2, 0, 0, 0);
    check("BSD GETGROUPS rejects NULL output", CC_C ? regs[0] : 0, EFAULT);
    memset(&dspace[03000], 0x55, 8);
    syscall_test(S_GETGROUPS, 16, 03001, 0, 0);
    check("BSD GETGROUPS returns actual count", CC_C ? -1 : regs[0], 2);
    check("BSD GETGROUPS first group", get16(03001), 123);
    check("BSD GETGROUPS unsigned group", get16(03003), 60000);
    check("BSD GETGROUPS leading canary", dspace[03000], 0x55);
    check("BSD GETGROUPS trailing canary", dspace[03005], 0x55);
    syscall_test(S_GETGROUPS, 16, 65532, 0, 0);
    check("BSD GETGROUPS validates actual copied count", CC_C ? -1 : regs[0], 2);
    fake_groups = 2;
    memset(&dspace[03000], 0x55, 8);
    syscall_test(S_GETGROUPS, 16, 03001, 0, 0);
    check("BSD GETGROUPS rejects unrepresentable group ID", CC_C ? regs[0] : 0, EOVERFLOW);
    check("BSD GETGROUPS overflow preserves all output", get32(03001), 0x55555555);
    fake_groups = 3;
    syscall_test(S_GETGROUPS, 0, 0, 0, 0);
    check("BSD GETGROUPS permits truly empty group list", CC_C ? -1 : regs[0], 0);
    fake_groups = 4;
    memset(&dspace[03000], 0x55, 8);
    syscall_test(S_GETGROUPS, 16, 03001, 0, 0);
    check("BSD GETGROUPS propagates host error", CC_C ? regs[0] : 0, EIO);
    check("BSD GETGROUPS host error preserves output", get32(03001), 0x55555555);
    fake_groups = 0;
    group_count = getgroups(0, NULL);
    require(group_count >= 0 && group_count <= 32767, "native group count");
    native_groups = malloc((size_t) (group_count + 1) * sizeof(*native_groups));
    require(native_groups != NULL, "native groups allocation");
    require(getgroups(group_count, native_groups) == group_count, "native groups");
    for (k = 0; k < group_count; k++)
        if (native_groups[k] > UINT16_MAX)
            unrepresentable = 1;
    syscall_test(S_GETGROUPS, group_count, 04001, 0, 0);
    check("BSD GETGROUPS native list translation",
          CC_C ? -(long) regs[0] : regs[0], unrepresentable ? -EOVERFLOW : group_count);
    if (!unrepresentable)
        for (k = 0; k < group_count; k++)
            check("BSD GETGROUPS native group content", get16(04001 + k * 2), native_groups[k]);
    free(native_groups);
}

static void limit_child_tests(void)
{
    int status;
    pid_t child = fork();

    require(child != -1, "fork resource test");
    if (child == 0) {
        struct rlimit original, changed;
        unsigned char saved[8];
        unsigned before = failures;
        int32_t hard;

        require(getrlimit(RLIMIT_CORE, &original) == 0, "child core limit");
        hard = original.rlim_max == RLIM_INFINITY ? INT32_MAX :
               (original.rlim_max > 4096 ? 4096 : (int32_t) original.rlim_max);
        put32(03001, 0);
        put32(03005, hard);
        memcpy(saved, &dspace[03001], 8);
        syscall_test(S_SETRLIMIT, 4, 03001, 0, 0);
        check("BSD SETRLIMIT stages complete native fields", CC_C, 0);
        check("BSD SETRLIMIT preserves input", memcmp(saved, &dspace[03001], 8), 0);
        require(getrlimit(RLIMIT_CORE, &changed) == 0, "child changed core limit");
        check("BSD SETRLIMIT native soft value", changed.rlim_cur, 0);
        check("BSD SETRLIMIT native hard value",
              changed.rlim_max == (hard == INT32_MAX ? RLIM_INFINITY : (rlim_t) hard), 1);
        syscall_test(S_GETRLIMIT, 4, 65528, 0, 0);
        check("BSD GETRLIMIT exact boundary", CC_C, 0);
        check("BSD GETRLIMIT returns installed soft limit", get32(65528), 0);
        check("BSD GETRLIMIT returns installed hard limit", get32(65532), hard);
        _exit(failures == before ? 0 : 1);
    }
    require(waitpid(child, &status, 0) == child, "wait resource test");
    check("Resource limit changes isolated to child",
          WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
}

static void wait_tests(void)
{
    int pipes[2], status;
    pid_t child;
    char byte;

    require(pipe(pipes) == 0, "wait test pipe");
    child = fork();
    require(child != -1, "wait test child");
    if (child == 0) {
        close(pipes[1]);
        if (read(pipes[0], &byte, 1) != 1)
            _exit(99);
        _exit(42);
    }
    require(close(pipes[0]) == 0, "close wait read end");
    memset(&dspace[03000], 0x55, 2);
    memset(&dspace[04000], 0x55, sizeof(struct tr_rusage));
    syscall_test(S_WAIT4, 0177777, 03000, 1, 04000);
    check("WAIT4 WNOHANG returns zero for blocked child", CC_C ? -1 : regs[0], 0);
    check("WAIT4 WNOHANG preserves status", get16(03000), 0x5555);
    check("WAIT4 WNOHANG preserves usage", get32(04000), 0x55555555);
    syscall_test(S_WAIT4, 0177777, 65535, 1, 04000);
    check("WAIT4 rejects status overrun before reaping", CC_C ? regs[0] : 0, EFAULT);
    syscall_test(S_WAIT4, 0177777, 03000, 1, 65530);
    check("WAIT4 rejects usage overrun before reaping", CC_C ? regs[0] : 0, EFAULT);
    syscall_test(S_WAIT4, 0177777, 03000, 4, 04000);
    check("WAIT4 rejects unsupported option", CC_C ? regs[0] : 0, EINVAL);
    check("WAIT4 invalid calls preserve status", get16(03000), 0x5555);
    check("WAIT4 invalid calls preserve usage", get32(04000), 0x55555555);
    require(write(pipes[1], "x", 1) == 1 && close(pipes[1]) == 0, "release child");
    memset(&dspace[03000], 0x55, 4);
    memset(&dspace[04000], 0x55, sizeof(struct tr_rusage) + 2);
    syscall_test(S_WAIT4, 0177777, 03001, 0, 04001);
    check("WAIT4 reaps child", CC_C ? -1 : regs[0], (u_int16_t) child);
    check("WAIT4 encodes exit status", get16(03001), 42 << 8);
    check("WAIT4 supplies child usage", get32(04001) >= 0 && get32(04001) != 0x55555555, 1);
    check("WAIT4 status leading canary", dspace[03000], 0x55);
    check("WAIT4 status trailing canary", dspace[03003], 0x55);
    check("WAIT4 usage leading canary", dspace[04000], 0x55);
    check("WAIT4 usage trailing canary", dspace[04001 + sizeof(struct tr_rusage)], 0x55);
    check("WAIT4 usage microseconds", get32(04005) >= 0 && get32(04005) < 1000000, 1);
    check("WAIT4 does not report parent overlays",
          get32(04001 + offsetof(struct tr_rusage, ru_ovly)), 0);
    memset(&dspace[03000], 0x55, 2);
    memset(&dspace[04000], 0x55, sizeof(struct tr_rusage));
    syscall_test(S_WAIT4, 0177777, 03000, 0, 04000);
    check("WAIT4 reports no children", CC_C ? regs[0] : 0, ECHILD);
    check("WAIT4 error preserves status", get16(03000), 0x5555);
    check("WAIT4 error preserves usage", get32(04000), 0x55555555);
    require(waitpid(child, &status, WNOHANG) == -1 && errno == ECHILD, "child reaped");

    child = fork();
    require(child != -1, "wait null child");
    if (child == 0)
        _exit(0);
    dspace[0] = 0x55;
    syscall_test(S_WAIT4, 0177777, 0, 0, 0);
    check("WAIT4 accepts NULL outputs", CC_C ? -1 : regs[0], (u_int16_t) child);
    check("WAIT4 NULL outputs preserve address zero", dspace[0], 0x55);

    child = fork();
    require(child != -1, "wait boundary child");
    if (child == 0)
        _exit(7);
    syscall_test(S_WAIT4, 0177777, 65534, 0, 65534 - sizeof(struct tr_rusage));
    check("WAIT4 accepts exact memory boundary", CC_C ? -1 : regs[0], (u_int16_t) child);
    check("WAIT4 boundary status", get16(65534), 7 << 8);

    child = fork();
    require(child != -1, "wait stopped child");
    if (child == 0) {
        signal(SIGUSR1, SIG_DFL);
        raise(SIGSTOP);
        raise(SIGUSR1);
        _exit(99);
    }
    memset(&dspace[04000], 0x55, sizeof(struct tr_rusage));
    syscall_test(S_WAIT4, 0177777, 03001, 2, 04000);
    check("WAIT4 maps WUNTRACED option", CC_C ? -1 : regs[0], (u_int16_t) child);
    check("WAIT4 maps stopped signal to BSD", get16(03001), (17 << 8) | 0177);
    check("WAIT4 stopped child preserves usage", get32(04000), 0x55555555);
    require(kill(child, SIGCONT) == 0, "resume wait child");
    syscall_test(S_WAIT4, 0177777, 03001, 0, 04000);
    check("WAIT4 reaps signaled child", CC_C ? -1 : regs[0], (u_int16_t) child);
    check("WAIT4 maps SIGUSR1 to BSD signal 30", get16(03001), 30);
    check("WAIT4 preserves core dump flag", bsd_wait_status(SIGQUIT | 0200), 3 | 0200);
    check("WAIT4 maps SIGBUS", bsd_wait_status(SIGBUS), 10);
    check("WAIT4 maps SIGUSR2", bsd_wait_status(SIGUSR2), 31);
    check("BSD signal map rejects unrepresentable host signal", bsd_signal_number(INT32_MAX), -1);
    check("BSD signal map error", errno, EOVERFLOW);
}

static void ioctl_tests(void)
{
    static const u_int32_t requests[] = {
        0x40067408, 0x80067409, 0x8006740a, 0x80067411,
        0x40027400, 0x80027401, 0x40067412, 0x40067474,
        0x80067475, 0x40087468, 0x80087467, 0x8002667b,
        0x4002746a, 0x40027477, 0x80027476
    };
    static const u_int32_t getters[] = {
        0x40067408, 0x40067412, 0x40067474, 0x40087468
    };
    static const u_int32_t setters[] = {
        0x80067409, 0x8006740a, 0x80067411, 0x80027401,
        0x80067475, 0x80087467, 0x8002667b, 0x80027476
    };
    static const u_int32_t word_getters[] = {0x40027400, 0x4002746a, 0x40027477};
    static const unsigned long native_getters[] = {TIOCGETD, TIOCMGET, TIOCGPGRP};
    struct winsize expected = {24, 80, 640, 480}, actual;
    struct termios before, after;
    int master = posix_openpt(O_RDWR | O_NOCTTY), slave;
    char *name;
    unsigned n, k, size;
    int native_value, result, error;
    unsigned char saved[8];
    u_int32_t request;

    require(master != -1 && grantpt(master) == 0 && unlockpt(master) == 0, "ioctl PTY");
    name = ptsname(master);
    require(name != NULL && (slave = open(name, O_RDWR | O_NOCTTY)) != -1, "ioctl slave");
    memcpy(&dspace[03001], &expected, sizeof(expected));
    syscall_test(S_IOCTL, slave, 0x8008, 0x7467, 03001);
    check("IOCTL accepts canonical BSD window setter", CC_C, 0);
    require(ioctl(slave, TIOCGWINSZ, &actual) == 0, "get private window");
    check("IOCTL window setter applies row count", actual.ws_row, expected.ws_row);
    check("IOCTL window setter applies column count", actual.ws_col, expected.ws_col);
    for (n = 0; n < sizeof(requests) / sizeof(requests[0]); n++) {
        request = requests[n];
        size = (request >> 16) & 0x7f;
        syscall_test(S_IOCTL, slave, request >> 16, request, 0);
        check("IOCTL rejects NULL buffer", CC_C ? regs[0] : 0, EFAULT);
        syscall_test(S_IOCTL, slave, request >> 16, request, PDP_MEM_SIZE - size + 1);
        check("IOCTL rejects buffer overrun", CC_C ? regs[0] : 0, EFAULT);
    }
    require(ioctl(slave, TIOCGWINSZ, &actual) == 0, "window after invalid ioctls");
    check("Invalid IOCTL setters preserve native window", actual.ws_row, expected.ws_row);
    for (n = 0; n < sizeof(getters) / sizeof(getters[0]); n++) {
        request = getters[n];
        size = (request >> 16) & 0x7f;
        memset(&dspace[03000], 0x55, 10);
        syscall_test(S_IOCTL, slave, request >> 16, request, 03001);
        check("IOCTL getter accepts byte-aligned output", CC_C, 0);
        check("IOCTL getter leading canary", dspace[03000], 0x55);
        check("IOCTL getter trailing canary", dspace[03001 + size], 0x55);
        memcpy(saved, &dspace[03001], size);
        syscall_test(S_IOCTL, 0177777, request >> 16, request, 03001);
        check("IOCTL getter propagates native failure", CC_C ? regs[0] : 0, EBADF);
        check("IOCTL getter preserves output on failure", memcmp(saved, &dspace[03001], size), 0);
        syscall_test(S_IOCTL, slave, request >> 16, request, PDP_MEM_SIZE - size);
        check("IOCTL getter accepts exact memory boundary", CC_C, 0);
    }
    for (n = 0; n < sizeof(word_getters) / sizeof(word_getters[0]); n++) {
        request = word_getters[n];
        result = ioctl(slave, native_getters[n], &native_value);
        error = errno;
        memset(&dspace[03000], 0x55, 4);
        syscall_test(S_IOCTL, slave, request >> 16, request, 03001);
        check("IOCTL word getter matches native result",
              CC_C ? -(long) regs[0] : 0, result == -1 ? -error : 0);
        check("IOCTL word getter stages native integer",
              get16(03001), result == -1 ? 0x5555 : (u_int16_t) native_value);
        check("IOCTL word getter leading canary", dspace[03000], 0x55);
        check("IOCTL word getter trailing canary", dspace[03003], 0x55);
        syscall_test(S_IOCTL, 0177777, request >> 16, request, 03001);
        check("IOCTL word getter reports bad descriptor", CC_C ? regs[0] : 0, EBADF);
    }
    for (n = 0; n < sizeof(setters) / sizeof(setters[0]); n++) {
        request = setters[n];
        size = (request >> 16) & 0x7f;
        memset(&dspace[03001], 0, size);
        memcpy(saved, &dspace[03001], size);
        syscall_test(S_IOCTL, 0177777, request >> 16, request, 03001);
        check("IOCTL canonical setter dispatches native failure", CC_C ? regs[0] : 0, EBADF);
        check("IOCTL setter failure preserves input", memcmp(saved, &dspace[03001], size), 0);
    }
    syscall_test(S_IOCTL, slave, 0x4008, 0x7468, 03001);
    check("IOCTL encodes window dimensions",
          get16(03001) == 24 && get16(03003) == 80 &&
          get16(03005) == 640 && get16(03007) == 480, 1);
    put16(65528, 25);
    put16(65530, 81);
    put16(65532, 641);
    put16(65534, 481);
    syscall_test(S_IOCTL, slave, 0x8008, 0x7467, 65528);
    check("IOCTL window setter accepts exact memory boundary", CC_C, 0);
    require(ioctl(slave, TIOCGWINSZ, &actual) == 0, "window boundary verification");
    check("IOCTL boundary window dimensions",
          actual.ws_row == 25 && actual.ws_col == 81 &&
          actual.ws_xpixel == 641 && actual.ws_ypixel == 481, 1);
    require(tcgetattr(slave, &before) == 0, "private terminal before characters");
    for (k = 0; k < 2; k++) {
        unsigned getcode = k ? 0x7474 : 0x7412;
        unsigned setcode = k ? 0x7475 : 0x7411;
        syscall_test(S_IOCTL, slave, 0x4006, getcode, 03001);
        memcpy(saved, &dspace[03001], 6);
        syscall_test(S_IOCTL, slave, 0x8006, setcode, 03001);
        check("IOCTL character setter accepts byte-aligned input", CC_C, 0);
        check("IOCTL character setter preserves input", memcmp(saved, &dspace[03001], 6), 0);
    }
    require(tcgetattr(slave, &after) == 0, "private terminal after characters");
    check("IOCTL character roundtrip preserves interrupt", after.c_cc[VINTR], before.c_cc[VINTR]);
    syscall_test(S_IOCTL, slave, 0x2000, 0x6601, 65535);
    check("IOCTL FIOCLEX ignores nonexistent buffer", CC_C, 0);
    check("IOCTL FIOCLEX sets close-on-exec", !!(fcntl(slave, F_GETFD) & FD_CLOEXEC), 1);
    syscall_test(S_IOCTL, slave, 0x1234, 0x5678, 0);
    check("IOCTL rejects unknown request", CC_C ? regs[0] : 0, ENOTTY);
    require(close(slave) == 0 && close(master) == 0, "close ioctl PTY");
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
    socket_name_tests();
    unix_socket_tests();
    inet_stream_tests();
    recvfrom_tests();
    pathname_tests();
    structure_tests();
    limit_child_tests();
    wait_tests();
    ioctl_tests();
    printf("BSD: %u checks, %u failures\n", checks, failures);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
