#include "../bsdtrap.c"
#include <netinet/in.h>
#include <poll.h>

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
    printf("BSD: %u checks, %u failures\n", checks, failures);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
