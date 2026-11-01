/* bsdtrap.c - Deal with 2.11BSD trap instructions.
 *
 * $Revision: 1.66 $
 * $Date: 2008/05/19 13:26:42 $
 */
#ifdef EMU211

/* NOTE NOTE NOTE NOTE
 * Grep for the word DONE in this file to see the implemented syscalls.
 */

#define BSDTRAP_NAME
#include "defines.h"
#include <sys/stat.h>
#include <sys/time.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/wait.h>
#include <signal.h>
#include <utime.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stddef.h>
#include <sys/uio.h>
#include "bsdtrap.h"
#ifdef __linux__
#include <grp.h>		/* setgroups() */
#endif

#define MAX_BLKSIZE	1024	/* Maximum block size from stat/fstat */

#undef STREAM_BUFFERING		/* This works, but doesn't seem to give */
/* any speed improvement */

arglist *A;			/* Pointer to various arguments on stack */


/* Forward prototypes */
#ifdef __STDC__
#define P(s) s
#else
#define P(s) ()
#endif
static int trap_execve P((int));
static int bsdopen_dir P((char *name));
#ifdef NEED_MAP_FCNTL
static int16_t map_fcntl P((int16_t f));
#endif
#undef P

int32_t bsd_load_long(unsigned addr)
{
    u_int16_t words[2];
    memcpy(words, &dspace[addr], sizeof(words));
    return (int32_t) (((u_int32_t) words[0] << 16) | words[1]);
}

void bsd_store_long(unsigned addr, int32_t value)
{
    u_int16_t words[2] = {(u_int32_t) value >> 16, (u_int16_t) value};
    memcpy(&dspace[addr], words, sizeof(words));
}

static void bsd_load_timeval(unsigned addr, struct timeval *value)
{
    value->tv_sec = bsd_load_long(addr);
    value->tv_usec = bsd_load_long(addr + 4);
}

static void bsd_store_timeval(unsigned addr, const struct timeval *value)
{
    bsd_store_long(addr, value->tv_sec);
    bsd_store_long(addr + 4, value->tv_usec);
}

static int bsd_resource(unsigned resource)
{
    static const int resources[] = {
        RLIMIT_CPU, RLIMIT_FSIZE, RLIMIT_DATA,
        RLIMIT_STACK, RLIMIT_CORE, RLIMIT_RSS
    };
    if (resource >= sizeof(resources) / sizeof(resources[0])) {
        errno = EINVAL;
        return -1;
    }
    return resources[resource];
}

static int32_t bsd_limit_value(rlim_t value)
{
    return value == RLIM_INFINITY || value > INT32_MAX ? INT32_MAX : (int32_t) value;
}

static void bsd_store_rusage(unsigned addr, const struct rusage *use, unsigned overlays)
{
    struct tr_rusage value;
    char *buf, *buf2;

    memset(&value, 0, sizeof(value));
    copylong(value.ru_utime.tv_sec, use->ru_utime.tv_sec);
    copylong(value.ru_utime.tv_usec, use->ru_utime.tv_usec);
    copylong(value.ru_stime.tv_sec, use->ru_stime.tv_sec);
    copylong(value.ru_stime.tv_usec, use->ru_stime.tv_usec);
    copylong(value.ru_maxrss, use->ru_maxrss);
    copylong(value.ru_ixrss, use->ru_ixrss);
    copylong(value.ru_idrss, use->ru_idrss);
    copylong(value.ru_isrss, use->ru_isrss);
    copylong(value.ru_minflt, use->ru_minflt);
    copylong(value.ru_majflt, use->ru_majflt);
    copylong(value.ru_nswap, use->ru_nswap);
    copylong(value.ru_inblock, use->ru_inblock);
    copylong(value.ru_oublock, use->ru_oublock);
    copylong(value.ru_msgsnd, use->ru_msgsnd);
    copylong(value.ru_msgrcv, use->ru_msgrcv);
    copylong(value.ru_nsignals, use->ru_nsignals);
    copylong(value.ru_nvcsw, use->ru_nvcsw);
    copylong(value.ru_nivcsw, use->ru_nivcsw);
    memcpy(&dspace[addr], &value, sizeof(value));
    bsd_store_long(addr + offsetof(struct tr_rusage, ru_ovly), overlays);
}

static int bsd_wait_status(int status)
{
    int sig;
    if (WIFEXITED(status))
        return WEXITSTATUS(status) << 8;
    if (WIFSTOPPED(status)) {
        sig = bsd_signal_number(WSTOPSIG(status));
        return sig == -1 ? -1 : (sig << 8) | 0177;
    }
    sig = bsd_signal_number(WTERMSIG(status));
    if (sig == -1)
        return -1;
#ifdef WCOREDUMP
    if (WCOREDUMP(status))
        sig |= 0200;
#endif
    return sig;
}

static int bsd_load_sockaddr(u_int16_t addr, unsigned length,
                             struct sockaddr_storage *value, socklen_t *size)
{
    struct sockaddr header;
    struct sockaddr_un local;
    u_int16_t family;
    const unsigned char *end;
    size_t path_length;

    if (length < 2 || length > sizeof(*value)) {
        errno = EINVAL;
        return -1;
    }
    if (!valid_dspace_range(addr, length))
        return -1;
    memcpy(&family, &dspace[addr], 2);
    memset(value, 0, sizeof(*value));
    memset(&header, 0, sizeof(header));
    header.sa_family = family;
    if (header.sa_family != family) {
        errno = EAFNOSUPPORT;
        return -1;
    }
    *size = length;
    if (family == AF_UNIX) {
        /* 2.11BSD's path field is 108 bytes, including any supplied padding. */
        if (length > 110 || length == 2) {
            errno = EINVAL;
            return -1;
        }
        end = memchr(&dspace[addr + 2], 0, length - 2);
        path_length = end ? (size_t) (end - &dspace[addr + 2]) + 1 : length - 2;
        if (path_length > sizeof(local.sun_path)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        memset(&local, 0, sizeof(local));
        local.sun_family = family;
        memcpy(local.sun_path, &dspace[addr + 2], path_length);
        *size = offsetof(struct sockaddr_un, sun_path) + path_length;
#ifndef __linux__
        local.sun_len = *size;
#endif
        memcpy(value, &local, *size);
    } else {
#ifndef __linux__
        header.sa_len = *size;
#endif
        memcpy(value, &header, 2);
        memcpy((unsigned char *) value + 2, &dspace[addr + 2], length - 2);
    }
    return 0;
}

static int bsd_prepare_sockaddr(u_int16_t addr, u_int16_t length_addr,
                                u_int16_t *capacity)
{
    if (!valid_dspace_range(length_addr, 2))
        return -1;
    memcpy(capacity, &dspace[length_addr], 2);
    return valid_dspace_range(addr, *capacity) ? 0 : -1;
}

static int bsd_store_sockaddr(u_int16_t addr, u_int16_t length_addr,
                              u_int16_t capacity,
                              const struct sockaddr_storage *value,
                              socklen_t size)
{
    u_int16_t family = value->ss_family;
    u_int16_t copied;

    if (size > sizeof(*value)) {
        errno = EOVERFLOW;
        return -1;
    }
    /* 2.11BSD returns the copied length, not the untruncated native length. */
    copied = size < capacity ? size : capacity;
    if (copied)
        memcpy(&dspace[addr], &family, copied < 2 ? copied : 2);
    if (copied > 2)
        memcpy(&dspace[addr + 2], (const unsigned char *) value + 2, copied - 2);
    memcpy(&dspace[length_addr], &copied, 2);
    return 0;
}

void bsdtrap()
{
    int i, j, len, pid, pfd[2];
    char *buf, *buf2;
    long larg1;
    char *fmode;		/* used with fdopen only */
    struct stat stbuf;		/* used in STAT */
    struct tr_stat guest_stat, *tr_stbuf = &guest_stat;
    struct timeval del, oldel;	/* used in ADJTIME */
    struct timeval utv[2];	/* used in UTIMES */
    struct tr_timezone guest_zone;
    struct timezone zone;	/* used in GETTIMEOFDAY */
    struct itimerval tval, oltval;	/* used in itimer calls */
    struct sockaddr_storage sock;
    socklen_t sock_length;
    u_int16_t sock_capacity;
    gid_t *gidset;		/* used in GETGROUPS */
    struct rlimit rlp;		/* used in rlimit calls */
    int32_t limit_cur, limit_max;
    struct rusage use;		/* used in getrusage */
    struct iovec ivec[16];	/* 2.11BSD's kernel vector limit. */
    struct tr_iovec vector;
    u_int16_t guest_fds[2];
    u_int16_t guest_gid, guest_status;
    size_t total;

    TrapDebug((dbg_file, "pid %d %s: ", (int) getpid(),
               bsdtrap_name[ir & 0xff]));

    A = (arglist *) & dspace[(regs[SP] + 2)];

    i = errno = 0;
    switch (ir & 0xff) {
    case S_LINK:
    case S_SYMLINK:
    case S_RENAME:
        i = 2;
        break;
    case S_ACCT:
        i = uarg1 ? 1 : 0;
        break;
    case S_READLINK:
    case S_ACCESS:
    case S_MKDIR:
    case S_RMDIR:
    case S_LSTAT:
    case S_STAT:
    case S_UTIMES:
    case S_UNLINK:
    case S_OPEN:
    case S_MKNOD:
    case S_CHMOD:
    case S_TRUNCATE:
    case S_CHOWN:
    case S_CHROOT:
    case S_CHDIR:
#ifndef NO_CHFLAGS
    case S_CHFLAGS:
#endif
    case S_CREAT:
        i = 1;
        break;
    }
    if ((i && !valid_guest_pathname(uarg1)) ||
        (i == 2 && !valid_guest_pathname(uarg2))) {
        i = -1;
        goto done;
    }
    i = 0;
    switch (ir & 0xff) {
    case S_INDIR:
        (void) printf("Does 2.11BSD use INDIR? I don't think so\n");
        exit(EXIT_FAILURE);

    case S_QUOTA:		/* DONE - for now */
    case S_SETQUOTA:	/* DONE - for now */
        i = -1;
        errno = EINVAL;
        break;

    /* These syscalls are not implemented, and */
    /* always return EPERM to the caller */
    case S_PTRACE:		/* DONE - bad syscall */
    case S_MOUNT:		/* DONE - bad syscall */
    case S_UMOUNT:		/* DONE - bad syscall */
    case S_PROFIL:		/* DONE - bad syscall */
    case S_NOSYS147:	/* DONE - bad syscall */
    case S_SYSCTL:
        i = -1;
        errno = EPERM;
        break;
    /* These syscalls are ignored, and */
    /* always return C=0 to the caller */
    case S_OLDLOCK:	/* DONE - ok syscall */
    case S_OLDPHYS:	/* DONE - ok syscall */
    case S_FSTATFS:	/* DONE - ok syscall */
    case S_VHANGUP:	/* DONE - ok syscall */
        i = 0;
        break;
    case S_SIGACTION:
        /* libc supplies its trampoline before the three public arguments. */
        i = do_sigaction(uarg2, uarg3, uarg4);
        break;
    case S_SIGPROCMASK:
        i = bsd_sigprocmask(uarg1, uarg2, uarg3);
        break;
    case S_SIGPENDING:
        i = bsd_sigpending(uarg1);
        break;
    case S_SIGRETURN:
    case S_SIGALTSTACK:
    case S_SIGSUSPEND:
    case S_SIGVEC:
    case S_SIGBLOCK:
    case S_SIGSETMASK:
    case S_SIGPAUSE:
    case S_SIGSTACK:
        i = -1;
        errno = ENOSYS;
        break;
    case S_IOCTL:		/* DONE a bit */
        i = trap_ioctl();
        break;
    case S_SBRK:		/* DONE */
        if (uarg1 < regs[SP]) {
            i = 0;
            TrapDebug((dbg_file, "set break to %d ", uarg1));
        } else {
            i = -1;
            errno = ENOMEM;
            TrapDebug((dbg_file, "break %d > SP %d", uarg1, regs[SP]));
        }
        break;
    case S_SYNC:		/* DONE */
        sync();
        i = 0;
        break;
    case S_FSYNC:		/* DONE */
        i = fsync(sarg1);
        break;
    case S_GETDTABLESIZE:	/* DONE */
        i = getdtablesize();
        break;
    case S_EXIT:		/* DONE */
#ifdef DEBUG
        TrapDebug((dbg_file, "val %d\n", sarg1));
        fflush(dbg_file);
#endif
        exit(sarg1);
    case S_DUP:		/* DONE */
        TrapDebug((dbg_file, "on %d ", sarg1));
        i = dup(sarg1);
#ifdef STREAM_BUFFERING
        if ((i != -1) && ValidFD(sarg1) && stream[sarg1]) {
            fmode = streammode[sarg1];
            stream[i] = fdopen(i, fmode);
            streammode[i] = fmode;
        }
#endif
        break;
    case S_DUP2:		/* DONE */
        TrapDebug((dbg_file, "on %d %d ", sarg1, sarg2));
        i = dup2(sarg1, sarg2);
#ifdef STREAM_BUFFERING
        if ((i != -1) && ValidFD(sarg2) && ValidFD(sarg1)
                && stream[sarg1]) {
            fmode = streammode[sarg1];
            stream[sarg2] = fdopen(sarg2, fmode);
            streammode[sarg2] = fmode;
        }
#endif
        break;
    case S_REBOOT:		/* DONE */
        (void) Reboot(sarg1);
        break;
    case S_UMASK:		/* DONE */
        i = umask((mode_t) sarg1);
        break;
    case S_GETPAGESIZE:	/* DONE */
        i = getpagesize();
        break;
    case S_GETHOSTNAME:	/* DONE */
        buf = (char *) &dspace[uarg1];
        i = gethostname(buf, sarg2);
        break;
    case S_SETHOSTNAME:	/* DONE */
        buf = (char *) &dspace[uarg1];
        sethostname(buf, sarg2);
        break;
    case S_LSEEK:		/* DONE */
        larg1 = (sarg2 << 16) | uarg3;
#ifdef STREAM_BUFFERING
        if (ValidFD(sarg1) && stream[sarg1]) {
            i = fseek(stream[sarg1], larg1, sarg4);
            if (i == 0)
                i = ftell(stream[sarg1]);
        } else
#endif
            i = lseek(sarg1, larg1, sarg4);
        if (i == -1)
            break;
        else {
            regs[1] = i & 0xffff;
            i = (i >> 16) & 0xffff;
            break;
        }
    case S_READ:		/* DONE */
        TrapDebug((dbg_file, "%d bytes on %d ", uarg3, sarg1));
        if (!valid_dspace_range(uarg2, uarg3)) {
            i = -1;
            break;
        }
        buf = (char *) &dspace[uarg2];
#ifdef STREAM_BUFFERING
        if (ValidFD(sarg1) && stream[sarg1])
            i = fread(buf, 1, uarg3, stream[sarg1]);
        else
#endif
            i = read(sarg1, buf, uarg3);
        break;
    case S_LINK:		/* DONE */
        buf = xlate_filename((char *) &dspace[uarg1]);
        buf2 = xlate_filename((char *) &dspace[uarg2]);
        i = link(buf, buf2);
        break;
    case S_SYMLINK:	/* DONE */
        buf = xlate_filename((char *) &dspace[uarg1]);
        buf2 = xlate_filename((char *) &dspace[uarg2]);
        i = symlink(buf, buf2);
        break;
    case S_RENAME:		/* DONE */
        buf = xlate_filename((char *) &dspace[uarg1]);
        buf2 = xlate_filename((char *) &dspace[uarg2]);
        i = rename(buf, buf2);
        break;
    case S_READLINK:	/* DONE */
        if (sarg3 < 0) {
            errno = EINVAL;
            i = -1;
            break;
        }
        if (!valid_dspace_range(uarg2, uarg3)) {
            i = -1;
            break;
        }
        buf = xlate_filename((char *) &dspace[uarg1]);
        i = readlink(buf, (char *) &dspace[uarg2], sarg3);
        break;
    case S_ACCESS:		/* DONE */
        buf = xlate_filename((char *) &dspace[uarg1]);
        i = access(buf, sarg2);
        break;
    case S_MKDIR:		/* DONE */
        buf = xlate_filename((char *) &dspace[uarg1]);
        i = mkdir(buf, sarg2);
        break;
    case S_RMDIR:		/* DONE */
        buf = xlate_filename((char *) &dspace[uarg1]);
        i = rmdir(buf);
        break;
    case S_ACCT:		/* DONE */
        buf = uarg1 ? xlate_filename((char *) &dspace[uarg1]) : NULL;
        i = acct(buf);
        break;
    case S_WRITEV:		/* DONE */
    case S_READV:		/* DONE */
        if (uarg3 > 16) {
            i = -1;
            errno = EINVAL;
            break;
        }
        if (uarg3 == 0) {
            i = fcntl(sarg1, F_GETFL);
            if (i == -1)
                break;
            if (((ir & 0xff) == S_READV && (i & O_ACCMODE) == O_WRONLY) ||
                    ((ir & 0xff) == S_WRITEV && (i & O_ACCMODE) == O_RDONLY)) {
                errno = EBADF;
                i = -1;
            } else
                i = 0;
            break;
        }
        if (!valid_dspace_range(uarg2, uarg3 * sizeof(vector))) {
            i = -1;
            break;
        }

        total = 0;
        for (j = 0; j < uarg3; j++) {
            memcpy(&vector, &dspace[uarg2 + j * sizeof(vector)], sizeof(vector));
            if (!valid_dspace_range(vector.iov_base, vector.iov_len))
                break;
            total += vector.iov_len;
            if (total > 65535) {
                errno = EINVAL;
                break;
            }
            ivec[j].iov_len = vector.iov_len;
            ivec[j].iov_base = &dspace[vector.iov_base];
        }
        if (j != uarg3)
            i = -1;
        else if ((ir & 0xff) == S_READV)
            i = readv(sarg1, ivec, uarg3);
        else
            i = writev(sarg1, ivec, uarg3);
        break;
    case S_WRITE:		/* DONE */
        if (!valid_dspace_range(uarg2, uarg3)) {
            i = -1;
            break;
        }
        buf = (char *) &dspace[uarg2];
        TrapDebug((dbg_file, "%d bytes on %d ", uarg3, sarg1));
#ifdef STREAM_BUFFERING
        if (ValidFD(sarg1) && stream[sarg1])
            i = fwrite(buf, 1, uarg3, stream[sarg1]);
        else
#endif
            i = write(sarg1, buf, uarg3);
        break;
    case S_CLOSE:		/* DONE */
#ifdef DEBUG
        TrapDebug((dbg_file, "on %d ", sarg1));
        if ((dbg_file != NULL) && (sarg1 == fileno(dbg_file))) {
            i = 0;
            break;		/* Don't close our debug file! */
        }
#endif
#ifdef STREAM_BUFFERING
        if (ValidFD(sarg1) && stream[sarg1]) {
            i = fclose(stream[sarg1]);
            stream[sarg1] = NULL;
        } else
#endif
            i = close(sarg1);
        break;
    case S_FCNTL:
        TrapDebug((dbg_file, "on %d %d %d ", sarg1, sarg2, sarg3));
        i = fcntl(sarg1, sarg2, sarg3);
        break;
    case S_FLOCK:
        i = flock(sarg1, sarg2);
        break;
    case S_LSTAT:		/* DONE */
        if (!valid_dspace_range(uarg2, sizeof(guest_stat))) {
            i = -1;
            break;
        }
        buf = xlate_filename((char *) &dspace[uarg1]);
        i = lstat(buf, &stbuf);
        TrapDebug((dbg_file, "on %s ", buf));
        goto dostat;
    case S_STAT:		/* DONE */
        if (!valid_dspace_range(uarg2, sizeof(guest_stat))) {
            i = -1;
            break;
        }
        buf = xlate_filename((char *) &dspace[uarg1]);
        i = stat(buf, &stbuf);
        TrapDebug((dbg_file, "on %s ", buf));
        goto dostat;
    case S_FSTAT:		/* DONE */
        if (!valid_dspace_range(uarg2, sizeof(guest_stat))) {
            i = -1;
            break;
        }
        i = fstat(uarg1, &stbuf);
        TrapDebug((dbg_file, "on fd %d ", uarg1));

dostat:
        if (i == -1)
            break;
        else {
            memset(tr_stbuf, 0, sizeof(*tr_stbuf));
            /* The following stops blksize equalling 64K,
             * which becomes 0 in a 16-bit int. This then
             * causes 2.11BSD flsbuf() to malloc(0), which
             * then causes malloc to go crazy - wkt.
             */
            if (stbuf.st_blksize > MAX_BLKSIZE)
                stbuf.st_blksize = MAX_BLKSIZE;

            tr_stbuf->st_dev = stbuf.st_dev;
            tr_stbuf->st_ino = stbuf.st_ino;
            tr_stbuf->st_mode = stbuf.st_mode;
            tr_stbuf->st_nlink = stbuf.st_nlink;
            tr_stbuf->st_uid = stbuf.st_uid;
            tr_stbuf->st_gid = stbuf.st_gid;
            tr_stbuf->st_rdev = stbuf.st_rdev;
#ifndef NO_STFLAGS
            tr_stbuf->st_flags = stbuf.st_flags;
#endif
            copylong(tr_stbuf->st_size, stbuf.st_size);
            copylong(tr_stbuf->st_atim, stbuf.st_atime);
            copylong(tr_stbuf->st_mtim, stbuf.st_mtime);
            copylong(tr_stbuf->st_ctim, stbuf.st_ctime);
            copylong(tr_stbuf->st_blksize, stbuf.st_blksize);
            larg1 = stbuf.st_blocks;
            copylong(tr_stbuf->st_blocks, larg1);
            memcpy(&dspace[uarg2], tr_stbuf, sizeof(*tr_stbuf));
        }
        break;
    case S_UTIMES:		/* DONE */
        if (uarg2 && !valid_dspace_range(uarg2, 16)) {
            i = -1;
            break;
        }
        buf = xlate_filename((char *) &dspace[uarg1]);
        if (uarg2) {
            bsd_load_timeval(uarg2, &utv[0]);
            bsd_load_timeval(uarg2 + 8, &utv[1]);
        }
        i = utimes(buf, uarg2 ? utv : NULL);
        break;
    case S_ADJTIME:	/* DONE */
        if (!valid_dspace_range(uarg1, 8) ||
                (uarg2 && !valid_dspace_range(uarg2, 8))) {
            i = -1;
            break;
        }
        bsd_load_timeval(uarg1, &del);
        i = adjtime(&del, &oldel);

        if (i != -1 && uarg2)
            bsd_store_timeval(uarg2, &oldel);
        break;
    case S_GETTIMEOFDAY:	/* DONE */
        if ((uarg1 && !valid_dspace_range(uarg1, 8)) ||
                (uarg2 && !valid_dspace_range(uarg2, sizeof(guest_zone)))) {
            i = -1;
            break;
        }
        i = gettimeofday(&del, uarg2 ? &zone : NULL);
        if (i == -1)
            break;
        if (uarg1)
            bsd_store_timeval(uarg1, &del);
        if (uarg2) {
            guest_zone.tz_minuteswest = zone.tz_minuteswest;
            guest_zone.tz_dsttime = zone.tz_dsttime;
            memcpy(&dspace[uarg2], &guest_zone, sizeof(guest_zone));
        }
        break;
    case S_SETTIMEOFDAY:	/* DONE */
        if ((uarg1 && !valid_dspace_range(uarg1, 8)) ||
                (uarg2 && !valid_dspace_range(uarg2, sizeof(guest_zone)))) {
            i = -1;
            break;
        }
        if (uarg1)
            bsd_load_timeval(uarg1, &del);
        if (uarg2) {
            memcpy(&guest_zone, &dspace[uarg2], sizeof(guest_zone));
            zone.tz_minuteswest = guest_zone.tz_minuteswest;
            zone.tz_dsttime = guest_zone.tz_dsttime;
        }
        i = settimeofday(uarg1 ? &del : NULL, uarg2 ? &zone : NULL);
        break;
    case S_GETITIMER:	/* DONE */
        if (!valid_dspace_range(uarg2, 16)) {
            i = -1;
            break;
        }
        i = getitimer(sarg1, &tval);
        if (i == -1)
            break;
        bsd_store_timeval(uarg2, &tval.it_interval);
        bsd_store_timeval(uarg2 + 8, &tval.it_value);
        break;
    case S_SETITIMER:	/* DONE */
        if (!valid_dspace_range(uarg2, 16) ||
                (uarg3 && !valid_dspace_range(uarg3, 16))) {
            i = -1;
            break;
        }
        bsd_load_timeval(uarg2, &tval.it_interval);
        bsd_load_timeval(uarg2 + 8, &tval.it_value);
        i = setitimer(sarg1, &tval, &oltval);
        if (i == -1)
            break;
        if (uarg3) {
            bsd_store_timeval(uarg3, &oltval.it_interval);
            bsd_store_timeval(uarg3 + 8, &oltval.it_value);
        }
        break;
    case S_UNLINK:		/* DONE */
        buf = xlate_filename((char *) &dspace[uarg1]);
        i = unlink(buf);
        break;
    case S_OPEN:		/* DONE */
        buf = xlate_filename((char *) &dspace[uarg1]);

        i = stat(buf, &stbuf);	/* If file is a directory */
        if (i == 0 && (stbuf.st_mode & S_IFDIR)) {
            i = bsdopen_dir(buf);
            fmode = "w+";
            TrapDebug((dbg_file, "(dir) on %s ", buf));
        } else {
#ifdef NEED_MAP_FCNTL
            sarg2 = map_fcntl(sarg2);
#endif
            switch (sarg2 & O_ACCMODE) {
            case O_RDONLY:
                fmode = "r";
                break;
            case O_WRONLY:
                fmode = "w";
                break;
            default:
                fmode = "w+";
                break;
            }
            i = open(buf, sarg2, sarg3);
            TrapDebug((dbg_file, "on %s ", buf));
            TrapDebug((dbg_file, "sarg2 is %d, sarg3 is 0x%x ", sarg2,
                       sarg3));
        }
#ifdef STREAM_BUFFERING
        if (i == -1)
            break;
        /* Now get its stream pointer if possible */
        /* Can someone explain why fdopen doesn't work for O_RDWR? */
#if 0
        if (ValidFD(i) && !isatty(i) && (sarg2 != O_RDWR)) {
            stream[i] = fdopen(i, fmode);
            streammode[i] = fmode;
        }
#endif
        stream[i] = fdopen(i, fmode);
        streammode[i] = fmode;
#endif
        break;
    case S_MKNOD:		/* DONE */
        buf = xlate_filename((char *) &dspace[uarg1]);
        i = mknod(buf, sarg2, sarg3);
        break;
    case S_CHMOD:		/* DONE */
        buf = xlate_filename((char *) &dspace[uarg1]);
        i = chmod(buf, sarg2);
        break;
    case S_FCHMOD:		/* DONE */
        i = fchmod(sarg1, sarg2);
        break;
    case S_TRUNCATE:	/* DONE */
        buf = xlate_filename((char *) &dspace[uarg1]);
        larg1 = (sarg2 << 16) | uarg3;
        i = truncate(buf, larg1);
        break;
    case S_FTRUNCATE:	/* DONE */
        larg1 = (sarg2 << 16) | uarg3;
        i = ftruncate(sarg1, larg1);
        break;
    case S_KILL:		/* DONE */
        j = bsd_native_signal(sarg2);
        i = j == -1 ? -1 : kill(sarg1, j);
        break;
    case S_KILLPG:		/* DONE */
        j = bsd_native_signal(sarg2);
        i = j == -1 ? -1 : killpg(sarg1, j);
        break;
    case S_CHOWN:		/* DONE */
        buf = xlate_filename((char *) &dspace[uarg1]);
        i = chown(buf, sarg2, sarg3);
        break;
    case S_PIPE:		/* DONE */
        i = pipe(pfd);
#ifdef STREAM_BUFFERING
        if (ValidFD(pfd[0])) {
            stream[pfd[0]] = fdopen(pfd[0], "r");
            streammode[pfd[0]] = "r";
        }
        if (ValidFD(pfd[1])) {
            stream[pfd[1]] = fdopen(pfd[1], "w");
            streammode[pfd[1]] = "w";
        }
#endif
        if (i == -1)
            break;
        i = pfd[0];
        regs[1] = pfd[1];
        break;
    case S_CHROOT:		/* DONE */
        buf = xlate_filename((char *) &dspace[uarg1]);
        if (buf == NULL) {
            errno = ENOENT;
            i = -1;
            break;
        }
        i = set_apout_root(buf);
        break;
    case S_CHDIR:		/* DONE */
        buf = xlate_filename((char *) &dspace[uarg1]);
        i = chdir(buf);
        break;
    case S_FCHDIR:		/* DONE */
        i = fchdir(sarg1);
        break;

#ifndef NO_CHFLAGS
    case S_CHFLAGS:	/* DONE */
        buf = xlate_filename((char *) &dspace[uarg1]);
        i = chflags(buf, uarg2);
        break;
    case S_FCHFLAGS:	/* DONE */
        i = fchflags(sarg1, uarg2);
        break;
#endif

    case S_CREAT:		/* DONE */
        buf = xlate_filename((char *) &dspace[uarg1]);
        i = creat(buf, sarg2);
#ifdef STREAM_BUFFERING
        if (ValidFD(i)) {
            stream[i] = fdopen(i, "w");
            streammode[i] = "w";
        }
#endif
        break;
    case S_EXECVE:		/* DONE, I think */
        i = trap_execve(1);
        break;
    case S_EXECV:		/* Not sure here */
        i = trap_execve(0);
        break;
    case S_WAIT:		/* Not sure here */
        i = wait(&pid);
        if (i == -1)
            break;
        regs[1] = pid;
        break;
    case S_WAIT4:
        TrapDebug((dbg_file, "on pid %d options %d ", sarg1, uarg3));
        if (uarg3 & ~3) {
            i = -1;
            errno = EINVAL;
            break;
        }
        if ((uarg2 && !valid_dspace_range(uarg2, 2)) ||
            (uarg4 && !valid_dspace_range(uarg4, sizeof(struct tr_rusage)))) {
            i = -1;
            break;
        }
        len = (uarg3 & 1 ? WNOHANG : 0) | (uarg3 & 2 ? WUNTRACED : 0);
        memset(&use, 0, sizeof(use));
        i = wait4(sarg1, &j, len, uarg4 ? &use : NULL);
        if (i > 0) {
            if (uarg2) {
                pid = bsd_wait_status(j);
                if (pid == -1) {
                    i = -1;
                    break;
                }
                guest_status = pid;
                memcpy(&dspace[uarg2], &guest_status, 2);
            }
            if (uarg4 && !WIFSTOPPED(j))
                bsd_store_rusage(uarg4, &use, 0);
        }
        break;
    case S_FORK:		/* DONE */
    case S_VFORK:		/* DONE */
        i = fork();
        if (i != 0) {
            regs[PC] += 2;
        } /* Took ages to find this! */
        else
            ov_changes = 0;
        break;
    case S_GETHOSTID:	/* DONE */
        i = gethostid();
        regs[1] = i & 0xffff;
        i = (i >> 16) & 0xffff;
        break;
    case S_SETHOSTID:	/* DONE */
        larg1 = (sarg2 << 16) | uarg3;
        sethostid(larg1);
        i = 0;
        break;
    case S_GETUID:		/* DONE */
        i = getuid();
        break;
    case S_SETUID:		/* DONE */
        i = setuid(uarg1);
        break;
    case S_GETEUID:	/* DONE */
        i = geteuid();
        break;
    case S_GETPID:		/* DONE */
        i = getpid();
        break;
    case S_GETPPID:	/* DONE */
        i = getppid();
        break;
    case S_GETGID:		/* DONE */
        i = getgid();
        break;
    case S_GETEGID:	/* DONE */
        i = getegid();
        break;
#ifndef NO_GETPGID
    case S_GETPGRP:	/* DONE */
        i = getpgid(sarg1);
        break;
#endif
    case S_SETPGRP:	/* DONE */
        i = setpgid(sarg1, sarg2);
        break;
    case S_SETREGID:	/* DONE */
        i = setregid(sarg1, sarg2);
        break;
    case S_SETREUID:	/* DONE */
        i = setreuid(sarg1, sarg2);
        break;
    case S_GETPRIORITY:	/* DONE */
        i = getpriority(sarg1, sarg2);
        break;
    case S_SETPRIORITY:	/* DONE */
        i = setpriority(sarg1, sarg2, sarg3);
        break;
    case S_LISTEN:		/* DONE */
        i = listen(sarg1, sarg2);
        break;
    case S_SHUTDOWN:	/* DONE */
        i = shutdown(sarg1, sarg2);
        break;
    case S_SOCKET:		/* DONE */
        i = socket(sarg1, sarg2, sarg3);
        break;
    case S_SOCKETPAIR:	/* DONE */
        if (!valid_dspace_range(uarg4, sizeof(guest_fds))) {
            i = -1;
            break;
        }
        i = socketpair(sarg1, sarg2, sarg3, pfd);
        if (i == -1)
            break;
        guest_fds[0] = pfd[0];
        guest_fds[1] = pfd[1];
        memcpy(&dspace[uarg4], guest_fds, sizeof(guest_fds));
        break;
    case S_RECV:		/* DONE */
        if (sarg3 < 0) {
            errno = EINVAL;
            i = -1;
            break;
        }
        if (!valid_dspace_range(uarg2, uarg3)) {
            i = -1;
            break;
        }
        buf = (char *) &dspace[uarg2];
        i = recv(sarg1, buf, sarg3, sarg4);
        break;
    case S_SEND:		/* DONE */
        if (sarg3 < 0) {
            errno = EINVAL;
            i = -1;
            break;
        }
        if (!valid_dspace_range(uarg2, uarg3)) {
            i = -1;
            break;
        }
        buf = (char *) &dspace[uarg2];
        i = send(sarg1, buf, sarg3, sarg4);
        break;
    case S_ACCEPT:		/* DONE */
    case S_GETPEERNAME:	/* DONE */
    case S_GETSOCKNAME:	/* DONE */
        if ((ir & 0xff) == S_ACCEPT && !uarg2) {
            i = accept(sarg1, NULL, NULL);
            break;
        }
        if (bsd_prepare_sockaddr(uarg2, uarg3, &sock_capacity) == -1) {
            i = -1;
            break;
        }
        memset(&sock, 0, sizeof(sock));
        sock_length = sizeof(sock);
        if ((ir & 0xff) == S_ACCEPT)
            i = accept(sarg1, (struct sockaddr *) &sock, &sock_length);
        else if ((ir & 0xff) == S_GETPEERNAME)
            i = getpeername(sarg1, (struct sockaddr *) &sock, &sock_length);
        else
            i = getsockname(sarg1, (struct sockaddr *) &sock, &sock_length);
        if (i != -1) {
            if (bsd_store_sockaddr(uarg2, uarg3, sock_capacity, &sock,
                                   sock_length) == -1) {
                if ((ir & 0xff) == S_ACCEPT) {
                    j = errno;
                    close(i);
                    errno = j;
                }
                i = -1;
            }
        }
        break;
    case S_BIND:		/* DONE */
    case S_CONNECT:	/* DONE */
        if (bsd_load_sockaddr(uarg2, uarg3, &sock, &sock_length) == -1) {
            i = -1;
            break;
        }
        if ((ir & 0xff) == S_BIND)
            i = bind(sarg1, (struct sockaddr *) &sock, sock_length);
        else
            i = connect(sarg1, (struct sockaddr *) &sock, sock_length);
        break;
    case S_RECVFROM:	/* DONE */
        if (sarg3 < 0) {
            i = -1;
            errno = EINVAL;
            break;
        }
        if (!valid_dspace_range(uarg2, uarg3) ||
            (uarg5 && bsd_prepare_sockaddr(uarg5, uarg6, &sock_capacity) == -1)) {
            i = -1;
            break;
        }
        memset(&sock, 0, sizeof(sock));
        sock_length = sizeof(sock);
        buf = (char *) &dspace[uarg2];
        i = recvfrom(sarg1, buf, uarg3, sarg4,
                     uarg5 ? (struct sockaddr *) &sock : NULL,
                     uarg5 ? &sock_length : NULL);
        if (i != -1 && uarg5 &&
            bsd_store_sockaddr(uarg5, uarg6, sock_capacity, &sock, sock_length) == -1)
            i = -1;
        break;
    case S_GETGROUPS:
        len = sarg1;
        if (len < 0) {
            i = -1;
            errno = EINVAL;
            break;
        }
        i = getgroups(0, NULL);
        if (i == -1)
            break;
        if (i > len) {
            i = -1;
            errno = EINVAL;
            break;
        }
        len = i;
        if (!valid_dspace_range(uarg2, (size_t) len * 2)) {
            i = -1;
            break;
        }
        if (len == 0)
            break;
        gidset = malloc((size_t) len * sizeof(*gidset));
        if (gidset == NULL) {
            i = -1;
            break;
        }
        i = getgroups(len, gidset);
        for (j = 0; j < i; j++) {
            if (gidset[j] > UINT16_MAX) {
                i = -1;
                errno = EOVERFLOW;
                break;
            }
        }
        for (j = 0; j < i; j++) {
            guest_gid = gidset[j];
            memcpy(&dspace[uarg2 + j * 2], &guest_gid, 2);
        }
        free(gidset);
        break;
    case S_SETGROUPS:
        len = sarg1;
        if (len < 0 || len > 16) {
            i = -1;
            errno = EINVAL;
            break;
        }
        if (!valid_dspace_range(uarg2, (size_t) len * 2)) {
            i = -1;
            break;
        }
        if (len == 0) {
            i = setgroups(0, NULL);
            break;
        }
        gidset = malloc((size_t) len * sizeof(*gidset));
        if (gidset == NULL) {
            i = -1;
            break;
        }
        for (j = 0; j < len; j++) {
            memcpy(&guest_gid, &dspace[uarg2 + j * 2], 2);
            gidset[j] = guest_gid;
        }
        i = setgroups(len, gidset);
        free(gidset);
        break;
    case S_GETRLIMIT:	/* DONE */
        j = bsd_resource(uarg1);
        if (j == -1 || !valid_dspace_range(uarg2, 8)) {
            i = -1;
            break;
        }
        i = getrlimit(j, &rlp);
        if (i == -1)
            break;
        bsd_store_long(uarg2, bsd_limit_value(rlp.rlim_cur));
        bsd_store_long(uarg2 + 4, bsd_limit_value(rlp.rlim_max));
        break;
    case S_SETRLIMIT:	/* DONE */
        j = bsd_resource(uarg1);
        if (j == -1 || !valid_dspace_range(uarg2, 8)) {
            i = -1;
            break;
        }
        limit_cur = bsd_load_long(uarg2);
        limit_max = bsd_load_long(uarg2 + 4);
        if (limit_cur < 0 || limit_max < 0) {
            i = -1;
            errno = EINVAL;
            break;
        }
        rlp.rlim_cur = limit_cur == INT32_MAX ? RLIM_INFINITY : (rlim_t) limit_cur;
        rlp.rlim_max = limit_max == INT32_MAX ? RLIM_INFINITY : (rlim_t) limit_max;
        i = setrlimit(j, &rlp);
        break;
    case S_GETRUSAGE:
        TrapDebug((dbg_file, "arg1 %d pointer 0%o ", sarg1, uarg2));
        if (!valid_dspace_range(uarg2, sizeof(struct tr_rusage))) {
            i = -1;
            break;
        }
        i = getrusage(sarg1, &use);
        if (i == -1)
            break;

        bsd_store_rusage(uarg2, &use, ov_changes);
        break;
    default:
        if ((ir & 0xff) > S_GETSOCKNAME) {
            TrapDebug((stderr,
                       "Apout - unknown syscall %d at PC 0%o\n",
                       ir & 0xff, regs[PC]));
        } else {
            (void) fprintf(stderr,
                           "Apout - the 2.11BSD %s syscall is not yet implemented\n",
                           bsdtrap_name[ir & 0xff]);
        }
        exit(EXIT_FAILURE);
    }

done:
    /* Set r0 to either errno or i, */
    /* and clear/set C bit */

    if (i == -1) {
        SET_CC_C();
        regs[0] = errno;
        TrapDebug((dbg_file, "errno is %s\n", strerror(errno)));
    } else {
        CLR_CC_C();
        regs[0] = i;
        TrapDebug((dbg_file, "return %d\n", i));
    }
    return;
}



static int trap_execve(int want_env)
{
    u_int16_t cptr, cptr2;
    char *buf, *name, *origpath;

    if (!valid_guest_pathname(uarg1) ||
        !valid_guest_exec_args(uarg2, uarg3, want_env))
        return -1;
    origpath = strdup((char *) &dspace[uarg1]);
    if (origpath == NULL)
        return -1;
    name = xlate_filename(origpath);
    TrapDebug((dbg_file, "%s Execing %s (%s) ", progname, name, origpath));

    cptr = uarg2;
    Argc = 0;
    Envc = 0;
    while (cptr && Argc < MAX_ARGS) {
        ll_word(cptr, cptr2);
        if (cptr2 == 0)
            break;
        buf = (char *) &dspace[cptr2];
        Argv[Argc++] = strdup(buf);
        cptr += 2;
        TrapDebug((dbg_file, "%s ", buf));
    }
    Argv[Argc] = NULL;
    TrapDebug((dbg_file, "\n"));

    if (want_env) {
        cptr = uarg3;
        while (cptr && Envc < MAX_ARGS) {
            ll_word(cptr, cptr2);
            if (cptr2 == 0)
                break;
            buf = (char *) &dspace[cptr2];
            Envp[Envc++] = strdup(buf);
            cptr += 2;
        }
        Envp[Envc] = NULL;
    }

    if (load_a_out(name, origpath, want_env) == -1) {
        for (Argc--; Argc >= 0; Argc--)
            free(Argv[Argc]);
        if (want_env)
            for (Envc--; Envc >= 0; Envc--)
                free(Envp[Envc]);
        free(origpath);
        if (errno == 0)
            errno = ENOENT;
        return (-1);
    }
    if (bsd_signal_exec() == -1)
        return -1;
    run();			/* Ok, so it's recursive, I dislike setjmp */
    return (0);			/* Just to shut the compiler up */
}

/* 2.11BSD reads directories as if they were ordinary files.
 * The solution is to read the directory entries, and build a
 * real file, which is passed back to the open call.
 *
 * A directory consists of some number of blocks of DIRBLKSIZ
 * bytes, where DIRBLKSIZ is chosen such that it can be transferred
 * to disk in a single atomic operation (e.g. 512 bytes on most machines).
 *
 * Each DIRBLKSIZ byte block contains some number of directory entry
 * structures, which are of variable length.  Each directory entry has
 * a struct direct at the front of it, containing its inode number,
 * the length of the entry, and the length of the name contained in
 * the entry.  These are followed by the name padded to a 4 byte boundary
 * with null bytes.  All names are guaranteed null terminated.
 * The maximum length of a name in a directory is MAXNAMLEN.
 *
 * The macro DIRSIZ(dp) gives the amount of space required to represent
 * a directory entry.  Free space in a directory is represented by
 * entries which have dp->d_reclen > DIRSIZ(dp).  All DIRBLKSIZ bytes
 * in a directory block are claimed by the directory entries.  This
 * usually results in the last entry in a directory having a large
 * dp->d_reclen.  When entries are deleted from a directory, the
 * space is returned to the previous entry in the same directory
 * block by increasing its dp->d_reclen.  If the first entry of
 * a directory block is free, then its dp->d_ino is set to 0.
 * Entries other than the first in a directory do not normally have
 * dp->d_ino set to 0.
 */

static int bsdopen_dir(char *name)
{
    DIR *d;
    char *tmpname;
    int i, nlen, total_left;
    struct dirent *dent;
    struct tr_direct odent, empty;

    d = opendir(name);
    if (d == NULL)
        return (-1);
    tmpname = strdup(TMP_PLATE);
    i = mkstemp(tmpname);
    if (i == -1) {
        (void) fprintf(stderr, "Apout - open_dir couldn't open %s\n",
                       tmpname);
        exit(EXIT_FAILURE);
    }
    unlink(tmpname);
    free(tmpname);

    total_left = TR_DIRBLKSIZ;
    empty.d_ino = 0;
    empty.d_namlen = 0;
    empty.d_name[0] = '\0';
    empty.d_name[1] = '\0';
    empty.d_name[2] = '\0';
    empty.d_name[3] = '\0';

    while ((dent = readdir(d)) != NULL) {
        memset(odent.d_name, 0, TR_MAXNAMLEN + 1);	/* Null name */
        nlen = strlen(dent->d_name) + 1;	/* Name length */
        if (nlen > TR_MAXNAMLEN + 1)
            nlen = TR_MAXNAMLEN + 1;
        strncpy(odent.d_name, dent->d_name, nlen);
        odent.d_ino = dent->d_fileno;
        /* Nasty hack: ensure inode */
        /* is never 0 */
        if (odent.d_ino == 0)
            odent.d_ino = 1;
        odent.d_namlen = nlen;
        nlen += (nlen & 3);	/* Round up to mult of 4 */
        odent.d_reclen = nlen + 6;	/* Name + 3 u_int16_ts */

        /* Not enough room, write */
        /* a blank entry */
        if ((total_left - odent.d_reclen) < 10) {
            empty.d_reclen = total_left;
            write(i, &empty, empty.d_reclen);
            total_left = TR_DIRBLKSIZ;
        }
        write(i, &odent, odent.d_reclen);
        total_left -= odent.d_reclen;
    }
    closedir(d);

    if (total_left) {
        empty.d_reclen = total_left;
        write(i, &empty, empty.d_reclen);
    }
    lseek(i, 0, SEEK_SET);
    return (i);
}

#ifdef NEED_MAP_FCNTL
/* Map the 2.11BSD fcntl mode bits to the underlying
 * system's bits. We have to do this for Linux
 */
static int16_t map_fcntl(int16_t f)
{
    int16_t out = 0;

    if (f & BSD_RDONLY)
        out |= O_RDONLY;
    if (f & BSD_WRONLY)
        out |= O_WRONLY;
    if (f & BSD_RDWR)
        out |= O_RDWR;
    if (f & BSD_NONBLOCK)
        out |= O_NONBLOCK;
    if (f & BSD_APPEND)
        out |= O_APPEND;
    if (f & BSD_SHLOCK)
        out |= O_SHLOCK;
    if (f & BSD_EXLOCK)
        out |= O_EXLOCK;
    if (f & BSD_ASYNC)
        out |= O_ASYNC;
    if (f & BSD_FSYNC)
        out |= O_FSYNC;
    if (f & BSD_CREAT)
        out |= O_CREAT;
    if (f & BSD_TRUNC)
        out |= O_TRUNC;
    if (f & BSD_EXCL)
        out |= O_EXCL;

    TrapDebug((dbg_file, "map_fcntl: 0x%x -> 0x%x, ", f, out));
    return (out);
}
#endif
#endif				/* EMU211 */
