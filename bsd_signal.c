/*
 * Much of this file comes from 2.11BSD's /usr/include/signal.h and is
 * Copyright (c) 1986 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 *
 *	Code to deal with 2.11BSD signals
 */
#include "defines.h"
#ifdef EMU211
#include <signal.h>
#include "bsdtrap.h"


#define NBSDSIG	32

#define	BSDSIGHUP	1	/* hangup */
#define	BSDSIGINT	2	/* interrupt */
#define	BSDSIGQUIT	3	/* quit */
#define	BSDSIGILL	4	/* illegal instruct (not reset when caught) */
#define	BSDSIGTRAP	5	/* trace trap (not reset when caught) */
#define	BSDSIGIOT	6	/* IOT instruction */
#define	BSDSIGEMT	7	/* EMT instruction */
#define	BSDSIGFPE	8	/* floating point exception */
#define	BSDSIGKILL	9	/* kill (cannot be caught or ignored) */
#define	BSDSIGBUS	10	/* bus error */
#define	BSDSIGSEGV	11	/* segmentation violation */
#define	BSDSIGSYS	12	/* bad argument to system call */
#define	BSDSIGPIPE	13	/* write on a pipe with no one to read it */
#define	BSDSIGALRM	14	/* alarm clock */
#define	BSDSIGTERM	15	/* software termination signal from kill */
#define	BSDSIGURG	16	/* urgent condition on IO channel */
#define	BSDSIGSTOP	17	/* sendable stop signal not from tty */
#define	BSDSIGTSTP	18	/* stop signal from tty */
#define	BSDSIGCONT	19	/* continue a stopped process */
#define	BSDSIGCHLD	20	/* to parent on child stop or exit */
#define	BSDSIGTTIN	21	/* to readers pgrp upon background tty read */
#define	BSDSIGTTOU	22	/* like TTIN for output if (tp->t_local&LTOSTOP) */
#define	BSDSIGIO	23	/* input/output possible signal */
#define	BSDSIGXCPU	24	/* exceeded CPU time limit */
#define	BSDSIGXFSZ	25	/* exceeded file size limit */
#define	BSDSIGVTALRM	26	/* virtual time alarm */
#define	BSDSIGPROF	27	/* profiling time alarm */
#define BSDSIGWINCH	28	/* window size changes */
#define BSDSIGUSR1	30	/* user defined signal 1 */
#define BSDSIGUSR2	31	/* user defined signal 2 */

#define	BSDSIG_ERR	-1
#define	BSDSIG_DFL	 0
#define	BSDSIG_IGN	 1

#define BSD_ONSTACK	0x0001	/* take signal on signal stack */
#define BSD_RESTART	0x0002	/* restart system on signal return */
#define	BSD_DISABLE	0x0004	/* disable taking signals on alternate stack */
#define BSD_NOCLDSTOP	0x0008	/* do not generate SIGCHLD on child stop */


/* Translate 2.11BSD signal value to our value */

static const int bsdsig[] = {
    0, SIGHUP, SIGINT, SIGQUIT, SIGILL, SIGTRAP, SIGIOT, SIGEMT,
    SIGFPE, SIGKILL, SIGBUS, SIGSEGV, SIGSYS, SIGPIPE, SIGALRM,
    SIGTERM, SIGURG, SIGSTOP, SIGTSTP, SIGCONT, SIGCHLD, SIGTTIN,
    SIGTTOU, SIGIO, SIGXCPU, SIGXFSZ, SIGVTALRM, SIGPROF, SIGWINCH,
    0, SIGUSR1, SIGUSR2
};

int bsd_signal_number(int native)
{
    int i;
    for (i = 1; i < NBSDSIG; i++)
        if (bsdsig[i] && bsdsig[i] == native)
            return i;
    errno = EOVERFLOW;
    return -1;
}

int bsd_native_signal(int sig)
{
    if (sig == 0)
        return 0;
    if (sig < 0 || sig >= NBSDSIG || !bsdsig[sig]) {
        errno = EINVAL;
        return -1;
    }
    return bsdsig[sig];
}

static void native_mask(u_int32_t mask, sigset_t *native)
{
    int i;
    sigemptyset(native);
    for (i = 1; i < NBSDSIG; i++)
        if (bsdsig[i] && i != BSDSIGKILL && i != BSDSIGSTOP &&
            (mask & ((u_int32_t) 1 << (i - 1))))
            sigaddset(native, bsdsig[i]);
}

static u_int32_t guest_mask(const sigset_t *native)
{
    int i;
    u_int32_t mask = 0;
    for (i = 1; i < NBSDSIG; i++)
        if (bsdsig[i] && sigismember(native, bsdsig[i]) == 1)
            mask |= (u_int32_t) 1 << (i - 1);
    return mask;
}

/* Exec preserves ignored dispositions and the process signal mask. */
int bsd_signal_exec(void)
{
    struct sigaction action;
    int i;
    for (i = 1; i < NBSDSIG; i++) {
        if (!bsdsig[i] || i == BSDSIGKILL || i == BSDSIGSTOP)
            continue;
        if (sigaction(bsdsig[i], NULL, &action) == -1)
            return -1;
        if (action.sa_handler != SIG_DFL && action.sa_handler != SIG_IGN) {
            memset(&action, 0, sizeof(action));
            sigemptyset(&action.sa_mask);
            action.sa_handler = SIG_DFL;
            if (sigaction(bsdsig[i], &action, NULL) == -1)
                return -1;
        }
    }
    return 0;
}

int do_sigaction(int sig, int a, int oa)
{
    struct sigaction action, old;
    u_int16_t handler = 0, flags = 0;
    int native = bsd_native_signal(sig);

    if (native <= 0 || (a && (sig == BSDSIGKILL || sig == BSDSIGSTOP))) {
        errno = EINVAL;
        return -1;
    }
    if ((a && !valid_dspace_range(a, 8)) ||
        (oa && !valid_dspace_range(oa, 8)))
        return -1;
    if (sig == BSDSIGKILL || sig == BSDSIGSTOP) {
        const u_int16_t uncatchable[4] = {BSDSIG_DFL, 0, 0, BSD_RESTART};
        if (oa)
            memcpy(&dspace[oa], uncatchable, sizeof(uncatchable));
        return 0;
    }
    memset(&action, 0, sizeof(action));
    if (a) {
        memcpy(&handler, &dspace[a], 2);
        memcpy(&flags, &dspace[a + 6], 2);
        if (flags & ~(BSD_ONSTACK | BSD_RESTART | BSD_DISABLE | BSD_NOCLDSTOP)) {
            errno = EINVAL;
            return -1;
        }
        /* Native SIGCHLD ignore can auto-reap; BSD still permits wait4. */
        if (handler > BSDSIG_IGN || (sig == BSDSIGCHLD && handler == BSDSIG_IGN)) {
            errno = ENOSYS;
            return -1;
        }
        action.sa_handler = handler == BSDSIG_IGN ? SIG_IGN : SIG_DFL;
        native_mask((u_int32_t) bsd_load_long(a + 2), &action.sa_mask);
        if (flags & BSD_ONSTACK)
            action.sa_flags |= SA_ONSTACK;
        if (flags & BSD_RESTART)
            action.sa_flags |= SA_RESTART;
        if (flags & BSD_NOCLDSTOP)
            action.sa_flags |= SA_NOCLDSTOP;
    }
    if (sigaction(native, NULL, &old) == -1)
        return -1;
    if (oa && old.sa_handler != SIG_DFL && old.sa_handler != SIG_IGN) {
        errno = ENOSYS;
        return -1;
    }
    if (a && sigaction(native, &action, NULL) == -1)
        return -1;
    if (oa) {
        handler = old.sa_handler == SIG_IGN ? BSDSIG_IGN : BSDSIG_DFL;
        flags = 0;
        if (old.sa_flags & SA_ONSTACK)
            flags |= BSD_ONSTACK;
        if (old.sa_flags & SA_RESTART)
            flags |= BSD_RESTART;
        if (old.sa_flags & SA_NOCLDSTOP)
            flags |= BSD_NOCLDSTOP;
        memcpy(&dspace[oa], &handler, 2);
        bsd_store_long(oa + 2, guest_mask(&old.sa_mask));
        memcpy(&dspace[oa + 6], &flags, 2);
    }
    return 0;
}

int bsd_sigprocmask(int how, unsigned set, unsigned oldset)
{
    sigset_t mask, oldmask;
    int native_how = SIG_SETMASK;
    if ((set && !valid_dspace_range(set, 4)) ||
        (oldset && !valid_dspace_range(oldset, 4)))
        return -1;
    if (set) {
        switch (how) {
        case 1: native_how = SIG_BLOCK; break;
        case 2: native_how = SIG_UNBLOCK; break;
        case 3: native_how = SIG_SETMASK; break;
        default:
            errno = EINVAL;
            return -1;
        }
        native_mask((u_int32_t) bsd_load_long(set), &mask);
    }
    if (sigprocmask(native_how, set ? &mask : NULL, &oldmask) == -1)
        return -1;
    if (oldset)
        bsd_store_long(oldset, guest_mask(&oldmask));
    return 0;
}

int bsd_sigpending(unsigned set)
{
    sigset_t pending;
    if (!set) {
        errno = EINVAL;
        return -1;
    }
    if (!valid_dspace_range(set, 4) || sigpending(&pending) == -1)
        return -1;
    bsd_store_long(set, guest_mask(&pending));
    return 0;
}
#endif
