/*
 * bsd_ioctl.c - Deal with 2.11BSD ioctl system calls.
 *
 * $Revision: 1.13 $ $Date: 1999/12/27 04:38:29 $
 */
#ifdef EMU211
#include "defines.h"
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#include "bsdtrap.h"
#ifdef __linux__
#include <linux/sockios.h>	/* FIOSETOWN */
#endif

/* Structures and defines required by this file */

/* First the list of ioctls handled so far */
#define TR_FIOCLEX	0x20006601	/* 0x2 is void */
#define TR_TIOCGETP	0x40067408	/* 0x4 is a read */
#define TR_TIOCSETP	0x80067409	/* 0x8 is a write */
#define	TR_TIOCSETN	0x8006740a
#define	TR_TIOCSETC	0x80067411
#define TR_TIOCGETD	0x40027400
#define TR_TIOCSETD	0x80027401
#define TR_TIOCGETC	0x40067412
#define TR_TIOCGLTC	0x40067474
#define TR_TIOCSLTC	0x80067475
#define TR_TIOCGWINSZ	0x40087468
#define TR_TIOCSWINSZ	0x80087467
#define TR_FIOSETOWN	0x8002667b
#define TR_TIOCMGET	0x4002746a
#define TR_TIOCGPGRP	0x40027477
#define TR_TIOCSPGRP	0x80027476

/* sgtty structure */
struct tr_sgttyb {
    int8_t sg_ispeed;		/* input speed */
    int8_t sg_ospeed;		/* output speed */
    int8_t sg_erase;		/* erase character */
    int8_t sg_kill;		/* kill character */
    int16_t sg_flags;		/* mode flags */
};

struct tr_tchars {
    int8_t t_intrc;		/* interrupt */
    int8_t t_quitc;		/* quit */
    int8_t t_startc;		/* start output */
    int8_t t_stopc;		/* stop output */
    int8_t t_eofc;		/* end-of-file */
    int8_t t_brkc;		/* input delimiter (like nl) */
};

struct tr_ltchars {
    int8_t t_suspc;		/* stop process signal */
    int8_t t_dsuspc;		/* delayed stop process signal */
    int8_t t_rprntc;		/* reprint line */
    int8_t t_flushc;		/* flush output (toggles) */
    int8_t t_werasc;		/* word erase */
    int8_t t_lnextc;		/* literal next character */
};

/*
 * Values for sg_flags
 */
#define      TR_TANDEM          0x00000001	/* send stopc on out q full */
#define      TR_CBREAK          0x00000002	/* half-cooked mode */
/* 0x4 (old LCASE) */
#define      TR_ECHO            0x00000008	/* echo input */
#define      TR_CRMOD           0x00000010	/* map \r to \r\n on output */
#define      TR_RAW             0x00000020	/* no i/o processing */
#define      TR_ODDP            0x00000040	/* get/send odd parity */
#define      TR_EVENP           0x00000080	/* get/send even parity */
#define      TR_ANYP            0x000000c0	/* get any parity/send none */
/* 0x100 (old NLDELAY) */
/* 0x200 */
#define      TR_XTABS           0x00000400	/* expand tabs on output */

/* Values for sg_ispeed and sg_ospeed */
#define TR_B0      0
#define TR_B50     1
#define TR_B75     2
#define TR_B110    3
#define TR_B134    4
#define TR_B150    5
#define TR_B200    6
#define TR_B300    7
#define TR_B600    8
#define TR_B1200   9
#define TR_B1800   10
#define TR_B2400   11
#define TR_B4800   12
#define TR_B9600   13
#define TR_EXTA    14
#define TR_EXTB    15



/* Variables, functions and the actual code of this file */

extern arglist *A;		/* Pointer to various arguments on stack */

/* Forward prototypes */
#ifdef __STDC__
#define P(s) s
#else
#define P(s) ()
#endif

static int trap_gettermios(u_int16_t fd, u_int32_t type, u_int16_t ucnt);
static int trap_settermios(u_int16_t fd, u_int32_t type, u_int16_t ucnt);

#undef P

int trap_ioctl()
{
    int i, val;
    u_int32_t larg1;
    size_t buffer_size = 0;
#ifdef DEBUG
    u_int8_t size = 0, letter, value;
#endif
    int16_t guest_value;
    u_int16_t dimensions[4];
    struct winsize window;

    larg1 = ((u_int32_t) uarg2 << 16) | uarg3;

    switch (larg1) {
    case TR_TIOCGETP:
    case TR_TIOCGETC:
    case TR_TIOCGLTC:
    case TR_TIOCSETP:
    case TR_TIOCSETN:
    case TR_TIOCSETC:
    case TR_TIOCSLTC:
        buffer_size = 6;
        break;
    case TR_TIOCGETD:
    case TR_TIOCSETD:
    case TR_TIOCGPGRP:
    case TR_TIOCSPGRP:
    case TR_FIOSETOWN:
    case TR_TIOCMGET:
        buffer_size = 2;
        break;
    case TR_TIOCGWINSZ:
    case TR_TIOCSWINSZ:
        buffer_size = 8;
        break;
    }
    if (buffer_size && !valid_dspace_range(uarg4, buffer_size))
        return -1;

#ifdef DEBUG
    if (trap_debug) {
        fprintf(dbg_file, "val %d ", uarg1);
        switch (larg1) {
        case TR_FIOCLEX:
            fprintf(dbg_file, "FIOCLEX ");
            break;
        case TR_TIOCGETP:
            fprintf(dbg_file, "TIOCGETP ");
            break;
        case TR_TIOCSETP:
            fprintf(dbg_file, "TIOCSETP ");
            break;
        case TR_TIOCSETN:
            fprintf(dbg_file, "TIOCSETN ");
            break;
        case TR_TIOCSETC:
            fprintf(dbg_file, "TIOCSETC ");
            break;
        case TR_TIOCGETD:
            fprintf(dbg_file, "TIOCGETD ");
            break;
        case TR_TIOCSETD:
            fprintf(dbg_file, "TIOCSETD ");
            break;
        case TR_TIOCGETC:
            fprintf(dbg_file, "TIOCGETC ");
            break;
        case TR_TIOCGLTC:
            fprintf(dbg_file, "TIOCGLTC ");
            break;
        case TR_TIOCSLTC:
            fprintf(dbg_file, "TIOCSLTC ");
            break;
        case TR_TIOCGWINSZ:
            fprintf(dbg_file, "TIOCGWINSZ ");
            break;
        case TR_TIOCSWINSZ:
            fprintf(dbg_file, "TIOCSWINSZ ");
            break;
        case TR_FIOSETOWN:
            fprintf(dbg_file, "FIOSETOWN ");
            break;
        case TR_TIOCMGET:
            fprintf(dbg_file, "TIOCMGET ");
            break;
        case TR_TIOCGPGRP:
            fprintf(dbg_file, "TIOCGPGRP ");
            break;
        case TR_TIOCSPGRP:
            fprintf(dbg_file, "TIOCSPGRP ");
            break;
        default:
            fprintf(dbg_file, "0x%lx ", (unsigned long) larg1);

            value = larg1 & 0xff;
            letter = (larg1 >> 8) & 0xff;
            size = (larg1 >> 16) & 0xff;

            fprintf(dbg_file, "('%c' ", letter);
            fprintf(dbg_file, "size %d ", size);
            fprintf(dbg_file, "val %d) ", value);
        }
        if (size)
            fprintf(dbg_file, "ptr %d ", uarg4);
    }
#endif

    switch (larg1) {

    case TR_TIOCGETP:
    case TR_TIOCGETC:
    case TR_TIOCGLTC:
        i = trap_gettermios(uarg1, larg1, uarg4);
        break;

    case TR_TIOCSETP:
    case TR_TIOCSETN:
    case TR_TIOCSETC:
    case TR_TIOCSLTC:
        i = trap_settermios(uarg1, larg1, uarg4);
        break;

    case TR_FIOCLEX:
        i = ioctl(uarg1, FIOCLEX, NULL);
        break;
    case TR_TIOCGETD:
        i = ioctl(uarg1, TIOCGETD, &val);
        goto store_value;
    case TR_TIOCGPGRP:
        i = ioctl(uarg1, TIOCGPGRP, &val);
        goto store_value;
    case TR_TIOCMGET:
        i = ioctl(uarg1, TIOCMGET, &val);
store_value:
        if (i == 0) {
            guest_value = val;
            memcpy(&dspace[uarg4], &guest_value, 2);
        }
        break;
    case TR_TIOCSPGRP:
    case TR_TIOCSETD:
    case TR_FIOSETOWN:
        memcpy(&guest_value, &dspace[uarg4], 2);
        val = guest_value;
        i = ioctl(uarg1, larg1 == TR_TIOCSPGRP ? TIOCSPGRP :
                  larg1 == TR_TIOCSETD ? TIOCSETD : FIOSETOWN, &val);
        break;

    case TR_TIOCGWINSZ:
        memset(&window, 0, sizeof(window));
        i = ioctl(uarg1, TIOCGWINSZ, &window);
        if (i == 0) {
            dimensions[0] = window.ws_row;
            dimensions[1] = window.ws_col;
            dimensions[2] = window.ws_xpixel;
            dimensions[3] = window.ws_ypixel;
            memcpy(&dspace[uarg4], dimensions, sizeof(dimensions));
        }
        break;
    case TR_TIOCSWINSZ:
        memcpy(dimensions, &dspace[uarg4], sizeof(dimensions));
        memset(&window, 0, sizeof(window));
        window.ws_row = dimensions[0];
        window.ws_col = dimensions[1];
        window.ws_xpixel = dimensions[2];
        window.ws_ypixel = dimensions[3];
        i = ioctl(uarg1, TIOCSWINSZ, &window);
        break;

    default:
        errno = ENOTTY;
        i = -1;
    }
    return (i);
}


static int8_t guest_character(cc_t value)
{
    return value == _POSIX_VDISABLE ? -1 : (int8_t) value;
}

static cc_t native_character(int8_t value)
{
    return (u_int8_t) value == 0xff ? _POSIX_VDISABLE : (u_int8_t) value;
}

static const speed_t terminal_speeds[] = {
    B0, B50, B75, B110, B134, B150, B200, B300,
    B600, B1200, B1800, B2400, B4800, B9600, B19200, B38400
};

static int sgtty_speed(speed_t speed)
{
    unsigned i;
    for (i = 0; i < sizeof(terminal_speeds) / sizeof(terminal_speeds[0]); i++)
        if (terminal_speeds[i] == speed)
            return i;
    errno = EOVERFLOW;
    return -1;
}

/* Convert from termios to old sgttyb structure */
static int to_sgttyb(struct tr_sgttyb *sgtb, struct termios *tios)
{
    int input = sgtty_speed(cfgetispeed(tios));
    int output = sgtty_speed(cfgetospeed(tios));
    if (input == -1 || output == -1)
        return -1;
    sgtb->sg_ispeed = input;
    sgtb->sg_ospeed = output;
    sgtb->sg_erase = guest_character(tios->c_cc[VERASE]);
    sgtb->sg_kill = guest_character(tios->c_cc[VKILL]);
    sgtb->sg_flags = 0;
    if (tios->c_iflag & IXOFF)
        sgtb->sg_flags |= TR_TANDEM;
    if ((tios->c_oflag & OXTABS) == OXTABS)
        sgtb->sg_flags |= TR_XTABS;
    if (tios->c_cflag & PARENB) {
        if (tios->c_cflag & PARODD)
            sgtb->sg_flags |= TR_ODDP;
        else
            sgtb->sg_flags |= TR_EVENP;
    } else
        sgtb->sg_flags |= TR_ANYP;
    if (tios->c_oflag & ONLCR)
        sgtb->sg_flags |= TR_CRMOD;
    if (tios->c_lflag & ECHO)
        sgtb->sg_flags |= TR_ECHO;
    if (!(tios->c_lflag & ICANON)) {
        if (!(tios->c_lflag & ISIG) && !(tios->c_oflag & OPOST))
            sgtb->sg_flags |= TR_RAW;
        else
            sgtb->sg_flags |= TR_CBREAK;
    }
    return 0;
}

/* Convert from old sgttyb to termios structure */
static int to_termios(struct tr_sgttyb *sgtb, struct termios *tios)
{
    unsigned input = (u_int8_t) sgtb->sg_ispeed;
    unsigned output = (u_int8_t) sgtb->sg_ospeed;
    unsigned parity = sgtb->sg_flags & TR_ANYP;

    TrapDebug((dbg_file, "\n\tto_termios: sgtty flags are 0x%x ",
               sgtb->sg_flags));

    if (input >= sizeof(terminal_speeds) / sizeof(terminal_speeds[0]) ||
        output >= sizeof(terminal_speeds) / sizeof(terminal_speeds[0])) {
        errno = EINVAL;
        return -1;
    }
    if (cfsetospeed(tios, terminal_speeds[output]) == -1 ||
        cfsetispeed(tios, terminal_speeds[input]) == -1)
        return -1;
    tios->c_cc[VERASE] = native_character(sgtb->sg_erase);
    tios->c_cc[VKILL] = native_character(sgtb->sg_kill);

    tios->c_iflag &= ~(IXOFF | ICRNL | INPCK | ISTRIP);
    tios->c_iflag |= BRKINT | IXON;
    tios->c_oflag &= ~(OXTABS | ONLCR);
    tios->c_oflag |= OPOST;
    tios->c_cflag &= ~(CSIZE | PARENB | PARODD);
    tios->c_cflag |= CS8;
    tios->c_lflag &= ~ECHO;
    tios->c_lflag |= ICANON | ISIG | IEXTEN;

    if (sgtb->sg_flags & TR_TANDEM)
        tios->c_iflag |= IXOFF;
    if (sgtb->sg_flags & TR_XTABS)
        tios->c_oflag |= OXTABS;
    if (parity == TR_ODDP || parity == TR_EVENP) {
        tios->c_cflag &= ~CSIZE;
        tios->c_cflag |= CS7;
        tios->c_cflag |= PARENB;
        tios->c_iflag |= INPCK | ISTRIP;
        if (parity == TR_ODDP)
            tios->c_cflag |= PARODD;
    }
    if (sgtb->sg_flags & TR_CRMOD) {
        tios->c_oflag |= ONLCR;
        tios->c_iflag |= ICRNL;
    }
    if (sgtb->sg_flags & TR_ECHO)
        tios->c_lflag |= ECHO;

    if (sgtb->sg_flags & TR_RAW) {
        tios->c_lflag &= ~(ICANON | IEXTEN | ISIG);
        tios->c_iflag &= ~(IGNBRK | BRKINT | PARMRK | INLCR | IGNCR |
                           ICRNL | INPCK | ISTRIP | IXON);
        tios->c_cflag &= ~(CSIZE | PARENB);
        tios->c_cflag |= CS8;
        tios->c_oflag &= ~(OPOST);
        tios->c_cc[VMIN] = 1;
        tios->c_cc[VTIME] = 0;
    }

    else if (sgtb->sg_flags & TR_CBREAK) {
        tios->c_lflag &= ~ICANON;
        tios->c_cc[VMIN] = 1;
        tios->c_cc[VTIME] = 0;
    }
    TrapDebug((dbg_file, "\n\tto_termios: iflag is 0x%x",
               (int) tios->c_iflag));
    TrapDebug((dbg_file, "\n\tto_termios: oflag is 0x%x",
               (int) tios->c_oflag));
    TrapDebug((dbg_file, "\n\tto_termios: lflag is 0x%x ",
               (int) tios->c_lflag));
    return 0;
}

/* Convert from termios to old [l]tchars structures */
static void to_tchars(struct tr_tchars *tc, struct tr_ltchars *ltc,
                      struct termios *tios)
{
    if (tc) {
        tc->t_intrc = guest_character(tios->c_cc[VINTR]);
        tc->t_quitc = guest_character(tios->c_cc[VQUIT]);
        tc->t_startc = guest_character(tios->c_cc[VSTART]);
        tc->t_stopc = guest_character(tios->c_cc[VSTOP]);
        tc->t_eofc = guest_character(tios->c_cc[VEOF]);
        tc->t_brkc = guest_character(tios->c_cc[VEOL]);
    }
    if (ltc) {
        ltc->t_suspc = guest_character(tios->c_cc[VSUSP]);
#if VDSUSP != VSUSP
        ltc->t_dsuspc = guest_character(tios->c_cc[VDSUSP]);
#else
        ltc->t_dsuspc = -1;
#endif
        ltc->t_rprntc = guest_character(tios->c_cc[VREPRINT]);
        ltc->t_flushc = guest_character(tios->c_cc[VDISCARD]);
        ltc->t_werasc = guest_character(tios->c_cc[VWERASE]);
        ltc->t_lnextc = guest_character(tios->c_cc[VLNEXT]);
    }
}

/* Convert from old [l]tchars to termios structures */
static void tc_to_tchars(struct tr_tchars *tc, struct tr_ltchars *ltc,
                         struct termios *tios)
{
    if (tc) {
        tios->c_cc[VINTR] = native_character(tc->t_intrc);
        tios->c_cc[VQUIT] = native_character(tc->t_quitc);
        tios->c_cc[VSTART] = native_character(tc->t_startc);
        tios->c_cc[VSTOP] = native_character(tc->t_stopc);
        tios->c_cc[VEOF] = native_character(tc->t_eofc);
        tios->c_cc[VEOL] = native_character(tc->t_brkc);
    }
    if (ltc) {
        tios->c_cc[VSUSP] = native_character(ltc->t_suspc);
#if VDSUSP != VSUSP
        tios->c_cc[VDSUSP] = native_character(ltc->t_dsuspc);
#endif
        tios->c_cc[VREPRINT] = native_character(ltc->t_rprntc);
        tios->c_cc[VDISCARD] = native_character(ltc->t_flushc);
        tios->c_cc[VWERASE] = native_character(ltc->t_werasc);
        tios->c_cc[VLNEXT] = native_character(ltc->t_lnextc);
    }
}

/* Handle most get ioctls that deal with termios stuff */
static int trap_gettermios(u_int16_t fd, u_int32_t type, u_int16_t ucnt)
{
    struct termios tios;
    union {
        struct tr_sgttyb sg;
        struct tr_tchars tc;
        struct tr_ltchars ltc;
    } value;
    int i;

    if (!valid_dspace_range(ucnt, 6))
        return -1;
    i = tcgetattr(fd, &tios);
    if (i == -1)
        return i;
    memset(&value, 0, sizeof(value));

    switch (type) {
    case TR_TIOCGETP:
        if (to_sgttyb(&value.sg, &tios) == -1)
            return -1;
        break;
    case TR_TIOCGETC:
        to_tchars(&value.tc, NULL, &tios);
        break;
    case TR_TIOCGLTC:
        to_tchars(NULL, &value.ltc, &tios);
        break;
    default:
        errno = EINVAL;
        return -1;
    }
    memcpy(&dspace[ucnt], &value, 6);
    return 0;
}

/* Handle most set ioctls that deal with termios stuff */
static int trap_settermios(u_int16_t fd, u_int32_t type, u_int16_t ucnt)
{
    struct termios tios;
    union {
        struct tr_sgttyb sg;
        struct tr_tchars tc;
        struct tr_ltchars ltc;
    } value;
    int i;

    if (!valid_dspace_range(ucnt, 6))
        return -1;
    memcpy(&value, &dspace[ucnt], 6);
    i = tcgetattr(fd, &tios);
    if (i == -1)
        return i;
    switch (type) {
    case TR_TIOCSETP:
    case TR_TIOCSETN:
        i = (type == TR_TIOCSETP || (value.sg.sg_flags & TR_RAW) ||
             (!(tios.c_lflag & (ICANON | ISIG)) && !(tios.c_oflag & OPOST))) ?
            TCSAFLUSH : TCSANOW;
        if (to_termios(&value.sg, &tios) == -1)
            return -1;
        i = tcsetattr(fd, i, &tios);
        return (i);
    case TR_TIOCSETC:
        tc_to_tchars(&value.tc, NULL, &tios);
        i = tcsetattr(fd, TCSANOW, &tios);
        return (i);
    case TR_TIOCSLTC:
#if VDSUSP == VSUSP
        if ((u_int8_t) value.ltc.t_dsuspc != 0xff) {
            errno = ENOSYS;
            return -1;
        }
#endif
        tc_to_tchars(NULL, &value.ltc, &tios);
        i = tcsetattr(fd, TCSANOW, &tios);
        return (i);
    }
    errno = EINVAL;
    return -1;
}
#endif				/* EMU211 */
