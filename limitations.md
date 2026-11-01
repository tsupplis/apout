# Limitations

Apout emulates PDP-11 Unix applications, not a complete PDP-11 machine or kernel.
This document separates remaining limitations from implemented safeguards.

## At a glance

| Area | Remaining limitation |
|---|---|
| Floating point | Host single precision is used; PDP-11 double precision and arithmetic exception delivery are not implemented. |
| Signals | Guest signal handlers are unsupported. V7 supports only default/ignored dispositions; BSD also supports masks and pending-signal queries. |
| Process IDs | No PID virtualization. Large native PIDs may be truncated and cannot reliably be passed back to process-control calls. |
| Syscall ABI | Native errno values and some flags are not fully translated to guest values. |
| Guest memory | Covered buffers and initial exec layouts are checked, but validation is not comprehensive; runtime stack growth is not checked. |
| Filesystem | Applications use the native filesystem. `APOUT_ROOT` is a pathname prefix, **not a sandbox**. |
| Host support | Big-endian hosts are unsupported. |

## Unix environment support

| Environment | Status and main limitations |
|---|---|
| V1 | Experimental; time handling and KE11A emulation remain incomplete. `GTTY`, `STTY` and `TELL` are not emulated. |
| V2 | Uses essentially the V1 environment with some syscall differences. Support is incomplete; the original implementation lacked V2 manuals. |
| V5 / V6 | Treated as V7 binaries. Historical compiler, archive and date workarounds apply; see [Known binary bugs](#known-binary-bugs). |
| V7 | Most binaries run, but signals, terminal calls and some syscalls are incomplete. V7-style `0405` overlays are not recognized. |
| 2.9BSD | Treated as V7; overlays and 2.9BSD-specific syscalls are unsupported. |
| 2.11BSD | Partial syscall translation; see the tables below. |

## V5 / V6 / V7 compatibility

| Area | Behavior / limitation |
|---|---|
| Error numbers | Native errno values are returned without full V7 translation. V7 defines only 32 error values. |
| Unimplemented syscalls | `phys`, `prof`, `ptrace`, `acct`, `mount`, `umount` and `times` return `EPERM`. |
| Ignored syscalls | `lock` and `stime` do nothing. |
| `signal` | Only `SIG_DFL` and `SIG_IGN` are supported. |
| `stty`, `gtty`, `ioctl` | Limited terminal emulation; historical V7 `stty(1)` incompatibility remains documented. |
| Filenames | Names returned to the guest are truncated to 14 characters. |
| Inodes | Native inode numbers are truncated to 16 bits. |

## 2.11BSD compatibility

### Remaining gaps

| Area | Limitation / observable behavior |
|---|---|
| Error numbers and flags | Errno values are not fully translated; some guest flags are promoted and passed directly to native syscalls. |
| Guest signal handlers | Installing a guest handler returns `ENOSYS`. |
| Signal APIs | Alternate stacks, signal return/suspension and legacy signal APIs return `ENOSYS`, not success. |
| Ignoring `SIGCHLD` | Returns `ENOSYS`: native automatic reaping would violate BSD `wait` semantics. |
| Process IDs | Large native PIDs may be truncated in process results; PID virtualization is not implemented. |
| `wait4` usage | Child overlay counts are unavailable and reported as zero. |
| `wait4` signals | An unrepresentable host signal returns `EOVERFLOW` when status is requested; the child may already have been reaped. |
| Terminal modes | Historical delay/local flags and full job-control translation remain incomplete. |
| Delayed suspend | On hosts without support, it is reported disabled; enabling it returns `ENOSYS`. |
| Socket addresses | Only Unix and IPv4 layouts are translated. Unix socket paths retain native pathname handling and length limits. |
| Socket options | `getsockopt` and `setsockopt` are not handled. |
| Other socket I/O | `recvmsg`, `sendmsg` and `sendto` are not handled. |
| Multiplexing | `select` is not handled. |

### Implemented behavior and safeguards

These are supported paths, not a claim that every syscall or buffer is validated.

| Area | Implemented behavior |
|---|---|
| Time and resource usage | Translate 32-bit guest values rather than copying host-sized fields. |
| Scalar/vector I/O | Covered buffers are bounds-checked. `socketpair` returns both descriptors. |
| Pathnames and exec vectors | Check string termination, vector bounds and root-translation capacity. |
| Initial exec stack | Accounts for strings, alignment and pointer vectors; cannot overlap loaded code/data/BSS or the V1/V2 KE11A window. Oversized stacks return `E2BIG` before guest writes; out-of-memory image layouts return `ENOEXEC`. |
| `stat` | Outputs are bounded, staged and initialized, including spare fields. |
| Resource limits | Use guest resource IDs and bounded 32-bit conversion. Native infinity or values above `0x7fffffff` report guest infinity. |
| Groups | Use bounded unsigned 16-bit IDs; unrepresentable native IDs return `EOVERFLOW`. |
| `wait4` | Checks optional outputs before waiting; translates exit/stopped/signal status. Errors and `WNOHANG` without an event preserve outputs. |
| `ioctl` | Supported buffers are bounded and staged. Canonical window/terminal requests are recognized; unknown requests return `ENOTTY`. |
| Terminal conversion | Covers RAW/CBREAK/cooked modes, parity, echo, CRMOD, TANDEM, control characters and the 16 BSD speeds. Invalid guest speeds return `EINVAL`; unrepresentable native speeds return `EOVERFLOW`, not a hangup speed. |
| Terminal input flushing | `TIOCSETP` flushes input. `TIOCSETN` preserves it except for RAW transitions. |
| Socket addresses | Unix/IPv4 headers are translated; truncated outputs report bytes copied, matching BSD. `accept` and `recvfrom` permit NULL address outputs without a length pointer. |
| `sigaction` | Supports default/ignored dispositions and bounded queries using libc's trampoline-first ABI; masks and supported flags are translated. |
| Signal masks | `sigprocmask` and `sigpending` translate bounded 32-bit guest masks. |
| Signal sending | `kill` and `killpg` translate BSD signal numbers. |
| Signals across exec | Failed exec preserves dispositions; successful exec preserves ignored dispositions and the process signal mask. |

For implementation details, consult [bsdtrap.c](bsdtrap.c),
[bsd_signal.c](bsd_signal.c) and [bsd_ioctl.c](bsd_ioctl.c).

## Known binary bugs

| Binary / environment | Problem | Workaround |
|---|---|---|
| V5 C compiler | A compiler pass appears to depend on uninitialized memory. | Build Apout with `-DZERO_MEMORY`. |
| V5 / V6 `ar(1)` | Leaves an output descriptor open; stream buffering can cause copied archives to be truncated. | Disable Apout stream buffering, or apply the close-before-read patch below. |
| V5 / V6 `ctime()` | Dates after November 1999 are displayed incorrectly. | Apout maps syscall dates in 1999 or later to 1998. |

### Historical archive workaround

Insert these instructions in `ar.s` after `sys write; magic; 2` and before
reopening/reading the temporary file:

```asm
mov     tfo,r0          / need to close before reading
sys     close
```

## Historical binary coverage

These are inherited compatibility notes, not a claim that all archived tools
are covered by the current regression suite.

| Environment / format | Historically known to work |
|---|---|
| V1 `0405`, Dennis Ritchie's `s2.tar` | `cat`, `cp`, `date`, `echo`, `ls`, `mkdir`, `sh`, `wc`. Other archived tools were not fully tested. |
| V2 `0407`, `s2.tar` | `bin/as`, `bin/cc`, `bin/ld`, `bin/size`, `bin/strip`, `etc/as2`, `usr/lib/c0`, `usr/lib/c1`. |
| V2 compiler | Can compile the `last1120c` C compiler from Dennis Ritchie's archive. |

For current regression commands and historical smoke-test coverage, see
[README.md](README.md#regression-tests).
