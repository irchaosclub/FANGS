// SPDX-License-Identifier: GPL-2.0
// FANGS sensor smoke test — two tracepoints (openat + execve).
//
// All events begin with `struct fangs_event_header`. Userspace peeks `header.type`
// to dispatch to the right decoder.
//
// Filtering rules per event type:
//   openat (file events):  CGMAP gate  +  path_filter LPM_TRIE allowlist
//   execve (process exec): CGMAP gate only — execs are rare + high signal,
//                          ALWAYS emitted regardless of path
//
// Notes:
//   * argv capture: first 8 args, each up to 64 B. Tail args truncated.
//   * ancestry: 5 levels deep via task->real_parent. Loop is fully unrolled —
//     BPF verifier on 5.15 is happier with that than trusting bounded-loop
//     inference for pointer chains.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define COMM_LEN              16
#define PATH_LEN              256
#define RUN_ID_LEN            16
#define ARGV_NUM              8
#define ARGV_LEN              64
#define ANCESTORS_DEPTH       5
#define MAX_WATCHED_CGROUPS   256
#define MAX_WATCHED_PATHS     1024

// Event type discriminator. Mirrored in internal/shared/proto/events.go.
#define EVENT_TYPE_FILE_ACCESS  1
#define EVENT_TYPE_EXEC         2
#define EVENT_TYPE_NET_CONNECT  3
#define EVENT_TYPE_DNS_QUERY    4
#define EVENT_TYPE_TLS_SNI      5

// TLS SNI mechanism — which probe captured this event. Lets userspace dedup
// across the three TLS capture sources.
#define TLS_SOURCE_LIBSSL          1   // uprobe SSL_ctrl in libssl.so
#define TLS_SOURCE_NODE_INTERNAL   2   // uprobe in Node binary's bundled TLS (future)
#define TLS_SOURCE_TCP_CLIENTHELLO 3   // kprobe parses ClientHello bytes (future)

// OpenSSL command codes (from openssl/ssl.h — stable across 1.1 and 3.x).
#define SSL_CTRL_SET_TLSEXT_HOSTNAME 55

// SNI string max captured length. RFC 6066 caps server_name at 255 bytes;
// we keep 256 for the NUL terminator.
#define SNI_MAX_LEN 256

// Address-family constants (kernel uapi values; not in vmlinux.h as macros).
#define AF_INET   2
#define AF_INET6 10

// NetConnect source discriminator — mirrored in proto.NetSource*. Lets
// userspace dedup the syscall-path (tracepoint+kprobe) without dropping
// io_uring connects (kprobe-only).
#define NET_SOURCE_SYSCALL 1
#define NET_SOURCE_KPROBE  2

// DNS port (UDP/53). Stored in host byte order after bpf_ntohs.
#define DNS_PORT 53

// Max DNS payload bytes captured. Typical DNS query < 100 B; 200 leaves margin
// without bloating the event past necessity.
#define DNS_CAPTURE_LEN 200

// Tags bitfield. Mirrored.
#define EVENT_TAG_INTERESTING   (1 << 0)
#define EVENT_TAG_CRED_ACCESS   (1 << 1)

// ---- common header -------------------------------------------------------
// 72 bytes. Sits at the start of every event.
struct fangs_event_header {
    __u64 ts_ns;
    __u64 cgroup_id;
    __u8  run_id[RUN_ID_LEN];
    __u32 pid;
    __u32 tid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char  comm[COMM_LEN];
    __u8  type;       // EVENT_TYPE_*
    __u8  tags;       // EVENT_TAG_*
    __u8  _pad[2];
};

// ---- CGMAP — watched-cgroup multiplexing ---------------------------------
struct cgmap_value {
    __u8  run_id[RUN_ID_LEN];
    __u32 flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_WATCHED_CGROUPS);
    __type(key, __u64);
    __type(value, struct cgmap_value);
} cgmap SEC(".maps");

// ---- path_filter — watched-prefix allowlist for file events --------------
struct path_filter_key {
    __u32 prefix_len_bits;
    char  path[PATH_LEN];
};

#define PATH_ACTION_KEEP             1
#define PATH_ACTION_KEEP_CRED_TAGGED 2

struct path_filter_action {
    __u8 action;
    __u8 _pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_WATCHED_PATHS);
    __type(key, struct path_filter_key);
    __type(value, struct path_filter_action);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} path_filter SEC(".maps");

// ---- ringbuf -------------------------------------------------------------
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024);
} events SEC(".maps");

// ---- drops counter -------------------------------------------------------
// Per-CPU u64 incremented whenever bpf_ringbuf_reserve() returns NULL (i.e.
// the ringbuf is full and an event was dropped at probe time). Userspace sums
// across CPUs at shutdown (and could poll periodically) to surface dropped
// counts — otherwise overflows are invisible and silently corrupt the dataset.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drops_counter SEC(".maps");

static __always_inline void bump_drops(void) {
    __u32 zero = 0;
    __u64 *cnt = bpf_map_lookup_elem(&drops_counter, &zero);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
}

// Diagnostic: records cgroup_ids that openat fired from but didn't
// match cgmap. Used to debug "missing events" cases where we expected
// a process to be in our watched cgroup but bpf_get_current_cgroup_id
// reports something else.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u64);
} cgmap_misses SEC(".maps");

static __always_inline void record_miss(__u64 cgid) {
    __u64 *cnt = bpf_map_lookup_elem(&cgmap_misses, &cgid);
    if (cnt) {
        __sync_fetch_and_add(cnt, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&cgmap_misses, &cgid, &one, BPF_ANY);
    }
}

// ---- openat event payload ------------------------------------------------
struct openat_event {
    struct fangs_event_header h;
    __s32 dfd;
    __s32 flags;
    __u16 path_len;
    __u8  truncated;
    __u8  _pad;
    char  path[PATH_LEN];
};

// ---- exec event payload --------------------------------------------------
struct ancestor {
    __u32 pid;
    __u32 ppid;
    char  comm[COMM_LEN];
};

struct exec_event {
    struct fangs_event_header h;
    __u8  argc;
    __u8  _pad[3];
    __u8  argv_lens[ARGV_NUM];          // per-arg captured length (excl NUL)
    char  argv[ARGV_NUM * ARGV_LEN];    // packed 8 × 64 B slots
    char  binary_path[PATH_LEN];        // ctx->args[0] (the filename arg)
    struct ancestor ancestors[ANCESTORS_DEPTH];
};

// ---- net connect event ---------------------------------------------------
struct net_connect_event {
    struct fangs_event_header h;
    __u8  family;            // AF_INET=2, AF_INET6=10
    __u8  source;            // NET_SOURCE_SYSCALL=1, NET_SOURCE_KPROBE=2
    __u16 dest_port;         // host byte order
    __u32 sockfd;
    __u8  dest_addr[16];     // IPv4 uses lower 4 bytes; IPv6 uses all 16
};

// ---- tls sni event -------------------------------------------------------
// `source` tells userspace where the SNI came from:
//   - LIBSSL:          we hooked the application's SSL_ctrl call directly.
//                      sni[] is populated; raw_payload[] is empty.
//   - TCP_CLIENTHELLO: we caught the ClientHello bytes on the way out via the
//                      sendto syscall. sni[] is empty; userspace parses the
//                      SNI extension from raw_payload[0..raw_payload_len].
#define TLS_RAW_CAPTURE 512

struct tls_sni_event {
    struct fangs_event_header h;
    __u8  source;                  // TLS_SOURCE_*
    __u8  _pad[1];
    __u16 sni_len;                 // bytes in sni[] (excl NUL); 0 for TCP source
    __u16 raw_payload_len;         // bytes in raw_payload[]; 0 for libssl source
    __u8  _pad2[2];
    char  sni[SNI_MAX_LEN];
    __u8  raw_payload[TLS_RAW_CAPTURE];
};

// ---- dns query event -----------------------------------------------------
// Captures the raw DNS query bytes; userspace parses the question section
// (label-prefix-encoded name). Keeping parsing out of BPF avoids a verifier
// nightmare with the recursive-looking label walk.
struct dns_query_event {
    struct fangs_event_header h;
    __u8  family;
    __u8  _pad[1];
    __u16 dest_port;         // host byte order; should always == DNS_PORT
    __u16 query_len;         // bytes actually captured into query[]
    __u8  _pad2[2];
    __u8  dest_addr[16];
    __u8  query[DNS_CAPTURE_LEN];
};

// ---- tracepoint context (generic sys_enter) ------------------------------
struct trace_event_raw_sys_enter_ctx {
    __u64 unused;
    long  syscall_nr;
    long  args[6];
};

// lookup_cgroup checks whether the current task is in (or descended
// from) a watched cgroup. Returns the matching cgmap_value plus the
// EFFECTIVE cgroup_id we matched on, or NULL if no ancestor matches.
//
// This handles the case where Docker (or another runtime) places
// container processes in a SUBCGROUP of the one we registered — common
// with systemd-cgroup driver, hybrid v1+v2 setups, and runtimes that
// create per-process scopes (init.scope, user.scope, etc).
//
// Walks up to 8 ancestor levels (Docker hierarchies are typically <=4
// deep). bpf_get_current_ancestor_cgroup_id(level) returns the ancestor
// at absolute depth `level` from root; we iterate from root downward,
// remembering the deepest match (longest match wins, like LPM).
static __always_inline struct cgmap_value *lookup_cgroup(__u64 *matched_cgid) {
    __u64 cgid = bpf_get_current_cgroup_id();
    struct cgmap_value *cgv = bpf_map_lookup_elem(&cgmap, &cgid);
    if (cgv) {
        *matched_cgid = cgid;
        return cgv;
    }
    // Walk ancestor levels 1..8 looking for a registered ancestor.
    // Deepest match wins (most specific).
    struct cgmap_value *best = NULL;
    __u64 best_cgid = 0;
#pragma unroll
    for (int level = 1; level <= 8; level++) {
        __u64 ancid = bpf_get_current_ancestor_cgroup_id(level);
        if (ancid == 0)
            continue;
        struct cgmap_value *v = bpf_map_lookup_elem(&cgmap, &ancid);
        if (v) {
            best = v;
            best_cgid = ancid;
        }
    }
    if (best) {
        *matched_cgid = best_cgid;
    } else {
        // Record the miss for diagnostic — only the LEAF cgroup_id, not
        // ancestors, to keep the map small.
        record_miss(cgid);
    }
    return best;
}

// fill_common writes the EventHeader fields shared by every event type.
// Static-inline so the verifier sees it as part of the calling program.
static __always_inline void fill_common(struct fangs_event_header *h, struct cgmap_value *cgv, __u64 cgid, __u8 type) {
    h->ts_ns     = bpf_ktime_get_ns();
    h->cgroup_id = cgid;
    __builtin_memcpy(h->run_id, cgv->run_id, RUN_ID_LEN);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    h->pid = pid_tgid >> 32;
    h->tid = (__u32)pid_tgid;

    __u64 uid_gid = bpf_get_current_uid_gid();
    h->uid = (__u32)uid_gid;
    h->gid = uid_gid >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    h->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_get_current_comm(&h->comm, sizeof(h->comm));

    h->type   = type;
    h->tags   = 0;
    h->_pad[0] = 0;
    h->_pad[1] = 0;
}

// ============================================================================
// openat — file access
// ============================================================================
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter_ctx *ctx) {
    __u64 cgid;
    struct cgmap_value *cgv = lookup_cgroup(&cgid);
    if (!cgv)
        return 0;

    struct openat_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bump_drops();
        return 0;
    }

    fill_common(&e->h, cgv, cgid, EVENT_TYPE_FILE_ACCESS);

    e->dfd   = (__s32)ctx->args[0];
    e->flags = (__s32)ctx->args[2];
    e->_pad  = 0;

    const char *filename = (const char *)ctx->args[1];
    long n = bpf_probe_read_user_str(&e->path, sizeof(e->path), filename);
    if (n < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    e->path_len  = (__u16)((n > 0) ? (n - 1) : 0);
    e->truncated = (n == sizeof(e->path)) ? 1 : 0;

    // path_filter LPM_TRIE — drop if no matching watched prefix.
    struct path_filter_key fk;
    fk.prefix_len_bits = PATH_LEN * 8;
    __builtin_memcpy(fk.path, e->path, PATH_LEN);
    struct path_filter_action *act = bpf_map_lookup_elem(&path_filter, &fk);
    if (!act) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    if (act->action == PATH_ACTION_KEEP_CRED_TAGGED)
        e->h.tags |= (EVENT_TAG_INTERESTING | EVENT_TAG_CRED_ACCESS);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ============================================================================
// execve — process exec
// ============================================================================
// argv capture: read first ARGV_NUM pointers from userspace argv[], deref
// each, copy up to ARGV_LEN bytes into the event. NUL terminator on argv
// (NULL pointer) stops capture early.
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter_ctx *ctx) {
    __u64 cgid;
    struct cgmap_value *cgv = lookup_cgroup(&cgid);
    if (!cgv)
        return 0;

    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bump_drops();
        return 0;
    }

    fill_common(&e->h, cgv, cgid, EVENT_TYPE_EXEC);

    // Zero the variable-content regions so unused slots are predictable.
    __builtin_memset(e->argv_lens, 0, sizeof(e->argv_lens));
    __builtin_memset(e->argv, 0, sizeof(e->argv));
    __builtin_memset(e->binary_path, 0, sizeof(e->binary_path));
    __builtin_memset(e->ancestors, 0, sizeof(e->ancestors));
    e->argc    = 0;
    e->_pad[0] = e->_pad[1] = e->_pad[2] = 0;

    // ctx->args[0] = filename (path to exec'd binary, user pointer)
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->binary_path, sizeof(e->binary_path), filename);

    // ctx->args[1] = argv (char ** in userspace)
    const char *const *argv = (const char *const *)ctx->args[1];

    // Unrolled argv capture — 8 iterations, verifier-friendly.
#pragma unroll
    for (int i = 0; i < ARGV_NUM; i++) {
        const char *arg_ptr = NULL;
        if (bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), &argv[i]) != 0)
            break;
        if (!arg_ptr)
            break;
        long n = bpf_probe_read_user_str(&e->argv[i * ARGV_LEN], ARGV_LEN, arg_ptr);
        if (n < 0)
            break;
        e->argv_lens[i] = (__u8)((n > 0) ? (n - 1) : 0);
        e->argc++;
    }

    // 5-level ancestry chain via real_parent. Index 0 = immediate parent.
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
#pragma unroll
    for (int i = 0; i < ANCESTORS_DEPTH; i++) {
        struct task_struct *p = BPF_CORE_READ(t, real_parent);
        if (!p)
            break;
        e->ancestors[i].pid  = BPF_CORE_READ(p, tgid);
        e->ancestors[i].ppid = BPF_CORE_READ(p, real_parent, tgid);
        BPF_CORE_READ_STR_INTO(&e->ancestors[i].comm, p, comm);
        t = p;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ============================================================================
// connect — network destinations (TCP + UDP, AF_INET/AF_INET6)
// ============================================================================
// sys_enter_connect signature: connect(int sockfd, struct sockaddr *addr, socklen_t len)
//   args[0] = sockfd
//   args[1] = user-space sockaddr pointer
//   args[2] = addrlen
SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter_ctx *ctx) {
    __u64 cgid;
    struct cgmap_value *cgv = lookup_cgroup(&cgid);
    if (!cgv)
        return 0;

    void *user_addr = (void *)ctx->args[1];
    if (!user_addr)
        return 0;

    // Peek sa_family first so we can decide whether to bother with the rest.
    // AF_UNIX, AF_NETLINK, etc are noise — only AF_INET / AF_INET6 are
    // interesting for supply-chain detection.
    __u16 family = 0;
    if (bpf_probe_read_user(&family, sizeof(family), user_addr) != 0)
        return 0;
    if (family != AF_INET && family != AF_INET6)
        return 0;

    struct net_connect_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bump_drops();
        return 0;
    }

    fill_common(&e->h, cgv, cgid, EVENT_TYPE_NET_CONNECT);
    e->family = (__u8)family;
    e->source = NET_SOURCE_SYSCALL;
    e->sockfd = (__u32)ctx->args[0];
    __builtin_memset(e->dest_addr, 0, sizeof(e->dest_addr));

    if (family == AF_INET) {
        struct sockaddr_in sin;
        if (bpf_probe_read_user(&sin, sizeof(sin), user_addr) != 0) {
            bpf_ringbuf_discard(e, 0);
            return 0;
        }
        e->dest_port = bpf_ntohs(sin.sin_port);
        __builtin_memcpy(e->dest_addr, &sin.sin_addr, 4);
    } else {
        struct sockaddr_in6 sin6;
        if (bpf_probe_read_user(&sin6, sizeof(sin6), user_addr) != 0) {
            bpf_ringbuf_discard(e, 0);
            return 0;
        }
        e->dest_port = bpf_ntohs(sin6.sin6_port);
        __builtin_memcpy(e->dest_addr, &sin6.sin6_addr, 16);
    }

    // Drop port=0 connects — these are glibc getaddrinfo source-address
    // selection probes (UDP connect-then-AF_UNSPEC pattern), not real
    // network activity. Keeps the baseline clean.
    if (e->dest_port == 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ============================================================================
// sendto — DNS query capture (handles send() on connected sockets too)
// ============================================================================
// sys_enter_sendto signature:
//   sendto(int sockfd, const void *buf, size_t len, int flags,
//          const struct sockaddr *dest_addr, socklen_t addrlen)
//
// glibc's send() and write() both lower to sys_sendto with dest_addr=NULL on
// connected sockets. To catch those (the common path on modern resolvers),
// we walk task->files->fdt->fd[sockfd]->private_data->sk and read the
// destination from the kernel-side struct sock.
//
// Filter to port 53 (DNS) only. The full DNS query payload is captured raw;
// userspace parses the label-prefix-encoded name.

// dns_dest holds the resolved destination for a sendto/send call.
struct dns_dest {
    __u8  family;
    __u16 port;
    __u8  addr[16];
};

// resolve_sock_dest walks the current task's fd table to find the destination
// associated with sockfd. Returns 0 on success (port == dport from struct
// sock), -1 on any miss. Used for connect()+send() paths where the explicit
// sendto dest_addr argument is NULL.
static __always_inline int resolve_sock_dest(__u32 sockfd, struct dns_dest *out) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return -1;
    struct files_struct *files = BPF_CORE_READ(task, files);
    if (!files)
        return -1;
    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt)
        return -1;

    // Bound check: max_fds tells us how big the fd array is.
    unsigned int max_fds = BPF_CORE_READ(fdt, max_fds);
    if (sockfd >= max_fds)
        return -1;

    struct file **fdarr = BPF_CORE_READ(fdt, fd);
    if (!fdarr)
        return -1;
    struct file *file = NULL;
    if (bpf_probe_read_kernel(&file, sizeof(file), &fdarr[sockfd]) != 0)
        return -1;
    if (!file)
        return -1;

    // file->private_data on a socket fd points at the struct socket.
    struct socket *sock = BPF_CORE_READ(file, private_data);
    if (!sock)
        return -1;
    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk)
        return -1;

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6)
        return -1;

    __u16 dport_be = BPF_CORE_READ(sk, __sk_common.skc_dport);
    out->port = bpf_ntohs(dport_be);
    out->family = (__u8)family;

    __builtin_memset(out->addr, 0, sizeof(out->addr));
    if (family == AF_INET) {
        __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(out->addr, &daddr, 4);
    } else {
        struct in6_addr daddr6 = BPF_CORE_READ(sk, __sk_common.skc_v6_daddr);
        __builtin_memcpy(out->addr, &daddr6, 16);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int handle_sendto(struct trace_event_raw_sys_enter_ctx *ctx) {
    __u64 cgid;
    struct cgmap_value *cgv = lookup_cgroup(&cgid);
    if (!cgv)
        return 0;

    struct dns_dest dest = {};
    void *user_addr = (void *)ctx->args[4];

    if (user_addr) {
        // sendto(...) called with an explicit dest_addr.
        __u16 family = 0;
        if (bpf_probe_read_user(&family, sizeof(family), user_addr) != 0)
            return 0;
        if (family != AF_INET && family != AF_INET6)
            return 0;

        // sa_family at offset 0; port follows at offset 2 for both v4 and v6.
        __u16 port_be = 0;
        if (bpf_probe_read_user(&port_be, sizeof(port_be), user_addr + 2) != 0)
            return 0;
        dest.family = (__u8)family;
        dest.port = bpf_ntohs(port_be);

        if (family == AF_INET) {
            struct sockaddr_in sin;
            if (bpf_probe_read_user(&sin, sizeof(sin), user_addr) == 0)
                __builtin_memcpy(dest.addr, &sin.sin_addr, 4);
        } else {
            struct sockaddr_in6 sin6;
            if (bpf_probe_read_user(&sin6, sizeof(sin6), user_addr) == 0)
                __builtin_memcpy(dest.addr, &sin6.sin6_addr, 16);
        }
    } else {
        // send() / write() on a connected socket — dest_addr is NULL.
        // Resolve via sockfd → file → sock → dport.
        __u32 sockfd = (__u32)ctx->args[0];
        if (resolve_sock_dest(sockfd, &dest) != 0)
            return 0;
    }

    const void *buf = (const void *)ctx->args[1];
    __u32 buflen = (__u32)ctx->args[2];

    if (dest.port == DNS_PORT) {
        // DNS branch — emit a dns_query_event.
        struct dns_query_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e) {
            bump_drops();
            return 0;
        }

        fill_common(&e->h, cgv, cgid, EVENT_TYPE_DNS_QUERY);
        e->family = dest.family;
        e->_pad[0] = 0;
        e->dest_port = dest.port;
        e->_pad2[0] = e->_pad2[1] = 0;
        __builtin_memcpy(e->dest_addr, dest.addr, sizeof(e->dest_addr));
        __builtin_memset(e->query, 0, sizeof(e->query));

        __u32 cap = buflen;
        if (cap > DNS_CAPTURE_LEN)
            cap = DNS_CAPTURE_LEN;
        cap &= 0xFF;
        e->query_len = (__u16)cap;
        if (cap > 0)
            bpf_probe_read_user(e->query, cap, buf);

        bpf_ringbuf_submit(e, 0);
        return 0;
    }

    // TLS ClientHello detection (TCP source for TLS SNI capture).
    // A ClientHello starts with the TLS record header:
    //   [0] = 0x16 (ContentType: handshake)
    //   [1..2] = ProtocolVersion (0x03 0x01 = TLS 1.0, 0x03 0x03 = TLS 1.2)
    //   [3..4] = record length
    // followed by handshake header:
    //   [5] = 0x01 (HandshakeType: ClientHello)
    //
    // We require at least 6 bytes to peek the signature. If it matches,
    // capture raw bytes and let userspace parse the SNI extension.
    if (buflen < 6)
        return 0;
    __u8 sig[6];
    if (bpf_probe_read_user(sig, sizeof(sig), buf) != 0)
        return 0;
    if (sig[0] != 0x16 || sig[1] != 0x03 || sig[5] != 0x01)
        return 0;

    struct tls_sni_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bump_drops();
        return 0;
    }

    fill_common(&e->h, cgv, cgid, EVENT_TYPE_TLS_SNI);
    e->source = TLS_SOURCE_TCP_CLIENTHELLO;
    e->_pad[0] = 0;
    e->sni_len = 0;
    e->_pad2[0] = e->_pad2[1] = 0;
    __builtin_memset(e->sni, 0, sizeof(e->sni));
    __builtin_memset(e->raw_payload, 0, sizeof(e->raw_payload));

    // Capture up to TLS_RAW_CAPTURE-1 bytes; mask 0x1FF (511) is the largest
    // power-of-two-minus-one that fits inside the buffer. The earlier mistake
    // was capping at 512 then masking with 0x1FF — `512 & 511 = 0`, which
    // silently zeroed every capture. Reading 511 bytes is still plenty:
    // typical ClientHello SNI sits in the first ~200 B even with curl's
    // long cipher suite list.
    __u32 cap = buflen;
    if (cap > TLS_RAW_CAPTURE - 1)
        cap = TLS_RAW_CAPTURE - 1;
    cap &= 0x1FF;  // verifier hint: cap ≤ 511
    e->raw_payload_len = (__u16)cap;
    if (cap > 0)
        bpf_probe_read_user(e->raw_payload, cap, buf);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ============================================================================
// write — catches TLS ClientHello on TCP sockets (Node's BoringSSL path)
// ============================================================================
// sys_enter_write signature: write(int fd, const void *buf, size_t count)
//
// Modern Node bundles BoringSSL/OpenSSL statically and writes the TLS
// handshake bytes via plain write() on a TCP socket — bypassing both our
// libssl uprobe and the sendto/sendmsg paths. To catch these handshakes
// we check every write for the ClientHello record signature. The 6-byte
// signature match rejects 99.9% of non-TLS writes in a few instructions.
//
// We do NOT check that fd is a TCP socket (would require a task->files
// walk per write — expensive). The signature is specific enough that
// false positives are negligible in practice.
SEC("tracepoint/syscalls/sys_enter_write")
int handle_write(struct trace_event_raw_sys_enter_ctx *ctx) {
    __u64 cgid;
    struct cgmap_value *cgv = lookup_cgroup(&cgid);
    if (!cgv)
        return 0;

    __u64 count = ctx->args[2];
    if (count < 6)
        return 0;
    void *buf = (void *)ctx->args[1];
    if (!buf)
        return 0;

    __u8 sig[6];
    if (bpf_probe_read_user(sig, sizeof(sig), buf) != 0)
        return 0;
    // TLS record: ContentType=0x16 (handshake), ProtocolVersion=0x03 0x{01..03},
    // HandshakeType=0x01 (ClientHello).
    if (sig[0] != 0x16 || sig[1] != 0x03 || sig[5] != 0x01)
        return 0;

    struct tls_sni_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bump_drops();
        return 0;
    }

    fill_common(&e->h, cgv, cgid, EVENT_TYPE_TLS_SNI);
    e->source = TLS_SOURCE_TCP_CLIENTHELLO;
    e->_pad[0] = 0;
    e->sni_len = 0;
    e->_pad2[0] = e->_pad2[1] = 0;
    __builtin_memset(e->sni, 0, sizeof(e->sni));
    __builtin_memset(e->raw_payload, 0, sizeof(e->raw_payload));

    __u32 cap = (__u32)count;
    if (cap > TLS_RAW_CAPTURE - 1)
        cap = TLS_RAW_CAPTURE - 1;
    cap &= 0x1FF; // verifier hint: cap ≤ 511
    e->raw_payload_len = (__u16)cap;
    if (cap > 0)
        bpf_probe_read_user(e->raw_payload, cap, buf);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ============================================================================
// sendmmsg — DNS query capture for parallel resolvers (curl, glibc 2.30+)
// ============================================================================
// sys_enter_sendmmsg signature:
//   sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags)
//
// glibc 2.30+ and curl's libc-resolver use sendmmsg() to send A + AAAA queries
// in a single syscall on a connected UDP socket. msgvec is an array of
// `struct mmsghdr` (= `struct msghdr msg_hdr` + `unsigned int msg_len`, padded
// to 64 B on x86_64). msg_name is NULL because the socket is connected.
//
// We resolve the destination once via the socket-fd walk shared with the
// sendto handler, then unroll over the first 2 entries (the common A+AAAA pair).

// Userspace struct msghdr layout (uapi, x86_64). Declared explicitly rather
// than relying on vmlinux.h because the kernel-internal `struct msghdr`
// differs (iov_iter wrap).
struct user_msghdr_layout {
    void *msg_name;         // offset 0
    int   msg_namelen;      // offset 8
    int   _pad1;            // offset 12 (alignment slot)
    void *msg_iov;          // offset 16
    __u64 msg_iovlen;       // offset 24
    void *msg_control;      // offset 32
    __u64 msg_controllen;   // offset 40
    int   msg_flags;        // offset 48
    int   _pad2;            // offset 52
};

struct iovec_layout {
    void *iov_base;
    __u64 iov_len;
};

// One mmsghdr entry: 56 B msg_hdr + 4 B msg_len + 4 B padding = 64 B.
#define MMSGHDR_ENTRY_SIZE 64

// Capture-and-emit helper. Reserves a ringbuf slot, fills one DNS event
// from (dest, iov_base, iov_len), submits. Returns 0 on success, -1 if
// the ringbuf is full.
static __always_inline int emit_dns_from_iov(
    struct cgmap_value *cgv, __u64 cgid,
    struct dns_dest *dest,
    const void *iov_base, __u64 iov_len) {

    struct dns_query_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bump_drops();
        return -1;
    }

    fill_common(&e->h, cgv, cgid, EVENT_TYPE_DNS_QUERY);
    e->family = dest->family;
    e->_pad[0] = 0;
    e->dest_port = dest->port;
    e->_pad2[0] = e->_pad2[1] = 0;
    __builtin_memcpy(e->dest_addr, dest->addr, sizeof(e->dest_addr));
    __builtin_memset(e->query, 0, sizeof(e->query));

    __u32 cap = (__u32)iov_len;
    if (cap > DNS_CAPTURE_LEN)
        cap = DNS_CAPTURE_LEN;
    cap &= 0xFF;
    e->query_len = (__u16)cap;
    if (cap > 0)
        bpf_probe_read_user(e->query, cap, iov_base);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmmsg")
int handle_sendmmsg(struct trace_event_raw_sys_enter_ctx *ctx) {
    __u64 cgid;
    struct cgmap_value *cgv = lookup_cgroup(&cgid);
    if (!cgv)
        return 0;

    void *user_msgvec = (void *)ctx->args[1];
    unsigned int vlen = (unsigned int)ctx->args[2];
    if (!user_msgvec || vlen == 0)
        return 0;

    // All messages in one sendmmsg() share the socket (and thus the
    // destination on a connected UDP socket). Resolve once.
    __u32 sockfd = (__u32)ctx->args[0];
    struct dns_dest dest = {};
    if (resolve_sock_dest(sockfd, &dest) != 0)
        return 0;
    if (dest.port != DNS_PORT)
        return 0;

    // Emit one event per message, capped at 2 (glibc's A+AAAA pair). Hand-
    // unrolled — clang refuses to #pragma unroll a loop bound by a dynamic
    // `vlen`, so we just write the two iterations out.

    if (vlen >= 1) {
        struct user_msghdr_layout mh;
        if (bpf_probe_read_user(&mh, sizeof(mh), user_msgvec) == 0
            && mh.msg_iovlen >= 1 && mh.msg_iov) {
            struct iovec_layout iov;
            if (bpf_probe_read_user(&iov, sizeof(iov), mh.msg_iov) == 0
                && iov.iov_base && iov.iov_len > 0) {
                emit_dns_from_iov(cgv, cgid, &dest, iov.iov_base, iov.iov_len);
            }
        }
    }
    if (vlen >= 2) {
        struct user_msghdr_layout mh;
        if (bpf_probe_read_user(&mh, sizeof(mh),
                                user_msgvec + MMSGHDR_ENTRY_SIZE) == 0
            && mh.msg_iovlen >= 1 && mh.msg_iov) {
            struct iovec_layout iov;
            if (bpf_probe_read_user(&iov, sizeof(iov), mh.msg_iov) == 0
                && iov.iov_base && iov.iov_len > 0) {
                emit_dns_from_iov(cgv, cgid, &dest, iov.iov_base, iov.iov_len);
            }
        }
    }
    return 0;
}

// ============================================================================
// sendmsg — DNS query capture for single-message custom resolvers
// ============================================================================
// sys_enter_sendmsg signature:
//   sendmsg(int sockfd, const struct user_msghdr *msg, int flags)
//
// Rare callers (some custom DNS libraries, libresolv variants) use sendmsg()
// with a single message instead of sendmmsg(). Same shape as one iteration of
// our sendmmsg handler — reuses resolve_sock_dest + user_msghdr_layout +
// iovec_layout + emit_dns_from_iov.
SEC("tracepoint/syscalls/sys_enter_sendmsg")
int handle_sendmsg(struct trace_event_raw_sys_enter_ctx *ctx) {
    __u64 cgid;
    struct cgmap_value *cgv = lookup_cgroup(&cgid);
    if (!cgv)
        return 0;

    void *user_msghdr_ptr = (void *)ctx->args[1];
    if (!user_msghdr_ptr)
        return 0;

    __u32 sockfd = (__u32)ctx->args[0];
    struct dns_dest dest = {};
    if (resolve_sock_dest(sockfd, &dest) != 0)
        return 0;
    if (dest.port != DNS_PORT)
        return 0;

    struct user_msghdr_layout mh;
    if (bpf_probe_read_user(&mh, sizeof(mh), user_msghdr_ptr) != 0)
        return 0;
    if (mh.msg_iovlen < 1 || !mh.msg_iov)
        return 0;

    struct iovec_layout iov;
    if (bpf_probe_read_user(&iov, sizeof(iov), mh.msg_iov) != 0)
        return 0;
    if (!iov.iov_base || iov.iov_len == 0)
        return 0;

    emit_dns_from_iov(cgv, cgid, &dest, iov.iov_base, iov.iov_len);
    return 0;
}

// ============================================================================
// tcp_v4_connect / tcp_v6_connect — kprobes catching io_uring TCP connects
// ============================================================================
// IORING_OP_CONNECT bypasses sys_enter_connect entirely — io_uring submits the
// request via the sqe ring and calls __sys_connect_file() directly, never
// passing through the syscall entry tracepoint. tcp_v{4,6}_connect is the
// kernel-side function both syscall-path and io_uring-path end up calling, so
// hooking it catches every TCP connect regardless of how it was initiated.
//
// Signature:
//   int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
//   int tcp_v6_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
//
// At kprobe entry, sk->__sk_common.skc_daddr is NOT yet populated (the
// function sets it later). Read from uaddr (PARM2) instead. uaddr is kernel
// memory by this point: __sys_connect already did move_addr_to_kernel() and
// io_uring does the same via move_addr_to_kernel() in io_connect_prep.
//
// Userspace dedups (pid, family, ip:port) tuples against the sys_enter_connect
// tracepoint within a short window, so syscall-path connects don't double-count.
SEC("kprobe/tcp_v4_connect")
int handle_tcp_v4_connect(struct pt_regs *ctx) {
    __u64 cgid;
    struct cgmap_value *cgv = lookup_cgroup(&cgid);
    if (!cgv)
        return 0;

    struct sockaddr *uaddr = (struct sockaddr *)PT_REGS_PARM2(ctx);
    if (!uaddr)
        return 0;

    struct sockaddr_in sin;
    if (bpf_probe_read_kernel(&sin, sizeof(sin), uaddr) != 0)
        return 0;
    if (sin.sin_family != AF_INET)
        return 0;

    __u16 port = bpf_ntohs(sin.sin_port);
    if (port == 0)
        return 0;

    struct net_connect_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bump_drops();
        return 0;
    }

    fill_common(&e->h, cgv, cgid, EVENT_TYPE_NET_CONNECT);
    e->family    = AF_INET;
    e->source    = NET_SOURCE_KPROBE;
    e->dest_port = port;
    e->sockfd    = 0;
    __builtin_memset(e->dest_addr, 0, sizeof(e->dest_addr));
    __builtin_memcpy(e->dest_addr, &sin.sin_addr, 4);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/tcp_v6_connect")
int handle_tcp_v6_connect(struct pt_regs *ctx) {
    __u64 cgid;
    struct cgmap_value *cgv = lookup_cgroup(&cgid);
    if (!cgv)
        return 0;

    struct sockaddr *uaddr = (struct sockaddr *)PT_REGS_PARM2(ctx);
    if (!uaddr)
        return 0;

    struct sockaddr_in6 sin6;
    if (bpf_probe_read_kernel(&sin6, sizeof(sin6), uaddr) != 0)
        return 0;
    if (sin6.sin6_family != AF_INET6)
        return 0;

    __u16 port = bpf_ntohs(sin6.sin6_port);
    if (port == 0)
        return 0;

    struct net_connect_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bump_drops();
        return 0;
    }

    fill_common(&e->h, cgv, cgid, EVENT_TYPE_NET_CONNECT);
    e->family    = AF_INET6;
    e->source    = NET_SOURCE_KPROBE;
    e->dest_port = port;
    e->sockfd    = 0;
    __builtin_memset(e->dest_addr, 0, sizeof(e->dest_addr));
    __builtin_memcpy(e->dest_addr, &sin6.sin6_addr, 16);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ============================================================================
// SSL_ctrl uprobe — TLS SNI capture (mechanism 1, libssl)
// ============================================================================
// OpenSSL's SSL_set_tlsext_host_name(ssl, hostname) is a preprocessor macro
// that lowers to:
//
//   SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME=55, 0, (void *)hostname)
//
// Every OpenSSL-based client that wants SNI calls this BEFORE the TLS
// handshake — we read the hostname argument here and emit a tls_sni_event.
//
// Signature (x86_64 SysV):
//   long SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg);
//
// args via PT_REGS macros (cilium/ebpf takes care of arch-specific naming):
//   PARM1 = ssl, PARM2 = cmd, PARM3 = larg, PARM4 = parg
//
// Userspace attaches this via link.OpenExecutable + Uprobe targeting
// "SSL_ctrl" in libssl.so.{3,1.1}.
SEC("uprobe/ssl_ctrl")
int handle_ssl_ctrl(struct pt_regs *ctx) {
    int cmd = (int)PT_REGS_PARM2(ctx);
    if (cmd != SSL_CTRL_SET_TLSEXT_HOSTNAME)
        return 0;

    const char *hostname = (const char *)PT_REGS_PARM4(ctx);
    if (!hostname)
        return 0;

    __u64 cgid;
    struct cgmap_value *cgv = lookup_cgroup(&cgid);
    if (!cgv)
        return 0;

    struct tls_sni_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bump_drops();
        return 0;
    }

    fill_common(&e->h, cgv, cgid, EVENT_TYPE_TLS_SNI);
    e->source = TLS_SOURCE_LIBSSL;
    e->_pad[0] = 0;
    e->raw_payload_len = 0;
    e->_pad2[0] = e->_pad2[1] = 0;
    __builtin_memset(e->sni, 0, sizeof(e->sni));
    __builtin_memset(e->raw_payload, 0, sizeof(e->raw_payload));

    long n = bpf_probe_read_user_str(e->sni, sizeof(e->sni), hostname);
    if (n < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    e->sni_len = (__u16)((n > 0) ? (n - 1) : 0);
    if (e->sni_len == 0) {
        // Empty SNI — drop. Catches NULL+trailing-zero edge cases.
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
