// ebpf_exporter program: page-cache hit ratio per Lucene index.
//
// Lucene's MMapDirectory reads index files via mmap; every mmap'd page access
// that faults is handled by filemap_fault. On return, VM_FAULT_MAJOR means the
// page was read from disk (a cache MISS); its absence means the page was already
// resident (a cache HIT). We count, per index, both the total number of lookups
// and the number of hits. The ratio hits/total is computed downstream in PromQL.
// We resolve the faulting file's PARENT DIRECTORY name via CO-RE (works even
// where bpftrace's struct resolution is broken) -- for files under
// indexes/<name>/, that parent name IS the index name -- and count per index.
//
// Scoping: only files matching the exact prefix /home/akarasavov/indexes/<index>/<file>
// are counted. The dentry chain is walked upwards and every path component is
// verified, ending at the filesystem root, so unrelated mmap faults on the host
// (shared libraries, look-alike paths elsewhere) are dropped in-kernel.

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define MAX_INDEXES 1024
#define INDEX_NAME_LEN 32

struct index_key_t {
    char index[INDEX_NAME_LEN];
};

// Two counters per index, kept in separate maps so each exports as its own
// ebpf_exporter counter metric (the exporter reads a map's value as one number).
// lookups = every matching filemap_fault; hits = the subset where the page was
// already cached (no VM_FAULT_MAJOR). The ratio hits/lookups is computed
// downstream in PromQL (eBPF has no float math).
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_INDEXES);
    __type(key, struct index_key_t);
    __type(value, u64);
} page_cache_lookups_per_index SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_INDEXES);
    __type(key, struct index_key_t);
    __type(value, u64);
} page_cache_hits_per_index SEC(".maps");

SEC("fexit/filemap_fault")
int BPF_PROG(filemap_fault_exit, struct vm_fault *vmf, vm_fault_t ret)
{
    // VM_FAULT_MAJOR: page was read from disk (a miss). The value comes from the
    // kernel's own enum vm_fault_reason (via vmlinux.h); bpf_core_enum_value
    // resolves it against the running kernel's BTF at load time. Unlike before,
    // we do NOT return early here -- every fault is a lookup; only the absence of
    // this flag marks a hit. The classification is applied after the path check.
    int is_hit = !(ret & bpf_core_enum_value(enum vm_fault_reason, VM_FAULT_MAJOR));

    struct dentry *parent =
        BPF_CORE_READ(vmf, vma, vm_file, f_path.dentry, d_parent);

    // Verify one path component and step up to its parent. The buffer is one
    // byte larger than the literal so a longer name (e.g. "indexes2") doesn't
    // get truncated into a false match; the compare includes the NUL.
    // Byte-by-byte loop: BPF has no memcmp, and __builtin_memcmp may lower
    // to an external memcmp call that fails to load.
#define CHECK_COMPONENT(d, literal)                                       \
    {                                                                     \
        char buf[sizeof(literal) + 1] = {};                               \
        const unsigned char *n = BPF_CORE_READ(d, d_name.name);           \
        bpf_probe_read_kernel_str(&buf, sizeof(buf), n);                  \
        for (unsigned i = 0; i < sizeof(literal); i++)                    \
            if (buf[i] != (literal)[i])                                   \
                return 0;                                                 \
        d = BPF_CORE_READ(d, d_parent);                                   \
    }

    // This needs to be edited in case you want to change the prefix.
    // Match the exact prefix /home/akarasavov/indexes/ bottom-up.
    struct dentry *d = BPF_CORE_READ(parent, d_parent);
    CHECK_COMPONENT(d, "indexes");
    CHECK_COMPONENT(d, "akarasavov");
    CHECK_COMPONENT(d, "home");
    // d must now be the filesystem root, which is its own parent.
    if (BPF_CORE_READ(d, d_parent) != d)
        return 0;

    const unsigned char *dirname = BPF_CORE_READ(parent, d_name.name);

    struct index_key_t key = {};
    bpf_probe_read_kernel_str(&key.index, sizeof(key.index), dirname);

    // Count the lookup, and the hit if it was one. Done as a small helper so the
    // two maps share identical increment-or-init logic.
#define BUMP(map)                                                         \
    {                                                                     \
        u64 *c = bpf_map_lookup_elem(&map, &key);                         \
        if (c) {                                                          \
            __sync_fetch_and_add(c, 1);                                   \
        } else {                                                          \
            u64 one = 1;                                                  \
            bpf_map_update_elem(&map, &key, &one, BPF_NOEXIST);           \
        }                                                                 \
    }

    BUMP(page_cache_lookups_per_index);
    if (is_hit)
        BUMP(page_cache_hits_per_index);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
