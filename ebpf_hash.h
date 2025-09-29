/*
 * eBPF Hash Functions
 * Contains hash function implementations for the Priority-Sketch system
 */

// Original Jenkin hash function implementation
static __always_inline u32 jenkins_hash(u32 a, u32 b, u32 c) {
    a -= b;
    a -= c;
    a ^= (c >> 13);
    b -= c;
    b -= a;
    b ^= (a << 8);
    c -= a;
    c -= b;
    c ^= (b >> 13);
    a -= b;
    a -= c;
    a ^= (c >> 12);
    b -= c;
    b -= a;
    b ^= (a << 16);
    c -= a;
    c -= b;
    c ^= (b >> 5);
    a -= b;
    a -= c;
    a ^= (c >> 3);
    b -= c;
    b -= a;
    b ^= (a << 10);
    c -= a;
    c -= b;
    c ^= (b >> 15);
    return c;
}

// Use the jenkins_hash function to create 5 unique hash function
// i is the ith hash function
// seed is the random seed value to create unique hash function
static __always_inline u32 unique_five_tuple_hash(u32 src_ip, u32 dst_ip, u16 src_port, u16 dst_port, u8 proto, u32 seed, u32 i) {
    u32 a = src_ip ^ dst_ip;
    u32 b = (src_port << 16) | dst_port;
    u32 c = proto | (seed + i) << 8;
    return jenkins_hash(a, b, c);
}

static __always_inline u32 get_hash_value(u32 src_ip, u32 dst_ip, u16 src_port, u16 dst_port, u8 proto, u32 index) {
    u32 seed = 42;
    return unique_five_tuple_hash(src_ip, dst_ip, src_port, dst_port, proto, seed, index)%SIZE;
}

static __always_inline u32 get_hash_value_lc(u32 src_ip, u32 dst_ip, u16 src_port, u16 dst_port, u8 proto, u32 index) {
    u32 seed = 42;
    return unique_five_tuple_hash(src_ip, dst_ip, src_port, dst_port, proto, seed, index)%3000;
}

static __always_inline u32 get_hash_value_cms(u32 src_ip, u32 dst_ip, u16 src_port, u16 dst_port, u8 proto, u32 index) {
    u32 seed = 42;
    return unique_five_tuple_hash(src_ip, dst_ip, src_port, dst_port, proto, seed, index)%3000;
}
