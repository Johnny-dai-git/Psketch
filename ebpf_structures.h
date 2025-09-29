/*
 * eBPF Data Structures
 * Contains all structure definitions for the Priority-Sketch system
 */

// Hashing key structure
struct flow_key {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 protocol;
};

// Meta data we need for tcp
struct tcp_meta_data{
  u32 seq;
  u32 next_expected_seq;
  u64 last_timestamp;
};

// transmit tcp_meta_data
struct transmit_metadata{
  u32 flow;
};

// flow stats for priority flows
struct flow_stats_priority {
    u64 packet_count;
    u64 retrans_count;
    u32 last_seq;
    u64 negative_count;
    u64 last_timestamp;
};

// flow stats for cms
struct flow_stats_cms {
    u64 packet_count;
    u64 retrans_count;
};

// flow stats for sketch
struct flow_stats_sketch {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 protocol;
    u64 packet_count;
    u64 retrans_count;
    u32 last_seq;
    u64 negative_count;
    u64 last_timestamp;
    u32 kick;
};
