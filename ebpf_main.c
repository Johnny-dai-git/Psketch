/*
 * Main eBPF Program for Priority-Sketch System
 * Refactored and organized version of the original sketch.c
 */

#include "ebpf_headers.h"
#include "ebpf_structures.h"
#include "ebpf_hash.h"
#include "ebpf_helpers.h"

// BPF Maps
BPF_HASH(priority_table, struct flow_key, struct flow_stats_priority);
BPF_ARRAY(elephant_flow, struct flow_stats_sketch, SIZE);
BPF_ARRAY(linear_counter, u32, 3000);
BPF_ARRAY(cms1, struct flow_stats_cms, 3000);
BPF_ARRAY(cms2, struct flow_stats_cms, 3000);
BPF_ARRAY(cms3, struct flow_stats_cms, 3000);

// Packet processing functions
static __always_inline int process_tcp_packet(struct sk_buff *skb, struct iphdr *ip, struct flow_key *key, struct tcp_meta_data *tcpmeta) {
    struct tcphdr *tcp = (struct tcphdr *)(skb->head + 98);
    struct tcphdr tcp_copy = *tcp;
    
    if (!tcp) return 0;
    if(tcp->source == 0) return 0;
    if(tcp->dest == 0) return 0;
    
    key->src_port = __builtin_bswap16(tcp->source);
    key->dst_port = __builtin_bswap16(tcp->dest);
    key->src_ip = __builtin_bswap32(ip->saddr);
    key->dst_ip = __builtin_bswap32(ip->daddr);
    key->protocol = ip->protocol;
    
    tcpmeta->seq = __builtin_bswap32(tcp->seq);
    u16 ip_total = __builtin_bswap16(ip->tot_len);
    u8 ip_hdl = ip->ihl;
    u16 tcp_header_length = tcp_copy.doff;
    u16 data_length = ip_total - ip_hdl*4 - tcp_header_length*4;
    tcpmeta->next_expected_seq = tcpmeta->seq + data_length;
    tcpmeta->last_timestamp = bpf_ktime_get_ns();
    
    return 1;
}

static __always_inline int process_udp_packet(struct sk_buff *skb, struct iphdr *ip, struct flow_key *key) {
    struct udphdr *udp = (struct udphdr *)(skb->head + 98);
    
    if (!udp) return 0;
    if(udp->source == 0) return 0;
    if(udp->dest == 0) return 0;
    
    key->src_port = __builtin_bswap16(udp->source);
    key->dst_port = __builtin_bswap16(udp->dest);
    key->src_ip = __builtin_bswap32(ip->saddr);
    key->dst_ip = __builtin_bswap32(ip->daddr);
    key->protocol = ip->protocol;
    
    return 1;
}

static __always_inline int process_priority_flow(struct flow_key *key, struct tcp_meta_data *tcpmeta) {
    struct flow_stats_priority *stats = priority_table.lookup(key);
    if (!stats) return 0;
    
    if (key->protocol == TCP_PROTO) {
        __sync_fetch_and_add(&(stats->packet_count), 1);
        if (stats->last_seq == 0) {
            stats->last_seq = tcpmeta->next_expected_seq;
            stats->last_timestamp = tcpmeta->last_timestamp;
        } else {
            if (tcpmeta->seq < stats->last_seq) {
                if (tcpmeta->last_timestamp - stats->last_timestamp >= THRE) {
                    __sync_fetch_and_add(&(stats->retrans_count), 1);
                }
            } else {
                stats->last_seq = tcpmeta->next_expected_seq;
                stats->last_timestamp = tcpmeta->last_timestamp;
            }
        }
    } else if (key->protocol == UDP_PROTO) {
        __sync_fetch_and_add(&(stats->packet_count), 1);
    }
    
    return 1;
}

static __always_inline int process_sketch_flow(struct flow_key *key, struct tcp_meta_data *tcpmeta) {
    u32 elephant_hash_value = get_hash_value(key->src_ip, key->dst_ip, key->src_port, key->dst_port, key->protocol, 0);
    struct transmit_metadata trans = {0};
    struct flow_stats_cms cms = {0, 0};
    struct flow_stats_sketch *stats_sketch = elephant_flow.lookup(&elephant_hash_value);
    
    if (!stats_sketch) return 0;
    
    if (stats_sketch->src_ip != 0) {
        bool result_inner = same_flow(stats_sketch, *key);
        if (result_inner) {
            __sync_fetch_and_add(&(stats_sketch->packet_count), 1);
            if (tcpmeta->seq < stats_sketch->last_seq) {
                if (tcpmeta->last_timestamp - stats_sketch->last_timestamp >= THRE) {
                    __sync_fetch_and_add(&(stats_sketch->retrans_count), 1);
                }
            } else {
                stats_sketch->last_seq = tcpmeta->next_expected_seq;
                stats_sketch->last_timestamp = tcpmeta->last_timestamp;
            }
            return 1;
        } else {
            __sync_fetch_and_add(&(stats_sketch->negative_count), 1);
            if (stats_sketch->negative_count * VOTE_THRE < stats_sketch->packet_count) {
                trans.flow = 0;
            } else {
                // Kick out existing flow and insert new one
                cms.packet_count = stats_sketch->packet_count;
                cms.retrans_count = stats_sketch->retrans_count;
                
                stats_sketch->packet_count = 1;
                stats_sketch->retrans_count = 0;
                
                if (key->protocol == TCP_PROTO) {
                    memcpy(&(stats_sketch->last_seq), &(tcpmeta->next_expected_seq), sizeof(tcpmeta->next_expected_seq));
                    memcpy(&(stats_sketch->last_timestamp), &(tcpmeta->last_timestamp), sizeof(tcpmeta->last_timestamp));
                } else {
                    u32 zero = 0;
                    u64 zero_2 = 0;
                    memcpy(&(stats_sketch->last_timestamp), &(zero_2), sizeof(zero_2));
                    memcpy(&(stats_sketch->last_seq), &(zero), sizeof(zero));
                }
                
                if (stats_sketch->kick != 1) {
                    u32 kick = 1;
                    memcpy(&(stats_sketch->kick), &(kick), sizeof(kick));
                }
                
                u64 reset_negative = 0;
                memcpy(&(stats_sketch->negative_count), &(reset_negative), sizeof(reset_negative));
                
                // Update 5-tuple information
                memcpy(&(stats_sketch->src_ip), &(key->src_ip), sizeof(key->src_ip));
                memcpy(&(stats_sketch->dst_ip), &(key->dst_ip), sizeof(key->dst_ip));
                memcpy(&(stats_sketch->src_port), &(key->src_port), sizeof(key->src_port));
                memcpy(&(stats_sketch->dst_port), &(key->dst_port), sizeof(key->dst_port));
                memcpy(&(stats_sketch->protocol), &(key->protocol), sizeof(key->protocol));
                
                trans.flow = 1;
            }
        }
    } else {
        // Empty slot, fill in new flow
        stats_sketch->src_ip = key->src_ip;
        stats_sketch->dst_ip = key->dst_ip;
        stats_sketch->src_port = key->src_port;
        stats_sketch->dst_port = key->dst_port;
        stats_sketch->protocol = key->protocol;
        stats_sketch->packet_count = 1;
        stats_sketch->retrans_count = 0;
        if (key->protocol == TCP_PROTO) {
            stats_sketch->last_seq = tcpmeta->next_expected_seq;
            stats_sketch->last_timestamp = tcpmeta->last_timestamp;
        }
        return 1;
    }
    
    return 0;
}

static __always_inline void update_cms_tables(struct flow_key *key, struct flow_stats_cms *cms, struct transmit_metadata *trans) {
    // Linear counter
    u32 linear_counter_hash_value_1 = get_hash_value_lc(key->src_ip, key->dst_ip, key->src_port, key->dst_port, key->protocol, 1);
    u32 value = 1;
    linear_counter.update(&linear_counter_hash_value_1, &value);
    
    // CMS tables
    u32 cms1_hash = get_hash_value_cms(key->src_ip, key->dst_ip, key->src_port, key->dst_port, key->protocol, 2);
    u32 cms2_hash = get_hash_value_cms(key->src_ip, key->dst_ip, key->src_port, key->dst_port, key->protocol, 3);
    u32 cms3_hash = get_hash_value_cms(key->src_ip, key->dst_ip, key->src_port, key->dst_port, key->protocol, 4);
    
    struct flow_stats_cms *exist_1 = cms1.lookup(&cms1_hash);
    struct flow_stats_cms *exist_2 = cms2.lookup(&cms2_hash);
    struct flow_stats_cms *exist_3 = cms3.lookup(&cms3_hash);
    
    if (exist_1) {
        if (trans->flow == 0) {
            __sync_fetch_and_add(&(exist_1->packet_count), 1);
        } else {
            __sync_fetch_and_add(&(exist_1->packet_count), cms->packet_count);
            if (key->protocol == TCP_PROTO) {
                __sync_fetch_and_add(&(exist_1->retrans_count), cms->retrans_count);
            }
        }
    }
    
    if (exist_2) {
        if (trans->flow == 0) {
            __sync_fetch_and_add(&(exist_2->packet_count), 1);
        } else {
            __sync_fetch_and_add(&(exist_2->packet_count), cms->packet_count);
            if (key->protocol == TCP_PROTO) {
                __sync_fetch_and_add(&(exist_2->retrans_count), cms->retrans_count);
            }
        }
    }
    
    if (exist_3) {
        if (trans->flow == 0) {
            __sync_fetch_and_add(&(exist_3->packet_count), 1);
        } else {
            __sync_fetch_and_add(&(exist_3->packet_count), cms->packet_count);
            if (key->protocol == TCP_PROTO) {
                __sync_fetch_and_add(&(exist_3->retrans_count), cms->retrans_count);
            }
        }
    }
}

// Main tracepoint handler
TRACEPOINT_PROBE(net, netif_receive_skb) {
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    if (!skb) return 0;
    
    struct ethhdr *eth = (struct ethhdr *)(skb->head + skb->network_header - ETH_HLEN);
    if (!eth) return 0;
    if (eth->h_proto != htons(ETH_P_IP)) return 0;
    
    struct iphdr *ip = (struct iphdr *)(skb->head + skb->network_header);
    if (!ip) return 0;
    
    // Filter out control and management IPs
    if (ip->saddr == CON || ip->daddr == CON) return 0;
    if (ip->saddr == MGT || ip->daddr == MGT) return 0;
    if (ip->saddr == 2130706433 || ip->daddr == 2130706433) return 0;
    if (ip->saddr == 0) return 0;
    if (ip->daddr == 0) return 0;
    if (ip->protocol != TCP_PROTO && ip->protocol != UDP_PROTO) return 0;
    
    struct flow_key key = {0, 0, 0, 0, 0};
    struct tcp_meta_data tcpmeta = {0, 0, 0};
    struct transmit_metadata trans = {0};
    struct flow_stats_cms cms = {0, 0};
    
    // Process packet based on protocol
    if (ip->protocol == TCP_PROTO) {
        if (!process_tcp_packet(skb, ip, &key, &tcpmeta)) return 0;
    } else if (ip->protocol == UDP_PROTO) {
        if (!process_udp_packet(skb, ip, &key)) return 0;
    } else {
        return 0;
    }
    
    // Check priority table first
    if (process_priority_flow(&key, &tcpmeta)) {
        return 0;
    }
    
    // Process sketch flow
    if (process_sketch_flow(&key, &tcpmeta)) {
        return 0;
    }
    
    // Update CMS tables
    update_cms_tables(&key, &cms, &trans);
    
    return 0;
}
