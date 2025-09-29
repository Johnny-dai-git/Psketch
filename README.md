# Psketch
PSketch is an in-kernel, priority-aware eBPF sketch on commodity Linux. It losslessly tracks high-priority flows via a hash table, approximates top-k elephants with a sketch pipeline, supports TCP/UDP, and tracks retransmissions in-kernel. On 10 Gbps CAIDA traces: 96.0% top-k, 96.4% retrans recall, ~0.7% throughput loss.
