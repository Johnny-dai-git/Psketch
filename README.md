PSketch: Priority-Aware In-Kernel Flow Monitoring via eBPF
PSketch is the first in-kernel priority-aware sketch framework built entirely in eBPF. It combines precise per-flow tracking for user-defined priority flows with Count-Min Sketch-based approximation for all other traffic, achieving >95% Top-K accuracy and <1.1% throughput overhead at 10 Gbps on commodity Linux servers without any specialized hardware.
Published at IEEE ICNC 2026: https://ieeexplore.ieee.org/document/11416971

Overview
Modern AI and distributed ML workloads generate highly heterogeneous network traffic. Monitoring all flows at line rate is prohibitively expensive, but missing critical flows (e.g., gradient synchronization traffic) can degrade system observability. PSketch addresses this by treating flows differently based on priority: high-priority flows are tracked precisely in a BPF hash map, while all other flows are estimated using a three-layer Count-Min Sketch running entirely in the kernel.
The system attaches to the netif_receive_skb tracepoint and processes every packet with sub-microsecond overhead, requiring no kernel modifications and no specialized NICs.

Key Features

Priority-aware design: User-defined priority flows (by 5-tuple) are tracked precisely. All other flows are approximated via sketch.
Top-K detection: Three-layer Count-Min Sketch with voting-based hash collision resolution identifies the top-K elephant flows.
Retransmission tracking: TCP retransmissions detected via sequence number comparison and configurable timeout thresholds.
In-kernel operation: Entire monitoring pipeline runs in the Linux kernel via eBPF. No user-space packet copies.
gRPC interface: User-space collector receives prioritized flow stats and logs via gRPC without polling.
Atomic safety: All shared counter updates use __sync_fetch_and_add for thread-safe concurrent access across CPU cores.


System Architecture
Incoming Packets
       |
       v
  netif_receive_skb (eBPF tracepoint)
       |
       +---> Priority Table (BPF_HASH)
       |         - Exact match on 5-tuple
       |         - Precise packet/retransmission counters
       |
       +---> Heavy Flow Table
       |         - Collision-aware eviction (negative_counter voting)
       |         - Tracks elephant flow candidates
       |
       +---> Count-Min Sketch (3-layer CMS)
                 - Approximate Top-K estimation
                 - min(cms1[i], cms2[j], cms3[k])
                 |
                 v
           gRPC Service --> User-space Collector

Technical Design
Priority Table
Implemented as a BPF_HASH map keyed by 5-tuple. Each matched packet atomically increments packet and retransmission counters. Provides O(1) lookup per packet.
Heavy Flow Table and Collision Resolution
Each slot maintains a negative_counter that increments on hash collisions. When negative_counter exceeds a configurable eviction threshold (VOTE_THRE), the entry is evicted and replaced. This prevents stale entries from polluting the sketch without requiring expensive locks.
Top-K Estimation (Count-Min Sketch)
Three independent hash functions map each flow to entries in three CMS layers. The packet count estimate uses:
estimated_count = min(cms1[h1(flow)], cms2[h2(flow)], cms3[h3(flow)])
This provides an upper-bound estimate with bounded error probability.
Retransmission Detection
A packet is flagged as a retransmission if:
seq < expected_seq  AND  (t_now - t_last) > RETRANS_THRESH
Sequence number state is maintained per-flow in the priority table.
Thread Safety
All counter updates across priority table, heavy flow table, and CMS layers use __sync_fetch_and_add. This is required because eBPF programs are dispatched to multiple CPU cores in parallel by the kernel and share the same BPF maps.

Project Structure
PSketch/
├── ebpf_main.c          # Main eBPF kernel program
├── ebpf_headers.h       # Constants and kernel headers
├── ebpf_structures.h    # BPF map and flow record definitions
├── ebpf_hash.h          # Hash function implementations
├── ebpf_helpers.h       # In-kernel helper functions
├── ebpf_manager.py      # eBPF program loader and map reader
├── grpc_service.py      # gRPC server for user-space collection
├── structures.py        # Python-side data structure definitions
├── config.py            # Configuration parameters
├── utils.py             # Utility functions
├── main.py              # Entry point
├── example_usage.py     # Usage examples
└── requirements.txt     # Python dependencies

Evaluation
Evaluated on CAIDA 10 Gbps backbone packet traces on the NSF FABRIC testbed.
MetricResultTop-K Accuracy>95%Retransmission Recall>96%Throughput Overhead<1.1%CPU Usage<30%

Quick Start
Prerequisites
bashsudo apt update
sudo apt install clang llvm python3-bcc
pip install -r requirements.txt
Run
bashsudo python3 main.py
Configuration
Edit config.py to set network interface, gRPC parameters, eBPF constants, priority flow definitions, and logging paths.

Citation
If you use PSketch in your research, please cite:
@inproceedings{dai2026psketch,
  title     = {PSketch: A Priority-Aware Sketch Architecture for Real-Time Flow Monitoring via eBPF},
  author    = {Dai, Yuanjun and Guo, Qingzhe and Wang, Xiangren},
  booktitle = {Proceedings of IEEE ICNC 2026},
  year      = {2026},
  doi       = {10.1109/ICNC68183.2026.11416971}
}
