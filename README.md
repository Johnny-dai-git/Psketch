PSketch: Priority-Aware In-Kernel Flow Monitoring via eBPF

The first in-kernel priority-aware sketch framework built entirely in eBPF.
Precise tracking for critical flows. Approximate Top-K detection for everything else. Zero specialized hardware required.

Show Image
Show Image
Show Image

Why PSketch?
Modern AI and distributed ML training clusters generate highly heterogeneous network traffic. Gradient synchronization packets are mission-critical — losing or misrouting them degrades model convergence. Background bulk traffic is much less sensitive. Yet most monitoring tools treat every flow the same.
PSketch solves this with a two-tier in-kernel design:

Priority flows (e.g., gradient traffic) get exact, per-packet tracking in a BPF hash map.
All other flows get approximate Top-K estimation via a three-layer Count-Min Sketch.

Everything runs inside the Linux kernel via eBPF — no user-space packet copies, no specialized NICs, no kernel modifications.

How It Works
                        Incoming Packet
                              │
                              ▼
                  ┌─────────────────────┐
                  │  netif_receive_skb  │  ← eBPF tracepoint
                  └─────────┬───────────┘
                             │
              ┌──────────────▼──────────────┐
              │     5-tuple Classification   │
              └───┬──────────────────────┬──┘
                  │                      │
         Priority Flow?              Other Flow
                  │                      │
                  ▼                      ▼
     ┌────────────────────┐   ┌────────────────────────┐
     │   Priority Table   │   │   Heavy Flow Table     │
     │   (BPF_HASH)       │   │   + 3-layer CMS        │
     │                    │   │                        │
     │  Exact counters:   │   │  min(cms1, cms2, cms3) │
     │  - packet count    │   │  Voting-based eviction │
     │  - retrans count   │   │  Top-K approximation   │
     └────────┬───────────┘   └────────────┬───────────┘
              │                            │
              └──────────────┬─────────────┘
                             ▼
                    ┌─────────────────┐
                    │  gRPC Service   │
                    └────────┬────────┘
                             ▼
                    User-space Collector

Key Features
FeatureDescriptionPriority-Aware DesignUser-defined priority flows tracked precisely via BPF_HASH (O(1) lookup)Top-K DetectionThree-layer Count-Min Sketch estimates elephant flows with bounded errorRetransmission TrackingSequence number + timeout logic detects TCP retransmissions in-kernelThread-Safe Updates__sync_fetch_and_add atomic ops prevent data races across CPU coresgRPC InterfaceUser-space collection without polling or packet copiesZero Hardware DependencyRuns on standard Linux 5.4+ with eBPF + BCC

Performance
Evaluated on 10 Gbps CAIDA backbone traces on the NSF FABRIC testbed:
MetricResultTop-K Accuracy> 95%Retransmission Recall> 96%Throughput Overhead< 1.1%CPU Usage< 30%

Technical Deep Dive
Retransmission Detection
A packet is flagged as a retransmission if:
cif (seq < entry->expected_seq && (t_now - entry->ts) > RETRANS_THRESH) {
    __sync_fetch_and_add(&entry->retrans_count, 1);
}
Top-K Estimation (Count-Min Sketch)
The packet count estimate for any flow uses the minimum across three independent hash layers:
estimated_count = min(cms1[h1(flow)], cms2[h2(flow)], cms3[h3(flow)])
Hash Collision Resolution
Each heavy flow table entry maintains a negative_counter. On collision, the counter increments. When it exceeds VOTE_THRE, the entry is evicted and replaced — keeping the table fresh without locks.
Why Atomic Operations?
eBPF programs are event-driven and kernel-dispatched: each packet triggers a separate eBPF instance, and on multi-core systems the kernel runs multiple instances in parallel across CPU cores. Without atomics, concurrent read-modify-write on shared BPF map counters causes data corruption. __sync_fetch_and_add makes each increment indivisible at the hardware level.

Project Structure
PSketch/
├── ebpf_main.c           # Core eBPF kernel program
├── ebpf_headers.h        # Kernel headers and constants
├── ebpf_structures.h     # BPF map and flow record definitions
├── ebpf_hash.h           # Hash function implementations
├── ebpf_helpers.h        # In-kernel helper functions
├── ebpf_manager.py       # eBPF loader and BPF map reader
├── grpc_service.py       # gRPC server for user-space collection
├── structures.py         # Python-side data structures
├── config.py             # Configuration parameters
├── utils.py              # Utility functions
├── main.py               # Entry point
├── example_usage.py      # Usage examples
└── requirements.txt      # Python dependencies

Quick Start
bash# Install dependencies
sudo apt update && sudo apt install clang llvm python3-bcc
pip install -r requirements.txt

# Run PSketch (requires root for eBPF)
sudo python3 main.py
Configure network interface, priority flows, gRPC settings, and eBPF parameters in config.py.

Citation
bibtex@inproceedings{dai2026psketch,
  title     = {PSketch: A Priority-Aware Sketch Architecture for Real-Time Flow Monitoring via eBPF},
  author    = {Dai, Yuanjun and Guo, Qingzhe and Wang, Xiangren},
  booktitle = {Proceedings of IEEE ICNC 2026},
  year      = {2026},
  doi       = {10.1109/ICNC68183.2026.11416971}
}
