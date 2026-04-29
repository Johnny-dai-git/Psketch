# Priority-Aware In-Kernel Flow Monitoring via eBPF

This repository contains an eBPF-based framework for real-time network flow monitoring that distinguishes and prioritizes selected high-priority flows while approximating top-k elephant flows. The system operates entirely in the Linux kernel and is built for environments requiring low overhead, accurate flow statistics, and retransmission tracking without the need for specialized hardware.

> 📌 This work is currently under peer review at a top-tier systems and networking venue.

---

## ✨ Key Features

- ⚡ **Real-Time Kernel Monitoring**: Uses eBPF to inspect packets at the `netif_receive_skb` tracepoint with minimal overhead.
- 🎯 **Priority-Aware Design**: Tracks user-defined priority flows precisely and all other flows via sketch-based approximation.
- 📊 **Top-k Detection**: Implements multi-layer Count-Min Sketch (CMS) structures to identify top-k flows.
- 🔁 **Retransmission Detection**: Integrates TCP retransmission tracking through sequence number and timeout logic.
- 📈 **Evaluated on 10Gbps CAIDA Traces**: Demonstrates >95% accuracy in top-k flow detection and >96% retransmission recall.

---

## 🏗️ Project Structure

```
Priority-Sketch-in-eBPF-main/
├── main.py                 # Main entry point
├── config.py              # Configuration and constants
├── structures.py           # Data structure definitions
├── utils.py               # Utility functions
├── ebpf_manager.py        # eBPF program management
├── grpc_service.py        # gRPC service implementation
├── ebpf_headers.h         # eBPF headers and constants
├── ebpf_structures.h      # eBPF data structures
├── ebpf_hash.h            # Hash function implementations
├── ebpf_helpers.h         # eBPF helper functions
├── ebpf_main.c            # Main eBPF program
├── example_usage.py       # Usage examples
├── requirements.txt       # Python dependencies
└── README.md             # Project documentation
```

---

## 🔧 Technical Highlights

### ✳️ Priority Table
Implemented using an eBPF hash map to maintain a whitelist of high-priority flows by 5-tuple.

### ✳️ Heavy Flow Table
Collision-aware eviction with a voting-based scheme. Each entry uses a `negative_counter` to track hash collisions and evict outdated flows.

### ✳️ Top-k Flow Estimation
Three-layer Count-Min Sketch estimates packet counts. Final estimate uses:
```
min(cms1[i], cms2[j], cms3[k])
```

### ✳️ Retransmission Detection
A packet is marked retransmitted if:
```
seq < expected_seq and (t_now - t_last) > THRESH
```

### ✳️ gRPC Interface
User-space collector connects to eBPF via gRPC to receive prioritized stats and logs.

---

## 📊 Evaluation Summary

- **Top-k Accuracy**: >95%
- **Retransmission Recall**: >96%
- **Throughput Overhead**: <1.1%
- **CPU Usage**: Moderate (<30%)
- **Trace Used**: CAIDA 10Gbps packet captures

---

## 🚀 Quick Start

### Prerequisites
```bash
# Install system dependencies
sudo apt update
sudo apt install clang llvm python3-bcc

# Install Python dependencies
pip install -r requirements.txt
```

### Running the System
```bash
# Start the Priority-Sketch system
sudo python3 main.py
```

### Configuration
Edit `config.py` to customize:
- Network interface names
- gRPC server settings
- eBPF program parameters
- File paths and logging

---

## 🔧 Development

### Code Organization
The codebase has been refactored for better organization:

- **`config.py`**: All constants and configuration parameters
- **`structures.py`**: Data structure definitions for both C and Python
- **`utils.py`**: Utility functions for network operations, hashing, and data processing
- **`ebpf_manager.py`**: eBPF program management and data collection
- **`grpc_service.py`**: gRPC service implementation
- **`main.py`**: Simple entry point

### Adding New Features
1. Add constants to `config.py`
2. Define new structures in `structures.py`
3. Implement utility functions in `utils.py`
4. Update eBPF code in the `ebpf_*.h` and `ebpf_main.c` files
5. Update Python managers as needed

---

The project now contains the following core files:

### Python Modules
- **`main.py`** - Simplified main entry point
- **`config.py`** - Configuration and constant management
- **`structures.py`** - Data structure definitions
- **`utils.py`** - Utility function collection
- **`ebpf_manager.py`** - eBPF program management
- **`grpc_service.py`** - gRPC service implementation
- **`example_usage.py`** - Usage examples

### eBPF Modules
- **`ebpf_headers.h`** - Headers and constants
- **`ebpf_structures.h`** - Data structure definitions
- **`ebpf_hash.h`** - Hash function implementations
- **`ebpf_helpers.h`** - Helper functions
- **`ebpf_main.c`** - Main eBPF program

### Documentation and Configuration
- **`README.md`** - Project documentation
- **`requirements.txt`** - Python dependencies

---

## 🚀 Usage

```bash
# Install dependencies
pip install -r requirements.txt

# Run the system
sudo python3 main.py

# View examples
python3 example_usage.py
```

---

## 🚀 Next Steps

1. **Add Unit Tests**: Write test cases for each module
2. **Performance Optimization**: Analyze and optimize critical paths
3. **Error Handling**: Enhance error handling and recovery mechanisms
4. **Monitoring**: Add system monitoring and metrics collection
5. **Documentation**: Complete API documentation and usage guides

---

## 📝 Summary

Through this refactoring and cleanup, the code has been transformed from a single-file structure to a modular architecture, greatly improving code maintainability, extensibility, and readability. The new structure enables:

- Developers to quickly locate and modify specific functionality
- New features to be developed and tested independently
- More flexible configuration management
- Higher code reusability
- Easier system deployment and maintenance

This modular design provides a solid foundation for future feature extensions and performance optimizations.

---

## 📎 Citation

> This project is currently under review. A formal citation will be added after publication.
