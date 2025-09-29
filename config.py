"""
Configuration file for Priority-Sketch eBPF system
Contains all constants, parameters, and configuration settings
"""

# Network Protocol Constants
TCP_PROTO = 6
UDP_PROTO = 17

# Thresholds and Limits
RETRANSMISSION_THRESHOLD = 3000000  # 3 seconds in nanoseconds
VOTE_THRESHOLD = 3
SKETCH_SIZE = 3000
CMS_SIZE = 3000

# Hash Function Constants
HASH_SEED = 42

# Network Interface Names
CONTROL_INTERFACE = "enp3s0"
MANAGEMENT_INTERFACE = "enp8s0"

# gRPC Configuration
GRPC_HOST = '10.10.6.3'
GRPC_PORT = 50051

# File Paths
EBPF_SOURCE_FILE = "sketch.c"
LOG_FILE = "record.txt"
CHECK_FILE = "checking.txt"

# Data Structure Sizes
FIVE_TUPLE_SIZE = 5
MAX_TOP_K = 10
