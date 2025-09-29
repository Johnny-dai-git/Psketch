"""
Example usage of Priority-Sketch eBPF system
Demonstrates how to use the refactored code
"""

import asyncio
from ebpf_manager import EBPFManager
from utils import NetworkUtils, DataUtils
from config import *


async def example_usage():
    """Example of how to use the Priority-Sketch system"""
    
    print("=== Priority-Sketch eBPF System Example ===")
    
    # Initialize eBPF manager
    ebpf_manager = EBPFManager()
    
    # Add some priority flows (5-tuple format: src_ip, src_port, dst_ip, dst_port, protocol)
    priority_flows = [
        ("192.168.1.100", 8080, "192.168.1.200", 80, 6),  # TCP flow
        ("10.0.0.1", 443, "10.0.0.2", 443, 6),            # HTTPS flow
        ("172.16.0.1", 53, "172.16.0.2", 53, 17),         # DNS flow
    ]
    
    # Set priority flows
    ebpf_manager.five_tuple_information = priority_flows
    
    print(f"Added {len(priority_flows)} priority flows")
    
    # Load eBPF program
    print("Loading eBPF program...")
    await ebpf_manager.load_ebpf_program()
    
    # Insert priority flows into eBPF hash table
    print("Inserting priority flows...")
    ebpf_manager.insert_priority_flows()
    
    # Simulate some data collection
    print("Collecting statistics...")
    
    # Get priority flow statistics
    priority_stats = ebpf_manager.get_priority_flow_stats()
    print(f"Priority flow retransmission ratio: {priority_stats}")
    
    # Get sketch flow statistics
    sketch_stats = ebpf_manager.get_sketch_flow_stats()
    print(f"Sketch flow statistics: {len(sketch_stats)} flows")
    
    # Get linear counter statistics
    flow_count = ebpf_manager.get_linear_counter_stats()
    print(f"Total flow count: {flow_count}")
    
    # Demonstrate data normalization
    sample_data = [[100, 5], [200, 10], [50, 2]]
    normalized_data = DataUtils.normalization(sample_data)
    print(f"Normalized data: {normalized_data}")
    
    # Demonstrate network utilities
    control_ip = NetworkUtils.get_control_ip()
    mgt_ip = NetworkUtils.get_management_ip()
    print(f"Control IP: {control_ip}")
    print(f"Management IP: {mgt_ip}")
    
    print("=== Example completed ===")


def demonstrate_config():
    """Demonstrate configuration usage"""
    print("=== Configuration Example ===")
    print(f"TCP Protocol: {TCP_PROTO}")
    print(f"UDP Protocol: {UDP_PROTO}")
    print(f"Retransmission Threshold: {RETRANSMISSION_THRESHOLD}")
    print(f"Sketch Size: {SKETCH_SIZE}")
    print(f"gRPC Host: {GRPC_HOST}")
    print(f"gRPC Port: {GRPC_PORT}")
    print("=== Configuration Example completed ===")


if __name__ == "__main__":
    print("Priority-Sketch eBPF System - Example Usage")
    print("=" * 50)
    
    # Demonstrate configuration
    demonstrate_config()
    print()
    
    # Run example (commented out to avoid requiring root privileges)
    # asyncio.run(example_usage())
    print("Note: Run with sudo to execute eBPF example")
