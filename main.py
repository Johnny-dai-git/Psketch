"""
Main entry point for Priority-Sketch eBPF system
Simplified and organized version
"""

import asyncio
from grpc_service import serve
from config import *


def main():
    """Main function to start the Priority-Sketch system"""
    print("Starting Priority-Sketch eBPF System...")
    print(f"gRPC Server: {GRPC_HOST}:{GRPC_PORT}")
    print(f"eBPF Source: {EBPF_SOURCE_FILE}")
    print(f"Sketch Size: {SKETCH_SIZE}")
    print(f"CMS Size: {CMS_SIZE}")
    
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        print("\nShutting down Priority-Sketch system...")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
