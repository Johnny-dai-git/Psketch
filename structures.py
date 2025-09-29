"""
Data structures for Priority-Sketch eBPF system
Contains all C structure definitions and Python equivalents
"""

from ctypes import Structure, c_uint32, c_uint16, c_uint8, c_uint64

class FiveTuple(Structure):
    """5-tuple flow identifier structure"""
    _fields_ = [
        ("src_ip", c_uint32),
        ("dest_ip", c_uint32),
        ("src_port", c_uint16),
        ("dest_port", c_uint16),
        ("proto", c_uint8)
    ]

class FlowStatsPriority(Structure):
    """Priority flow statistics structure"""
    _fields_ = [
        ("packet_count", c_uint64),
        ("retrans_count", c_uint64),
        ("last_seq", c_uint32),
        ("negative_count", c_uint64),
        ("last_timestamp", c_uint64)
    ]

class FlowStatsCMS(Structure):
    """Count-Min Sketch flow statistics structure"""
    _fields_ = [
        ("packet_count", c_uint64),
        ("retrans_count", c_uint64)
    ]

class FlowStatsSketch(Structure):
    """Sketch flow statistics structure"""
    _fields_ = [
        ("key", FiveTuple),
        ("packet_count", c_uint64),
        ("retrans_count", c_uint64),
        ("last_seq", c_uint32),
        ("negative_count", c_uint64),
        ("last_timestamp", c_uint64),
        ("kick", c_uint32),
    ]

class TCPMetaData:
    """TCP metadata for retransmission detection"""
    def __init__(self, seq=0, next_expected_seq=0, last_timestamp=0):
        self.seq = seq
        self.next_expected_seq = next_expected_seq
        self.last_timestamp = last_timestamp

class TransmitMetadata:
    """Metadata for flow transmission tracking"""
    def __init__(self, flow=0):
        self.flow = flow
