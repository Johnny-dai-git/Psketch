"""
eBPF Program Manager
Handles eBPF program loading, execution, and data collection
"""

import asyncio
import socket
import struct
from bcc import BPF
from structures import *
from utils import NetworkUtils, HashUtils, DataUtils, FileUtils
from config import *


class EBPFManager:
    """Manages eBPF program execution and data collection"""
    
    def __init__(self):
        self.bpf_instance = None
        self.five_tuple_information = []
        self.total_subtraction_packet = 0
        self.total_subtraction_retrans = 0
    
    async def load_ebpf_program(self):
        """Load and initialize the eBPF program"""
        # Get network interface IPs
        control_ip = NetworkUtils.get_control_ip()
        mgt_ip = NetworkUtils.get_management_ip()
        
        # Read and modify eBPF source code
        with open(EBPF_SOURCE_FILE, "r") as c_file:
            ebpf_c_code = c_file.read()
            modified_ebpf_c_code = ebpf_c_code.replace("CON", str(control_ip))
            modified_ebpf_c_code = modified_ebpf_c_code.replace("MGT", str(mgt_ip))
            modified_ebpf_c_code = modified_ebpf_c_code.replace("SIZE", str(SKETCH_SIZE))
        
        # Load eBPF program
        self.bpf_instance = BPF(text=modified_ebpf_c_code)
        return self.bpf_instance
    
    def insert_priority_flows(self):
        """Insert priority flows into the eBPF hash table"""
        if not self.bpf_instance:
            return
        
        priority_hash_table = self.bpf_instance['priority_table']
        for tuple_info in self.five_tuple_information:
            int_src = socket.inet_aton(tuple_info[0])
            int_src = struct.unpack("!I", int_src)[0]
            int_dst = socket.inet_aton(tuple_info[2])
            int_dst = struct.unpack("!I", int_dst)[0]
            src_port = tuple_info[1]
            dst_port = tuple_info[3]
            proto = tuple_info[4]
            
            key = FiveTuple(int_src, int_dst, src_port, dst_port, proto)
            inserted_entry = FlowStatsPriority(0, 0, 0, 0, 0)
            priority_hash_table[key] = inserted_entry
    
    def get_priority_flow_stats(self):
        """Get statistics from priority flows"""
        if not self.bpf_instance:
            return [0]
        
        priority_flow_table = self.bpf_instance['priority_table']
        total_packet = 0
        retransmission = 0
        
        for k, v in priority_flow_table.items():
            total_packet += v.packet_count
            retransmission += v.retrans_count
        
        data = DataUtils.calculate_retransmission_ratio(total_packet, retransmission)
        FileUtils.log_stats(total_packet, retransmission, data)
        return [data]
    
    def get_sketch_flow_stats(self):
        """Get statistics from sketch flows"""
        if not self.bpf_instance:
            return []
        
        # Get elephant flow table
        elephant_flows = self.bpf_instance['elephant_flow']
        elephant_list = []
        
        for i in range(len(elephant_flows)):
            value = elephant_flows[i]
            if value.kick == 1:
                values_list = self._cms_sketch(value)
                elephant_list.append(values_list)
            else:
                elephant_list.append([value.packet_count, value.retrans_count])
        
        return elephant_list
    
    def _cms_sketch(self, value):
        """Process CMS sketch for a flow"""
        cms1_table = self.bpf_instance['cms1']
        cms2_table = self.bpf_instance['cms2']
        cms3_table = self.bpf_instance['cms3']
        
        cms1_hash_value = HashUtils.get_hash_value_cms(
            value.src_ip, value.dst_ip, value.src_port, value.dst_port, value.protocol, 2
        )
        cms2_hash_value = HashUtils.get_hash_value_cms(
            value.src_ip, value.dst_ip, value.src_port, value.dst_port, value.protocol, 3
        )
        cms3_hash_value = HashUtils.get_hash_value_cms(
            value.src_ip, value.dst_ip, value.src_port, value.dst_port, value.protocol, 4
        )
        
        cms1_packet_count = cms1_table[cms1_hash_value].packet_count
        cms1_retran_count = cms1_table[cms1_hash_value].retrans_count
        cms2_packet_count = cms2_table[cms2_hash_value].packet_count
        cms2_retran_count = cms2_table[cms2_hash_value].retrans_count
        cms3_packet_count = cms3_table[cms3_hash_value].packet_count
        cms3_retran_count = cms3_table[cms3_hash_value].retrans_count
        
        packet_list = [cms1_packet_count, cms2_packet_count, cms3_packet_count]
        retran_list = [cms1_retran_count, cms2_retran_count, cms3_retran_count]
        
        min_packet_list = min(packet_list)
        min_retran_list = min(retran_list)
        
        packet_count = value.packet_count + min_packet_list
        retran_count = value.retrans_count + min_retran_list if value.protocol == 6 else 0
        
        # Update CMS tables
        cms1_table[cms1_hash_value].packet_count -= min_packet_list
        cms2_table[cms2_hash_value].packet_count -= min_packet_list
        cms3_table[cms3_hash_value].packet_count -= min_packet_list
        
        if value.protocol == 6:
            cms1_table[cms1_hash_value].retrans_count -= min_retran_list
            cms2_table[cms2_hash_value].retrans_count -= min_retran_list
            cms3_table[cms3_hash_value].retrans_count -= min_retran_list
        
        self.total_subtraction_packet += min_packet_list
        self.total_subtraction_retrans += min_retran_list
        
        return [packet_count, retran_count]
    
    def reset_data_structures(self):
        """Reset all eBPF data structures"""
        if not self.bpf_instance:
            return
        
        # Clear all tables
        self.bpf_instance['priority_table'].clear()
        self.bpf_instance['elephant_flow'].clear()
        self.bpf_instance['cms1'].clear()
        self.bpf_instance['cms2'].clear()
        self.bpf_instance['cms3'].clear()
        self.bpf_instance['linear_counter'].clear()
        
        # Re-insert priority flows
        self.insert_priority_flows()
    
    def get_linear_counter_stats(self):
        """Get linear counter statistics"""
        if not self.bpf_instance:
            return 0
        
        linear_counter_table = self.bpf_instance['linear_counter']
        flow_counting = 0
        
        for i in range(len(linear_counter_table)):
            value = linear_counter_table[i].value
            flow_counting += value
        
        return flow_counting
