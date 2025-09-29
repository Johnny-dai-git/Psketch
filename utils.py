"""
Utility functions for Priority-Sketch eBPF system
Contains helper functions for network operations, hashing, and data processing
"""

import socket
import struct
import math
import netifaces
from config import *


class NetworkUtils:
    """Network utility functions"""
    
    @staticmethod
    def get_interface_ip(interface_name):
        """Get IPv4 address of a network interface"""
        if interface_name in netifaces.interfaces():
            iface_data = netifaces.ifaddresses(interface_name)
            if netifaces.AF_INET in iface_data:
                ipv4_data = iface_data[netifaces.AF_INET][0]
                return ipv4_data['addr']
        return None
    
    @staticmethod
    def ip_to_int_little_endian(ip_address):
        """Convert IP address to little-endian integer"""
        if ip_address is not None:
            packed_ip = socket.inet_aton(ip_address)
            return struct.unpack("<L", packed_ip)[0]
        return None
    
    @staticmethod
    def get_control_ip():
        """Get control interface IP in little-endian format"""
        ip = NetworkUtils.get_interface_ip(CONTROL_INTERFACE)
        return NetworkUtils.ip_to_int_little_endian(ip)
    
    @staticmethod
    def get_management_ip():
        """Get management interface IP in little-endian format"""
        ip = NetworkUtils.get_interface_ip(MANAGEMENT_INTERFACE)
        return NetworkUtils.ip_to_int_little_endian(ip)


class HashUtils:
    """Hash function utilities"""
    
    @staticmethod
    def jenkins_hash(a, b, c):
        """Jenkins hash function implementation"""
        a &= 0xffffffff
        b &= 0xffffffff
        c &= 0xffffffff
        a -= b
        a -= c
        a &= 0xffffffff
        a ^= c >> 13
        b -= c
        b -= a
        b &= 0xffffffff
        b ^= (a << 8) & 0xffffffff
        c -= a
        c -= b
        c &= 0xffffffff
        c ^= b >> 13
        a -= b
        a -= c
        a &= 0xffffffff
        a ^= c >> 12
        b -= c
        b -= a
        b &= 0xffffffff
        b ^= (a << 16) & 0xffffffff
        c -= a
        c -= b
        c &= 0xffffffff
        c ^= b >> 5
        a -= b
        a -= c
        a &= 0xffffffff
        a ^= c >> 3
        b -= c
        b -= a
        b &= 0xffffffff
        b ^= (a << 10) & 0xffffffff
        c -= a
        c -= b
        c &= 0xffffffff
        c ^= b >> 15
        return c
    
    @staticmethod
    def unique_five_tuple_hash(src_ip, dst_ip, src_port, dst_port, proto, seed, i):
        """Generate unique hash for 5-tuple"""
        a = src_ip ^ dst_ip
        b = (src_port << 16) | dst_port
        c = proto | (seed + i) << 8
        return HashUtils.jenkins_hash(a, b, c)
    
    @staticmethod
    def get_hash_value(src_ip, dst_ip, src_port, dst_port, proto, index, table_size=SKETCH_SIZE):
        """Get hash value for specified table"""
        return HashUtils.unique_five_tuple_hash(
            src_ip, dst_ip, src_port, dst_port, proto, HASH_SEED, index
        ) % table_size
    
    @staticmethod
    def get_hash_value_cms(src_ip, dst_ip, src_port, dst_port, proto, index):
        """Get hash value for CMS table"""
        return HashUtils.get_hash_value(src_ip, dst_ip, src_port, dst_port, proto, index, CMS_SIZE)


class DataUtils:
    """Data processing utilities"""
    
    @staticmethod
    def format_if_decimal(number):
        """Format number to 7 decimal places if it's a float"""
        if isinstance(number, float):
            return round(number, 7)
        return number
    
    @staticmethod
    def normalization(data_list):
        """Normalize data using logarithmic scaling"""
        processed_list = []
        for pair in data_list:
            first_value = math.log10(pair[0]) if pair[0] > 0 else 0
            second_value = math.log(pair[1], 5) if pair[1] > 0 else 0
            first_value = DataUtils.format_if_decimal(first_value)
            second_value = DataUtils.format_if_decimal(second_value)
            processed_list.append([first_value, second_value])
        return processed_list
    
    @staticmethod
    def calculate_retransmission_ratio(total_packets, retransmissions):
        """Calculate retransmission ratio"""
        if total_packets == 0:
            return 0
        return retransmissions / total_packets


class FileUtils:
    """File operation utilities"""
    
    @staticmethod
    def write_to_file(filename, content):
        """Write content to file"""
        with open(filename, "a") as file:
            file.write(content + '\n')
    
    @staticmethod
    def log_data_length(data_length):
        """Log data length to record file"""
        FileUtils.write_to_file(LOG_FILE, f"data_length:{data_length}")
    
    @staticmethod
    def log_data(data):
        """Log data to record file"""
        FileUtils.write_to_file(LOG_FILE, f"data:{data}")
    
    @staticmethod
    def log_clear(iteration):
        """Log clear operation"""
        FileUtils.write_to_file(LOG_FILE, f"clear:{iteration}")
    
    @staticmethod
    def log_stats(total_packets, retransmissions, data):
        """Log statistics to check file"""
        stats_data = [
            f"total_packet:{total_packets}",
            f"retransmission:{retransmissions}",
            f"check:{data}",
            ""
        ]
        for line in stats_data:
            FileUtils.write_to_file(CHECK_FILE, line)
