"""
gRPC Service Implementation
Handles gRPC communication and message processing
"""

import asyncio
import grpc
import grpc_connector_pb2_grpc as pb2_grpc
import grpc_connector_pb2 as pb2
from ebpf_manager import EBPFManager
from utils import FileUtils
from config import *


class GrpcService(pb2_grpc.GrpcServiceServicer):
    """gRPC service implementation for Priority-Sketch system"""
    
    def __init__(self):
        self.ebpf_manager = EBPFManager()
        self.start = False
        self.run_ebpf_signal = False
        self.switch_ready = False
        self.wait_signal_task = asyncio.create_task(self.wait_for_signal())
    
    async def connector(self, request_iterator, context):
        """Main gRPC connector method"""
        send_queue = asyncio.Queue()
        listen_task = asyncio.create_task(self.listening(request_iterator, send_queue))
        send_task = asyncio.create_task(self.spontaneous_messages(send_queue))
        
        try:
            async for message in self.send_messages(send_queue):
                yield message
        finally:
            # Clean up tasks
            send_task.cancel()
            listen_task.cancel()
            self.wait_signal_task.cancel()
    
    async def wait_for_signal(self):
        """Wait for eBPF execution signal"""
        while not self.run_ebpf_signal:
            await asyncio.sleep(0.001)
        
        print("Signal received, running eBPF program...")
        await self.run_ebpf()
    
    async def listening(self, request_iterator, queue):
        """Listen for incoming gRPC messages"""
        i = 0
        async for message in request_iterator:
            if message.run:
                response = pb2.Message()
                response.ping_confirm = True
                await queue.put(response)
            
            if message.termination:
                exit(0)
            
            if message.tuple:
                self.ebpf_manager.five_tuple_information.append([
                    message.src_ip, message.src_port, message.dst_ip, message.dst_port, message.proto
                ])
            
            if message.tuple_finish:
                self.run_ebpf_signal = True
            
            if message.switchclear:
                FileUtils.log_clear(i)
                i += 1
                self.ebpf_manager.reset_data_structures()
    
    async def send_messages(self, queue):
        """Send messages from queue"""
        while True:
            await asyncio.sleep(0.001)
            message = await queue.get()
            if message is None:
                break
            yield message
    
    async def spontaneous_messages(self, send_queue):
        """Send spontaneous messages with statistics"""
        while True:
            await asyncio.sleep(0.001)
            
            if self.start:
                data = self.ebpf_manager.get_priority_flow_stats()
                FileUtils.log_data_length(len(data) * 2)
                FileUtils.log_data(data)
                
                message = pb2.Message()
                for ele in data:
                    message.retransmission = round(ele, 7)
                message.stats = True
                await send_queue.put(message)
            
            if self.switch_ready:
                message = pb2.Message()
                message.switch_ready = True
                await send_queue.put(message)
                self.switch_ready = False
                self.start = True
    
    async def run_ebpf(self):
        """Run the eBPF program"""
        await self.ebpf_manager.load_ebpf_program()
        self.ebpf_manager.insert_priority_flows()
        self.switch_ready = True


async def serve():
    """Start the gRPC server"""
    server = grpc.aio.server()
    pb2_grpc.add_GrpcServiceServicer_to_server(GrpcService(), server)
    server.add_insecure_port(f'{GRPC_HOST}:{GRPC_PORT}')
    await server.start()
    await server.wait_for_termination()


if __name__ == "__main__":
    asyncio.run(serve())
