# data/packet_capture.py
"""
实时流量捕获模块
使用scapy进行网络数据包捕获
"""
import threading
import queue
import time
from typing import Optional, Callable, Dict, Any
from dataclasses import dataclass, field
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from scapy.packet import Packet
from scapy.error import Scapy_Exception

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import DETECTION_CONFIG

# 移除 logger 相关代码


@dataclass
class CapturedPacket:
    """捕获的数据包数据结构"""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    payload: bytes = b''
    payload_preview: str = ''
    ttl: int = 64
    length: int = 0
    raw_packet: Optional[Packet] = None
    
    def __post_init__(self):
        if self.payload_preview and not self.payload:
            self.payload = self.payload_preview.encode('utf-8', errors='ignore')
        elif self.payload and not self.payload_preview:
            self.payload_preview = self.payload[:256].hex() if self.payload else ''


class PacketCapturer:
    """
    实时流量捕获器
    
    使用scapy捕获网络数据包，支持BPF过滤器
    """
    
    def __init__(
        self,
        interface: Optional[str] = None,
        filter_str: Optional[str] = None,
        packet_count: int = -1,
        timeout: Optional[int] = None
    ):
        """
        初始化包捕获器
        
        Args:
            interface: 网卡接口名称，None表示自动选择
            filter_str: BPF过滤器字符串
            packet_count: 捕获包数量限制，-1表示无限制
            timeout: 捕获超时时间（秒）
        """
        self.interface = interface or DETECTION_CONFIG.get('network_interface')
        self.filter_str = filter_str or DETECTION_CONFIG.get('capture_filter')
        self.packet_count = packet_count or DETECTION_CONFIG.get('packet_count', -1)
        self.timeout = timeout
        
        self._packet_queue: queue.Queue = queue.Queue(maxsize=10000)
        self._stop_event = threading.Event()
        self._capture_thread: Optional[threading.Thread] = None
        self._callback: Optional[Callable[[CapturedPacket], None]] = None
        
        print(f"[INFO] PacketCapturer initialized: interface={self.interface}, filter={self.filter_str}")
    
    def _process_packet(self, packet: Packet) -> None:
        """
        处理捕获的数据包，提取关键信息
        
        Args:
            packet: scapy数据包对象
        """
        if not packet or not packet.haslayer(IP):
            return
        
        ip_layer = packet[IP]
        
        # 提取IP信息
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        ttl = ip_layer.ttl
        length = len(packet)
        
        # 提取传输层信息
        src_port = 0
        dst_port = 0
        protocol = 'ip'
        payload = b''
        
        if packet.haslayer(TCP):
            protocol = 'tcp'
            tcp_layer = packet[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            if tcp_layer.payload:
                payload = bytes(tcp_layer.payload)
                
        elif packet.haslayer(UDP):
            protocol = 'udp'
            udp_layer = packet[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            if udp_layer.payload:
                payload = bytes(udp_layer.payload)
                
        elif packet.haslayer(ICMP):
            protocol = 'icmp'
            icmp_layer = packet[ICMP]
            src_port = icmp_layer.type
            dst_port = icmp_layer.code
            if icmp_layer.payload:
                payload = bytes(icmp_layer.payload)
        
        # 创建捕获的数据包对象
        captured = CapturedPacket(
            timestamp=time.time(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            payload=payload,
            payload_preview=payload[:256].hex() if payload else '',
            ttl=ttl,
            length=length,
            raw_packet=packet
        )
        
        # 加入队列或调用回调
        if self._callback:
            try:
                self._callback(captured)
            except Exception as e:
                print(f"[ERROR] Callback error: {e}")
        else:
            try:
                self._packet_queue.put_nowait(captured)
            except queue.Full:
                print("[WARNING] Packet queue is full, dropping packet")
    
    def _capture_loop(self) -> None:
        """捕获循环（在独立线程中运行）"""
        print(f"[INFO] Starting packet capture on {self.interface or 'any'}...")
        try:
            sniff(
                iface=self.interface,
                filter=self.filter_str,
                prn=self._process_packet,
                count=self.packet_count if self.packet_count > 0 else 0,
                timeout=self.timeout,
                stop_filter=lambda x: self._stop_event.is_set()
            )
        except Scapy_Exception as e:
            print(f"[ERROR] Scapy error: {e}")
        except Exception as e:
            print(f"[ERROR] Unexpected error in capture loop: {e}")
        finally:
            print("[INFO] Packet capture stopped")
    
    def start(self, callback: Optional[Callable[[CapturedPacket], None]] = None) -> None:
        """
        启动包捕获
        
        Args:
            callback: 可选的回调函数，用于实时处理每个数据包
        """
        if self._capture_thread and self._capture_thread.is_alive():
            print("[WARNING] Capture already running")
            return
        
        self._stop_event.clear()
        self._callback = callback
        self._capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._capture_thread.start()
        print("[INFO] Packet capture started")
    
    def stop(self) -> None:
        """停止包捕获"""
        self._stop_event.set()
        if self._capture_thread:
            self._capture_thread.join(timeout=5)
        print("[INFO] Packet capture stopped")
    
    def get_packet(self, timeout: float = 1.0) -> Optional[CapturedPacket]:
        """
        获取一个数据包（非阻塞）
        
        Args:
            timeout: 等待超时时间（秒）
            
        Returns:
            数据包对象，如果超时返回None
        """
        try:
            return self._packet_queue.get(timeout=timeout)
        except queue.Empty:
            return None
    
    def get_packet_batch(self, batch_size: int = 100, timeout: float = 0.1) -> list:
        """
        批量获取数据包
        
        Args:
            batch_size: 批次大小
            timeout: 每次获取的超时时间
            
        Returns:
            数据包列表
        """
        packets = []
        for _ in range(batch_size):
            pkt = self.get_packet(timeout=timeout)
            if pkt:
                packets.append(pkt)
            else:
                break
        return packets
    
    @property
    def is_running(self) -> bool:
        """检查是否正在捕获"""
        return self._capture_thread is not None and self._capture_thread.is_alive()
    
    @property
    def queue_size(self) -> int:
        """获取队列大小"""
        return self._packet_queue.qsize()