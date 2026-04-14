# storage/packet_cache.py
"""数据包缓存 - 临时存储未命中规则的包"""
import time
import threading
from typing import Dict, Optional, List
from dataclasses import dataclass, field
from datetime import datetime
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@dataclass
class CachedPacket:
    """缓存的包数据结构"""
    packet_id: str
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
    processed: bool = False
    flow_key: Optional[tuple] = None


class PacketCache:
    """
    数据包缓存
    
    特点：
    - 内存缓存，高性能
    - 支持TTL自动过期
    - 线程安全
    """
    
    def __init__(self, max_size: int = 10000, ttl: int = 300):
        """
        初始化缓存
        
        Args:
            max_size: 最大缓存数量
            ttl: 缓存生存时间（秒）
        """
        self.max_size = max_size
        self.ttl = ttl
        self._cache: Dict[str, CachedPacket] = {}
        self._lock = threading.RLock()
        self._packet_counter = 0
        
        # 启动清理线程
        self._cleanup_thread = None
        self._stop_cleanup = False
        self._start_cleanup_thread()
        
        print(f"[INFO] PacketCache initialized: max_size={max_size}, ttl={ttl}s")
    
    def _start_cleanup_thread(self):
        """启动清理线程"""
        def cleanup_loop():
            while not self._stop_cleanup:
                time.sleep(60)  # 每分钟清理一次
                self._cleanup_expired()
        
        self._cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        self._cleanup_thread.start()
    
    def _cleanup_expired(self):
        """清理过期的缓存"""
        now = time.time()
        with self._lock:
            expired_keys = [
                packet_id for packet_id, packet in self._cache.items()
                if now - packet.timestamp > self.ttl
            ]
            for key in expired_keys:
                del self._cache[key]
            
            if expired_keys:
                print(f"[DEBUG] Cleaned up {len(expired_keys)} expired packets")
    
    def _generate_packet_id(self) -> str:
        """生成唯一的包ID"""
        self._packet_counter += 1
        return f"pkt_{int(time.time()*1000)}_{self._packet_counter}"
    
    def save_packet(self, packet) -> str:
        """
        保存数据包到缓存
        
        Args:
            packet: CapturedPacket 对象
            
        Returns:
            packet_id: 生成的包ID
        """
        packet_id = self._generate_packet_id()
        
        cached = CachedPacket(
            packet_id=packet_id,
            timestamp=packet.timestamp,
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            protocol=packet.protocol,
            payload=packet.payload,
            payload_preview=packet.payload_preview,
            ttl=packet.ttl,
            length=packet.length,
            flow_key=(packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port, packet.protocol)
        )
        
        with self._lock:
            # 检查缓存大小
            if len(self._cache) >= self.max_size:
                self._evict_oldest()
            
            self._cache[packet_id] = cached
        
        return packet_id
    
    def get_packet(self, packet_id: str) -> Optional[CachedPacket]:
        """获取缓存的包"""
        with self._lock:
            packet = self._cache.get(packet_id)
            if packet and not self._is_expired(packet):
                return packet
            elif packet:
                # 过期则删除
                del self._cache[packet_id]
            return None
    
    def _is_expired(self, packet: CachedPacket) -> bool:
        """检查包是否过期"""
        return time.time() - packet.timestamp > self.ttl
    
    def _evict_oldest(self):
        """淘汰最旧的包"""
        if not self._cache:
            return
        
        oldest_id = min(self._cache.keys(), key=lambda k: self._cache[k].timestamp)
        del self._cache[oldest_id]
    
    def mark_processed(self, packet_id: str):
        """标记包已处理"""
        with self._lock:
            if packet_id in self._cache:
                self._cache[packet_id].processed = True
    
    def delete_packet(self, packet_id: str):
        """删除缓存的包"""
        with self._lock:
            if packet_id in self._cache:
                del self._cache[packet_id]
    
    def get_packets_by_flow(self, flow_key: tuple) -> List[CachedPacket]:
        """获取同一流的所有包"""
        with self._lock:
            return [
                p for p in self._cache.values()
                if p.flow_key == flow_key and not self._is_expired(p)
            ]
    
    def size(self) -> int:
        """获取缓存大小"""
        with self._lock:
            return len(self._cache)
    
    def clear(self):
        """清空缓存"""
        with self._lock:
            self._cache.clear()
    
    def shutdown(self):
        """关闭缓存"""
        self._stop_cleanup = True
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=5)
        self.clear()
        print("[INFO] PacketCache shutdown")