# data/flow_aggregator.py
"""
流聚合器模块
将数据包按五元组聚合成流，提取流级别的统计特征
"""
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Optional, List, Tuple
from enum import Enum

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data.packet_capture import CapturedPacket
from config import DETECTION_CONFIG

# 移除 logger 相关代码


class FlowState(Enum):
    """流状态枚举"""
    NEW = "new"           # 新流
    ACTIVE = "active"     # 活跃流
    TIMEOUT = "timeout"   # 超时流
    FINISHED = "finished" # 正常结束


@dataclass
class FlowKey:
    """流标识符（五元组）"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    
    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol))
    
    def __eq__(self, other):
        if not isinstance(other, FlowKey):
            return False
        return (self.src_ip == other.src_ip and 
                self.dst_ip == other.dst_ip and
                self.src_port == other.src_port and
                self.dst_port == other.dst_port and
                self.protocol == other.protocol)
    
    def reverse(self) -> 'FlowKey':
        """获取反向流标识符"""
        return FlowKey(
            src_ip=self.dst_ip,
            dst_ip=self.src_ip,
            src_port=self.dst_port,
            dst_port=self.src_port,
            protocol=self.protocol
        )


@dataclass
class FlowStats:
    """
    流统计信息
    
    对应模型需要的特征：
    - sbytes, dbytes: 源到目的/目的到源的字节数
    - sttl, dttl: 源/目的TTL
    - sloss, dloss: 源/目的丢包数
    - spkts, dpkts: 源/目的包数
    - sjit, djit: 源/目的抖动
    - tcprtt, synack, ackdat: TCP时序特征
    - trans_depth: 传输深度
    """
    # 基础信息
    key: FlowKey = None
    start_time: float = 0.0
    last_time: float = 0.0
    state: FlowState = FlowState.NEW
    
    # 包计数
    forward_packets: int = 0      # 源->目的包数 (spkts)
    backward_packets: int = 0     # 目的->源包数 (dpkts)
    
    # 字节计数
    forward_bytes: int = 0        # 源->目的字节数 (sbytes)
    backward_bytes: int = 0       # 目的->源字节数 (dbytes)
    
    # TTL统计
    forward_ttl_sum: int = 0
    backward_ttl_sum: int = 0
    forward_ttl_count: int = 0
    backward_ttl_count: int = 0
    
    # 丢包计数（基于序列号）
    forward_seq_last: int = 0
    backward_seq_last: int = 0
    forward_loss: int = 0         # sloss
    backward_loss: int = 0        # dloss
    
    # 时间戳列表（用于抖动计算）
    forward_timestamps: List[float] = field(default_factory=list)
    backward_timestamps: List[float] = field(default_factory=list)
    
    # TCP时序特征
    tcp_syn_time: float = 0.0
    tcp_synack_time: float = 0.0
    tcp_ack_time: float = 0.0
    tcp_rtt: float = 0.0          # 往返时间
    tcp_synack: float = 0.0       # SYN-ACK时间
    tcp_ackdat: float = 0.0       # ACK数据时间
    
    # 其他特征
    trans_depth: int = 0          # 传输深度（HTTP事务深度）
    is_ftp_login: bool = False    # 是否为FTP登录
    is_sm_ips_ports: bool = False # 是否为小IP/端口
    ct_flw_http_mthd: int = 0     # HTTP方法计数
    
    def __post_init__(self):
        if not self.start_time:
            self.start_time = time.time()
        if not self.last_time:
            self.last_time = self.start_time
    
    @property
    def duration(self) -> float:
        """流持续时间"""
        return self.last_time - self.start_time
    
    @property
    def forward_ttl(self) -> int:
        """平均源TTL"""
        if self.forward_ttl_count > 0:
            return int(self.forward_ttl_sum / self.forward_ttl_count)
        return 64
    
    @property
    def backward_ttl(self) -> int:
        """平均目的TTL"""
        if self.backward_ttl_count > 0:
            return int(self.backward_ttl_sum / self.backward_ttl_count)
        return 64
    
    @property
    def forward_jitter(self) -> float:
        """源抖动（相邻包时间间隔的标准差）"""
        if len(self.forward_timestamps) < 2:
            return 0.0
        diffs = []
        for i in range(1, len(self.forward_timestamps)):
            diffs.append(self.forward_timestamps[i] - self.forward_timestamps[i-1])
        if not diffs:
            return 0.0
        mean = sum(diffs) / len(diffs)
        variance = sum((d - mean) ** 2 for d in diffs) / len(diffs)
        return variance ** 0.5
    
    @property
    def backward_jitter(self) -> float:
        """目的抖动"""
        if len(self.backward_timestamps) < 2:
            return 0.0
        diffs = []
        for i in range(1, len(self.backward_timestamps)):
            diffs.append(self.backward_timestamps[i] - self.backward_timestamps[i-1])
        if not diffs:
            return 0.0
        mean = sum(diffs) / len(diffs)
        variance = sum((d - mean) ** 2 for d in diffs) / len(diffs)
        return variance ** 0.5
    
    def update_forward(self, packet: CapturedPacket) -> None:
        """更新前向流统计（源->目的）"""
        self.forward_packets += 1
        self.forward_bytes += packet.length
        self.forward_ttl_sum += packet.ttl
        self.forward_ttl_count += 1
        self.forward_timestamps.append(packet.timestamp)
        self.last_time = packet.timestamp
        
        # TCP序列号分析
        if packet.protocol == 'tcp' and packet.raw_packet and packet.raw_packet.haslayer('TCP'):
            tcp = packet.raw_packet['TCP']
            seq = tcp.seq
            if self.forward_seq_last > 0:
                expected = self.forward_seq_last + 1
                if seq > expected + 1:
                    self.forward_loss += seq - expected
            self.forward_seq_last = seq
    
    def update_backward(self, packet: CapturedPacket) -> None:
        """更新后向流统计（目的->源）"""
        self.backward_packets += 1
        self.backward_bytes += packet.length
        self.backward_ttl_sum += packet.ttl
        self.backward_ttl_count += 1
        self.backward_timestamps.append(packet.timestamp)
        self.last_time = packet.timestamp
        
        # TCP序列号分析
        if packet.protocol == 'tcp' and packet.raw_packet and packet.raw_packet.haslayer('TCP'):
            tcp = packet.raw_packet['TCP']
            seq = tcp.seq
            if self.backward_seq_last > 0:
                expected = self.backward_seq_last + 1
                if seq > expected + 1:
                    self.backward_loss += seq - expected
            self.backward_seq_last = seq
    
    def update_tcp_flags(self, packet: CapturedPacket) -> None:
        """更新TCP标志位时序"""
        if packet.protocol != 'tcp' or not packet.raw_packet:
            return
        
        tcp = packet.raw_packet['TCP']
        flags = tcp.flags
        
        # 检测SYN包
        if flags & 0x02:  # SYN flag
            if self.tcp_syn_time == 0:
                self.tcp_syn_time = packet.timestamp
        
        # 检测SYN-ACK包
        if (flags & 0x12) == 0x12:  # SYN+ACK
            if self.tcp_synack_time == 0 and self.tcp_syn_time > 0:
                self.tcp_synack_time = packet.timestamp
                self.tcp_synack = self.tcp_synack_time - self.tcp_syn_time
        
        # 检测ACK包
        if flags & 0x10:  # ACK flag
            if self.tcp_ack_time == 0 and self.tcp_synack_time > 0:
                self.tcp_ack_time = packet.timestamp
                self.tcp_ackdat = self.tcp_ack_time - self.tcp_synack_time
                self.tcp_rtt = self.tcp_ack_time - self.tcp_syn_time
    
    def update_application(self, packet: CapturedPacket) -> None:
        """更新应用层特征"""
        if not packet.payload:
            return
        
        payload_str = packet.payload.decode('utf-8', errors='ignore').lower()
        
        # FTP登录检测
        if not self.is_ftp_login and ('user ' in payload_str or 'pass ' in payload_str):
            self.is_ftp_login = True
        
        # HTTP方法计数
        http_methods = ['get ', 'post ', 'put ', 'delete ', 'head ', 'options ']
        for method in http_methods:
            if method in payload_str:
                self.ct_flw_http_mthd += 1
                break
        
        # 传输深度（HTTP事务）
        if 'http' in payload_str or 'https' in payload_str:
            self.trans_depth += 1
    
    def to_feature_dict(self) -> Dict[str, any]:
        """
        转换为特征字典，供模型使用
        
        Returns:
            包含所有模型特征的字典
        """
        return {
            'proto': self.key.protocol,
            'state': self._get_state_string(),
            'sbytes': self.forward_bytes,
            'dbytes': self.backward_bytes,
            'sttl': self.forward_ttl,
            'dttl': self.backward_ttl,
            'sloss': self.forward_loss,
            'dloss': self.backward_loss,
            'spkts': self.forward_packets,
            'dpkts': self.backward_packets,
            'sjit': self.forward_jitter,
            'djit': self.backward_jitter,
            'tcprtt': self.tcp_rtt,
            'synack': self.tcp_synack,
            'ackdat': self.tcp_ackdat,
            'service': self._get_service(),
            'ct_srv_src': 0,      # 需要在全局上下文中计算
            'ct_srv_dst': 0,      # 需要在全局上下文中计算
            'ct_dst_ltm': 0,      # 需要在全局上下文中计算
            'ct_src_ltm': 0,      # 需要在全局上下文中计算
            'trans_depth': self.trans_depth,
            'is_sm_ips_ports': self._check_small_ips_ports(),
            'ct_flw_http_mthd': self.ct_flw_http_mthd,
            'is_ftp_login': 1 if self.is_ftp_login else 0,
        }
    
    def _get_state_string(self) -> str:
        """获取流状态字符串"""
        if self.forward_packets == 0 and self.backward_packets == 0:
            return 'no'
        if self.state == FlowState.FINISHED:
            return 'FIN'
        if self.duration > 60:
            return 'INT'
        return 'CON'
    
    def _get_service(self) -> str:
        """根据端口推断服务类型"""
        port_to_service = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap',
            443: 'https', 993: 'imaps', 995: 'pop3s', 3306: 'mysql',
            3389: 'rdp', 8080: 'http-proxy'
        }
        
        # 检查源端口和目标端口
        for port, service in port_to_service.items():
            if self.key.src_port == port or self.key.dst_port == port:
                return service
        
        return '-'
    
    def _check_small_ips_ports(self) -> int:
        """
        检查是否为小IP/端口
        小IP：私有IP地址
        小端口：< 1024
        """
        def is_private_ip(ip: str) -> bool:
            if ip.startswith('10.'):
                return True
            if ip.startswith('192.168.'):
                return True
            if ip.startswith('172.'):
                parts = ip.split('.')
                if len(parts) >= 2:
                    second = int(parts[1])
                    if 16 <= second <= 31:
                        return True
            return False
        
        src_private = is_private_ip(self.key.src_ip)
        dst_private = is_private_ip(self.key.dst_ip)
        src_small_port = self.key.src_port < 1024 if self.key.src_port else False
        dst_small_port = self.key.dst_port < 1024 if self.key.dst_port else False
        
        return 1 if (src_private or dst_private or src_small_port or dst_small_port) else 0


class FlowAggregator:
    """
    流聚合器
    
    将数据包按五元组聚合成流，并在流超时后输出统计特征
    """
    
    def __init__(self, flow_timeout: int = 60):
        """
        初始化流聚合器
        
        Args:
            flow_timeout: 流超时时间（秒），超过此时间未收到包则视为超时
        """
        self.flow_timeout = flow_timeout or DETECTION_CONFIG.get('flow_timeout', 60)
        self._flows: Dict[FlowKey, FlowStats] = {}
        self._lock = threading.Lock()
        self._last_cleanup = time.time()
        
        print(f"[INFO] FlowAggregator initialized: timeout={self.flow_timeout}s")
    
    def add_packet(self, packet: CapturedPacket) -> Optional[FlowStats]:
        """
        添加数据包到流聚合器
        
        Args:
            packet: 捕获的数据包
            
        Returns:
            如果流超时或结束，返回完成的流统计；否则返回None
        """
        # 创建流键
        key = FlowKey(
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            protocol=packet.protocol
        )
        
        completed_flows = []
        
        with self._lock:
            # 获取或创建流
            if key not in self._flows:
                flow = FlowStats(key=key)
                self._flows[key] = flow
                print(f"[DEBUG] New flow created: {key}")
            else:
                flow = self._flows[key]
            
            # 更新流统计
            flow.update_forward(packet)
            flow.update_tcp_flags(packet)
            flow.update_application(packet)
            
            # 检查流是否应该结束
            if self._should_finish_flow(flow):
                flow.state = FlowState.FINISHED
                completed_flows.append(flow)
                del self._flows[key]
            
            # 定期清理超时流
            completed_flows.extend(self._cleanup_timeout_flows())
        
        # 返回完成的流（取第一个非空）
        for flow in completed_flows:
            if flow is not None:
                return flow
        
        return None
    
    def _should_finish_flow(self, flow: FlowStats) -> bool:
        """
        判断流是否应该结束
        
        TCP FIN/RST包或流超时
        """
        # 如果有FIN/RST标志，标记为结束
        # 这里简化处理，通过包数判断
        if flow.forward_packets > 0 and flow.backward_packets > 0:
            if flow.forward_packets + flow.backward_packets > 100:
                return True
        
        return False
    
    def _cleanup_timeout_flows(self) -> List[FlowStats]:
        """清理超时的流"""
        now = time.time()
        timeout_flows = []
        
        keys_to_remove = []
        for key, flow in self._flows.items():
            if now - flow.last_time > self.flow_timeout:
                flow.state = FlowState.TIMEOUT
                timeout_flows.append(flow)
                keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del self._flows[key]
        
        if timeout_flows:
            print(f"[DEBUG] Cleaned up {len(timeout_flows)} timeout flows")
        
        return timeout_flows
    
    def get_active_flows(self) -> List[FlowStats]:
        """获取所有活跃流"""
        with self._lock:
            return list(self._flows.values())
    
    def get_flow_count(self) -> int:
        """获取当前活跃流数量"""
        with self._lock:
            return len(self._flows)
    
    def flush_all(self) -> List[FlowStats]:
        """
        强制刷新所有流
        
        Returns:
            所有未完成的流列表
        """
        with self._lock:
            flows = list(self._flows.values())
            for flow in flows:
                flow.state = FlowState.TIMEOUT
            self._flows.clear()
            return flows