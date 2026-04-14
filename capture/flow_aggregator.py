# capture/flow_aggregator.py
"""流聚合器模块 - 将数据包聚合成流，提取流级别统计特征"""
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Optional, List, Tuple
from enum import Enum

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import DETECTION_CONFIG


class FlowState(Enum):
    NEW = "new"
    ACTIVE = "active"
    TIMEOUT = "timeout"
    FINISHED = "finished"


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
    
    def get_bidirectional_key(self) -> tuple:
        """获取双向流键（用于关联请求和响应）"""
        key_tuple = (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol)
        reverse_tuple = (self.dst_ip, self.src_ip, self.dst_port, self.src_port, self.protocol)
        # 按排序后的元组作为双向流标识
        return tuple(sorted([key_tuple, reverse_tuple]))


@dataclass
class FlowStats:
    """
    流统计信息
    
    对应模型需要的24个特征：
    - proto, state: 协议和状态
    - sbytes, dbytes: 源到目的/目的到源的字节数
    - sttl, dttl: 源/目的TTL
    - sloss, dloss: 源/目的丢包数
    - spkts, dpkts: 源/目的包数
    - sjit, djit: 源/目的抖动
    - tcprtt, synack, ackdat: TCP时序特征
    - service: 服务类型
    - ct_srv_src, ct_srv_dst: 连接统计
    - ct_dst_ltm, ct_src_ltm: 时间窗口连接数
    - trans_depth: 传输深度
    - is_sm_ips_ports: 小IP/端口标志
    - ct_flw_http_mthd: HTTP方法计数
    - is_ftp_login: FTP登录标志
    """
    key: FlowKey = None
    start_time: float = 0.0
    last_time: float = 0.0
    state: FlowState = FlowState.NEW
    
    # 包计数 (spkts, dpkts)
    forward_packets: int = 0      # 源->目的
    backward_packets: int = 0     # 目的->源
    
    # 字节计数 (sbytes, dbytes)
    forward_bytes: int = 0
    backward_bytes: int = 0
    
    # TTL统计 (sttl, dttl)
    forward_ttl_sum: int = 0
    backward_ttl_sum: int = 0
    forward_ttl_count: int = 0
    backward_ttl_count: int = 0
    
    # 丢包计数 (sloss, dloss) - 基于TCP序列号
    forward_seq_last: int = 0
    backward_seq_last: int = 0
    forward_loss: int = 0
    backward_loss: int = 0
    
    # 时间戳列表（用于抖动计算 sjit, djit）
    forward_timestamps: List[float] = field(default_factory=list)
    backward_timestamps: List[float] = field(default_factory=list)
    
    # TCP时序特征 (tcprtt, synack, ackdat)
    tcp_syn_time: float = 0.0
    tcp_synack_time: float = 0.0
    tcp_ack_time: float = 0.0
    tcp_rtt: float = 0.0          # 往返时间
    tcp_synack: float = 0.0       # SYN-ACK时间
    tcp_ackdat: float = 0.0       # ACK数据时间
    
    # 应用层特征
    trans_depth: int = 0          # 传输深度（HTTP事务深度）
    is_ftp_login: bool = False    # 是否为FTP登录
    is_sm_ips_ports: bool = False # 是否为小IP/端口
    ct_flw_http_mthd: int = 0     # HTTP方法计数
    
    # 原始payload（用于规则匹配）
    payloads: List[bytes] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.start_time:
            self.start_time = time.time()
        if not self.last_time:
            self.last_time = self.start_time
    
    @property
    def duration(self) -> float:
        return self.last_time - self.start_time
    
    @property
    def forward_ttl(self) -> int:
        """平均源TTL (sttl)"""
        if self.forward_ttl_count > 0:
            return int(self.forward_ttl_sum / self.forward_ttl_count)
        return 64
    
    @property
    def backward_ttl(self) -> int:
        """平均目的TTL (dttl)"""
        if self.backward_ttl_count > 0:
            return int(self.backward_ttl_sum / self.backward_ttl_count)
        return 64
    
    @property
    def forward_jitter(self) -> float:
        """源抖动 (sjit) - 相邻包时间间隔的标准差"""
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
        """目的抖动 (djit)"""
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
    
    def update_forward(self, packet) -> None:
        """更新前向流统计（源->目的）"""
        self.forward_packets += 1
        self.forward_bytes += packet.length
        self.forward_ttl_sum += packet.ttl
        self.forward_ttl_count += 1
        self.forward_timestamps.append(packet.timestamp)
        self.last_time = packet.timestamp
        
        # 保存payload用于规则匹配
        if packet.payload:
            self.payloads.append(packet.payload)
        
        # TCP序列号分析（丢包检测）
        if packet.protocol == 'tcp' and hasattr(packet, 'raw_packet') and packet.raw_packet:
            try:
                tcp = packet.raw_packet['TCP']
                seq = tcp.seq
                if self.forward_seq_last > 0:
                    expected = self.forward_seq_last + 1
                    if seq > expected + 1:
                        self.forward_loss += seq - expected
                self.forward_seq_last = seq
            except Exception:
                pass
    
    def update_backward(self, packet) -> None:
        """更新后向流统计（目的->源）"""
        self.backward_packets += 1
        self.backward_bytes += packet.length
        self.backward_ttl_sum += packet.ttl
        self.backward_ttl_count += 1
        self.backward_timestamps.append(packet.timestamp)
        self.last_time = packet.timestamp
        
        if packet.payload:
            self.payloads.append(packet.payload)
        
        # TCP序列号分析
        if packet.protocol == 'tcp' and hasattr(packet, 'raw_packet') and packet.raw_packet:
            try:
                tcp = packet.raw_packet['TCP']
                seq = tcp.seq
                if self.backward_seq_last > 0:
                    expected = self.backward_seq_last + 1
                    if seq > expected + 1:
                        self.backward_loss += seq - expected
                self.backward_seq_last = seq
            except Exception:
                pass
    
    def update_tcp_flags(self, packet) -> None:
        """更新TCP标志位时序"""
        if packet.protocol != 'tcp':
            return
        
        if not (hasattr(packet, 'raw_packet') and packet.raw_packet):
            return
        
        try:
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
        except Exception:
            pass
    
    def update_application(self, packet) -> None:
        """更新应用层特征"""
        if not packet.payload:
            return
        
        try:
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
        except Exception:
            pass
    
    def add_packet(self, packet, is_forward: bool) -> None:
        """添加数据包到流"""
        if is_forward:
            self.update_forward(packet)
        else:
            self.update_backward(packet)
        
        self.update_tcp_flags(packet)
        self.update_application(packet)
    
    def get_state_string(self) -> str:
        """获取流状态字符串（对应模型的state特征）"""
        if self.forward_packets == 0 and self.backward_packets == 0:
            return 'no'
        if self.state == FlowState.FINISHED:
            return 'FIN'
        if self.duration > 60:
            return 'INT'
        return 'CON'
    
    def get_service(self) -> str:
        """根据端口推断服务类型（对应模型的service特征）"""
        port_to_service = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap',
            443: 'https', 993: 'imaps', 995: 'pop3s', 3306: 'mysql',
            3389: 'rdp', 8080: 'http-proxy'
        }
        
        # 检查目标端口（常见服务）
        if self.key.dst_port in port_to_service:
            return port_to_service[self.key.dst_port]
        if self.key.src_port in port_to_service:
            return port_to_service[self.key.src_port]
        
        return '-'
    
    def check_small_ips_ports(self) -> int:
        """
        检查是否为小IP/端口（对应模型的is_sm_ips_ports特征）
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
                    try:
                        second = int(parts[1])
                        if 16 <= second <= 31:
                            return True
                    except ValueError:
                        pass
            return False
        
        src_private = is_private_ip(self.key.src_ip)
        dst_private = is_private_ip(self.key.dst_ip)
        src_small_port = self.key.src_port < 1024 if self.key.src_port else False
        dst_small_port = self.key.dst_port < 1024 if self.key.dst_port else False
        
        return 1 if (src_private or dst_private or src_small_port or dst_small_port) else 0
    
    def get_all_payload(self) -> bytes:
        """获取流的所有payload（用于规则匹配）"""
        return b''.join(self.payloads)
    
    def get_payload_preview(self, max_len: int = 256) -> str:
        """获取payload预览（十六进制）"""
        payload = self.get_all_payload()
        if not payload:
            return ''
        return payload[:max_len].hex()
    
    def to_feature_dict(self, global_stats: dict = None) -> Dict[str, any]:
        """
        转换为特征字典，供模型使用
        
        Args:
            global_stats: 全局统计信息，包含 ct_srv_src, ct_srv_dst, ct_src_ltm, ct_dst_ltm
        
        Returns:
            包含所有24个特征的字典
        """
        if global_stats is None:
            global_stats = {}
        
        return {
            'proto': self.key.protocol,
            'state': self.get_state_string(),
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
            'service': self.get_service(),
            'ct_srv_src': global_stats.get('ct_srv_src', 0),
            'ct_srv_dst': global_stats.get('ct_srv_dst', 0),
            'ct_dst_ltm': global_stats.get('ct_dst_ltm', 0),
            'ct_src_ltm': global_stats.get('ct_src_ltm', 0),
            'trans_depth': self.trans_depth,
            'is_sm_ips_ports': self.check_small_ips_ports(),
            'ct_flw_http_mthd': self.ct_flw_http_mthd,
            'is_ftp_login': 1 if self.is_ftp_login else 0,
        }


class FlowAggregator:
    """
    流聚合器
    
    将数据包按五元组聚合成流，在流超时或结束后输出完整的流统计
    """
    
    def __init__(self, flow_timeout: int = 60, max_flows: int = 10000):
        """
        初始化流聚合器
        
        Args:
            flow_timeout: 流超时时间（秒），超过此时间未收到包则视为超时
            max_flows: 最大并发流数量
        """
        self.flow_timeout = flow_timeout or DETECTION_CONFIG.get('flow_timeout', 60)
        self.max_flows = max_flows
        self._flows: Dict[FlowKey, FlowStats] = {}
        self._lock = threading.RLock()
        self._last_cleanup = time.time()
        
        print(f"[INFO] FlowAggregator initialized: timeout={self.flow_timeout}s, max_flows={max_flows}")
    
    def add_packet(self, packet) -> Optional[FlowStats]:
        """
        添加数据包到流聚合器
        
        Args:
            packet: CapturedPacket 对象
            
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
        
        with self._lock:
            # 获取或创建流
            if key not in self._flows:
                # 检查流数量限制
                if len(self._flows) >= self.max_flows:
                    self._evict_oldest_flow()
                
                flow = FlowStats(key=key)
                self._flows[key] = flow
                is_forward = True
            else:
                flow = self._flows[key]
                # 判断方向：如果源IP和端口与流键匹配，则是前向
                is_forward = (packet.src_ip == key.src_ip and packet.src_port == key.src_port)
            
            # 更新流统计
            flow.add_packet(packet, is_forward)
            
            # 检查流是否应该结束（TCP FIN/RST或达到最大包数）
            completed_flow = self._check_flow_completion(flow)
            if completed_flow:
                del self._flows[key]
                return completed_flow
        
        # 定期清理超时流
        timeout_flows = self._cleanup_timeout_flows()
        if timeout_flows:
            return timeout_flows[0]  # 返回第一个超时流
        
        return None
    
    def _check_flow_completion(self, flow: FlowStats) -> Optional[FlowStats]:
        """检查流是否应该结束"""
        # TCP FIN/RST 检测（简化：包数超过阈值）
        if flow.forward_packets + flow.backward_packets > 1000:
            flow.state = FlowState.FINISHED
            return flow
        
        # 双向都有数据且持续时间超过30秒
        if flow.forward_packets > 0 and flow.backward_packets > 0 and flow.duration > 30:
            flow.state = FlowState.FINISHED
            return flow
        
        return None
    
    def _cleanup_timeout_flows(self) -> List[FlowStats]:
        """清理超时的流"""
        now = time.time()
        
        # 每10秒清理一次
        if now - self._last_cleanup < 10:
            return []
        
        self._last_cleanup = now
        timeout_flows = []
        
        with self._lock:
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
    
    def _evict_oldest_flow(self) -> None:
        """淘汰最旧的流（当流数量超限时）"""
        if not self._flows:
            return
        
        oldest_key = min(self._flows.keys(), key=lambda k: self._flows[k].last_time)
        oldest_flow = self._flows[oldest_key]
        oldest_flow.state = FlowState.TIMEOUT
        del self._flows[oldest_key]
        print(f"[WARNING] Evicted oldest flow due to limit: {oldest_key}")
    
    def flush_all(self) -> List[FlowStats]:
        """强制刷新所有流"""
        with self._lock:
            flows = list(self._flows.values())
            for flow in flows:
                flow.state = FlowState.TIMEOUT
            self._flows.clear()
            return flows
    
    def get_active_flow_count(self) -> int:
        """获取当前活跃流数量"""
        with self._lock:
            return len(self._flows)