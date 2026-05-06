"""流聚合器模块 - 将数据包聚合成流，提取流级别统计特征"""
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Optional, List, Tuple
from enum import Enum
import sys, os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import DETECTION_CONFIG


class FlowState(Enum):
    """流状态枚举"""
    NEW = "new"          # 新流
    ACTIVE = "active"    # 活跃流
    TIMEOUT = "timeout"  # 超时流
    FINISHED = "finished"  # 已完成流


@dataclass
class FlowKey:
    """流标识符（五元组）"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    
    def __hash__(self):
        """哈希值，用于字典键"""
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol))
    
    def __eq__(self, other):
        """相等判断"""
        if not isinstance(other, FlowKey):
            return False
        return (self.src_ip == other.src_ip and self.dst_ip == other.dst_ip and
                self.src_port == other.src_port and self.dst_port == other.dst_port and
                self.protocol == other.protocol)
    
    def get_bidirectional_key(self) -> tuple:
        """获取双向流键（用于关联请求和响应）
        
        Returns:
            排序后的五元组元组，使正反方向流使用相同键
        """
        key_tuple = (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol)
        reverse_tuple = (self.dst_ip, self.src_ip, self.dst_port, self.src_port, self.protocol)
        return tuple(sorted([key_tuple, reverse_tuple]))


@dataclass
class FlowStats:
    """流统计信息（对应模型需要的24个特征）"""
    key: FlowKey = None
    start_time: float = 0.0
    last_time: float = 0.0
    state: FlowState = FlowState.NEW
    
    # 包计数和字节计数
    forward_packets: int = 0      # 源->目的包数
    backward_packets: int = 0     # 目的->源包数
    forward_bytes: int = 0        # 源->目的字节数
    backward_bytes: int = 0       # 目的->源字节数
    
    # TTL统计
    forward_ttl_sum: int = 0      # 源TTL累加
    backward_ttl_sum: int = 0     # 目的TTL累加
    forward_ttl_count: int = 0    # 源TTL计数
    backward_ttl_count: int = 0   # 目的TTL计数
    
    # 丢包计数（基于TCP序列号）
    forward_seq_last: int = 0     # 最后收到的源序列号
    backward_seq_last: int = 0    # 最后收到的目的序列号
    forward_loss: int = 0         # 源方向丢包数
    backward_loss: int = 0        # 目的方向丢包数
    
    # 时间戳列表（用于抖动计算）
    forward_timestamps: List[float] = field(default_factory=list)
    backward_timestamps: List[float] = field(default_factory=list)
    
    # TCP时序特征
    tcp_syn_time: float = 0.0     # SYN包时间
    tcp_synack_time: float = 0.0  # SYN-ACK包时间
    tcp_ack_time: float = 0.0     # ACK包时间
    tcp_rtt: float = 0.0          # 往返时间
    tcp_synack: float = 0.0       # SYN-ACK响应时间
    tcp_ackdat: float = 0.0       # ACK数据时间
    
    # 应用层特征
    trans_depth: int = 0          # HTTP事务深度
    is_ftp_login: bool = False    # 是否FTP登录
    is_sm_ips_ports: bool = False # 是否小IP/端口
    ct_flw_http_mthd: int = 0     # HTTP方法计数
    
    # 原始payload
    payloads: List[bytes] = field(default_factory=list)
    
    def __post_init__(self):
        """初始化后设置时间戳"""
        if not self.start_time:
            self.start_time = time.time()
        if not self.last_time:
            self.last_time = self.start_time
    
    @property
    def duration(self) -> float:
        """流持续时间（秒）"""
        return self.last_time - self.start_time
    
    @property
    def forward_ttl(self) -> int:
        """平均源TTL (sttl)"""
        return int(self.forward_ttl_sum / self.forward_ttl_count) if self.forward_ttl_count > 0 else 64
    
    @property
    def backward_ttl(self) -> int:
        """平均目的TTL (dttl)"""
        return int(self.backward_ttl_sum / self.backward_ttl_count) if self.backward_ttl_count > 0 else 64
    
    def _calc_jitter(self, timestamps: List[float]) -> float:
        """计算抖动（相邻包时间间隔的标准差）
        
        Args:
            timestamps: 时间戳列表
        
        Returns:
            抖动值（秒）
        """
        if len(timestamps) < 2:
            return 0.0
        diffs = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
        mean = sum(diffs) / len(diffs)
        variance = sum((d - mean) ** 2 for d in diffs) / len(diffs)
        return variance ** 0.5
    
    @property
    def forward_jitter(self) -> float:
        """源抖动 (sjit)"""
        return self._calc_jitter(self.forward_timestamps)
    
    @property
    def backward_jitter(self) -> float:
        """目的抖动 (djit)"""
        return self._calc_jitter(self.backward_timestamps)
    
    def _update_common(self, packet, is_forward: bool) -> None:
        """通用更新逻辑（包计数、字节计数、TTL、时间戳）
        
        Args:
            packet: 数据包对象
            is_forward: 是否为前向包
        """
        if is_forward:
            self.forward_packets += 1
            self.forward_bytes += packet.length
            self.forward_ttl_sum += packet.ttl
            self.forward_ttl_count += 1
            self.forward_timestamps.append(packet.timestamp)
        else:
            self.backward_packets += 1
            self.backward_bytes += packet.length
            self.backward_ttl_sum += packet.ttl
            self.backward_ttl_count += 1
            self.backward_timestamps.append(packet.timestamp)
        
        self.last_time = packet.timestamp
        
        if packet.payload:
            self.payloads.append(packet.payload)
    
    def _update_loss(self, packet, is_forward: bool) -> None:
        """更新丢包统计（基于TCP序列号）
        
        Args:
            packet: 数据包对象
            is_forward: 是否为前向包
        """
        if packet.protocol != 'tcp' or not (hasattr(packet, 'raw_packet') and packet.raw_packet):
            return
        
        try:
            tcp = packet.raw_packet['TCP']
            seq = tcp.seq
            
            if is_forward:
                if self.forward_seq_last > 0 and seq > self.forward_seq_last + 1:
                    self.forward_loss += seq - self.forward_seq_last - 1
                self.forward_seq_last = seq
            else:
                if self.backward_seq_last > 0 and seq > self.backward_seq_last + 1:
                    self.backward_loss += seq - self.backward_seq_last - 1
                self.backward_seq_last = seq
        except Exception:
            pass
    
    def update_forward(self, packet) -> None:
        """更新前向流统计（源->目的）"""
        self._update_common(packet, True)
        self._update_loss(packet, True)
    
    def update_backward(self, packet) -> None:
        """更新后向流统计（目的->源）"""
        self._update_common(packet, False)
        self._update_loss(packet, False)
    
    def update_tcp_flags(self, packet) -> None:
        """更新TCP标志位时序（SYN、SYN-ACK、ACK）
        
        Args:
            packet: 数据包对象
        """
        if packet.protocol != 'tcp' or not (hasattr(packet, 'raw_packet') and packet.raw_packet):
            return
        
        try:
            tcp = packet.raw_packet['TCP']
            flags = tcp.flags
            
            # SYN包
            if flags & 0x02 and self.tcp_syn_time == 0:
                self.tcp_syn_time = packet.timestamp
            
            # SYN-ACK包
            if (flags & 0x12) == 0x12 and self.tcp_synack_time == 0 and self.tcp_syn_time > 0:
                self.tcp_synack_time = packet.timestamp
                self.tcp_synack = self.tcp_synack_time - self.tcp_syn_time
            
            # ACK包
            if flags & 0x10 and self.tcp_ack_time == 0 and self.tcp_synack_time > 0:
                self.tcp_ack_time = packet.timestamp
                self.tcp_ackdat = self.tcp_ack_time - self.tcp_synack_time
                self.tcp_rtt = self.tcp_ack_time - self.tcp_syn_time
        except Exception:
            pass
    
    def update_application(self, packet) -> None:
        """更新应用层特征（FTP登录、HTTP方法、HTTP事务深度）
        
        Args:
            packet: 数据包对象
        """
        if not packet.payload:
            return
        
        try:
            payload_str = packet.payload.decode('utf-8', errors='ignore').lower()
            
            # FTP登录检测
            if not self.is_ftp_login and ('user ' in payload_str or 'pass ' in payload_str):
                self.is_ftp_login = True
            
            # HTTP方法计数
            for method in ['get ', 'post ', 'put ', 'delete ', 'head ', 'options ']:
                if method in payload_str:
                    self.ct_flw_http_mthd += 1
                    break
            
            # HTTP事务深度
            if 'http' in payload_str or 'https' in payload_str:
                self.trans_depth += 1
        except Exception:
            pass
    
    def add_packet(self, packet, is_forward: bool) -> None:
        """添加数据包到流
        
        Args:
            packet: 数据包对象
            is_forward: 是否为前向包
        """
        if is_forward:
            self.update_forward(packet)
        else:
            self.update_backward(packet)
        self.update_tcp_flags(packet)
        self.update_application(packet)
    
    def get_state_string(self) -> str:
        """获取流状态字符串（对应模型的state特征）
        
        Returns:
            no/FIN/INT/CON 状态字符串
        """
        if self.forward_packets == 0 and self.backward_packets == 0:
            return 'no'
        if self.state == FlowState.FINISHED:
            return 'FIN'
        if self.duration > 60:
            return 'INT'
        return 'CON'
    
    def get_service(self) -> str:
        """根据端口推断服务类型（对应模型的service特征）
        
        Returns:
            服务名称字符串
        """
        port_to_service = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 993: 'imaps',
            995: 'pop3s', 3306: 'mysql', 3389: 'rdp', 8080: 'http-proxy'
        }
        if self.key.dst_port in port_to_service:
            return port_to_service[self.key.dst_port]
        if self.key.src_port in port_to_service:
            return port_to_service[self.key.src_port]
        return '-'
    
    def check_small_ips_ports(self) -> int:
        """检查是否为小IP/端口（私有IP或端口<1024）
        
        Returns:
            1表示是小IP/端口，0表示不是
        """
        def is_private_ip(ip: str) -> bool:
            """检查是否为私有IP地址"""
            if ip.startswith('10.') or ip.startswith('192.168.'):
                return True
            if ip.startswith('172.'):
                parts = ip.split('.')
                if len(parts) >= 2:
                    try:
                        return 16 <= int(parts[1]) <= 31
                    except ValueError:
                        pass
            return False
        
        src_private = is_private_ip(self.key.src_ip)
        dst_private = is_private_ip(self.key.dst_ip)
        src_small_port = self.key.src_port < 1024 if self.key.src_port else False
        dst_small_port = self.key.dst_port < 1024 if self.key.dst_port else False
        
        return 1 if (src_private or dst_private or src_small_port or dst_small_port) else 0
    
    def get_all_payload(self) -> bytes:
        """获取流的所有payload"""
        return b''.join(self.payloads)
    
    def get_payload_preview(self, max_len: int = 256) -> str:
        """获取payload预览（十六进制）
        
        Args:
            max_len: 最大长度，默认256字节
        
        Returns:
            十六进制字符串
        """
        payload = self.get_all_payload()
        return payload[:max_len].hex() if payload else ''
    
    def to_feature_dict(self, global_stats: dict = None) -> Dict[str, any]:
        """转换为特征字典，供模型使用
        
        Args:
            global_stats: 全局统计信息，包含ct_srv_src、ct_srv_dst、ct_src_ltm、ct_dst_ltm
        
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
    """流聚合器 - 将数据包按五元组聚合成流"""
    
    def __init__(self, flow_timeout: int = 60, max_flows: int = 10000):
        """初始化流聚合器
        
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
        """添加数据包到流聚合器
        
        Args:
            packet: CapturedPacket对象
        
        Returns:
            如果流超时或结束，返回完成的流统计；否则返回None
        """
        key = FlowKey(
            src_ip=packet.src_ip, dst_ip=packet.dst_ip,
            src_port=packet.src_port, dst_port=packet.dst_port,
            protocol=packet.protocol
        )
        
        with self._lock:
            if key not in self._flows:
                if len(self._flows) >= self.max_flows:
                    self._evict_oldest_flow()
                flow = FlowStats(key=key)
                self._flows[key] = flow
                is_forward = True
            else:
                flow = self._flows[key]
                is_forward = (packet.src_ip == key.src_ip and packet.src_port == key.src_port)
            
            flow.add_packet(packet, is_forward)
            
            completed_flow = self._check_flow_completion(flow)
            if completed_flow:
                del self._flows[key]
                return completed_flow
        
        timeout_flows = self._cleanup_timeout_flows()
        return timeout_flows[0] if timeout_flows else None
    
    def _check_flow_completion(self, flow: FlowStats) -> Optional[FlowStats]:
        """检查流是否应该结束
        
        Args:
            flow: 流统计对象
        
        Returns:
            如果流应该结束则返回流对象，否则返回None
        """
        total_packets = flow.forward_packets + flow.backward_packets
        # 包数超过阈值
        if total_packets > 1000:
            flow.state = FlowState.FINISHED
            return flow
        # 双向都有数据且持续时间超过30秒
        if flow.forward_packets > 0 and flow.backward_packets > 0 and flow.duration > 30:
            flow.state = FlowState.FINISHED
            return flow
        return None
    
    def _cleanup_timeout_flows(self) -> List[FlowStats]:
        """清理超时的流
        
        Returns:
            超时流列表
        """
        now = time.time()
        # 每10秒清理一次
        if now - self._last_cleanup < 10:
            return []
        
        self._last_cleanup = now
        timeout_flows = []
        
        with self._lock:
            # 找出超时的流
            keys_to_remove = [key for key, flow in self._flows.items() 
                            if now - flow.last_time > self.flow_timeout]
            for key in keys_to_remove:
                flow = self._flows[key]
                flow.state = FlowState.TIMEOUT
                timeout_flows.append(flow)
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
        """强制刷新所有流
        
        Returns:
            所有流统计列表
        """
        with self._lock:
            flows = list(self._flows.values())
            for flow in flows:
                flow.state = FlowState.TIMEOUT
            self._flows.clear()
            return flows
    
    def get_active_flow_count(self) -> int:
        """获取当前活跃流数量
        
        Returns:
            活跃流数量
        """
        with self._lock:
            return len(self._flows)
