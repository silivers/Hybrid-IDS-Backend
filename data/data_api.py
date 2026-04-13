#!/usr/bin/env python
"""
data/data_api.py - 实时数据流生成API
持续捕获网络流量，直到应用关闭
"""

import sys
import os
import time
import signal
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass

# 添加项目根目录到路径（用于直接运行）
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data.packet_capture import PacketCapturer, CapturedPacket
from data.flow_aggregator import FlowAggregator, FlowStats
from data.feature_extractor import FeatureExtractor


@dataclass
class FlowData:
    """
    流数据结构 - 包含完整的流信息和特征
    可直接用于模型预测
    """
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    duration: float
    forward_packets: int
    backward_packets: int
    forward_bytes: int
    backward_bytes: int
    features: Dict[str, any]
    raw_flow: Optional[FlowStats] = None
    
    def to_dict(self) -> Dict:
        """转换为字典格式"""
        return {
            'src': f"{self.src_ip}:{self.src_port}",
            'dst': f"{self.dst_ip}:{self.dst_port}",
            'protocol': self.protocol,
            'duration': self.duration,
            'packets': f"{self.forward_packets}→{self.backward_packets}",
            'bytes': f"{self.forward_bytes}→{self.backward_bytes}",
            'features': self.features
        }
    
    def get_feature_array(self) -> List[float]:
        """获取特征数组（按模型需要的顺序）"""
        feature_order = [
            'proto', 'state', 'sbytes', 'dbytes', 'sttl', 'dttl',
            'sloss', 'dloss', 'spkts', 'dpkts', 'sjit', 'djit',
            'tcprtt', 'synack', 'ackdat', 'service', 'ct_srv_src',
            'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm', 'trans_depth',
            'is_sm_ips_ports', 'ct_flw_http_mthd', 'is_ftp_login'
        ]
        
        result = []
        for feat_name in feature_order:
            value = self.features.get(feat_name)
            if feat_name in ['proto', 'state', 'service']:
                result.append(hash(str(value)) % 100)
            else:
                result.append(float(value) if value is not None else 0.0)
        
        return result


class LiveFlowGenerator:
    """实时流生成器 - 持续捕获，直到手动停止"""
    
    def __init__(self, flow_timeout: int = 60, reset_stats: bool = True):
        self.flow_timeout = flow_timeout
        self.aggregator = None
        self.extractor = None
        self.capturer = None
        self.reset_stats = reset_stats
        self._on_flow_callback = None
        self._running = False
        self._init_components()
    
    def _init_components(self):
        self.aggregator = FlowAggregator(flow_timeout=self.flow_timeout)
        self.extractor = FeatureExtractor()
        if self.reset_stats:
            self.extractor.reset()
    
    def reset(self):
        self._init_components()
    
    def _flow_to_flowdata(self, flow: FlowStats) -> Optional[FlowData]:
        try:
            features = self.extractor.extract_features(flow)
            if not features:
                return None
            
            return FlowData(
                src_ip=flow.key.src_ip,
                src_port=flow.key.src_port,
                dst_ip=flow.key.dst_ip,
                dst_port=flow.key.dst_port,
                protocol=flow.key.protocol,
                duration=flow.duration,
                forward_packets=flow.forward_packets,
                backward_packets=flow.backward_packets,
                forward_bytes=flow.forward_bytes,
                backward_bytes=flow.backward_bytes,
                features=features,
                raw_flow=flow
            )
        except Exception as e:
            print(f"[ERROR] 流数据转换失败: {e}")
            return None
    
    def _on_packet(self, packet: CapturedPacket):
        if not self._running:
            return
        completed_flow = self.aggregator.add_packet(packet)
        if completed_flow:
            flow_data = self._flow_to_flowdata(completed_flow)
            if flow_data and self._on_flow_callback:
                self._on_flow_callback(flow_data)
    
    def start(self, interface: str = None, filter_str: str = None, 
              callback: Callable[[FlowData], None] = None):
        print(f"[INFO] 开始持续捕获: interface={interface or 'any'}")
        self._running = True
        self._on_flow_callback = callback
        self.capturer = PacketCapturer(interface=interface, filter_str=filter_str, packet_count=-1)
        self.capturer.start(callback=self._on_packet)
        print("[INFO] 持续捕获已启动，按 Ctrl+C 停止")
    
    def stop(self):
        self._running = False
        if self.capturer:
            self.capturer.stop()
        if self.aggregator:
            for flow in self.aggregator.flush_all():
                flow_data = self._flow_to_flowdata(flow)
                if flow_data and self._on_flow_callback:
                    self._on_flow_callback(flow_data)
    
    def is_running(self) -> bool:
        return self._running and self.capturer is not None and self.capturer.is_running
    
    def get_stats(self) -> Dict:
        if self.aggregator:
            return {'active_flows': self.aggregator.get_flow_count(), 'is_capturing': self.is_running()}
        return {'active_flows': 0, 'is_capturing': False}


# 全局实例
_default_generator = None


def _signal_handler(sig, frame):
    global _default_generator
    print("\n\n[INFO] 收到停止信号，正在关闭...")
    if _default_generator:
        _default_generator.stop()
    sys.exit(0)


def start_capture(interface: str = None, filter_str: str = None,
                  callback: Callable[[FlowData], None] = None):
    """启动持续捕获（直到应用关闭）"""
    global _default_generator
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    _default_generator = LiveFlowGenerator()
    _default_generator.start(interface=interface, filter_str=filter_str, callback=callback)
    try:
        while _default_generator.is_running():
            time.sleep(1)
    except KeyboardInterrupt:
        _signal_handler(None, None)


def capture_flows(interface: str = None, filter_str: str = None,
                  callback: Callable[[FlowData], None] = None):
    """持续捕获流量（别名函数）"""
    start_capture(interface=interface, filter_str=filter_str, callback=callback)


def get_generator() -> LiveFlowGenerator:
    global _default_generator
    if _default_generator is None:
        _default_generator = LiveFlowGenerator()
    return _default_generator


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='实时数据流捕获API')
    parser.add_argument('-i', '--interface', type=str, default=None, help='网卡接口')
    parser.add_argument('-f', '--filter', type=str, default=None, help='BPF过滤器')
    args = parser.parse_args()
    
    print("="*60)
    print("实时数据流捕获 - 持续运行模式")
    print("按 Ctrl+C 停止\n")
    
    def on_flow(flow):
        print(f"\n[流] {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port}")
        print(f"  协议: {flow.protocol}, 包数: {flow.forward_packets}→{flow.backward_packets}")
    
    start_capture(interface=args.interface, filter_str=args.filter, callback=on_flow)