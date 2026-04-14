# engine/detection_engine.py
"""检测引擎 - 协调规则匹配和模型判断"""
import time
from typing import Optional
from dataclasses import dataclass
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.rule_matcher import RuleMatcher, MatchResult
from storage.alert_repo import AlertRepository
from storage.packet_cache import PacketCache
from capture.packet_capture import CapturedPacket


@dataclass
class DetectionResult:
    """检测结果"""
    is_threat: bool
    source: str  # 'rule' or 'model'
    sid: Optional[int] = None
    severity: int = 3
    message: str = ""
    matched_content: Optional[str] = None


class DetectionEngine:
    """
    检测引擎
    
    数据流：
    1. 接收原始数据包
    2. 规则匹配（快速路径）
    3. 命中规则 → 立即告警
    4. 未命中 → 缓存包，异步交给模型处理
    """
    
    def __init__(self, async_processor=None):
        """
        初始化检测引擎
        
        Args:
            async_processor: 异步处理器实例
        """
        self.rule_matcher = RuleMatcher()
        self.alert_repo = AlertRepository()
        self.packet_cache = PacketCache()
        self.async_processor = async_processor
        
        # 统计信息
        self.stats = {
            'total_packets': 0,
            'rule_matches': 0,
            'cache_packets': 0,
            'errors': 0
        }
        
        print("[INFO] DetectionEngine initialized")
    
    def process_packet(self, packet: CapturedPacket) -> DetectionResult:
        """
        处理单个数据包
        
        Args:
            packet: 捕获的数据包
            
        Returns:
            DetectionResult: 检测结果
        """
        self.stats['total_packets'] += 1
        
        # 阶段1：规则匹配（快速路径）
        match_result = self.rule_matcher.match(packet)
        
        if match_result.matched:
            # 命中规则，立即告警
            self.stats['rule_matches'] += 1
            
            alert_id = self.alert_repo.save_alert(
                sid=match_result.sid,
                src_ip=packet.src_ip,
                src_port=packet.src_port,
                dst_ip=packet.dst_ip,
                dst_port=packet.dst_port,
                protocol=packet.protocol,
                severity=match_result.severity,
                matched_content=match_result.matched_content,
                payload_preview=packet.payload_preview,
                msg=match_result.msg
            )
            
            return DetectionResult(
                is_threat=True,
                source='rule',
                sid=match_result.sid,
                severity=match_result.severity,
                message=match_result.msg or f"Rule matched: sid={match_result.sid}",
                matched_content=match_result.matched_content
            )
        
        # 阶段2：未命中规则，缓存包等待模型处理
        self.stats['cache_packets'] += 1
        
        # 保存到缓存
        packet_id = self.packet_cache.save_packet(packet)
        
        # 提交给异步处理器
        if self.async_processor:
            self.async_processor.add_packet(packet_id, packet)
        
        return DetectionResult(
            is_threat=False,
            source='pending',
            message="Packet cached for model analysis"
        )
    
    def process_flow(self, flow_stats) -> Optional[DetectionResult]:
        """
        处理完整的流（由异步处理器调用）
        
        Args:
            flow_stats: 聚合后的流统计
            
        Returns:
            DetectionResult: 模型检测结果
        """
        # 对完整流进行规则匹配（包含payload聚合）
        match_result = self.rule_matcher.match_flow(flow_stats)
        
        if match_result.matched:
            # 命中规则
            alert_id = self.alert_repo.save_alert(
                sid=match_result.sid,
                src_ip=flow_stats.key.src_ip,
                src_port=flow_stats.key.src_port,
                dst_ip=flow_stats.key.dst_ip,
                dst_port=flow_stats.key.dst_port,
                protocol=flow_stats.key.protocol,
                severity=match_result.severity,
                matched_content=match_result.matched_content,
                payload_preview=flow_stats.get_payload_preview()
            )
            
            return DetectionResult(
                is_threat=True,
                source='rule',
                sid=match_result.sid,
                severity=match_result.severity,
                message=match_result.msg or f"Rule matched: sid={match_result.sid}"
            )
        
        # 未命中规则，返回None表示需要模型预测
        return None
    
    def get_stats(self) -> dict:
        """获取统计信息"""
        return {
            **self.stats,
            'cache_size': self.packet_cache.size()
        }
    
    def reset_stats(self):
        """重置统计信息"""
        self.stats = {
            'total_packets': 0,
            'rule_matches': 0,
            'cache_packets': 0,
            'errors': 0
        }