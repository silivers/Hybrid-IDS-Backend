# engine/detection_engine.py
"""检测引擎 - 协调规则匹配和模型判断"""
import time
from typing import Optional, Dict, Set
from dataclasses import dataclass
from collections import defaultdict
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
    3. 命中规则 → 流级别去重 → 立即告警
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
        
        # 告警去重缓存
        # key: (src_ip, dst_ip, src_port, dst_port, protocol, sid)
        # value: 上次告警时间戳
        self._alert_cache: Dict[tuple, float] = {}
        self._alert_cache_ttl = 60  # 同一流+同一规则60秒内只告警一次
        
        # 流级别已处理标记（避免同一流重复产生告警）
        self._processed_flows: Set[str] = set()
        self._flow_cache_ttl = 300  # 5分钟
        
        # 统计信息
        self.stats = {
            'total_packets': 0,
            'rule_matches': 0,
            'deduplicated_alerts': 0,
            'cache_packets': 0,
            'errors': 0
        }
        
        print("[INFO] DetectionEngine initialized with alert deduplication")
    
    def _get_flow_key(self, packet: CapturedPacket) -> str:
        """生成流的唯一标识"""
        return f"{packet.src_ip}:{packet.src_port}-{packet.dst_ip}:{packet.dst_port}-{packet.protocol}"
    
    def _get_alert_cache_key(self, packet: CapturedPacket, sid: int) -> tuple:
        """生成告警缓存的键"""
        return (
            packet.src_ip, packet.dst_ip, 
            packet.src_port, packet.dst_port,
            packet.protocol, sid
        )
    
    def _is_duplicate_alert(self, packet: CapturedPacket, sid: int) -> bool:
        """检查是否为重复告警"""
        cache_key = self._get_alert_cache_key(packet, sid)
        now = time.time()
        
        # 清理过期缓存
        expired_keys = [
            k for k, ts in self._alert_cache.items() 
            if now - ts > self._alert_cache_ttl
        ]
        for k in expired_keys:
            del self._alert_cache[k]
        
        # 检查是否重复
        if cache_key in self._alert_cache:
            self.stats['deduplicated_alerts'] += 1
            return True
        
        # 记录本次告警
        self._alert_cache[cache_key] = now
        return False
    
    def _is_flow_processed(self, flow_key: str, sid: int = None) -> bool:
        """检查流是否已经处理过（用于模型检测）"""
        key = f"{flow_key}:{sid}" if sid else flow_key
        
        # 清理过期
        now = time.time()
        # 注意：这里简化处理，实际可以用带时间戳的字典
        return key in self._processed_flows
    
    def _mark_flow_processed(self, flow_key: str, sid: int = None):
        """标记流已处理"""
        key = f"{flow_key}:{sid}" if sid else flow_key
        self._processed_flows.add(key)
        # 定期清理（简单实现：超过1000个就清空一半）
        if len(self._processed_flows) > 1000:
            # 转换为列表并保留后500个
            self._processed_flows = set(list(self._processed_flows)[-500:])
    
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
            # 检查是否为重复告警（同一流+同一规则）
            if self._is_duplicate_alert(packet, match_result.sid):
                # 重复告警，不写入数据库
                return DetectionResult(
                    is_threat=True,
                    source='rule_deduplicated',
                    sid=match_result.sid,
                    severity=match_result.severity,
                    message=f"Duplicate alert suppressed: sid={match_result.sid}"
                )
            
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
            
            # 标记流已处理
            flow_key = self._get_flow_key(packet)
            self._mark_flow_processed(flow_key, match_result.sid)
            
            return DetectionResult(
                is_threat=True,
                source='rule',
                sid=match_result.sid,
                severity=match_result.severity,
                message=match_result.msg or f"Rule matched: sid={match_result.sid}",
                matched_content=match_result.matched_content
            )
        
        # 阶段2：未命中规则，缓存包等待模型处理
        # 检查是否已经是重复流
        flow_key = self._get_flow_key(packet)
        if self._is_flow_processed(flow_key):
            # 这个流已经处理过了，跳过
            return DetectionResult(
                is_threat=False,
                source='skipped',
                message="Flow already processed"
            )
        
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
        flow_key = f"{flow_stats.key.src_ip}:{flow_stats.key.src_port}-{flow_stats.key.dst_ip}:{flow_stats.key.dst_port}-{flow_stats.key.protocol}"
        
        # 检查是否已处理
        if self._is_flow_processed(flow_key):
            return None
        
        # 对完整流进行规则匹配（包含payload聚合）
        match_result = self.rule_matcher.match_flow(flow_stats)
        
        if match_result.matched:
            # 检查重复
            # 构造一个模拟packet用于去重检查
            class MockPacket:
                def __init__(self, flow):
                    self.src_ip = flow.key.src_ip
                    self.dst_ip = flow.key.dst_ip
                    self.src_port = flow.key.src_port
                    self.dst_port = flow.key.dst_port
                    self.protocol = flow.key.protocol
                    self.payload_preview = flow.get_payload_preview()
            
            mock_packet = MockPacket(flow_stats)
            if self._is_duplicate_alert(mock_packet, match_result.sid):
                self._mark_flow_processed(flow_key, match_result.sid)
                return None
            
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
            
            self._mark_flow_processed(flow_key, match_result.sid)
            
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
            'cache_size': self.packet_cache.size(),
            'alert_cache_size': len(self._alert_cache)
        }
    
    def reset_stats(self):
        """重置统计信息"""
        self.stats = {
            'total_packets': 0,
            'rule_matches': 0,
            'deduplicated_alerts': 0,
            'cache_packets': 0,
            'errors': 0
        }
        self._alert_cache.clear()
        self._processed_flows.clear()