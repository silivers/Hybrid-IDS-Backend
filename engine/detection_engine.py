# engine/detection_engine.py
"""检测引擎 - 协调规则匹配和模型判断"""
import time
from typing import Optional, Dict, Set, Tuple
from dataclasses import dataclass
from collections import defaultdict
import sys
import os
import threading

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
        
        # ========== 告警去重缓存 ==========
        # key: (src_ip, dst_ip, dst_port, protocol, sid) - 不包含源端口（因为端口会变化）
        # value: 上次告警时间戳
        self._alert_cache: Dict[Tuple, float] = {}
        self._alert_cache_ttl = 60  # 60秒内同一目标+同一规则只告警一次
        
        # 更细粒度的去重：按五元组+规则
        self._alert_cache_detailed: Dict[Tuple, float] = {}
        self._alert_cache_detailed_ttl = 30  # 30秒内同一五元组+规则只告警一次
        
        # 流级别已处理标记（整个流只处理一次）
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
        
        # 启动清理线程
        self._stop_cleanup = False
        self._start_cleanup_thread()
        
        print("[INFO] DetectionEngine initialized with multi-level deduplication")
    
    def _start_cleanup_thread(self):
        """启动缓存清理线程"""
        def cleanup_loop():
            while not self._stop_cleanup:
                time.sleep(30)  # 每30秒清理一次
                self._cleanup_expired_cache()
        
        cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        cleanup_thread.start()
    
    def _cleanup_expired_cache(self):
        """清理过期的缓存"""
        now = time.time()
        
        # 清理普通缓存
        expired = [k for k, ts in self._alert_cache.items() if now - ts > self._alert_cache_ttl]
        for k in expired:
            del self._alert_cache[k]
        
        # 清理详细缓存
        expired = [k for k, ts in self._alert_cache_detailed.items() 
                   if now - ts > self._alert_cache_detailed_ttl]
        for k in expired:
            del self._alert_cache_detailed[k]
        
        # 清理流缓存（简单清理：超过1000条就清空一半）
        if len(self._processed_flows) > 1000:
            self._processed_flows = set(list(self._processed_flows)[-500:])
    
    def _get_flow_key(self, packet: CapturedPacket) -> str:
        """生成流的唯一标识（不包含源端口，因为攻击可能变化源端口）"""
        return f"{packet.src_ip}->{packet.dst_ip}:{packet.dst_port}-{packet.protocol}"
    
    def _get_alert_cache_key(self, packet: CapturedPacket, sid: int, detailed: bool = False) -> tuple:
        """生成告警缓存的键"""
        if detailed:
            # 详细模式：包含源端口（更严格）
            return (
                packet.src_ip, packet.src_port,
                packet.dst_ip, packet.dst_port,
                packet.protocol, sid
            )
        else:
            # 普通模式：不包含源端口（宽松去重，防止端口扫描刷屏）
            return (
                packet.src_ip,
                packet.dst_ip, packet.dst_port,
                packet.protocol, sid
            )
    
    def _is_duplicate_alert(self, packet: CapturedPacket, sid: int) -> bool:
        """检查是否为重复告警"""
        now = time.time()
        
        # 1. 先检查详细缓存（同五元组+规则）
        detailed_key = self._get_alert_cache_key(packet, sid, detailed=True)
        if detailed_key in self._alert_cache_detailed:
            self.stats['deduplicated_alerts'] += 1
            return True
        
        # 2. 再检查普通缓存（同目标+规则，忽略源端口）
        normal_key = self._get_alert_cache_key(packet, sid, detailed=False)
        if normal_key in self._alert_cache:
            self.stats['deduplicated_alerts'] += 1
            return True
        
        # 记录本次告警
        self._alert_cache[normal_key] = now
        self._alert_cache_detailed[detailed_key] = now
        
        return False
    
    def _is_flow_processed(self, flow_key: str) -> bool:
        """检查流是否已经处理过"""
        return flow_key in self._processed_flows
    
    def _mark_flow_processed(self, flow_key: str):
        """标记流已处理"""
        self._processed_flows.add(flow_key)
    
    def process_packet(self, packet: CapturedPacket) -> DetectionResult:
        """
        处理单个数据包
        
        Args:
            packet: 捕获的数据包
            
        Returns:
            DetectionResult: 检测结果
        """
        self.stats['total_packets'] += 1
        
        # 生成流键
        flow_key = self._get_flow_key(packet)
        
        # 如果整个流已经处理过，跳过所有后续包
        if self._is_flow_processed(flow_key):
            return DetectionResult(
                is_threat=False,
                source='skipped',
                message="Flow already processed"
            )
        
        # 阶段1：规则匹配（快速路径）
        match_result = self.rule_matcher.match(packet)
        
        if match_result.matched:
            # 检查是否为重复告警
            if self._is_duplicate_alert(packet, match_result.sid):
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
            
            # 标记整个流已处理（防止后续包继续告警）
            self._mark_flow_processed(flow_key)
            
            print(f"[ALERT] sid={match_result.sid}, src={packet.src_ip}:{packet.src_port} -> "
                  f"dst={packet.dst_ip}:{packet.dst_port}, severity={match_result.severity}, "
                  f"content={match_result.matched_content} (alert_id={alert_id})")
            
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
        flow_key = f"{flow_stats.key.src_ip}->{flow_stats.key.dst_ip}:{flow_stats.key.dst_port}-{flow_stats.key.protocol}"
        
        # 检查是否已处理
        if self._is_flow_processed(flow_key):
            return None
        
        # 对完整流进行规则匹配（包含payload聚合）
        match_result = self.rule_matcher.match_flow(flow_stats)
        
        if match_result.matched:
            # 构造模拟packet用于去重检查
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
                self._mark_flow_processed(flow_key)
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
                payload_preview=flow_stats.get_payload_preview(),
                msg=match_result.msg
            )
            
            self._mark_flow_processed(flow_key)
            
            print(f"[ALERT] sid={match_result.sid}, src={flow_stats.key.src_ip}:{flow_stats.key.src_port} -> "
                  f"dst={flow_stats.key.dst_ip}:{flow_stats.key.dst_port}, severity={match_result.severity}, "
                  f"content={match_result.matched_content} (flow alert_id={alert_id})")
            
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
            'alert_cache_size': len(self._alert_cache),
            'alert_detailed_cache_size': len(self._alert_cache_detailed),
            'processed_flows_size': len(self._processed_flows)
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
    
    def clear_caches(self):
        """清空所有缓存"""
        self._alert_cache.clear()
        self._alert_cache_detailed.clear()
        self._processed_flows.clear()
        print("[INFO] All detection caches cleared")
    
    def shutdown(self):
        """关闭检测引擎"""
        self._stop_cleanup = True
        self.clear_caches()
        print("[INFO] DetectionEngine shutdown")