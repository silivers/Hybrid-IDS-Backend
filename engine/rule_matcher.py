# engine/rule_matcher.py
"""规则匹配器 - 查询MySQL规则库"""
import re
import time
from typing import Optional, Tuple, Dict, Any
from dataclasses import dataclass
from functools import lru_cache
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage.rule_repo import RuleRepository


@dataclass
class MatchResult:
    """规则匹配结果"""
    matched: bool
    sid: Optional[int] = None
    msg: Optional[str] = None
    severity: int = 3
    matched_content: Optional[str] = None
    classtype: Optional[str] = None


class RuleMatcher:
    """
    规则匹配器
    
    根据数据包的五元组和payload匹配Snort规则
    """
    
    def __init__(self):
        """初始化规则匹配器"""
        self.rule_repo = RuleRepository()
        
        # 匹配结果缓存
        self._match_cache: Dict[tuple, Tuple[bool, float]] = {}
        self._cache_ttl = 10  # 10秒内相同包不重复匹配
        
        print("[INFO] RuleMatcher initialized with caching")
    
    def _get_cache_key(self, packet) -> tuple:
        """生成缓存键"""
        return (
            packet.src_ip, packet.src_port,
            packet.dst_ip, packet.dst_port,
            packet.protocol,
            hash(packet.payload[:100]) if packet.payload else 0  # 只哈希前100字节
        )
    
    def match(self, packet) -> MatchResult:
        """
        匹配单个数据包（带缓存）
        
        Args:
            packet: CapturedPacket 对象
            
        Returns:
            MatchResult 匹配结果
        """
        # 检查缓存
        cache_key = self._get_cache_key(packet)
        now = time.time()
        
        if cache_key in self._match_cache:
            matched, timestamp = self._match_cache[cache_key]
            if now - timestamp < self._cache_ttl:
                if not matched:
                    return MatchResult(matched=False)
                # 缓存命中且匹配成功，需要重新获取规则详情
                # 这里简化处理，继续执行匹配
        
        # 1. 先匹配五元组规则
        rule = self.rule_repo.find_rule_by_5tuple(
            protocol=packet.protocol,
            src_ip=packet.src_ip,
            src_port=packet.src_port,
            dst_ip=packet.dst_ip,
            dst_port=packet.dst_port
        )
        
        result = MatchResult(matched=False)
        
        if rule:
            # 2. 如果有payload匹配条件，进一步匹配
            if self._match_payload(rule, packet.payload):
                result = MatchResult(
                    matched=True,
                    sid=rule['sid'],
                    msg=rule.get('msg'),
                    severity=rule.get('severity', 3),
                    matched_content=self._extract_matched_content(rule, packet.payload),
                    classtype=rule.get('classtype')
                )
        
        # 缓存结果（只缓存不匹配的结果，匹配的结果不缓存因为需要详细信息）
        if not result.matched:
            self._match_cache[cache_key] = (False, now)
            
            # 定期清理缓存
            if len(self._match_cache) > 1000:
                self._cleanup_cache()
        
        return result
    
    def _cleanup_cache(self):
        """清理过期缓存"""
        now = time.time()
        expired = [k for k, (_, ts) in self._match_cache.items() 
                   if now - ts > self._cache_ttl]
        for k in expired:
            del self._match_cache[k]
    
    def match_flow(self, flow_stats) -> MatchResult:
        """
        匹配整个流（聚合多个payload）
        
        Args:
            flow_stats: FlowStats 对象
            
        Returns:
            MatchResult 匹配结果
        """
        # 获取流的payload
        payload = flow_stats.get_all_payload()
        
        rule = self.rule_repo.find_rule_by_5tuple(
            protocol=flow_stats.key.protocol,
            src_ip=flow_stats.key.src_ip,
            src_port=flow_stats.key.src_port,
            dst_ip=flow_stats.key.dst_ip,
            dst_port=flow_stats.key.dst_port
        )
        
        if rule and self._match_payload(rule, payload):
            return MatchResult(
                matched=True,
                sid=rule['sid'],
                msg=rule.get('msg'),
                severity=rule.get('severity', 3),
                matched_content=self._extract_matched_content(rule, payload),
                classtype=rule.get('classtype')
            )
        
        return MatchResult(matched=False)
    
    def _match_payload(self, rule: Dict, payload: bytes) -> bool:
        """匹配payload内容"""
        if not payload:
            # 如果没有payload，只匹配五元组规则
            return True
        
        # 获取规则的content条件
        contents = self.rule_repo.get_rule_contents(rule['sid'])
        
        if not contents:
            # 没有content条件，只匹配五元组
            return True
        
        payload_str = payload.hex()
        payload_text = payload.decode('utf-8', errors='ignore').lower()
        
        for content in contents:
            pattern = content['content_pattern']
            content_type = content.get('content_type', 'content')
            is_negated = content.get('is_negated', False)
            
            matched = False
            
            if content_type == 'content':
                # 精确匹配（十六进制或文本）
                if pattern.startswith('|') and pattern.endswith('|'):
                    # 十六进制格式
                    hex_pattern = pattern[1:-1].replace(' ', '').replace('|', '')
                    matched = hex_pattern in payload_str
                else:
                    # 文本格式
                    matched = pattern.lower() in payload_text
            
            elif content_type == 'regex':
                # 正则匹配
                try:
                    matched = re.search(pattern, payload_text, re.IGNORECASE) is not None
                except re.error:
                    matched = False
            
            # 处理取反
            if is_negated and matched:
                return False
            if not is_negated and not matched:
                return False
        
        return True
    
    def _extract_matched_content(self, rule: Dict, payload: bytes) -> Optional[str]:
        """提取匹配到的content"""
        contents = self.rule_repo.get_rule_contents(rule['sid'])
        for content in contents:
            if not content.get('is_negated'):
                return content['content_pattern']
        return None
    
    def clear_cache(self):
        """清除匹配缓存"""
        self._match_cache.clear()
        print("[INFO] RuleMatcher cache cleared")
    
    def reload_rules(self) -> None:
        """重新加载规则（用于热更新）"""
        self.rule_repo.reload()
        self.clear_cache()
        print("[INFO] Rules reloaded")