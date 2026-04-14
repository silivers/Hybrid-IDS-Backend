# engine/rule_matcher.py
"""规则匹配器 - 查询MySQL规则库"""
import re
from typing import Optional, Tuple, Dict, Any
from dataclasses import dataclass
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
        self._cache = {}  # 简单缓存
        self._cache_ttl = 300
        
        print("[INFO] RuleMatcher initialized")
    
    def match(self, packet) -> MatchResult:
        """
        匹配单个数据包
        
        Args:
            packet: CapturedPacket 对象
            
        Returns:
            MatchResult 匹配结果
        """
        # 1. 先匹配五元组规则
        rule = self.rule_repo.find_rule_by_5tuple(
            protocol=packet.protocol,
            src_ip=packet.src_ip,
            src_port=packet.src_port,
            dst_ip=packet.dst_ip,
            dst_port=packet.dst_port
        )
        
        if rule:
            # 2. 如果有payload匹配条件，进一步匹配
            if self._match_payload(rule, packet.payload):
                return MatchResult(
                    matched=True,
                    sid=rule['sid'],
                    msg=rule['msg'],
                    severity=rule.get('severity', 3),
                    matched_content=self._extract_matched_content(rule, packet.payload),
                    classtype=rule.get('classtype')
                )
        
        return MatchResult(matched=False)
    
    def match_flow(self, flow_stats) -> MatchResult:
        """
        匹配整个流（聚合多个payload）
        
        Args:
            flow_stats: FlowStats 对象
            
        Returns:
            MatchResult 匹配结果
        """
        # 获取流的第一个数据包的五元组（用于规则匹配）
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
                msg=rule['msg'],
                severity=rule.get('severity', 3),
                matched_content=self._extract_matched_content(rule, payload),
                classtype=rule.get('classtype')
            )
        
        return MatchResult(matched=False)
    
    def _match_payload(self, rule: Dict, payload: bytes) -> bool:
        """
        匹配payload内容
        
        Args:
            rule: 规则字典
            payload: 数据包payload
            
        Returns:
            是否匹配
        """
        if not payload:
            # 如果没有payload，只匹配五元组规则
            return True
        
        # 获取规则的content条件
        contents = self.rule_repo.get_rule_contents(rule['sid'])
        
        if not contents:
            # 没有content条件，只匹配五元组
            return True
        
        payload_str = payload.hex()
        
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
                    matched = pattern.encode().lower() in payload.lower()
            
            elif content_type == 'regex':
                # 正则匹配
                try:
                    matched = re.search(pattern, payload, re.IGNORECASE) is not None
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
    
    def reload_rules(self) -> None:
        """重新加载规则（用于热更新）"""
        self.rule_repo.reload()
        self._cache.clear()
        print("[INFO] Rules reloaded")