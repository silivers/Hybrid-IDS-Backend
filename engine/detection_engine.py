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
        
        print("[信息] 检测引擎初始化完成（启用多级去重机制）")
    
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
    
    def _get_threat_type_from_rule(self, match_result: MatchResult) -> str:
        """从规则匹配结果中获取威胁类型（仅用于控制台显示）"""
        
        # 扩展的 classtype 映射表
        classtype_map = {
            # SQL注入相关
            'sql-injection': 'SQL注入攻击',
            'sqli': 'SQL注入攻击',
            
            # XSS相关
            'xss': '跨站脚本攻击',
            'cross-site-scripting': 'XSS跨站脚本攻击',
            
            # Web攻击相关
            'web-application-attack': 'Web应用攻击',
            'web-attack': 'Web攻击',
            'webshell': 'Webshell后门',
            'file-inclusion': '文件包含漏洞',
            'command-injection': '命令注入攻击',
            
            # 缓冲区溢出
            'buffer-overflow': '缓冲区溢出攻击',
            'stack-overflow': '栈溢出攻击',
            
            # DoS/DDoS相关
            'dos': '拒绝服务攻击',
            'ddos': '分布式拒绝服务攻击',
            'flood': '流量洪水攻击',
            
            # 扫描探测
            'scan': '端口扫描探测',
            'port-scan': '端口扫描',
            'attempted-recon': '信息探测',
            'reconnaissance': '侦察探测',
            'attempted-reconnaissance': '信息探测尝试',
            'scanning': '网络扫描',
            
            # 恶意软件
            'trojan': '木马活动',
            'backdoor': '后门访问',
            'worm': '蠕虫病毒',
            'malware': '恶意软件',
            'ransomware': '勒索软件',
            
            # 僵尸网络
            'irc': 'IRC僵尸网络',
            'ircbot': 'IRC僵尸网络',
            'botnet': '僵尸网络',
            'c2': 'C2服务器通信',
            'irc-activity': 'IRC活动流量',
            'irc-communication': 'IRC通信',
            
            # 暴力破解
            'brute-force': '暴力破解攻击',
            'bruteforce': '暴力破解',
            'suspicious-login': '可疑登录',
            'default-login': '默认口令登录',
            'login-brute-force': '登录暴力破解',
            
            # 协议滥用
            'dns-tunnel': 'DNS隧道',
            'ntp-amplification': 'NTP放大攻击',
            'amplification': '反射放大攻击',
            
            # 其他
            'misc-activity': '异常行为',
            'attempted-admin': '提权尝试',
            'attempted-user': '用户权限尝试',
            'successful-admin': '成功提权',
            'successful-user': '成功登录',
            'successful-recon': '成功侦察',
            
            # 未知/可疑
            'bad-unknown': '可疑恶意流量',
            'unknown': '未知威胁',
            'potential-threat': '潜在威胁',
            'suspicious': '可疑行为',
            'bad-traffic': '恶意流量',
            'malicious-activity': '恶意活动',
        }
        
        # 优先使用 classtype
        if match_result.classtype:
            classtype_lower = match_result.classtype.lower()
            # 精确匹配
            if classtype_lower in classtype_map:
                return classtype_map[classtype_lower]
            # 模糊匹配（包含关键词）
            for key, value in classtype_map.items():
                if key in classtype_lower:
                    return value
            # 返回格式化的原始值
            return match_result.classtype.replace('-', ' ').title()
        
        # 根据匹配内容推断威胁类型
        if match_result.matched_content:
            content = match_result.matched_content.lower()
            
            # IRC/僵尸网络特征（针对你的告警）
            if 'psybnc' in content or 'irc' in content or 'bot' in content:
                return 'IRC僵尸网络'
            if 'welcome' in content and 'psybnc' in content:
                return 'IRC僵尸网络'
            
            # SQL注入特征
            sql_patterns = ['union select', 'select from', 'or 1=1', 'and 1=1', 
                            'sql injection', 'sleep(', 'benchmark(', 'information_schema']
            for pattern in sql_patterns:
                if pattern in content:
                    return 'SQL注入攻击'
            
            # XSS特征
            xss_patterns = ['<script', 'javascript:', 'onerror=', 'onload=', 
                            'alert(', 'document.cookie', 'xss']
            for pattern in xss_patterns:
                if pattern in content:
                    return 'XSS跨站脚本攻击'
            
            # 后门特征
            backdoor_patterns = ['backdoor', 'shell', 'cmd.exe', '/bin/sh', 'eval(']
            for pattern in backdoor_patterns:
                if pattern in content:
                    return '后门访问'
            
            # 扫描特征
            if 'scan' in content or 'nmap' in content:
                return '端口扫描探测'
            
            # 暴力破解特征
            if 'login' in content or 'password' in content or 'brute' in content:
                return '暴力破解攻击'
        
        # 根据规则ID范围推断
        if match_result.sid:
            if 1 <= match_result.sid <= 1000:
                return 'Web攻击'
            elif 1001 <= match_result.sid <= 2000:
                return '扫描探测'
            elif 2001 <= match_result.sid <= 3000:
                return 'DoS攻击'
            elif 3001 <= match_result.sid <= 4000:
                return '恶意软件'
            elif 4001 <= match_result.sid <= 5000:
                return '协议异常'
        
        return '规则告警'
    
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
                message="流已处理，跳过后续包"
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
                    message=f"重复告警已被抑制：sid={match_result.sid}"
                )
            
            # 命中规则，立即告警
            self.stats['rule_matches'] += 1
            
            # 获取威胁类型（仅用于显示）
            threat_type = self._get_threat_type_from_rule(match_result)
            
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
            
            # 增强控制台输出：添加威胁类型信息
            print(f"[告警] sid={match_result.sid}, 威胁类型={threat_type}, "
                  f"源={packet.src_ip}:{packet.src_port} -> 目标={packet.dst_ip}:{packet.dst_port}, "
                  f"严重级别={match_result.severity}, "
                  f"匹配内容={match_result.matched_content} (告警ID={alert_id})")
            
            return DetectionResult(
                is_threat=True,
                source='rule',
                sid=match_result.sid,
                severity=match_result.severity,
                message=match_result.msg or f"规则匹配：sid={match_result.sid}",
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
            message="数据包已缓存，等待模型分析"
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
            
            # 获取威胁类型（仅用于显示）
            threat_type = self._get_threat_type_from_rule(match_result)
            
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
            
            # 增强控制台输出：添加威胁类型信息
            print(f"[告警] sid={match_result.sid}, 威胁类型={threat_type}, "
                  f"源={flow_stats.key.src_ip}:{flow_stats.key.src_port} -> "
                  f"目标={flow_stats.key.dst_ip}:{flow_stats.key.dst_port}, "
                  f"严重级别={match_result.severity}, "
                  f"匹配内容={match_result.matched_content} (流告警ID={alert_id})")
            
            return DetectionResult(
                is_threat=True,
                source='rule',
                sid=match_result.sid,
                severity=match_result.severity,
                message=match_result.msg or f"规则匹配：sid={match_result.sid}"
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
        print("[信息] 所有检测缓存已清空")
    
    def shutdown(self):
        """关闭检测引擎"""
        self._stop_cleanup = True
        self.clear_caches()
        print("[信息] 检测引擎已关闭")