# data/feature_extractor.py
"""
特征提取器模块
从流统计信息中提取模型所需的24个特征
"""
from typing import Dict, List, Optional
from collections import defaultdict

from capture.flow_aggregator import FlowStats
from config import FEATURE_CONFIG

# 移除 logger 相关代码


class FeatureExtractor:
    """
    特征提取器
    
    从流统计中提取模型所需的24个特征
    支持全局统计特征的计算（如ct_srv_src, ct_srv_dst等）
    """
    
    def __init__(self):
        """初始化特征提取器"""
        self.feature_columns = FEATURE_CONFIG['feature_columns']
        self.categorical_columns = FEATURE_CONFIG['categorical_columns']
        
        # 全局统计计数器
        self._reset_global_stats()
        
        print(f"[INFO] FeatureExtractor initialized: {len(self.feature_columns)} features")
    
    def _reset_global_stats(self) -> None:
        """重置全局统计计数器"""
        # ct_srv_src: 源IP到同一服务的连接数
        self._srv_src_count: Dict[tuple, int] = defaultdict(int)
        # ct_srv_dst: 目的IP到同一服务的连接数
        self._srv_dst_count: Dict[tuple, int] = defaultdict(int)
        # ct_dst_ltm: 目的IP在时间窗口内的连接数
        self._dst_ltm_count: Dict[str, List[float]] = defaultdict(list)
        # ct_src_ltm: 源IP在时间窗口内的连接数
        self._src_ltm_count: Dict[str, List[float]] = defaultdict(list)
        
        # 时间窗口（秒）
        self._time_window = 60
    
    def _get_service_from_flow(self, flow: FlowStats) -> str:
        """
        从流中获取服务类型（公开方法）
        根据端口推断服务类型
        """
        port_to_service = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap',
            443: 'https', 993: 'imaps', 995: 'pop3s', 3306: 'mysql',
            3389: 'rdp', 8080: 'http-proxy'
        }
        
        # 检查源端口和目标端口
        for port, service in port_to_service.items():
            if flow.key.src_port == port or flow.key.dst_port == port:
                return service
        
        return '-'
    
    def _get_state_from_flow(self, flow: FlowStats) -> str:
        """从流中获取状态字符串"""
        if flow.forward_packets == 0 and flow.backward_packets == 0:
            return 'no'
        if flow.state.value == 'finished':  # FlowState.FINISHED
            return 'FIN'
        if flow.duration > 60:
            return 'INT'
        return 'CON'
    
    def _update_global_stats(self, flow: FlowStats) -> None:
        """
        更新全局统计特征
        
        这些特征需要跨流统计，必须在处理流时实时更新
        """
        now = flow.last_time
        service = self._get_service_from_flow(flow)
        
        # ct_srv_src: 源IP+服务组合
        srv_src_key = (flow.key.src_ip, service)
        self._srv_src_count[srv_src_key] += 1
        
        # ct_srv_dst: 目的IP+服务组合
        srv_dst_key = (flow.key.dst_ip, service)
        self._srv_dst_count[srv_dst_key] += 1
        
        # ct_src_ltm: 源IP在时间窗口内的连接数
        self._src_ltm_count[flow.key.src_ip].append(now)
        # 清理旧记录
        self._cleanup_old_records(self._src_ltm_count, now)
        
        # ct_dst_ltm: 目的IP在时间窗口内的连接数
        self._dst_ltm_count[flow.key.dst_ip].append(now)
        self._cleanup_old_records(self._dst_ltm_count, now)
    
    def _cleanup_old_records(self, counter: Dict[str, List[float]], now: float) -> None:
        """清理时间窗口外的旧记录"""
        for ip in list(counter.keys()):
            counter[ip] = [t for t in counter[ip] if now - t <= self._time_window]
            if not counter[ip]:
                del counter[ip]
    
    def _get_ct_srv_src(self, flow: FlowStats) -> int:
        """获取源IP到同一服务的连接数"""
        service = self._get_service_from_flow(flow)
        key = (flow.key.src_ip, service)
        return self._srv_src_count.get(key, 0)
    
    def _get_ct_srv_dst(self, flow: FlowStats) -> int:
        """获取目的IP到同一服务的连接数"""
        service = self._get_service_from_flow(flow)
        key = (flow.key.dst_ip, service)
        return self._srv_dst_count.get(key, 0)
    
    def _get_ct_src_ltm(self, flow: FlowStats) -> int:
        """获取源IP在时间窗口内的连接数"""
        return len(self._src_ltm_count.get(flow.key.src_ip, []))
    
    def _get_ct_dst_ltm(self, flow: FlowStats) -> int:
        """获取目的IP在时间窗口内的连接数"""
        return len(self._dst_ltm_count.get(flow.key.dst_ip, []))
    
    def extract_features(self, flow: FlowStats) -> Optional[Dict[str, any]]:
        """
        从流统计中提取特征
        
        Args:
            flow: 流统计对象
            
        Returns:
            特征字典，包含所有24个特征
        """
        if not flow:
            return None
        
        # 更新全局统计
        self._update_global_stats(flow)
        
        # 获取基础特征（直接构建，不依赖私有方法）
        features = {
            'proto': flow.key.protocol,
            'state': self._get_state_from_flow(flow),
            'sbytes': flow.forward_bytes,
            'dbytes': flow.backward_bytes,
            'sttl': flow.forward_ttl,
            'dttl': flow.backward_ttl,
            'sloss': flow.forward_loss,
            'dloss': flow.backward_loss,
            'spkts': flow.forward_packets,
            'dpkts': flow.backward_packets,
            'sjit': flow.forward_jitter,
            'djit': flow.backward_jitter,
            'tcprtt': flow.tcp_rtt,
            'synack': flow.tcp_synack,
            'ackdat': flow.tcp_ackdat,
            'service': self._get_service_from_flow(flow),
            'trans_depth': flow.trans_depth,
            'is_sm_ips_ports': flow.is_sm_ips_ports,
            'ct_flw_http_mthd': flow.ct_flw_http_mthd,
            'is_ftp_login': 1 if flow.is_ftp_login else 0,
            'ct_srv_src': 0,      # 临时值，下面覆盖
            'ct_srv_dst': 0,      # 临时值，下面覆盖
            'ct_src_ltm': 0,      # 临时值，下面覆盖
            'ct_dst_ltm': 0,      # 临时值，下面覆盖
        }
        
        # 覆盖需要全局计算的统计特征
        features['ct_srv_src'] = self._get_ct_srv_src(flow)
        features['ct_srv_dst'] = self._get_ct_srv_dst(flow)
        features['ct_src_ltm'] = self._get_ct_src_ltm(flow)
        features['ct_dst_ltm'] = self._get_ct_dst_ltm(flow)
        
        # 确保所有特征都存在
        for col in self.feature_columns:
            if col not in features:
                print(f"[WARNING] Missing feature: {col}, setting to 0")
                features[col] = 0
        
        return features
    
    def extract_features_batch(self, flows: List[FlowStats]) -> List[Dict[str, any]]:
        """
        批量提取特征
        
        Args:
            flows: 流统计对象列表
            
        Returns:
            特征字典列表
        """
        features_list = []
        for flow in flows:
            features = self.extract_features(flow)
            if features:
                features_list.append(features)
        return features_list
    
    def get_feature_names(self) -> List[str]:
        """获取特征名称列表"""
        return self.feature_columns.copy()
    
    def validate_features(self, features: Dict[str, any]) -> bool:
        """
        验证特征是否有效
        
        Args:
            features: 特征字典
            
        Returns:
            是否有效
        """
        # 检查必需特征
        for col in self.feature_columns:
            if col not in features:
                print(f"[ERROR] Missing required feature: {col}")
                return False
        
        # 检查数值类型
        for col, value in features.items():
            if col in self.categorical_columns:
                # 类别特征应该是字符串
                if not isinstance(value, str) and value is not None:
                    print(f"[WARNING] Categorical feature {col} should be string, got {type(value)}")
            else:
                # 数值特征应该是数字
                if not isinstance(value, (int, float)) and value is not None:
                    print(f"[WARNING] Numerical feature {col} should be number, got {type(value)}")
        
        return True
    
    def reset(self) -> None:
        """重置全局统计"""
        self._reset_global_stats()
        print("[INFO] FeatureExtractor global stats reset")