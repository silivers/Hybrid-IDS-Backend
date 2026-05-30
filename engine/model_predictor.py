# engine/model_predictor.py
"""模型预测器 - 加载XGBoost模型并进行预测"""
import pickle
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Optional, List, Tuple
from pathlib import Path
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import MODEL_CONFIG, DETECTION_CONFIG, THREAT_CLASSIFICATION_CONFIG
from capture.preprocessor import DataPreprocessor


class ModelPredictor:
    """
    XGBoost模型预测器
    
    负责：
    1. 加载训练好的XGBoost模型
    2. 对特征进行预测
    3. 返回威胁概率和分类结果
    """
    
    def __init__(self, model_dir: Optional[Path] = None):
        """
        初始化模型预测器
        
        Args:
            model_dir: 模型文件目录
        """
        self.model_dir = Path(model_dir) if model_dir else Path(MODEL_CONFIG['model_path']).parent
        
        self.model = None
        self.preprocessor = None
        self.threat_threshold = DETECTION_CONFIG.get('threat_threshold', 0.5)
        self.uncertain_threshold = DETECTION_CONFIG.get('uncertain_threshold', 0.3)
        
        # 加载模型和预处理器
        self._load_model()
        self._load_preprocessor()
        
        # 攻击类型映射（仅用于显示）
        self.attack_types = THREAT_CLASSIFICATION_CONFIG.get('attack_types', {})
        self.thresholds = THREAT_CLASSIFICATION_CONFIG.get('thresholds', {})
        
        print(f"[信息] 模型预测器初始化完成：威胁阈值={self.threat_threshold}")
    
    def _load_model(self):
        """加载XGBoost模型"""
        model_path = self.model_dir / 'xgboost.pkl'
        
        try:
            if model_path.exists():
                # 尝试用joblib加载
                self.model = joblib.load(model_path)
                print(f"[信息] 成功加载XGBoost模型：{model_path}")
                
                # 打印模型信息
                if hasattr(self.model, 'get_params'):
                    params = self.model.get_params()
                    print(f"[信息] 模型参数：n_estimators={params.get('n_estimators', '未知')}, "
                          f"max_depth={params.get('max_depth', '未知')}")
            else:
                raise FileNotFoundError(f"模型文件未找到：{model_path}")
                
        except Exception as e:
            print(f"[错误] 加载模型失败：{e}")
            self.model = None
    
    def _load_preprocessor(self):
        """加载数据预处理器"""
        try:
            self.preprocessor = DataPreprocessor(model_dir=self.model_dir)
            if not self.preprocessor.is_ready():
                print("[警告] 预处理器未完全就绪")
        except Exception as e:
            print(f"[错误] 加载预处理器失败：{e}")
            self.preprocessor = None
    
    def _classify_attack_type(self, features: Dict[str, any], probability: float) -> Tuple[str, str]:
        """
        根据特征和概率判断具体攻击类型（仅用于控制台显示）
        
        Args:
            features: 特征字典
            probability: 威胁概率
            
        Returns:
            (attack_type, attack_name_cn): 攻击类型和中文名称
        """
        # 获取关键特征
        proto = features.get('proto', '').lower()
        service = features.get('service', '').lower()
        spkts = features.get('spkts', 0)
        dpkts = features.get('dpkts', 0)
        sbytes = features.get('sbytes', 0)
        dbytes = features.get('dbytes', 0)
        ct_srv_src = features.get('ct_srv_src', 0)
        ct_srv_dst = features.get('ct_srv_dst', 0)
        ct_src_ltm = features.get('ct_src_ltm', 0)
        ct_dst_ltm = features.get('ct_dst_ltm', 0)
        trans_depth = features.get('trans_depth', 0)
        
        # 1. 判断 DDoS 攻击
        if ct_src_ltm > self.thresholds.get('ddos_packet_rate', 100):
            return 'ddos', self.attack_types.get('ddos', {}).get('name_cn', 'DDoS攻击')
        
        # 2. 判断 NTP 放大攻击
        if service == 'ntp' and dbytes > sbytes * self.thresholds.get('ntp_amplification_factor', 10):
            return 'ntp_amplification', self.attack_types.get('ntp_amplification', {}).get('name_cn', 'NTP放大攻击')
        
        # 3. 判断 DNS 隧道或恶意DNS
        if service == 'dns':
            if trans_depth > 10:  # 深层DNS查询
                return 'dns_tunnel', self.attack_types.get('dns_tunnel', {}).get('name_cn', 'DNS隧道')
            elif probability > 0.7:
                return 'malicious_dns', self.attack_types.get('malicious_dns', {}).get('name_cn', '恶意DNS查询')
        
        # 4. 判断端口扫描
        if ct_srv_dst > self.thresholds.get('port_scan_count', 50) and ct_src_ltm > 20:
            return 'port_scan', self.attack_types.get('port_scan', {}).get('name_cn', '端口扫描')
        
        # 5. 判断暴力破解
        if service in ['ssh', 'ftp', 'telnet', 'rdp']:
            if ct_srv_src > self.thresholds.get('brute_force_count', 10):
                return 'brute_force', self.attack_types.get('brute_force', {}).get('name_cn', '暴力破解')
        
        # 6. 判断 Web 攻击
        if service in ['http', 'https', 'http-proxy']:
            if probability > 0.7:
                return 'web_attack', self.attack_types.get('web_attack', {}).get('name_cn', 'Web攻击')
        
        # 7. 判断 C2 通信
        if proto == 'tcp' and ct_srv_src > 5 and trans_depth > 5:
            return 'c2_communication', self.attack_types.get('c2_communication', {}).get('name_cn', 'C2通信')
        
        # 8. 判断数据外泄
        if sbytes > 1000000 and ct_src_ltm < 10:
            return 'data_exfiltration', self.attack_types.get('data_exfiltration', {}).get('name_cn', '数据外泄')
        
        # 9. 默认返回未知威胁
        if probability >= self.threat_threshold:
            return 'unknown', self.attack_types.get('unknown', {}).get('name_cn', '未知威胁')
        
        return 'normal', '正常流量'
    
    def predict(self, features: Dict[str, any]) -> Tuple[float, int]:
        """
        预测单个样本
        
        Args:
            features: 特征字典（包含24个特征）
            
        Returns:
            (probability, prediction): 威胁概率和预测类别（0=正常,1=威胁）
        """
        if self.model is None:
            print("[错误] 模型未加载")
            return 0.0, 0
        
        if self.preprocessor is None:
            print("[错误] 预处理器未加载")
            return 0.0, 0
        
        try:
            # 预处理特征
            X = self.preprocessor.preprocess(features)
            
            if X is None:
                print("[错误] 特征预处理失败")
                return 0.0, 0
            
            # 预测概率
            probability = float(self.model.predict_proba(X)[0, 1])
            
            # 预测类别
            prediction = 1 if probability >= self.threat_threshold else 0
            
            return probability, prediction
            
        except Exception as e:
            print(f"[错误] 预测失败：{e}")
            return 0.0, 0
    
    def predict_batch(self, features_list: List[Dict[str, any]]) -> List[Tuple[float, int]]:
        """
        批量预测
        
        Args:
            features_list: 特征字典列表
            
        Returns:
            [(probability, prediction), ...]
        """
        if self.model is None or self.preprocessor is None:
            print("[错误] 模型或预处理器未加载")
            return [(0.0, 0) for _ in features_list]
        
        try:
            # 批量预处理
            df = pd.DataFrame(features_list)
            X = self.preprocessor.preprocess_batch(df)
            
            if X is None:
                return [(0.0, 0) for _ in features_list]
            
            # 批量预测
            probabilities = self.model.predict_proba(X)[:, 1]
            predictions = (probabilities >= self.threat_threshold).astype(int)
            
            return list(zip(probabilities, predictions))
            
        except Exception as e:
            print(f"[错误] 批量预测失败：{e}")
            return [(0.0, 0) for _ in features_list]
    
    def predict_with_confidence(self, features: Dict[str, any]) -> Dict:
        """
        预测并返回详细信息
        
        Args:
            features: 特征字典
            
        Returns:
            包含概率、预测和置信度等级的字典
        """
        probability, prediction = self.predict(features)
        
        # 判断攻击类型（仅用于显示）
        attack_type, attack_name = self._classify_attack_type(features, probability)
        
        # 确定威胁等级
        if probability >= self.threat_threshold:
            threat_level = "high"
            verdict = "malicious"
        elif probability >= self.uncertain_threshold:
            threat_level = "medium"
            verdict = "uncertain"
        else:
            threat_level = "low"
            verdict = "normal"
        
        return {
            'probability': probability,
            'prediction': prediction,
            'verdict': verdict,
            'threat_level': threat_level,
            'threshold': self.threat_threshold,
            'attack_type': attack_type,
            'attack_name': attack_name
        }
    
    def is_ready(self) -> bool:
        """检查模型是否就绪"""
        return self.model is not None and self.preprocessor is not None
    
    def reload(self):
        """重新加载模型（用于热更新）"""
        print("[信息] 正在重新加载模型...")
        self._load_model()
        self._load_preprocessor()
        print("[信息] 模型重新加载完成")