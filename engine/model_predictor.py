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

from config import MODEL_CONFIG, DETECTION_CONFIG
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
        
        print(f"[INFO] ModelPredictor initialized: threshold={self.threat_threshold}")
    
    def _load_model(self):
        """加载XGBoost模型"""
        model_path = self.model_dir / 'xgboost.pkl'
        
        try:
            if model_path.exists():
                # 尝试用joblib加载
                self.model = joblib.load(model_path)
                print(f"[INFO] Loaded XGBoost model from {model_path}")
                
                # 打印模型信息
                if hasattr(self.model, 'get_params'):
                    params = self.model.get_params()
                    print(f"[INFO] Model params: n_estimators={params.get('n_estimators', 'N/A')}, "
                          f"max_depth={params.get('max_depth', 'N/A')}")
            else:
                raise FileNotFoundError(f"Model not found at {model_path}")
                
        except Exception as e:
            print(f"[ERROR] Failed to load model: {e}")
            self.model = None
    
    def _load_preprocessor(self):
        """加载数据预处理器"""
        try:
            self.preprocessor = DataPreprocessor(model_dir=self.model_dir)
            if not self.preprocessor.is_ready():
                print("[WARNING] Preprocessor not fully ready")
        except Exception as e:
            print(f"[ERROR] Failed to load preprocessor: {e}")
            self.preprocessor = None
    
    def predict(self, features: Dict[str, any]) -> Tuple[float, int]:
        """
        预测单个样本
        
        Args:
            features: 特征字典（包含24个特征）
            
        Returns:
            (probability, prediction): 威胁概率和预测类别（0=正常,1=威胁）
        """
        if self.model is None:
            print("[ERROR] Model not loaded")
            return 0.0, 0
        
        if self.preprocessor is None:
            print("[ERROR] Preprocessor not loaded")
            return 0.0, 0
        
        try:
            # 预处理特征
            X = self.preprocessor.preprocess(features)
            
            if X is None:
                print("[ERROR] Feature preprocessing failed")
                return 0.0, 0
            
            # 预测概率
            probability = float(self.model.predict_proba(X)[0, 1])
            
            # 预测类别
            prediction = 1 if probability >= self.threat_threshold else 0
            
            return probability, prediction
            
        except Exception as e:
            print(f"[ERROR] Prediction failed: {e}")
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
            print("[ERROR] Model or preprocessor not loaded")
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
            print(f"[ERROR] Batch prediction failed: {e}")
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
            'threshold': self.threat_threshold
        }
    
    def is_ready(self) -> bool:
        """检查模型是否就绪"""
        return self.model is not None and self.preprocessor is not None
    
    def reload(self):
        """重新加载模型（用于热更新）"""
        print("[INFO] Reloading model...")
        self._load_model()
        self._load_preprocessor()
        print("[INFO] Model reload complete")