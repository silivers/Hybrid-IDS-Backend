# data/preprocessor.py (完整修改版)

"""
数据预处理器模块
对提取的特征进行编码和标准化，使其适合模型输入
"""
import pickle
import joblib
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Union
from pathlib import Path

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import MODEL_CONFIG, FEATURE_CONFIG


class DataPreprocessor:
    """
    数据预处理器
    
    负责：
    1. 加载训练时保存的编码器和标准化器
    2. 对类别特征进行Label Encoding（支持大小写不敏感）
    3. 对数值特征进行标准化
    4. 处理缺失值
    """
    
    def __init__(self, model_dir: Optional[Path] = None):
        """
        初始化预处理器
        
        Args:
            model_dir: 模型文件目录，默认使用配置中的路径
        """
        self.model_dir = Path(model_dir) if model_dir else MODEL_CONFIG.get('model_path', Path('models')).parent
        
        self.encoders = None
        self.scaler = None
        self.feature_names = None
        self.categorical_columns = FEATURE_CONFIG['categorical_columns']
        self.feature_columns = FEATURE_CONFIG['feature_columns']
        
        # 加载模型资源
        self._load_encoders()
        self._load_scaler()
        self._load_feature_names()
        
        print(f"[INFO] DataPreprocessor initialized: {len(self.feature_columns)} features, "
                   f"categorical={self.categorical_columns}")
    
    def _load_encoders(self) -> None:
        """加载标签编码器 - 使用 joblib 与训练代码保持一致"""
        encoder_path = self.model_dir / 'xgboost_label_encoders.pkl'
        try:
            if encoder_path.exists():
                self.encoders = joblib.load(encoder_path)
                print(f"[INFO] Loaded label encoders from {encoder_path}")
                print(f"[INFO] Encoder keys: {list(self.encoders.keys())}")
                
                # 打印每个编码器的类别，便于调试
                for col, encoder in self.encoders.items():
                    if hasattr(encoder, 'classes_'):
                        print(f"[INFO] {col} encoder classes: {list(encoder.classes_)}")
            else:
                print(f"[WARNING] Label encoders not found at {encoder_path}, using default")
                self.encoders = {}
        except Exception as e:
            print(f"[ERROR] Failed to load label encoders: {e}")
            self.encoders = {}
    
    def _load_scaler(self) -> None:
        """加载标准化器 - 使用 joblib 与训练代码保持一致"""
        scaler_path = self.model_dir / 'xgboost_scaler.pkl'
        try:
            if scaler_path.exists():
                self.scaler = joblib.load(scaler_path)
                print(f"[INFO] Loaded scaler from {scaler_path}")
                if hasattr(self.scaler, 'mean_'):
                    print(f"[INFO] Scaler mean shape: {self.scaler.mean_.shape}")
            else:
                print(f"[WARNING] Scaler not found at {scaler_path}, using default")
                self.scaler = None
        except Exception as e:
            print(f"[ERROR] Failed to load scaler: {e}")
            self.scaler = None
    
    def _load_feature_names(self) -> None:
        """加载特征名称列表"""
        feature_path = self.model_dir / 'xgboost_feature_names.txt'
        try:
            if feature_path.exists():
                with open(feature_path, 'r') as f:
                    self.feature_names = [line.strip() for line in f if line.strip()]
                print(f"[INFO] Loaded feature names from {feature_path}")
                print(f"[INFO] Feature count: {len(self.feature_names)}")
            else:
                print(f"[WARNING] Feature names not found at {feature_path}, using config")
                self.feature_names = self.feature_columns
        except Exception as e:
            print(f"[ERROR] Failed to load feature names: {e}")
            self.feature_names = self.feature_columns
    
    def _encode_categorical(self, value: Union[str, int], column: str) -> int:
        """
        对单个类别值进行编码（支持大小写不敏感）
        
        Args:
            value: 原始类别值
            column: 列名
            
        Returns:
            编码后的整数，未知类别返回-1
        """
        # 处理空值
        if value is None or value == '' or value == '-':
            value = 'unknown'
        
        # 转换为字符串
        value_str = str(value)
        value_lower = value_str.lower()
        
        if self.encoders and column in self.encoders:
            encoder = self.encoders[column]
            
            # 处理 sklearn 的 LabelEncoder
            if hasattr(encoder, 'classes_'):
                # 获取编码器中所有类别
                classes = encoder.classes_
                
                # 1. 优先尝试精确匹配
                if value_str in classes:
                    return int(encoder.transform([value_str])[0])
                
                # 2. 尝试大小写不敏感匹配
                # 创建大小写映射（注意：可能有重复，取第一个）
                lower_to_original = {}
                for cls in classes:
                    cls_lower = cls.lower()
                    if cls_lower not in lower_to_original:
                        lower_to_original[cls_lower] = cls
                
                if value_lower in lower_to_original:
                    original = lower_to_original[value_lower]
                    encoded = int(encoder.transform([original])[0])
                    # 使用 DEBUG 级别记录映射（可选）
                    # print(f"[DEBUG] Mapped '{value_str}' -> '{original}' for column '{column}'")
                    return encoded
                
                # 3. 如果是数字字符串，尝试直接转换（某些情况下类别可能被预处理成数字）
                if value_str.isdigit():
                    return int(value_str)
                
                # 4. 完全未知，返回-1
                print(f"[DEBUG] Unknown category '{value_str}' for column '{column}', using -1")
                return -1
            
            # 处理自定义字典编码器
            elif isinstance(encoder, dict):
                # 尝试精确匹配
                if value_str in encoder:
                    return encoder[value_str]
                
                # 尝试大小写不敏感匹配
                for key, code in encoder.items():
                    if key.lower() == value_lower:
                        return code
                
                return -1
        
        # 没有编码器时的后备方案
        return hash(value_str) % 1000
    
    def _encode_categorical_batch(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        批量编码类别特征（支持大小写不敏感）
        
        Args:
            df: 包含类别特征的数据框
            
        Returns:
            编码后的数据框
        """
        for col in self.categorical_columns:
            if col in df.columns:
                df[col] = df[col].apply(lambda x: self._encode_categorical(x, col))
            else:
                print(f"[WARNING] Categorical column '{col}' not found in data")
                df[col] = -1
        return df
    
    def _standardize_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        标准化所有特征（包括类别特征）
        
        注意：训练时 scaler 是对所有24个特征（包括编码后的类别特征）进行拟合的，
        所以预测时也必须对所有特征进行标准化，不能只标准化数值特征。
        
        Args:
            df: 包含所有特征的数据框（类别特征已经编码为整数）
            
        Returns:
            标准化后的数据框
        """
        if self.scaler is None:
            print("[WARNING] Scaler not available, skipping standardization")
            return df
        
        try:
            # 将所有特征转换为 float 类型
            X = df.astype(float)
            
            # 对所有特征进行标准化
            X_scaled = self.scaler.transform(X)
            
            # 将标准化后的数据写回 DataFrame
            df_scaled = pd.DataFrame(X_scaled, columns=df.columns, index=df.index)
            
            return df_scaled
        except Exception as e:
            print(f"[ERROR] Standardization failed: {e}")
            return df
    
    def _handle_missing_values(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        处理缺失值
        
        Args:
            df: 原始数据框
            
        Returns:
            处理后的数据框
        """
        # 数值特征用0填充
        numerical_cols = [col for col in df.columns if col not in self.categorical_columns]
        for col in numerical_cols:
            if col in df.columns:
                df[col] = df[col].fillna(0)
        
        # 类别特征用'unknown'填充
        for col in self.categorical_columns:
            if col in df.columns:
                df[col] = df[col].fillna('unknown')
        
        return df
    
    def preprocess(self, features: Dict[str, any]) -> Optional[np.ndarray]:
        """
        预处理单个特征字典
        
        Args:
            features: 特征字典
            
        Returns:
            预处理后的特征数组，形状为(1, n_features)
        """
        # 转换为DataFrame
        df = pd.DataFrame([features])
        return self.preprocess_batch(df)
    
    def preprocess_batch(self, features_list: Union[List[Dict], pd.DataFrame]) -> Optional[np.ndarray]:
        """
        批量预处理特征
        
        Args:
            features_list: 特征字典列表或DataFrame
            
        Returns:
            预处理后的特征数组，形状为(n_samples, n_features)
        """
        if isinstance(features_list, list):
            df = pd.DataFrame(features_list)
        else:
            df = features_list.copy()
        
        if df.empty:
            print("[WARNING] Empty features list")
            return None
        
        # 确保所有必需特征都存在
        for col in self.feature_names:
            if col not in df.columns:
                print(f"[WARNING] Missing feature column '{col}', filling with 0")
                df[col] = 0
        
        # 只保留需要的特征列，按顺序排列
        df = df[self.feature_names]
        
        # 处理缺失值
        df = self._handle_missing_values(df)
        
        # 编码类别特征（将字符串转换为整数）- 现在支持大小写不敏感
        df = self._encode_categorical_batch(df)
        
        # 标准化所有特征（包括编码后的类别特征）
        df = self._standardize_features(df)
        
        # 转换为numpy数组
        X = df.values.astype(np.float32)
        
        print(f"[DEBUG] Preprocessed {len(df)} samples, shape={X.shape}")
        
        return X
    
    def inverse_encode(self, encoded_value: int, column: str) -> str:
        """
        将编码值还原为原始类别
        
        Args:
            encoded_value: 编码后的值
            column: 列名
            
        Returns:
            原始类别字符串
        """
        if self.encoders and column in self.encoders:
            encoder = self.encoders[column]
            if hasattr(encoder, 'inverse_transform'):
                try:
                    return encoder.inverse_transform([encoded_value])[0]
                except ValueError:
                    return 'unknown'
            elif isinstance(encoder, dict):
                # 反向查找
                for k, v in encoder.items():
                    if v == encoded_value:
                        return k
                return 'unknown'
        
        return str(encoded_value)
    
    def get_feature_names(self) -> List[str]:
        """获取特征名称列表"""
        return self.feature_names.copy()
    
    def get_feature_count(self) -> int:
        """获取特征数量"""
        return len(self.feature_names)
    
    def is_ready(self) -> bool:
        """检查预处理器是否就绪"""
        return self.encoders is not None and self.scaler is not None