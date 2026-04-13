# config.py
"""
全局配置文件
"""
import os
from pathlib import Path

# 项目根目录
BASE_DIR = Path(__file__).resolve().parent

# ========== 数据库配置 ==========
DB_CONFIG = {
    'host': 'localhost',
    'port': 3306,
    'user': 'root',
    'password': '1234',  # 请修改为实际密码
    'database': 'snort_db',
    'charset': 'utf8mb4',
    'autocommit': True,
    'pool_size': 10,
    'pool_recycle': 3600,
}

# ========== 模型配置 ==========
MODEL_CONFIG = {
    'model_path': BASE_DIR / 'models' / 'xgboost.pkl',
    'encoder_path': BASE_DIR / 'models' / 'xgboost_label_encoders.pkl',
    'scaler_path': BASE_DIR / 'models' / 'xgboost_scaler.pkl',
    'feature_names_path': BASE_DIR / 'models' / 'xgboost_feature_names.txt',
}

# ========== 检测配置 ==========
DETECTION_CONFIG = {
    # 威胁概率阈值（超过此值判定为威胁）
    'threat_threshold': 0.5,
    # 模糊区域阈值（在此阈值和威胁阈值之间为模糊行为）
    'uncertain_threshold': 0.3,
    # 流超时时间（秒）
    'flow_timeout': 60,
    # 包捕获数量限制（-1表示无限制）
    'packet_count': -1,
    # 网卡接口（None表示自动选择）
    'network_interface': None,
    # 捕获过滤器（BPF语法）
    'capture_filter': 'ip',  # 捕获所有IP流量
}

# ========== 特征配置 ==========
FEATURE_CONFIG = {
    # 需要提取的特征列表（顺序必须与训练时一致）
    'feature_columns': [
        'proto', 'state', 'sbytes', 'dbytes', 'sttl', 'dttl',
        'sloss', 'dloss', 'spkts', 'dpkts', 'sjit', 'djit',
        'tcprtt', 'synack', 'ackdat', 'service', 'ct_srv_src',
        'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm', 'trans_depth',
        'is_sm_ips_ports', 'ct_flw_http_mthd', 'is_ftp_login'
    ],
    # 类别特征列
    'categorical_columns': ['proto', 'service', 'state'],
    # 需要删除的列
    'drop_columns': ['id'],
}

# ========== 规则匹配配置 ==========
RULE_MATCH_CONFIG = {
    # 是否启用规则缓存
    'enable_cache': True,
    # 规则缓存过期时间（秒）
    'cache_ttl': 300,
    # 规则匹配超时时间（秒）
    'match_timeout': 5,
}