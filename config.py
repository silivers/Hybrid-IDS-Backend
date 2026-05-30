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
    'host': os.getenv('DB_HOST', 'localhost'),  # 从环境变量读取，默认 localhost
    'port': int(os.getenv('DB_PORT', 3306)),    # 从环境变量读取，默认 3306
    'user': os.getenv('DB_USER', 'root'),       # 从环境变量读取，默认 root
    'password': os.getenv('DB_PASSWORD', '1234'), # 从环境变量读取，默认 1234
    'database': os.getenv('DB_NAME', 'snort_db'), # 从环境变量读取，默认 snort_db
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
    'threat_threshold': 0.9,
    # 模糊区域阈值（在此阈值和威胁阈值之间为模糊行为）
    'uncertain_threshold': 0.5,
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

# ========== API 配置 ==========
API_CONFIG = {
    'enabled': True,                    # 是否启用API服务
    'host': '0.0.0.0',                  # 监听地址
    'port': 8000,                       # 监听端口（FastAPI默认8000）
    'reload': False,                    # 自动重载（生产环境关闭）
}

# 分页配置
PAGINATION_CONFIG = {
    'default_page_size': 20,
    'max_page_size': 100,
}

# ========== 告警去重配置 ==========
DEDUPLICATION_CONFIG = {
    # 同一流+同一规则的告警缓存时间（秒）
    'alert_cache_ttl': 60,
    # 流级别处理状态缓存时间（秒）
    'flow_cache_ttl': 300,
    # 是否启用告警去重
    'enable_deduplication': True,
    # 同一源IP+目标IP的相似告警聚合窗口（秒）
    'aggregation_window': 10,
}

# ========== 威胁分类配置（仅用于控制台输出） ==========
THREAT_CLASSIFICATION_CONFIG = {
    # 攻击类型映射（用于控制台显示）
    'attack_types': {
        'ddos': {
            'name_cn': 'DDoS攻击',
            'description': '分布式拒绝服务攻击'
        },
        'port_scan': {
            'name_cn': '端口扫描',
            'description': '端口扫描探测'
        },
        'web_attack': {
            'name_cn': 'Web攻击',
            'description': 'Web应用攻击（SQL注入、XSS等）'
        },
        'brute_force': {
            'name_cn': '暴力破解',
            'description': '密码暴力破解攻击'
        },
        'ntp_amplification': {
            'name_cn': 'NTP放大攻击',
            'description': 'NTP协议放大反射攻击'
        },
        'dns_tunnel': {
            'name_cn': 'DNS隧道',
            'description': 'DNS协议隧道通信'
        },
        'malicious_dns': {
            'name_cn': '恶意DNS查询',
            'description': '恶意DNS域名查询'
        },
        'c2_communication': {
            'name_cn': 'C2通信',
            'description': '命令与控制服务器通信'
        },
        'data_exfiltration': {
            'name_cn': '数据外泄',
            'description': '敏感数据外传'
        },
        'irc_bot': {
            'name_cn': 'IRC僵尸网络',
            'description': 'IRC协议僵尸网络通信'
        },
        'unknown': {
            'name_cn': '未知威胁',
            'description': '无法分类的异常流量'
        }
    },
    
    # 攻击检测阈值
    'thresholds': {
        'ddos_packet_rate': 100,      # 每秒包数阈值
        'port_scan_count': 50,         # 端口扫描数量阈值
        'brute_force_count': 10,       # 暴力破解尝试次数阈值
        'ntp_amplification_factor': 10, # NTP放大倍数阈值
    }
}