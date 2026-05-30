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
    # 攻击类型映射（用于控制台显示）- 完整版适配测试脚本
    'attack_types': {
        # DDoS/DoS攻击
        'ddos': {
            'name_cn': 'DDoS攻击',
            'name_en': 'DDoS Attack',
            'description': '分布式拒绝服务攻击',
            'severity': 1
        },
        'dos': {
            'name_cn': 'DoS攻击',
            'name_en': 'DoS Attack',
            'description': '拒绝服务攻击',
            'severity': 1
        },
        'dos_simulate': {
            'name_cn': 'DoS攻击模拟',
            'name_en': 'DoS Simulation',
            'description': 'SYN洪水攻击模拟',
            'severity': 1
        },
        
        # Web攻击
        'sql_injection': {
            'name_cn': 'SQL注入攻击',
            'name_en': 'SQL Injection',
            'description': '结构化查询语言注入攻击',
            'severity': 1
        },
        'sql_union': {
            'name_cn': 'SQL注入-联合查询',
            'name_en': 'SQL Injection - Union',
            'description': '使用UNION查询的SQL注入',
            'severity': 1
        },
        'sql_drop': {
            'name_cn': 'SQL注入-删表攻击',
            'name_en': 'SQL Injection - Drop Table',
            'description': '尝试删除数据库表的SQL注入',
            'severity': 1
        },
        'sql_time': {
            'name_cn': 'SQL注入-时间盲注',
            'name_en': 'SQL Injection - Time Blind',
            'description': '基于时间延迟的SQL盲注',
            'severity': 1
        },
        'xss': {
            'name_cn': 'XSS跨站脚本攻击',
            'name_en': 'Cross-Site Scripting',
            'description': '跨站脚本注入攻击',
            'severity': 2
        },
        'xss_script': {
            'name_cn': 'XSS-脚本注入',
            'name_en': 'XSS - Script Injection',
            'description': '通过<script>标签的XSS攻击',
            'severity': 2
        },
        'xss_event': {
            'name_cn': 'XSS-事件触发',
            'name_en': 'XSS - Event Handler',
            'description': '通过事件处理器触发的XSS攻击',
            'severity': 2
        },
        'xss_protocol': {
            'name_cn': 'XSS-伪协议',
            'name_en': 'XSS - Pseudo Protocol',
            'description': '通过javascript:伪协议的XSS攻击',
            'severity': 2
        },
        
        # 路径遍历
        'path_traversal': {
            'name_cn': '路径遍历攻击',
            'name_en': 'Path Traversal',
            'description': '目录穿越攻击',
            'severity': 2
        },
        'path_traversal_passwd': {
            'name_cn': '路径遍历-读取密码文件',
            'name_en': 'Path Traversal - Password File',
            'description': '尝试读取/etc/passwd文件',
            'severity': 2
        },
        'path_traversal_windows': {
            'name_cn': '路径遍历-Windows配置',
            'name_en': 'Path Traversal - Windows Config',
            'description': '尝试读取Windows配置文件',
            'severity': 2
        },
        
        # 命令注入
        'cmd_injection': {
            'name_cn': '命令注入攻击',
            'name_en': 'Command Injection',
            'description': '操作系统命令注入攻击',
            'severity': 1
        },
        'cmd_injection_passwd': {
            'name_cn': '命令注入-读取密码',
            'name_en': 'Command Injection - Read Password',
            'description': '尝试读取密码文件',
            'severity': 1
        },
        'cmd_injection_download': {
            'name_cn': '命令注入-下载木马',
            'name_en': 'Command Injection - Download Malware',
            'description': '尝试下载恶意软件',
            'severity': 1
        },
        
        # 扫描探测
        'port_scan': {
            'name_cn': '端口扫描',
            'name_en': 'Port Scan',
            'description': '端口扫描探测活动',
            'severity': 2
        },
        'port_scan_syn': {
            'name_cn': 'SYN端口扫描',
            'name_en': 'SYN Port Scan',
            'description': 'SYN半开端口扫描',
            'severity': 2
        },
        'port_scan_connect': {
            'name_cn': '全连接端口扫描',
            'name_en': 'Full Connect Port Scan',
            'description': 'TCP全连接端口扫描',
            'severity': 2
        },
        
        # 服务攻击
        'web_attack': {
            'name_cn': 'Web攻击',
            'name_en': 'Web Attack',
            'description': 'Web应用攻击（SQL注入、XSS等）',
            'severity': 1
        },
        'brute_force': {
            'name_cn': '暴力破解',
            'name_en': 'Brute Force',
            'description': '密码暴力破解攻击',
            'severity': 2
        },
        'brute_force_ssh': {
            'name_cn': 'SSH暴力破解',
            'name_en': 'SSH Brute Force',
            'description': 'SSH服务密码暴力破解',
            'severity': 2
        },
        'brute_force_ftp': {
            'name_cn': 'FTP暴力破解',
            'name_en': 'FTP Brute Force',
            'description': 'FTP服务密码暴力破解',
            'severity': 2
        },
        'brute_force_http': {
            'name_cn': 'HTTP登录暴力破解',
            'name_en': 'HTTP Login Brute Force',
            'description': 'Web登录接口暴力破解',
            'severity': 2
        },
        
        # 协议攻击
        'ntp_amplification': {
            'name_cn': 'NTP放大攻击',
            'name_en': 'NTP Amplification',
            'description': 'NTP协议放大反射攻击',
            'severity': 1
        },
        'dns_tunnel': {
            'name_cn': 'DNS隧道',
            'name_en': 'DNS Tunnel',
            'description': 'DNS协议隧道通信',
            'severity': 1
        },
        'malicious_dns': {
            'name_cn': '恶意DNS查询',
            'name_en': 'Malicious DNS',
            'description': '恶意DNS域名查询',
            'severity': 2
        },
        
        # 恶意软件通信
        'c2_communication': {
            'name_cn': 'C2通信',
            'name_en': 'C2 Communication',
            'description': '命令与控制服务器通信',
            'severity': 1
        },
        'irc_bot': {
            'name_cn': 'IRC僵尸网络',
            'name_en': 'IRC Botnet',
            'description': 'IRC协议僵尸网络通信',
            'severity': 1
        },
        'data_exfiltration': {
            'name_cn': '数据外泄',
            'name_en': 'Data Exfiltration',
            'description': '敏感数据外传',
            'severity': 1
        },
        
        # 其他攻击
        'webshell': {
            'name_cn': 'Webshell后门',
            'name_en': 'Webshell',
            'description': 'Webshell后门访问',
            'severity': 1
        },
        'file_inclusion': {
            'name_cn': '文件包含漏洞',
            'name_en': 'File Inclusion',
            'description': '远程/本地文件包含攻击',
            'severity': 1
        },
        'buffer_overflow': {
            'name_cn': '缓冲区溢出攻击',
            'name_en': 'Buffer Overflow',
            'description': '缓冲区溢出漏洞利用',
            'severity': 1
        },
        
        # 正常流量（非攻击）
        'normal': {
            'name_cn': '正常流量',
            'name_en': 'Normal Traffic',
            'description': '正常网络流量',
            'severity': 0
        },
        'unknown': {
            'name_cn': '未知威胁',
            'name_en': 'Unknown Threat',
            'description': '无法分类的异常流量',
            'severity': 2
        }
    },
    
    # 攻击检测阈值
    'thresholds': {
        'ddos_packet_rate': 100,      # 每秒包数阈值
        'port_scan_count': 50,         # 端口扫描数量阈值
        'brute_force_count': 10,       # 暴力破解尝试次数阈值
        'ntp_amplification_factor': 10, # NTP放大倍数阈值
    },
    
    # 规则classtype到攻击类型的映射（用于规则匹配）
    'classtype_mapping': {
        'sql-injection': 'sql_injection',
        'sqli': 'sql_injection',
        'xss': 'xss',
        'cross-site-scripting': 'xss',
        'web-application-attack': 'web_attack',
        'web-attack': 'web_attack',
        'webshell': 'webshell',
        'file-inclusion': 'file_inclusion',
        'command-injection': 'cmd_injection',
        'buffer-overflow': 'buffer_overflow',
        'dos': 'dos',
        'ddos': 'ddos',
        'flood': 'dos',
        'scan': 'port_scan',
        'port-scan': 'port_scan',
        'attempted-recon': 'port_scan',
        'reconnaissance': 'port_scan',
        'trojan': 'c2_communication',
        'backdoor': 'webshell',
        'worm': 'c2_communication',
        'malware': 'c2_communication',
        'irc': 'irc_bot',
        'ircbot': 'irc_bot',
        'botnet': 'irc_bot',
        'c2': 'c2_communication',
        'brute-force': 'brute_force',
        'bruteforce': 'brute_force',
        'suspicious-login': 'brute_force',
        'default-login': 'brute_force',
        'dns-tunnel': 'dns_tunnel',
        'ntp-amplification': 'ntp_amplification',
        'amplification': 'ntp_amplification',
        'misc-activity': 'unknown',
        'attempted-admin': 'brute_force',
        'attempted-user': 'brute_force',
        'bad-unknown': 'unknown',
        'unknown': 'unknown',
        'potential-threat': 'unknown',
        'suspicious': 'unknown',
        'bad-traffic': 'unknown',
        'malicious-activity': 'unknown'
    }
}