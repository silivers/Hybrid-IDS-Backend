# Hybrid-IDS 混合入侵检测系统

Hybrid-IDS 是一个结合 Snort 规则匹配和 XGBoost 机器学习模型的混合入侵检测系统。系统采用两层检测策略：优先使用规则库快速匹配已知攻击，未命中规则的数据包交由 XGBoost 模型进行深度分析，实现对未知攻击的检测能力。

## 目录结构

| 文件/目录 | 说明 |
| --- | --- |
| Hybrid-IDS-Backend/ | 项目根目录 |
| ├── main.py | 系统主入口 |
| ├── config.py | 全局配置文件 |
| ├── requirements.txt | 依赖清单 |
├── Dockerfile | Docker镜像构建文件 |
├── .dockerignore | Docker 构建忽略文件 |
| ├── capture/ | 流量捕获与处理模块 |
| │   ├── feature_extractor.py | 24维特征提取器 |
| │   ├── flow_aggregator.py | 五元组流聚合器 |
| │   ├── __init__.py | 模块初始化 |
| │   ├── packet_capture.py | 实时数据包捕获 |
| │   ├── preprocessor.py | 特征编码与标准化 |
| │   └── README.md | 模块说明文档 |
| ├── engine/ | 检测引擎模块 |
| │   ├── detection_engine.py | 检测引擎（协调规则和模型） |
| │   ├── model_predictor.py | XGBoost模型预测器 |
| │   └── rule_matcher.py | Snort规则匹配器 |
| ├── models/ | 机器学习模型文件 |
| │   ├── xgboost_feature_names.txt | 特征名称列表 |
| │   ├── xgboost_label_encoders.pkl | 标签编码器 |
| │   ├── xgboost.pkl | XGBoost模型 |
| │   └── xgboost_scaler.pkl | 标准化器 |
| ├── storage/ | 数据持久化模块 |
| │   ├── alert_repo.py | 告警记录仓库（MySQL） |
| │   ├── packet_cache.py | 数据包内存缓存 |
| │   └── rule_repo.py | 规则库仓库（MySQL） |
| ├── utils/ | 工具函数模块 |
| │   └── validators.py | IP/端口/协议校验 |
| └── worker/ | 异步处理模块 |
|     └── async_processor.py | 异步特征提取与模型预测 |

## 系统架构

系统采用分层异步架构，将实时流量处理与深度分析解耦：

1. 数据采集层：从网卡捕获原始数据包，提取五元组和payload
2. 快速检测层：基于MySQL规则库进行规则匹配，命中则立即告警
3. 异步处理层：未命中规则的数据包进入内存缓存，交由后台线程处理
4. 特征工程层：流聚合、24维特征提取、编码与标准化
5. 模型推理层：XGBoost模型预测，输出威胁概率和分类结果
6. 告警存储层：将检测结果写入MySQL告警表，供前端查询

## 核心数据流

1. 网卡数据包 -> PacketCapturer（scapy抓包）
2. CapturedPacket -> DetectionEngine（检测引擎）
3. RuleMatcher查询MySQL snort_rules表进行规则匹配
4. 命中规则 -> AlertRepository写入snort_alerts表
5. 未命中规则 -> PacketCache内存缓存 + AsyncProcessor异步队列
6. 后台线程从队列读取 -> FlowAggregator流聚合
7. FeatureExtractor提取24维特征 -> DataPreprocessor编码+标准化
8. ModelPredictor加载XGBoost模型预测 -> 输出威胁概率
9. 概率高于阈值或处于模糊区间 -> AlertRepository写入告警

## 功能特点

- 混合检测：规则匹配快速响应已知攻击，机器学习识别未知威胁
- 异步处理：流量捕获与模型分析解耦，避免慢速操作阻塞实时流量
- 流聚合：基于五元组聚合数据包，提取会话级统计特征
- 内存缓存：未命中规则的数据包暂存于内存，支持TTL自动过期
- 规则缓存：规则查询结果缓存，减少MySQL访问频率
- 连接池：MySQL连接池复用，提升数据库操作效率
- 威胁分级：根据模型输出概率分为高/中/低三个威胁等级
- 模糊上报：概率处于0.3-0.7之间的流量上报管理员人工判断

## 模型特征

系统使用XGBoost分类器，共24个特征：

基础特征：proto, state, sbytes, dbytes, sttl, dttl, sloss, dloss, spkts, dpkts
时序特征：sjit, djit, tcprtt, synack, ackdat
服务特征：service, trans_depth, is_ftp_login
连接统计：ct_srv_src, ct_srv_dst, ct_dst_ltm, ct_src_ltm
其他特征：is_sm_ips_ports, ct_flw_http_mthd

模型参数：
- 决策树数量：200
- 最大深度：10
- 学习率：0.05
- 样本采样：0.8
- 特征采样：0.8

## 配置说明

编辑 config.py 文件：

数据库配置：
DB_CONFIG = {
    'host': 'localhost',
    'port': 3306,
    'user': 'root',
    'password': 'your_password',
    'database': 'snort_db'
}

检测阈值：
DETECTION_CONFIG = {
    'threat_threshold': 0.7,       # 高于此值为威胁
    'uncertain_threshold': 0.3,    # 介于0.3-0.7为模糊行为
    'flow_timeout': 60,            # 流超时时间（秒）
    'network_interface': None,     # 网卡接口（None自动选择）
    'capture_filter': 'ip'         # BPF过滤器
}

## 安装与运行

环境要求：
- Python 3.8+
- MySQL 5.7+
- Linux操作系统（推荐Ubuntu 20.04+）

安装依赖：
pip install -r requirements.txt

启动系统：
sudo python main.py

注意：数据包捕获需要root权限，建议使用sudo运行。

## Docker 部署

1. 构建镜像：
```bash
docker build -t hybrid-ids-backend:latest .
```
2. 运行容器：
```bash
docker run -d hybrid-ids-backend
```

## 数据库表结构

系统依赖以下MySQL表：

snort_rules：规则主表，存储Snort规则的sid、msg、classtype、severity等信息
snort_alerts：告警表，记录所有触发的告警事件
rule_contents：规则内容匹配表，存储规则的content匹配条件

告警表中sid=0表示由模型检测产生的告警，matched_content字段记录模型预测的概率。

## 检测结果处理

规则命中告警：
- sid：匹配规则的唯一标识符
- severity：规则的严重程度（1=高，2=中，3=低）
- matched_content：匹配到的content模式

模型检测告警：
- sid：0（表示模型检测）
- severity：根据概率确定（>=0.7为高，>=0.5为中，否则为低）
- matched_content：格式为"model_prediction=x,prob=0.xxx"

