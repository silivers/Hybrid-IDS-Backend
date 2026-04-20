# Hybrid IDS API 文档

## 概述

混合入侵检测系统（Hybrid IDS）RESTful API，提供安全监控、告警管理、事件调查和规则管理等功能。

### 基础信息

| 项目 | 说明 |
|------|------|
| 基础URL | http://localhost:8000/api |
| 文档地址 | http://localhost:8000/docs |
| 交互式文档 | http://localhost:8000/redoc |
| 响应格式 | JSON |
| 字符编码 | UTF-8 |

### 响应格式

所有接口统一返回以下格式：

{
    "code": 200,
    "message": "success",
    "data": {}
}

### 错误码说明

| 错误码 | 说明 |
|--------|------|
| 200 | 成功 |
| 400 | 请求参数错误 |
| 404 | 资源不存在 |
| 500 | 服务器内部错误 |

---

## 目录

1. 仪表盘 API
2. 告警管理 API
3. 事件调查 API
4. 资产管理 API
5. 规则管理 API
6. 报表 API
7. 统计辅助 API
8. 健康检查

---

## 1. 仪表盘 API

### 1.1 获取仪表盘总览数据

获取系统总览、告警趋势、TOP统计等仪表盘核心数据。

**请求**

GET /api/dashboard/overview

**查询参数**

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| days | integer | 否 | 7 | 统计天数，范围 1-90 |

**响应示例**

{
    "code": 200,
    "message": "success",
    "data": {
        "metrics": {
            "total_alerts": 1250,
            "high_severity": 342,
            "unprocessed": 89,
            "affected_assets": 45
        },
        "trend": {
            "last_24h": [
                {"time_bucket": "2026-04-20 00:00:00", "count": 23},
                {"time_bucket": "2026-04-20 01:00:00", "count": 18}
            ],
            "last_7d": [
                {"date": "2026-04-14", "count": 156},
                {"date": "2026-04-15", "count": 203}
            ]
        },
        "severity_distribution": [
            {"severity": 1, "level": "高", "count": 342},
            {"severity": 2, "level": "中", "count": 567},
            {"severity": 3, "level": "低", "count": 341}
        ],
        "top_stats": {
            "src_ips": [
                {"src_ip": "192.168.1.100", "count": 234, "high_count": 45}
            ],
            "dst_ips": [
                {"dst_ip": "192.168.1.50", "count": 567, "high_count": 89}
            ],
            "alert_types": [
                {"sid": 117, "msg": "ET SCAN Potential SSH Scan", "count": 89}
            ],
            "rules": [
                {"sid": 117, "msg": "ET SCAN Potential SSH Scan", "count": 89}
            ]
        }
    }
}

---

## 2. 告警管理 API

### 2.1 获取告警列表

获取告警列表，支持分页、多条件筛选和排序。

**请求**

GET /api/alerts

**查询参数**

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| page | integer | 否 | 1 | 页码，从1开始 |
| page_size | integer | 否 | 20 | 每页数量，最大100 |
| start_time | string | 否 | - | 开始时间，格式：YYYY-MM-DDTHH:MM:SS |
| end_time | string | 否 | - | 结束时间 |
| severity | integer | 否 | - | 严重程度：1=高，2=中，3=低 |
| src_ip | string | 否 | - | 源IP地址 |
| dst_ip | string | 否 | - | 目标IP地址 |
| protocol | string | 否 | - | 协议类型：tcp/udp/icmp |
| processed | integer | 否 | - | 处理状态：0=未处理，1=已处理 |
| sid | integer | 否 | - | 规则ID |
| sort_by | string | 否 | timestamp | 排序字段 |
| sort_order | string | 否 | DESC | 排序方向：ASC/DESC |

**响应示例**

{
    "code": 200,
    "message": "success",
    "data": {
        "items": [
            {
                "alert_id": 364,
                "sid": 117,
                "timestamp": "2026-04-20 10:23:45",
                "src_ip": "192.168.10.41",
                "src_port": 64431,
                "dst_ip": "192.168.10.8",
                "dst_port": 22,
                "protocol": "tcp",
                "severity": 3,
                "severity_level": "低",
                "processed": 0,
                "matched_content": "WHATISIT",
                "payload_preview": "SSH-2.0-OpenSSH_7.4..."
            }
        ],
        "pagination": {
            "page": 1,
            "page_size": 20,
            "total": 1250,
            "total_pages": 63,
            "has_next": true,
            "has_prev": false
        }
    }
}

### 2.2 获取告警详情

获取指定告警的详细信息，包括关联的规则内容和匹配条件。

**请求**

GET /api/alerts/{alert_id}

**路径参数**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| alert_id | integer | 是 | 告警ID |

**响应示例**

{
    "code": 200,
    "message": "success",
    "data": {
        "alert_id": 364,
        "timestamp": "2026-04-20 10:23:45",
        "src_ip": "192.168.10.41",
        "src_port": 64431,
        "dst_ip": "192.168.10.8",
        "dst_port": 22,
        "protocol": "tcp",
        "severity": 3,
        "severity_level": "低",
        "processed": 0,
        "matched_content": "WHATISIT",
        "payload_preview": "SSH-2.0-OpenSSH_7.4...",
        "rule": {
            "sid": 117,
            "msg": "ET SCAN Potential SSH Scan",
            "classtype": "attempted-recon",
            "rule_text": "alert tcp $HOME_NET any -> $EXTERNAL_NET 22 ...",
            "reference": "cve,2021-1234;bugtraq,5678",
            "rev": 2,
            "severity": 3
        },
        "rule_contents": [
            {
                "position_order": 1,
                "content_pattern": "WHATISIT",
                "content_type": "content",
                "offset_val": 0,
                "depth_val": 9,
                "within_val": null,
                "distance_val": null,
                "is_negated": 0
            }
        ]
    }
}

### 2.3 标记告警为已处理

将指定告警标记为已处理状态。

**请求**

PUT /api/alerts/{alert_id}/process

**路径参数**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| alert_id | integer | 是 | 告警ID |

**请求体**

{
    "processed": 1
}

**响应示例**

{
    "code": 200,
    "message": "success",
    "data": {
        "alert_id": 364,
        "processed": 1
    }
}

### 2.4 批量标记告警

批量将多个告警标记为已处理或未处理状态。

**请求**

PUT /api/alerts/batch-process

**请求体**

{
    "alert_ids": [364, 365, 366],
    "processed": 1
}

**响应示例**

{
    "code": 200,
    "message": "success",
    "data": {
        "processed_count": 3,
        "alert_ids": [364, 365, 366],
        "processed": 1
    }
}

---

## 3. 事件调查 API

### 3.1 按源IP聚合调查

按攻击源IP聚合查询所有告警，用于溯源分析。

**请求**

GET /api/investigate/source/{src_ip}

**路径参数**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| src_ip | string | 是 | 源IP地址（攻击者IP） |

**查询参数**

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| start_time | string | 否 | - | 开始时间 |
| end_time | string | 否 | - | 结束时间 |
| limit | integer | 否 | 100 | 返回记录数，最大500 |

**响应示例**

{
    "code": 200,
    "message": "success",
    "data": {
        "src_ip": "192.168.10.41",
        "statistics": {
            "total_alerts": 234,
            "unique_dst_ips": 12,
            "severity_breakdown": {
                "high": 45,
                "medium": 123,
                "low": 66
            },
            "first_alert": "2026-04-19 08:00:00",
            "last_alert": "2026-04-20 10:23:45"
        },
        "alerts": [
            {
                "alert_id": 364,
                "timestamp": "2026-04-20 10:23:45",
                "dst_ip": "192.168.10.8",
                "dst_port": 22,
                "severity": 3,
                "matched_content": "WHATISIT"
            }
        ],
        "dst_ip_summary": [
            {"dst_ip": "192.168.10.8", "alert_count": 156},
            {"dst_ip": "192.168.10.50", "alert_count": 78}
        ]
    }
}

### 3.2 对话聚合查询

查询两个IP之间的所有通信告警，支持时间窗口聚合。

**请求**

GET /api/investigate/conversation

**查询参数**

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| src_ip | string | 是 | - | 源IP地址 |
| dst_ip | string | 是 | - | 目标IP地址 |
| start_time | string | 否 | - | 开始时间 |
| end_time | string | 否 | - | 结束时间 |
| time_window_minutes | integer | 否 | 5 | 聚合时间窗口（分钟），范围1-60 |

**响应示例**

{
    "code": 200,
    "message": "success",
    "data": {
        "src_ip": "192.168.10.41",
        "dst_ip": "192.168.10.8",
        "total_alerts": 156,
        "time_window_minutes": 5,
        "aggregated_alerts": [
            {
                "window_start": "2026-04-20 10:20:00",
                "window_end": "2026-04-20 10:25:00",
                "alert_count": 23,
                "rule_sids": [117, 118, 119],
                "unique_severities": [2, 3]
            }
        ],
        "timeline": [
            {
                "alert_id": 364,
                "timestamp": "2026-04-20 10:23:45",
                "sid": 117,
                "severity": 3
            }
        ]
    }
}

### 3.3 资产上下文查询

获取指定资产的完整安全上下文信息。

**请求**

GET /api/investigate/asset/{dst_ip}

**路径参数**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| dst_ip | string | 是 | 目标IP地址（资产IP） |

**响应示例**

{
    "code": 200,
    "message": "success",
    "data": {
        "dst_ip": "192.168.10.8",
        "statistics": {
            "total_alerts": 567,
            "max_severity": 1,
            "last_alert": "2026-04-20 10:23:45",
            "first_alert": "2026-04-01 00:00:00",
            "avg_daily_alerts": 18.9,
            "unique_attackers": 23,
            "unique_rules": 45
        },
        "severity_timeline": [
            {"date": "2026-04-20", "count": 45, "high_count": 12}
        ],
        "top_attackers": [
            {"src_ip": "192.168.10.41", "alert_count": 234, "high_count": 34, "last_alert": "2026-04-20 10:23:45"}
        ],
        "rule_type_distribution": [
            {"classtype": "attempted-recon", "count": 234},
            {"classtype": "trojan-activity", "count": 156}
        ]
    }
}

---

## 4. 资产管理 API

### 4.1 获取资产列表

获取所有受监控资产列表，支持筛选和排序。

**请求**

GET /api/assets

**查询参数**

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| severity_threshold | integer | 否 | - | 严重程度阈值，只显示达到该等级的资产 |
| has_unprocessed | boolean | 否 | - | 是否只显示有未处理告警的资产 |
| sort_by | string | 否 | total_alerts | 排序字段 |
| limit | integer | 否 | 50 | 返回数量，最大200 |

**响应示例**

{
    "code": 200,
    "message": "success",
    "data": {
        "total_assets": 45,
        "items": [
            {
                "dst_ip": "192.168.10.8",
                "total_alerts": 567,
                "max_severity": 1,
                "max_severity_level": "高",
                "last_alert": "2026-04-20 10:23:45",
                "unprocessed_count": 23,
                "risk_score": 78.5
            }
        ]
    }
}

### 4.2 获取资产风险详情

获取指定资产的详细风险分析报告。

**请求**

GET /api/assets/{dst_ip}/risk

**路径参数**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| dst_ip | string | 是 | 目标IP地址 |

**响应示例**

{
    "code": 200,
    "message": "success",
    "data": {
        "dst_ip": "192.168.10.8",
        "risk_score": 78.5,
        "high_severity_count": 89,
        "alert_trend": [
            {"date": "2026-04-20", "count": 45, "high_count": 12},
            {"date": "2026-04-19", "count": 67, "high_count": 23}
        ],
        "attack_sources": [
            {"src_ip": "192.168.10.41", "alert_count": 234, "high_count": 34, "last_alert": "2026-04-20 10:23:45"}
        ],
        "recommendations": [
            "高风险资产，建议立即调查",
            "高频攻击源 192.168.10.41，建议考虑封禁",
            "检测到 89 次高危告警，建议深入分析"
        ]
    }
}

---

## 5. 规则管理 API

### 5.1 获取规则列表

获取Snort规则列表，支持分页和多条件筛选。

**请求**

GET /api/rules

**查询参数**

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| page | integer | 否 | 1 | 页码，从1开始 |
| page_size | integer | 否 | 20 | 每页数量，最大100 |
| sid | integer | 否 | - | 规则ID |
| msg_keyword | string | 否 | - | 规则消息关键词 |
| classtype | string | 否 | - | 攻击分类 |
| protocol | string | 否 | - | 协议类型 |
| severity | integer | 否 | - | 严重程度：1=高，2=中，3=低 |
| enabled | integer | 否 | - | 启用状态：1=启用，0=禁用 |

**响应示例**

{
    "code": 200,
    "message": "success",
    "data": {
        "items": [
            {
                "sid": 117,
                "msg": "ET SCAN Potential SSH Scan",
                "classtype": "attempted-recon",
                "protocol": "tcp",
                "source_ip": "$HOME_NET",
                "source_port": "any",
                "dest_ip": "$EXTERNAL_NET",
                "dest_port": "22",
                "severity": 3,
                "severity_level": "低",
                "enabled": 1,
                "content_preview": ["WHATISIT", "SSH"],
                "rev": 2
            }
        ],
        "pagination": {
            "page": 1,
            "page_size": 20,
            "total": 4017,
            "total_pages": 201,
            "has_next": true,
            "has_prev": false
        }
    }
}

### 5.2 获取规则详情

获取指定规则的完整信息。

**请求**

GET /api/rules/{sid}

**路径参数**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| sid | integer | 是 | 规则ID |

**响应示例**

{
    "code": 200,
    "message": "success",
    "data": {
        "sid": 117,
        "msg": "ET SCAN Potential SSH Scan",
        "classtype": "attempted-recon",
        "rule_text": "alert tcp $HOME_NET any -> $EXTERNAL_NET 22 (msg:\"ET SCAN Potential SSH Scan\"; flow:to_server,established; content:\"WHATISIT\"; depth:9; content:\"SSH\"; nocase; within:20; sid:117; rev:2;)",
        "protocol": "tcp",
        "source_ip": "$HOME_NET",
        "source_port": "any",
        "dest_ip": "$EXTERNAL_NET",
        "dest_port": "22",
        "flow": "to_server,established",
        "reference": "cve,2021-1234;bugtraq,5678",
        "rev": 2,
        "severity": 3,
        "enabled": 1,
        "cve_list": ["cve,2021-1234"],
        "contents": [
            {
                "position_order": 1,
                "content_pattern": "WHATISIT",
                "content_type": "content",
                "offset_val": 0,
                "depth_val": 9,
                "within_val": null,
                "distance_val": null,
                "is_negated": 0
            }
        ],
        "classtype_stats": {
            "classtype": "attempted-recon",
            "rule_count": 234,
            "avg_severity": 2.3
        }
    }
}

### 5.3 启用/禁用规则

切换规则的启用状态。

**请求**

PUT /api/rules/{sid}/toggle

**路径参数**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| sid | integer | 是 | 规则ID |

**请求体**

{
    "enabled": 0
}

**响应示例**

{
    "code": 200,
    "message": "success",
    "data": {
        "sid": 117,
        "enabled": 0,
        "status": "禁用"
    }
}

---

## 6. 报表 API

### 6.1 告警摘要报表

生成指定时间范围内的告警摘要报表。

**请求**

GET /api/reports/summary

**查询参数**

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| start_date | string | 否 | 7天前 | 开始日期，格式：YYYY-MM-DD |
| end_date | string | 否 | 今天 | 结束日期 |
| group_by | string | 否 | day | 分组方式：day=按天，hour=按小时 |

**响应示例**

{
    "code": 200,
    "message": "success",
    "data": {
        "period": {
            "start": "2026-04-01",
            "end": "2026-04-20",
            "days": 20
        },
        "summary": {
            "total_alerts": 1250,
            "high_count": 342,
            "high_percentage": 27.36,
            "medium_count": 567,
            "medium_percentage": 45.36,
            "low_count": 341,
            "low_percentage": 27.28,
            "unique_sources": 34,
            "unique_targets": 45,
            "unique_rules": 89
        },
        "daily_trend": [
            {"time_bucket": "2026-04-01", "total_alerts": 45, "high_count": 12, "medium_count": 23, "low_count": 10}
        ]
    }
}

### 6.2 TOP攻击源报表

统计指定时间范围内最活跃的攻击源IP。

**请求**

GET /api/reports/top-sources

**查询参数**

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| start_date | string | 否 | 7天前 | 开始日期 |
| end_date | string | 否 | 今天 | 结束日期 |
| limit | integer | 否 | 10 | 返回数量，最大50 |

**响应示例**

{
    "code": 200,
    "message": "success",
    "data": {
        "period": {
            "start": "2026-04-01",
            "end": "2026-04-20"
        },
        "top_sources": [
            {
                "src_ip": "192.168.10.41",
                "alert_count": 234,
                "percentage": 18.72,
                "high_count": 45,
                "medium_count": 123,
                "low_count": 66,
                "target_count": 12,
                "first_seen": "2026-04-01 08:00:00",
                "last_seen": "2026-04-20 10:23:45"
            }
        ]
    }
}

### 6.3 TOP规则命中报表

统计指定时间范围内命中次数最多的Snort规则。

**请求**

GET /api/reports/top-rules

**查询参数**

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| start_date | string | 否 | 7天前 | 开始日期 |
| end_date | string | 否 | 今天 | 结束日期 |
| limit | integer | 否 | 10 | 返回数量，最大50 |

**响应示例**

{
    "code": 200,
    "message": "success",
    "data": {
        "period": {
            "start": "2026-04-01",
            "end": "2026-04-20"
        },
        "top_rules": [
            {
                "sid": 117,
                "msg": "ET SCAN Potential SSH Scan",
                "classtype": "attempted-recon",
                "hit_count": 456,
                "percentage": 36.48,
                "rule_severity": 3,
                "unique_sources": 23,
                "unique_targets": 12
            }
        ]
    }
}

---

## 7. 统计辅助 API

### 7.1 获取规则分类统计

获取所有规则分类及其统计信息（数据来源于rule_stats视图）。

**请求**

GET /api/stats/classtypes

**响应示例**

{
    "code": 200,
    "message": "success",
    "data": {
        "classtypes": [
            {"classtype": "attempted-recon", "rule_count": 234, "avg_severity": 2.3},
            {"classtype": "trojan-activity", "rule_count": 156, "avg_severity": 1.8}
        ]
    }
}

### 7.2 获取筛选器选项

获取前端筛选器所需的所有选项及其当前数量统计。

**请求**

GET /api/stats/filter-options

**响应示例**

{
    "code": 200,
    "message": "success",
    "data": {
        "protocols": [
            {"protocol": "tcp", "count": 856},
            {"protocol": "udp", "count": 342},
            {"protocol": "icmp", "count": 52}
        ],
        "severities": [
            {"severity": 1, "label": "高", "count": 342},
            {"severity": 2, "label": "中", "count": 567},
            {"severity": 3, "label": "低", "count": 341}
        ],
        "processed_status": [
            {"processed": 0, "label": "未处理", "count": 89},
            {"processed": 1, "label": "已处理", "count": 1161}
        ],
        "classtypes": [
            {"classtype": "attempted-recon", "count": 234},
            {"classtype": "trojan-activity", "count": 156}
        ]
    }
}



## API 接口汇总表

| 模块 | 方法 | 路径 | 说明 |
|------|------|------|------|
| 仪表盘 | GET | /api/dashboard/overview | 获取仪表盘总览数据 |
| 告警管理 | GET | /api/alerts | 获取告警列表 |
| 告警管理 | GET | /api/alerts/{alert_id} | 获取告警详情 |
| 告警管理 | PUT | /api/alerts/{alert_id}/process | 标记告警为已处理 |
| 告警管理 | PUT | /api/alerts/batch-process | 批量标记告警 |
| 事件调查 | GET | /api/investigate/source/{src_ip} | 按源IP聚合调查 |
| 事件调查 | GET | /api/investigate/conversation | 对话聚合查询 |
| 事件调查 | GET | /api/investigate/asset/{dst_ip} | 资产上下文查询 |
| 资产管理 | GET | /api/assets | 获取资产列表 |
| 资产管理 | GET | /api/assets/{dst_ip}/risk | 获取资产风险详情 |
| 规则管理 | GET | /api/rules | 获取规则列表 |
| 规则管理 | GET | /api/rules/{sid} | 获取规则详情 |
| 规则管理 | PUT | /api/rules/{sid}/toggle | 启用/禁用规则 |
| 报表 | GET | /api/reports/summary | 告警摘要报表 |
| 报表 | GET | /api/reports/top-sources | TOP攻击源报表 |
| 报表 | GET | /api/reports/top-rules | TOP规则命中报表 |
| 统计 | GET | /api/stats/classtypes | 获取规则分类统计 |
| 统计 | GET | /api/stats/filter-options | 获取筛选器选项 |
