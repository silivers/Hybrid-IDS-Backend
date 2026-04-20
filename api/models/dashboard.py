#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
仪表盘数据模型定义
包含总览统计、趋势图、TOP统计等数据结构
"""

from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime


class OverviewStats(BaseModel):
    """
    仪表盘总览统计数据模型
    
    Attributes:
        total_alerts: 总告警数
        high_severity_count: 高危告警数（severity=1）
        unprocessed_count: 未处理告警数（processed=0）
        affected_assets: 受影响资产数（去重后的目标IP数量）
    """
    total_alerts: int = Field(..., description="总告警数")
    high_severity_count: int = Field(..., description="高危告警数（severity=1）")
    unprocessed_count: int = Field(..., description="未处理告警数（processed=0）")
    affected_assets: int = Field(..., description="受影响资产数（去重后的目标IP数量）")


class TrendPoint(BaseModel):
    """
    告警趋势数据点模型
    
    Attributes:
        timestamp: 时间点（小时或天）
        count: 该时间点的告警总数
        high_count: 该时间点的高危告警数（可选）
    """
    timestamp: str = Field(..., description="时间点，格式：2026-04-20 10:00:00 或 2026-04-20")
    count: int = Field(..., description="该时间点的告警总数")
    high_count: Optional[int] = Field(None, description="该时间点的高危告警数")


class SeverityDistribution(BaseModel):
    """
    严重程度分布数据模型
    
    Attributes:
        severity: 严重程度值（1/2/3）
        severity_label: 严重程度标签（高/中/低）
        count: 该严重程度的告警数量
        percentage: 占比百分比
    """
    severity: int = Field(..., description="严重程度值：1=高，2=中，3=低")
    severity_label: str = Field(..., description="严重程度标签：高/中/低")
    count: int = Field(..., description="该严重程度的告警数量")
    percentage: float = Field(..., description="占比百分比，保留两位小数")


class TopItem(BaseModel):
    """
    TOP N 统计项数据模型
    
    Attributes:
        key: 统计项的键值（IP地址、规则ID等）
        alert_count: 告警数量
        high_severity_count: 高危告警数量（可选）
        msg: 规则消息（仅当type=rule时）
    """
    key: str = Field(..., description="统计项的键值（IP地址、规则ID等）")
    alert_count: int = Field(..., description="告警数量")
    high_severity_count: Optional[int] = Field(None, description="高危告警数量")
    msg: Optional[str] = Field(None, description="规则消息（仅当type=rule时）")