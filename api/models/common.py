#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
通用数据模型定义
包含分页参数、时间范围等通用数据结构
"""

from pydantic import BaseModel, Field
from typing import Optional, Any, List
from datetime import datetime


class PaginationParams(BaseModel):
    """
    分页参数模型
    
    Attributes:
        page: 页码，从1开始
        page_size: 每页记录数，范围1-100
    """
    page: int = Field(1, ge=1, description="页码，从1开始")
    page_size: int = Field(20, ge=1, le=100, description="每页记录数，最大100")


class DateRange(BaseModel):
    """
    时间范围参数模型
    
    Attributes:
        start_time: 开始时间（ISO格式）
        end_time: 结束时间（ISO格式）
    """
    start_time: Optional[datetime] = Field(None, description="开始时间，格式：2026-04-20T00:00:00+08:00")
    end_time: Optional[datetime] = Field(None, description="结束时间，格式：2026-04-20T23:59:59+08:00")


class FilterParams(BaseModel):
    """
    通用筛选参数模型
    
    Attributes:
        severity: 严重程度（1=高，2=中，3=低）
        protocol: 协议类型（tcp/udp/icmp）
        processed: 处理状态（0=未处理，1=已处理）
    """
    severity: Optional[int] = Field(None, ge=1, le=3, description="严重程度：1=高，2=中，3=低")
    protocol: Optional[str] = Field(None, pattern="^(tcp|udp|icmp|ip)$", description="协议类型：tcp/udp/icmp/ip")
    processed: Optional[int] = Field(None, ge=0, le=1, description="处理状态：0=未处理，1=已处理")