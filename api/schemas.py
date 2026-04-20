# api/schemas.py
"""Pydantic模型定义"""
from pydantic import BaseModel
from typing import Optional, List, Any, Dict
from datetime import datetime


class SuccessResponse(BaseModel):
    """成功响应格式"""
    code: int = 200
    message: str = "success"
    data: Optional[Any] = None


class ErrorResponse(BaseModel):
    """错误响应格式"""
    code: int
    message: str
    data: Optional[Any] = None


class PaginationParams(BaseModel):
    """分页参数"""
    page: int = 1
    page_size: int = 20
    
    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size


class PaginatedResponse(BaseModel):
    """分页响应格式"""
    items: List[Any]
    pagination: Dict[str, Any]


# 告警相关Schema
class AlertFilter(BaseModel):
    """告警筛选条件"""
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    severity: Optional[int] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: Optional[str] = None
    processed: Optional[int] = None
    sid: Optional[int] = None


class BatchProcessRequest(BaseModel):
    """批量处理请求"""
    alert_ids: List[int]
    processed: int = 1


class ToggleRuleRequest(BaseModel):
    """规则启用/禁用请求"""
    enabled: int = 1