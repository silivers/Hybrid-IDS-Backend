#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API统一响应格式工具
提供标准化的成功/错误响应和分页响应格式
"""

from datetime import datetime
from typing import Any, Optional, Dict, List


def success_response(data: Any = None, message: str = "success", request_id: Optional[str] = None) -> Dict:
    """
    生成统一格式的成功响应
    
    Args:
        data: 响应数据，可以是任意类型
        message: 响应消息，默认为"success"
        request_id: 请求追踪ID，用于日志关联
    
    Returns:
        标准格式的成功响应字典
        {
            "code": 200,
            "message": "success",
            "data": {...},
            "timestamp": "2026-04-20T10:30:00+08:00",
            "request_id": "req_abc123"
        }
    """
    return {
        "code": 200,
        "message": message,
        "data": data,
        "timestamp": datetime.now().isoformat(),
        "request_id": request_id or "unknown"
    }


def error_response(code: int, message: str, request_id: Optional[str] = None) -> Dict:
    """
    生成统一格式的错误响应
    
    Args:
        code: HTTP状态码或业务错误码
        message: 错误描述信息
        request_id: 请求追踪ID
    
    Returns:
        标准格式的错误响应字典
    """
    return {
        "code": code,
        "message": message,
        "timestamp": datetime.now().isoformat(),
        "request_id": request_id or "unknown"
    }


def paginated_response(items: List[Any], page: int, page_size: int, total: int) -> Dict:
    """
    生成分页格式的响应数据
    
    Args:
        items: 当前页的数据列表
        page: 当前页码
        page_size: 每页记录数
        total: 总记录数
    
    Returns:
        包含分页信息的响应数据字典
        {
            "items": [...],
            "pagination": {
                "page": 1,
                "page_size": 20,
                "total": 100,
                "total_pages": 5
            }
        }
    """
    total_pages = (total + page_size - 1) // page_size if total > 0 else 0
    return {
        "items": items,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": total_pages
        }
    }