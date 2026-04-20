# api/middleware/pagination.py
"""分页辅助函数"""
from fastapi import Query
from typing import Tuple
from config import PAGINATION_CONFIG


def get_pagination_params(
    page: int = Query(1, ge=1, description="页码"),
    page_size: int = Query(PAGINATION_CONFIG['default_page_size'], ge=1, le=PAGINATION_CONFIG['max_page_size'], description="每页数量")
) -> Tuple[int, int, int]:
    """
    获取分页参数
    
    Returns:
        (page, page_size, offset)
    """
    offset = (page - 1) * page_size
    return page, page_size, offset