# api/routes/stats.py
"""统计辅助API"""
from fastapi import APIRouter, Depends

from api import get_alert_repo, get_rule_repo
from api.schemas import SuccessResponse, ErrorResponse

router = APIRouter()


@router.get("/classtypes", response_model=SuccessResponse)
async def get_classtypes(
    rule_repo = Depends(get_rule_repo)
):
    """获取所有可用的规则分类"""
    try:
        classtype_stats = rule_repo.get_classtype_stats()
        
        return SuccessResponse(data={'classtypes': classtype_stats})
        
    except Exception as e:
        return ErrorResponse(code=500, message=str(e))


@router.get("/filter-options", response_model=SuccessResponse)
async def get_filter_options(
    alert_repo = Depends(get_alert_repo)
):
    """获取所有筛选器选项"""
    try:
        filter_options = alert_repo.get_filter_options()
        
        return SuccessResponse(data=filter_options)
        
    except Exception as e:
        return ErrorResponse(code=500, message=str(e))