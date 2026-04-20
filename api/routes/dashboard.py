# api/routes/dashboard.py
"""仪表盘API"""
from fastapi import APIRouter, Depends, Query
from typing import Optional
from datetime import datetime

from api import get_alert_repo
from api.schemas import SuccessResponse, ErrorResponse

router = APIRouter()


@router.get("/overview", response_model=SuccessResponse)
async def get_overview(
    days: int = Query(7, ge=1, le=90, description="统计天数"),
    alert_repo = Depends(get_alert_repo)
):
    """获取仪表盘总览数据"""
    try:
        # 获取各项指标
        metrics = alert_repo.get_dashboard_metrics(days)
        trend = alert_repo.get_alert_trend(24)
        severity_dist = alert_repo.get_severity_distribution(days)
        top_src = alert_repo.get_top_src_ips(10, days)
        top_dst = alert_repo.get_top_dst_ips(10, days)
        top_alerts = alert_repo.get_top_alert_types(10, days)
        top_rules = alert_repo.get_top_rules(10, days)
        
        data = {
            'metrics': metrics,
            'trend': trend,
            'severity_distribution': severity_dist,
            'top_stats': {
                'src_ips': top_src,
                'dst_ips': top_dst,
                'alert_types': top_alerts,
                'rules': top_rules
            }
        }
        
        return SuccessResponse(data=data)
        
    except Exception as e:
        return ErrorResponse(code=500, message=str(e))