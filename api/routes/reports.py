# api/routes/reports.py
"""报表与合规API"""
from fastapi import APIRouter, Depends, Query
from typing import Optional
from datetime import datetime, date, timedelta

from api import get_alert_repo
from api.schemas import SuccessResponse, ErrorResponse

router = APIRouter()


def parse_date(date_str: Optional[str]) -> Optional[date]:
    """解析日期字符串"""
    if not date_str:
        return None
    try:
        return datetime.fromisoformat(date_str.replace('Z', '+00:00')).date()
    except:
        return None


@router.get("/summary", response_model=SuccessResponse)
async def get_report_summary(
    start_date: Optional[str] = Query(None, description="开始日期"),
    end_date: Optional[str] = Query(None, description="结束日期"),
    group_by: str = Query("day", description="分组方式: day/hour"),
    alert_repo = Depends(get_alert_repo)
):
    """告警摘要报表"""
    try:
        start = parse_date(start_date)
        end = parse_date(end_date)
        
        # 默认最近7天
        if not start:
            end = date.today()
            start = end - timedelta(days=7)
        if not end:
            end = date.today()
        
        result = alert_repo.get_report_summary(start, end, group_by)
        
        # 计算百分比
        summary = result.get('summary', {})
        total = summary.get('total_alerts', 0)
        if total > 0:
            for severity in ['high_count', 'medium_count', 'low_count']:
                if severity in summary:
                    summary[severity.replace('_count', '_percentage')] = round(summary[severity] * 100 / total, 2)
        
        data = {
            'period': {
                'start': start.isoformat(),
                'end': end.isoformat(),
                'days': (end - start).days + 1
            },
            'summary': summary,
            'daily_trend': result.get('trend', [])
        }
        
        return SuccessResponse(data=data)
        
    except Exception as e:
        return ErrorResponse(code=500, message=str(e))


@router.get("/top-sources", response_model=SuccessResponse)
async def get_top_sources(
    start_date: Optional[str] = Query(None, description="开始日期"),
    end_date: Optional[str] = Query(None, description="结束日期"),
    limit: int = Query(10, ge=1, le=50, description="返回数量"),
    alert_repo = Depends(get_alert_repo)
):
    """TOP攻击源报表"""
    try:
        start = parse_date(start_date)
        end = parse_date(end_date)
        
        if not start:
            end = date.today()
            start = end - timedelta(days=7)
        if not end:
            end = date.today()
        
        top_sources = alert_repo.get_top_sources_report(start, end, limit)
        
        # 计算总告警数用于百分比
        total_alerts = sum(s.get('alert_count', 0) for s in top_sources)
        
        for source in top_sources:
            if total_alerts > 0:
                source['percentage'] = round(source['alert_count'] * 100 / total_alerts, 2)
            else:
                source['percentage'] = 0
        
        data = {
            'period': {
                'start': start.isoformat(),
                'end': end.isoformat()
            },
            'top_sources': top_sources
        }
        
        return SuccessResponse(data=data)
        
    except Exception as e:
        return ErrorResponse(code=500, message=str(e))


@router.get("/top-rules", response_model=SuccessResponse)
async def get_top_rules(
    start_date: Optional[str] = Query(None, description="开始日期"),
    end_date: Optional[str] = Query(None, description="结束日期"),
    limit: int = Query(10, ge=1, le=50, description="返回数量"),
    alert_repo = Depends(get_alert_repo)
):
    """TOP规则命中报表"""
    try:
        start = parse_date(start_date)
        end = parse_date(end_date)
        
        if not start:
            end = date.today()
            start = end - timedelta(days=7)
        if not end:
            end = date.today()
        
        top_rules = alert_repo.get_top_rules_report(start, end, limit)
        
        # 计算总告警数用于百分比
        total_alerts = sum(r.get('hit_count', 0) for r in top_rules)
        
        for rule in top_rules:
            if total_alerts > 0:
                rule['percentage'] = round(rule['hit_count'] * 100 / total_alerts, 2)
            else:
                rule['percentage'] = 0
        
        data = {
            'period': {
                'start': start.isoformat(),
                'end': end.isoformat()
            },
            'top_rules': top_rules
        }
        
        return SuccessResponse(data=data)
        
    except Exception as e:
        return ErrorResponse(code=500, message=str(e))