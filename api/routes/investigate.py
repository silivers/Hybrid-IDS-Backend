# api/routes/investigate.py
"""事件调查与溯源API"""
from fastapi import APIRouter, Depends, Query, HTTPException
from typing import Optional
from datetime import datetime

from api import get_alert_repo, get_rule_repo
from api.schemas import SuccessResponse, ErrorResponse

router = APIRouter()


@router.get("/source/{src_ip}", response_model=SuccessResponse)
async def investigate_source(
    src_ip: str,
    start_time: Optional[str] = Query(None, description="开始时间"),
    end_time: Optional[str] = Query(None, description="结束时间"),
    limit: int = Query(100, ge=1, le=500, description="返回记录数"),
    alert_repo = Depends(get_alert_repo)
):
    """按源IP聚合调查"""
    try:
        # 解析时间
        start_dt = None
        end_dt = None
        if start_time:
            start_dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        if end_time:
            end_dt = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
        
        alerts = alert_repo.get_alerts_by_src_ip(src_ip, start_dt, end_dt, limit)
        
        # 统计信息
        if alerts:
            total = len(alerts)
            unique_dst = len(set(a['dst_ip'] for a in alerts))
            severity_breakdown = {1: 0, 2: 0, 3: 0}
            for a in alerts:
                severity_breakdown[a['severity']] = severity_breakdown.get(a['severity'], 0) + 1
            
            first_alert = alerts[-1]['timestamp'] if alerts else None
            last_alert = alerts[0]['timestamp'] if alerts else None
            
            # 按目标IP汇总
            dst_summary = {}
            for a in alerts:
                dst = a['dst_ip']
                dst_summary[dst] = dst_summary.get(dst, 0) + 1
            dst_summary_list = [{'dst_ip': ip, 'alert_count': cnt} for ip, cnt in sorted(dst_summary.items(), key=lambda x: x[1], reverse=True)]
        else:
            unique_dst = 0
            severity_breakdown = {1: 0, 2: 0, 3: 0}
            first_alert = None
            last_alert = None
            dst_summary_list = []
            total = 0
        
        data = {
            'src_ip': src_ip,
            'statistics': {
                'total_alerts': total,
                'unique_dst_ips': unique_dst,
                'severity_breakdown': {
                    'high': severity_breakdown.get(1, 0),
                    'medium': severity_breakdown.get(2, 0),
                    'low': severity_breakdown.get(3, 0)
                },
                'first_alert': first_alert,
                'last_alert': last_alert
            },
            'alerts': alerts[:50],
            'dst_ip_summary': dst_summary_list[:20]
        }
        
        return SuccessResponse(data=data)
        
    except Exception as e:
        return ErrorResponse(code=500, message=str(e))


@router.get("/conversation", response_model=SuccessResponse)
async def investigate_conversation(
    src_ip: str = Query(..., description="源IP"),
    dst_ip: str = Query(..., description="目标IP"),
    start_time: Optional[str] = Query(None, description="开始时间"),
    end_time: Optional[str] = Query(None, description="结束时间"),
    time_window_minutes: int = Query(5, ge=1, le=60, description="聚合时间窗口（分钟）"),
    alert_repo = Depends(get_alert_repo)
):
    """按(src_ip, dst_ip)聚合查询"""
    try:
        # 解析时间
        start_dt = None
        end_dt = None
        if start_time:
            start_dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        if end_time:
            end_dt = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
        
        alerts = alert_repo.get_conversation_alerts(src_ip, dst_ip, start_dt, end_dt)
        
        # 按时间窗口聚合
        aggregated = {}
        for alert in alerts:
            ts = datetime.fromisoformat(alert['timestamp'])
            window_key = ts.replace(minute=(ts.minute // time_window_minutes) * time_window_minutes, second=0, microsecond=0)
            key_str = window_key.strftime('%Y-%m-%d %H:%M:%S')
            
            if key_str not in aggregated:
                aggregated[key_str] = {
                    'window_start': key_str,
                    'window_end': (window_key.replace(minute=window_key.minute + time_window_minutes)).strftime('%Y-%m-%d %H:%M:%S'),
                    'alert_count': 0,
                    'rule_sids': set(),
                    'unique_severities': set()
                }
            aggregated[key_str]['alert_count'] += 1
            aggregated[key_str]['rule_sids'].add(alert['sid'])
            aggregated[key_str]['unique_severities'].add(alert['severity'])
        
        # 转换set为list
        aggregated_list = []
        for key, value in aggregated.items():
            value['rule_sids'] = list(value['rule_sids'])
            value['unique_severities'] = list(value['unique_severities'])
            aggregated_list.append(value)
        
        data = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'total_alerts': len(alerts),
            'time_window_minutes': time_window_minutes,
            'aggregated_alerts': aggregated_list,
            'timeline': alerts
        }
        
        return SuccessResponse(data=data)
        
    except Exception as e:
        return ErrorResponse(code=500, message=str(e))


@router.get("/asset/{dst_ip}", response_model=SuccessResponse)
async def investigate_asset(
    dst_ip: str,
    alert_repo = Depends(get_alert_repo),
    rule_repo = Depends(get_rule_repo)
):
    """资产上下文查询"""
    try:
        asset_context = alert_repo.get_asset_context(dst_ip)
        attacker_summary = alert_repo.get_attacker_summary(dst_ip, 10)
        asset_timeline = alert_repo.get_asset_timeline(dst_ip, 7)
        rule_type_dist = rule_repo.get_rule_type_distribution_for_asset(dst_ip)
        
        # 计算平均每日告警数
        avg_daily = 0
        if asset_context.get('first_alert') and asset_context.get('total_alerts', 0) > 0:
            first = datetime.fromisoformat(asset_context['first_alert'])
            last = datetime.fromisoformat(asset_context['last_alert'])
            days = max(1, (last - first).days)
            avg_daily = asset_context['total_alerts'] / days
        
        data = {
            'dst_ip': dst_ip,
            'statistics': {
                'total_alerts': asset_context.get('total_alerts', 0),
                'max_severity': asset_context.get('max_severity', 0),
                'last_alert': asset_context.get('last_alert'),
                'first_alert': asset_context.get('first_alert'),
                'avg_daily_alerts': round(avg_daily, 2),
                'unique_attackers': asset_context.get('unique_attackers', 0),
                'unique_rules': asset_context.get('unique_rules', 0)
            },
            'severity_timeline': asset_timeline,
            'top_attackers': attacker_summary,
            'rule_type_distribution': rule_type_dist
        }
        
        return SuccessResponse(data=data)
        
    except Exception as e:
        return ErrorResponse(code=500, message=str(e))