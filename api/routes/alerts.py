# api/routes/alerts.py
"""告警管理API"""
from fastapi import APIRouter, Depends, Query, HTTPException
from typing import Optional
from datetime import datetime

from api import get_alert_repo, get_rule_repo
from api.schemas import SuccessResponse, ErrorResponse, PaginatedResponse, BatchProcessRequest
from api.middleware.pagination import get_pagination_params

router = APIRouter()


@router.get("", response_model=SuccessResponse)
async def get_alerts(
    page: int = Query(1, ge=1, description="页码"),
    page_size: int = Query(20, ge=1, le=100, description="每页数量"),
    start_time: Optional[str] = Query(None, description="开始时间"),
    end_time: Optional[str] = Query(None, description="结束时间"),
    severity: Optional[int] = Query(None, ge=1, le=3, description="严重程度"),
    src_ip: Optional[str] = Query(None, description="源IP"),
    dst_ip: Optional[str] = Query(None, description="目标IP"),
    protocol: Optional[str] = Query(None, description="协议"),
    processed: Optional[int] = Query(None, ge=0, le=1, description="处理状态"),
    sid: Optional[int] = Query(None, description="规则ID"),
    sort_by: str = Query("timestamp", description="排序字段"),
    sort_order: str = Query("DESC", description="排序方向"),
    alert_repo = Depends(get_alert_repo)
):
    """获取告警列表（支持分页、筛选、排序）"""
    try:
        # 构建筛选条件
        filters = {}
        if start_time:
            filters['start_time'] = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        if end_time:
            filters['end_time'] = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
        if severity:
            filters['severity'] = severity
        if src_ip:
            filters['src_ip'] = src_ip
        if dst_ip:
            filters['dst_ip'] = dst_ip
        if protocol:
            filters['protocol'] = protocol
        if processed is not None:
            filters['processed'] = processed
        if sid:
            filters['sid'] = sid
        
        total, alerts = alert_repo.get_alerts_with_filters(
            filters=filters,
            page=page,
            page_size=page_size,
            sort_by=sort_by,
            sort_order=sort_order
        )
        
        # 添加严重程度标签
        severity_labels = {1: '高', 2: '中', 3: '低'}
        for alert in alerts:
            alert['severity_level'] = severity_labels.get(alert['severity'], '未知')
        
        # 构建分页响应
        total_pages = (total + page_size - 1) // page_size if total > 0 else 0
        
        data = {
            'items': alerts,
            'pagination': {
                'page': page,
                'page_size': page_size,
                'total': total,
                'total_pages': total_pages,
                'has_next': page < total_pages,
                'has_prev': page > 1
            }
        }
        
        return SuccessResponse(data=data)
        
    except Exception as e:
        return ErrorResponse(code=500, message=str(e))


@router.get("/{alert_id}", response_model=SuccessResponse)
async def get_alert_detail(
    alert_id: int,
    alert_repo = Depends(get_alert_repo),
    rule_repo = Depends(get_rule_repo)
):
    """获取告警详情（包含规则完整信息）"""
    try:
        alert = alert_repo.get_alert_by_id_with_rule(alert_id)
        if not alert:
            return ErrorResponse(code=404, message=f'Alert {alert_id} not found')
        
        # 获取规则信息（如果sid不为0）
        rule_info = None
        rule_contents = []
        if alert['sid'] != 0:
            rule_info = rule_repo.get_rule_by_id_with_contents(alert['sid'])
            if rule_info:
                rule_contents = rule_info.pop('contents', [])
        
        data = {
            'alert_id': alert['alert_id'],
            'timestamp': alert['timestamp'],
            'src_ip': alert['src_ip'],
            'src_port': alert['src_port'],
            'dst_ip': alert['dst_ip'],
            'dst_port': alert['dst_port'],
            'protocol': alert['protocol'],
            'severity': alert['severity'],
            'severity_level': {1: '高', 2: '中', 3: '低'}.get(alert['severity'], '未知'),
            'processed': alert['processed'],
            'matched_content': alert['matched_content'],
            'payload_preview': alert['payload_preview'],
            'rule': rule_info,
            'rule_contents': rule_contents
        }
        
        return SuccessResponse(data=data)
        
    except Exception as e:
        return ErrorResponse(code=500, message=str(e))


@router.put("/{alert_id}/process", response_model=SuccessResponse)
async def mark_processed(
    alert_id: int,
    processed: int = 1,
    alert_repo = Depends(get_alert_repo)
):
    """标记单个告警为已处理"""
    try:
        affected = alert_repo.batch_update_processed([alert_id], processed)
        
        if affected > 0:
            return SuccessResponse(data={'alert_id': alert_id, 'processed': processed})
        else:
            return ErrorResponse(code=404, message=f'Alert {alert_id} not found')
        
    except Exception as e:
        return ErrorResponse(code=500, message=str(e))


@router.put("/batch-process", response_model=SuccessResponse)
async def batch_mark_processed(
    request: BatchProcessRequest,
    alert_repo = Depends(get_alert_repo)
):
    """批量标记告警"""
    try:
        if not request.alert_ids:
            return ErrorResponse(code=400, message='alert_ids cannot be empty')
        
        affected = alert_repo.batch_update_processed(request.alert_ids, request.processed)
        
        return SuccessResponse(data={
            'processed_count': affected,
            'alert_ids': request.alert_ids,
            'processed': request.processed
        })
        
    except Exception as e:
        return ErrorResponse(code=500, message=str(e))