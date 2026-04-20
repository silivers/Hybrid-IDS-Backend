# api/routes/rules.py
"""规则管理API"""
from fastapi import APIRouter, Depends, Query, HTTPException
from typing import Optional

from api import get_rule_repo
from api.schemas import SuccessResponse, ErrorResponse, ToggleRuleRequest

router = APIRouter()


@router.get("", response_model=SuccessResponse)
async def get_rules(
    page: int = Query(1, ge=1, description="页码"),
    page_size: int = Query(20, ge=1, le=100, description="每页数量"),
    sid: Optional[int] = Query(None, description="规则ID"),
    msg_keyword: Optional[str] = Query(None, description="消息关键词"),
    classtype: Optional[str] = Query(None, description="分类"),
    protocol: Optional[str] = Query(None, description="协议"),
    severity: Optional[int] = Query(None, ge=1, le=3, description="严重程度"),
    enabled: Optional[int] = Query(None, ge=0, le=1, description="启用状态"),
    rule_repo = Depends(get_rule_repo)
):
    """获取规则列表（支持分页、筛选）"""
    try:
        filters = {}
        if sid:
            filters['sid'] = sid
        if msg_keyword:
            filters['msg_keyword'] = msg_keyword
        if classtype:
            filters['classtype'] = classtype
        if protocol:
            filters['protocol'] = protocol
        if severity:
            filters['severity'] = severity
        if enabled is not None:
            filters['enabled'] = enabled
        
        total, rules = rule_repo.get_rules_with_filters(
            filters=filters,
            page=page,
            page_size=page_size
        )
        
        # 添加严重程度标签
        severity_labels = {1: '高', 2: '中', 3: '低'}
        for rule in rules:
            rule['severity_level'] = severity_labels.get(rule.get('severity'), '未知')
            contents = rule_repo.get_content_patterns_for_rule(rule['sid'])
            rule['content_preview'] = [c.get('content_pattern', '')[:30] for c in contents[:3]]
        
        total_pages = (total + page_size - 1) // page_size if total > 0 else 0
        
        data = {
            'items': rules,
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


@router.get("/{sid}", response_model=SuccessResponse)
async def get_rule_detail(
    sid: int,
    rule_repo = Depends(get_rule_repo)
):
    """获取规则详情"""
    try:
        rule = rule_repo.get_rule_by_id_with_contents(sid)
        
        if not rule:
            return ErrorResponse(code=404, message=f'Rule {sid} not found')
        
        # 获取分类统计
        classtype_stats = rule_repo.get_classtype_stats()
        rule['classtype_stats'] = next((s for s in classtype_stats if s.get('classtype') == rule.get('classtype')), None)
        
        # 解析reference（CVE编号）
        if rule.get('reference'):
            references = rule['reference'].split(';')
            cve_list = [ref.strip() for ref in references if ref.strip().startswith('cve')]
            rule['cve_list'] = cve_list
        
        return SuccessResponse(data=rule)
        
    except Exception as e:
        return ErrorResponse(code=500, message=str(e))


@router.put("/{sid}/toggle", response_model=SuccessResponse)
async def toggle_rule(
    sid: int,
    request: ToggleRuleRequest,
    rule_repo = Depends(get_rule_repo)
):
    """启用/禁用规则"""
    try:
        success = rule_repo.update_rule_enabled(sid, request.enabled)
        
        if success:
            return SuccessResponse(data={'sid': sid, 'enabled': request.enabled})
        else:
            return ErrorResponse(code=404, message=f'Rule {sid} not found')
        
    except Exception as e:
        return ErrorResponse(code=500, message=str(e))