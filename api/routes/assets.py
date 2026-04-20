# api/routes/assets.py
"""资产管理API"""
from fastapi import APIRouter, Depends, Query
from typing import Optional

from api import get_alert_repo
from api.schemas import SuccessResponse, ErrorResponse

router = APIRouter()


@router.get("", response_model=SuccessResponse)
async def get_assets(
    severity_threshold: Optional[int] = Query(None, ge=1, le=3, description="严重程度阈值"),
    has_unprocessed: Optional[bool] = Query(None, description="是否有未处理告警"),
    sort_by: str = Query("total_alerts", description="排序字段"),
    limit: int = Query(50, ge=1, le=200, description="返回数量"),
    alert_repo = Depends(get_alert_repo)
):
    """获取受监控资产列表"""
    try:
        assets = alert_repo.get_all_assets(
            severity_threshold=severity_threshold,
            has_unprocessed=has_unprocessed,
            sort_by=sort_by,
            limit=limit
        )
        
        # 添加风险分数
        for asset in assets:
            risk_score = alert_repo.get_asset_risk_score(asset['dst_ip'])
            asset['risk_score'] = round(risk_score, 1)
        
        data = {
            'total_assets': len(assets),
            'items': assets
        }
        
        return SuccessResponse(data=data)
        
    except Exception as e:
        return ErrorResponse(code=500, message=str(e))


@router.get("/{dst_ip}/risk", response_model=SuccessResponse)
async def get_asset_risk(
    dst_ip: str,
    alert_repo = Depends(get_alert_repo)
):
    """资产风险详情视图"""
    try:
        # 获取风险分数
        risk_score = alert_repo.get_asset_risk_score(dst_ip)
        
        # 获取高严重告警数量
        severity_dist = alert_repo.get_severity_distribution()
        high_count = 0
        for item in severity_dist:
            if item.get('severity') == 1:
                high_count = item.get('count', 0)
                break
        
        # 获取告警趋势
        alert_trend = alert_repo.get_asset_alert_trend(dst_ip, 7)
        
        # 获取攻击源列表
        attack_sources = alert_repo.get_attack_sources_for_asset(dst_ip, 20)
        
        # 生成建议
        recommendations = []
        if risk_score > 70:
            recommendations.append("高风险资产，建议立即调查")
        elif risk_score > 40:
            recommendations.append("中等风险，建议关注")
        
        for source in attack_sources[:3]:
            if source.get('alert_count', 0) > 50:
                recommendations.append(f"高频攻击源 {source['src_ip']}，建议考虑封禁")
        
        if high_count > 10:
            recommendations.append(f"检测到 {high_count} 次高危告警，建议深入分析")
        
        data = {
            'dst_ip': dst_ip,
            'risk_score': round(risk_score, 1),
            'high_severity_count': high_count,
            'alert_trend': alert_trend,
            'attack_sources': attack_sources,
            'recommendations': recommendations
        }
        
        return SuccessResponse(data=data)
        
    except Exception as e:
        return ErrorResponse(code=500, message=str(e))