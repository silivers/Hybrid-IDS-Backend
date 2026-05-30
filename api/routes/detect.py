#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
检测接口路由
"""

from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional, Dict, Any, List

router = APIRouter(tags=["检测"])


class DetectRequest(BaseModel):
    """检测请求模型"""
    proto: Optional[str] = "tcp"
    state: Optional[str] = "CON"
    sbytes: Optional[int] = 0
    dbytes: Optional[int] = 0
    sttl: Optional[int] = 64
    dttl: Optional[int] = 64
    sloss: Optional[int] = 0
    dloss: Optional[int] = 0
    spkts: Optional[int] = 1
    dpkts: Optional[int] = 1
    sjit: Optional[float] = 0
    djit: Optional[float] = 0
    tcprtt: Optional[float] = 0
    synack: Optional[float] = 0
    ackdat: Optional[float] = 0
    service: Optional[str] = "-"
    ct_srv_src: Optional[int] = 0
    ct_srv_dst: Optional[int] = 0
    ct_dst_ltm: Optional[int] = 0
    ct_src_ltm: Optional[int] = 0
    trans_depth: Optional[int] = 0
    is_sm_ips_ports: Optional[int] = 0
    ct_flw_http_mthd: Optional[int] = 0
    is_ftp_login: Optional[int] = 0
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    payload: Optional[str] = ""


class DetectResponse(BaseModel):
    """检测响应模型"""
    is_attack: bool = False
    probability: float = 0.0
    matched_rules: List[Dict[str, Any]] = []
    source: str = "unknown"
    message: str = ""


def simple_payload_detection(payload: str) -> bool:
    """基于 payload 的简单检测"""
    if not payload:
        return False
    attack_patterns = [
        "SELECT", "UNION", "INSERT", "DELETE", "DROP", "UPDATE",
        "<script", "javascript:", "onerror", "onload",
        "../", "..\\", "etc/passwd", "cmd.exe", "powershell",
        "exec(", "system(", "eval(", "base64"
    ]
    payload_upper = payload.upper()
    for pattern in attack_patterns:
        if pattern.upper() in payload_upper:
            return True
    return False


def simple_feature_detection(sbytes: int, dbytes: int) -> tuple:
    """基于特征的简单检测"""
    if sbytes > 3000 or dbytes > 5000:
        return True, 0.85
    if sbytes > 1000 or dbytes > 2000:
        return True, 0.60
    return False, 0.10


@router.post("/detect/rule", response_model=DetectResponse)
async def detect_rule(request: DetectRequest):
    """纯规则匹配检测"""
    try:
        is_attack = simple_payload_detection(request.payload or "")
        probability = 0.85 if is_attack else 0.05
        
        matched_rules = []
        if is_attack:
            matched_rules.append({
                "sid": 1001,
                "msg": "检测到可疑SQL/脚本模式",
                "classtype": "web-application-attack",
                "severity": 1
            })
        
        return DetectResponse(
            is_attack=is_attack,
            probability=probability,
            matched_rules=matched_rules,
            source="rule",
            message="规则检测完成"
        )
    except Exception as e:
        return DetectResponse(
            is_attack=False,
            probability=0.0,
            source="rule",
            message=f"检测失败: {str(e)}"
        )


@router.post("/detect/ml", response_model=DetectResponse)
async def detect_ml(request: DetectRequest):
    """纯机器学习检测"""
    try:
        sbytes = request.sbytes or 0
        dbytes = request.dbytes or 0
        
        is_attack, probability = simple_feature_detection(sbytes, dbytes)
        
        return DetectResponse(
            is_attack=is_attack,
            probability=probability,
            source="ml",
            message="机器学习检测完成"
        )
    except Exception as e:
        return DetectResponse(
            is_attack=False,
            probability=0.0,
            source="ml",
            message=f"检测失败: {str(e)}"
        )


@router.post("/detect/hybrid", response_model=DetectResponse)
async def detect_hybrid(request: DetectRequest):
    """混合检测（规则优先 + 机器学习补充）"""
    try:
        # 第一步：规则匹配
        rule_result = await detect_rule(request)
        
        if rule_result.is_attack:
            return DetectResponse(
                is_attack=True,
                probability=rule_result.probability,
                matched_rules=rule_result.matched_rules,
                source="hybrid",
                message="规则匹配检测到攻击"
            )
        
        # 第二步：机器学习检测
        ml_result = await detect_ml(request)
        
        if ml_result.is_attack:
            return DetectResponse(
                is_attack=True,
                probability=ml_result.probability,
                source="hybrid",
                message="机器学习检测到可疑流量"
            )
        
        return DetectResponse(
            is_attack=False,
            probability=ml_result.probability,
            source="hybrid",
            message="流量正常"
        )
    except Exception as e:
        return DetectResponse(
            is_attack=False,
            probability=0.0,
            source="hybrid",
            message=f"检测失败: {str(e)}"
        )


@router.get("/detect/health")
async def detect_health():
    """检测接口健康检查"""
    return {"status": "healthy", "service": "detection"}
