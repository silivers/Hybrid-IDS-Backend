# api/__init__.py
"""API模块 - 使用FastAPI实现RESTful接口"""
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from typing import Optional

from config import API_CONFIG


# 全局存储IDS实例（通过lifespan管理）
_ids_instance = None


def get_ids_instance():
    """依赖注入：获取IDS实例"""
    return _ids_instance


def get_alert_repo(ids=Depends(get_ids_instance)):
    """依赖注入：获取告警仓库"""
    return ids.get_alert_repository()


def get_rule_repo(ids=Depends(get_ids_instance)):
    """依赖注入：获取规则仓库"""
    return ids.get_rule_repository()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    # 启动时执行
    global _ids_instance
    _ids_instance = app.state.ids_instance
    print("[INFO] FastAPI application started")
    yield
    # 关闭时执行
    print("[INFO] FastAPI application shutting down")


def create_app(ids_instance):
    """
    创建FastAPI应用实例
    
    Args:
        ids_instance: HybridIDS实例，用于访问Repository层
    
    Returns:
        FastAPI应用实例
    """
    global _ids_instance
    _ids_instance = ids_instance
    
    app = FastAPI(
        title="Hybrid IDS API",
        description="混合入侵检测系统RESTful API",
        version="1.0.0",
        lifespan=lifespan
    )
    
    # 存储IDS实例到app状态
    app.state.ids_instance = ids_instance
    
    # CORS配置
    app.add_middleware(
        CORSMiddleware,
        allow_origins=API_CONFIG.get('cors_origins', ['*']),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # 注册路由
    from api.routes import dashboard, alerts, investigate, assets, rules, reports, stats
    
    app.include_router(dashboard.router, prefix="/api/dashboard", tags=["仪表盘"])
    app.include_router(alerts.router, prefix="/api/alerts", tags=["告警管理"])
    app.include_router(investigate.router, prefix="/api/investigate", tags=["事件调查"])
    app.include_router(assets.router, prefix="/api/assets", tags=["资产管理"])
    app.include_router(rules.router, prefix="/api/rules", tags=["规则管理"])
    app.include_router(reports.router, prefix="/api/reports", tags=["报表"])
    app.include_router(stats.router, prefix="/api/stats", tags=["统计"])

    
    # 根路径
    @app.get("/", tags=["根路径"])
    async def root():
        return {
            "message": "Hybrid IDS API Server",
            "docs": "/docs",
            "redoc": "/redoc"
        }
    
    return app