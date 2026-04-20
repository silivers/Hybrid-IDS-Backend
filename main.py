# main.py
"""Hybrid IDS 系统主入口"""
import signal
import sys
import time
import threading
from pathlib import Path

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent))

from config import DETECTION_CONFIG, API_CONFIG
from capture.packet_capture import PacketCapturer
from capture.flow_aggregator import FlowAggregator
from engine.detection_engine import DetectionEngine
from worker.async_processor import AsyncProcessor


class HybridIDS:
    """混合入侵检测系统"""
    
    def __init__(self):
        self.running = False
        self.packet_capturer = None
        self.detection_engine = None
        self.async_processor = None
        self.flow_aggregator = None
        self.api_thread = None
        self.api_app = None
        
        # 存储Repository实例供API访问
        self.alert_repo = None
        self.rule_repo = None
    
    def _init_repositories(self):
        """初始化Repository层（供API使用）"""
        if self.alert_repo is None:
            from storage.alert_repo import AlertRepository
            self.alert_repo = AlertRepository()
            print("[INFO] AlertRepository initialized for API")
        
        if self.rule_repo is None:
            from storage.rule_repo import RuleRepository
            self.rule_repo = RuleRepository()
            print("[INFO] RuleRepository initialized for API")
    
    def _start_api_server(self):
        """启动FastAPI服务器（在独立线程中运行）"""
        try:
            import uvicorn
            from api import create_app
            
            # 确保Repository已初始化
            self._init_repositories()
            
            # 创建FastAPI应用
            self.api_app = create_app(self)
            
            def run_api():
                """在独立线程中运行API服务器"""
                try:
                    print(f"[INFO] Starting FastAPI server on http://{API_CONFIG['host']}:{API_CONFIG['port']}")
                    print(f"[INFO] API Docs available at http://{API_CONFIG['host']}:{API_CONFIG['port']}/docs")
                    uvicorn.run(
                        self.api_app,
                        host=API_CONFIG['host'],
                        port=API_CONFIG['port'],
                        log_level="warning",
                        access_log=False
                    )
                except Exception as e:
                    print(f"[ERROR] API server failed: {e}")
            
            # 启动API线程（daemon线程，主进程退出时自动结束）
            self.api_thread = threading.Thread(target=run_api, daemon=True)
            self.api_thread.start()
            print("[INFO] FastAPI server started successfully")
            
        except ImportError as e:
            print(f"[WARNING] FastAPI not available: {e}")
            print("[INFO] Continuing without API server")
        except Exception as e:
            print(f"[ERROR] Failed to start API server: {e}")
    
    def start(self):
        """启动系统"""
        print("=" * 60)
        print("Hybrid IDS System Starting...")
        print("=" * 60)
        
        # 初始化流聚合器
        self.flow_aggregator = FlowAggregator(
            flow_timeout=DETECTION_CONFIG.get('flow_timeout', 60)
        )
        
        # 初始化异步处理器
        self.async_processor = AsyncProcessor(self.flow_aggregator)
        self.async_processor.start()
        
        # 初始化检测引擎
        self.detection_engine = DetectionEngine(self.async_processor)
        
        # 初始化包捕获器
        self.packet_capturer = PacketCapturer(
            interface=DETECTION_CONFIG.get('network_interface'),
            filter_str=DETECTION_CONFIG.get('capture_filter')
        )
        
        # 设置信号处理
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # ========== 启动API服务器（如果启用） ==========
        if API_CONFIG.get('enabled', True):
            self._start_api_server()
        else:
            print("[INFO] API server disabled by configuration")
        
        # 启动捕获（带回调）
        self.running = True
        self.packet_capturer.start(callback=self._on_packet_captured)
        
        print("[INFO] Hybrid IDS is running. Press Ctrl+C to stop.")
        if API_CONFIG.get('enabled', True):
            print(f"[INFO] API available at: http://{API_CONFIG['host']}:{API_CONFIG['port']}")
            print(f"[INFO] API docs: http://{API_CONFIG['host']}:{API_CONFIG['port']}/docs")
        
        # 主循环（保持运行）
        try:
            while self.running:
                time.sleep(1)
                # 打印状态（每30秒）
                if int(time.time()) % 30 == 0:
                    self._print_status()
        except KeyboardInterrupt:
            self.stop()
    
    def _on_packet_captured(self, packet):
        """数据包捕获回调"""
        if not self.running:
            return
        
        # 传递给检测引擎
        self.detection_engine.process_packet(packet)
    
    def _print_status(self):
        """打印系统状态"""
        queue_size = self.async_processor.get_queue_size() if self.async_processor else 0
        active_flows = self.flow_aggregator.get_active_flow_count() if self.flow_aggregator else 0
        print(f"[STATUS] Active flows: {active_flows}, Queue size: {queue_size}")
    
    def _signal_handler(self, signum, frame):
        """信号处理"""
        print(f"\n[INFO] Received signal {signum}, shutting down...")
        self.stop()
    
    def stop(self):
        """停止系统"""
        print("[INFO] Stopping Hybrid IDS...")
        self.running = False
        
        # 停止包捕获
        if self.packet_capturer:
            self.packet_capturer.stop()
        
        # 停止异步处理器
        if self.async_processor:
            self.async_processor.stop()
        
        print("[INFO] Hybrid IDS stopped.")
    
    # ========== 以下方法供API访问 ==========
    def get_alert_repository(self):
        """获取告警仓库实例（供API使用）"""
        if self.alert_repo is None:
            self._init_repositories()
        return self.alert_repo
    
    def get_rule_repository(self):
        """获取规则仓库实例（供API使用）"""
        if self.rule_repo is None:
            self._init_repositories()
        return self.rule_repo


def main():
    """主函数"""
    # 检查必要的目录
    Path('models').mkdir(exist_ok=True)
    
    # 启动系统
    ids = HybridIDS()
    ids.start()


if __name__ == "__main__":
    main()