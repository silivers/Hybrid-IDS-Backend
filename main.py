# main.py
"""Hybrid IDS 系统主入口"""
import signal
import sys
import time
from pathlib import Path

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent))

from config import DETECTION_CONFIG
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
        
        # 启动捕获（带回调）
        self.running = True
        self.packet_capturer.start(callback=self._on_packet_captured)
        
        print("[INFO] Hybrid IDS is running. Press Ctrl+C to stop.")
        
        # 主循环（保持运行）
        try:
            while self.running:
                time.sleep(1)
                # 打印状态
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
        print(f"[STATUS] Active flows: {self.flow_aggregator.get_active_flow_count()}, "
              f"Queue size: {self.async_processor.get_queue_size() if self.async_processor else 0}")
    
    def _signal_handler(self, signum, frame):
        """信号处理"""
        print(f"\n[INFO] Received signal {signum}, shutting down...")
        self.stop()
    
    def stop(self):
        """停止系统"""
        print("[INFO] Stopping Hybrid IDS...")
        self.running = False
        
        if self.packet_capturer:
            self.packet_capturer.stop()
        
        if self.async_processor:
            self.async_processor.stop()
        
        print("[INFO] Hybrid IDS stopped.")


def main():
    """主函数"""
    # 检查必要的目录
    Path('models').mkdir(exist_ok=True)
    
    # 启动系统
    ids = HybridIDS()
    ids.start()


if __name__ == "__main__":
    main()