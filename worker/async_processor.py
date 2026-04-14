# worker/async_processor.py
"""异步处理器 - 从缓存读取包，提取特征，模型预测"""
import threading
import time
import queue
from typing import Optional, Dict, List
from collections import defaultdict
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from capture.flow_aggregator import FlowAggregator, FlowStats
from capture.feature_extractor import FeatureExtractor
from engine.model_predictor import ModelPredictor
from storage.alert_repo import AlertRepository
from storage.packet_cache import PacketCache


class AsyncProcessor:
    """
    异步处理器
    
    工作流程：
    1. 从队列获取packet_id
    2. 从缓存读取数据包
    3. 聚合到流（FlowAggregator）
    4. 流完成后提取特征
    5. 模型预测
    6. 写入告警
    """
    
    def __init__(self, flow_aggregator: FlowAggregator = None):
        """
        初始化异步处理器
        
        Args:
            flow_aggregator: 流聚合器实例
        """
        self.task_queue = queue.Queue(maxsize=10000)
        self.flow_aggregator = flow_aggregator or FlowAggregator()
        self.feature_extractor = FeatureExtractor()
        self.model_predictor = ModelPredictor()
        self.alert_repo = AlertRepository()
        self.packet_cache = PacketCache()
        
        self._worker_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.RLock()
        
        # 全局统计特征（用于ct_srv_src等）
        self._global_stats = defaultdict(int)
        
        print("[INFO] AsyncProcessor initialized")
    
    def start(self, num_workers: int = 2):
        """
        启动异步处理器
        
        Args:
            num_workers: 工作线程数量
        """
        self._stop_event.clear()
        
        # 启动多个工作线程
        self._workers = []
        for i in range(num_workers):
            worker = threading.Thread(
                target=self._worker_loop,
                name=f"AsyncWorker-{i+1}",
                daemon=True
            )
            worker.start()
            self._workers.append(worker)
        
        print(f"[INFO] AsyncProcessor started with {num_workers} workers")
    
    def add_packet(self, packet_id: str, packet):
        """
        添加数据包到处理队列
        
        Args:
            packet_id: 包ID
            packet: CapturedPacket对象
        """
        try:
            self.task_queue.put_nowait((packet_id, packet))
        except queue.Full:
            print(f"[WARNING] Task queue full, dropping packet {packet_id}")
    
    def _worker_loop(self):
        """工作线程主循环"""
        while not self._stop_event.is_set():
            try:
                # 获取任务（超时1秒）
                packet_id, packet = self.task_queue.get(timeout=1)
                
                # 处理数据包
                self._process_packet(packet_id, packet)
                
                self.task_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[ERROR] Worker error: {e}")
    
    def _process_packet(self, packet_id: str, packet):
        """
        处理单个数据包
        
        流程：
        1. 添加到流聚合器
        2. 如果流完成，提取特征并预测
        """
        # 添加到流聚合器
        completed_flow = self.flow_aggregator.add_packet(packet)
        
        # 如果流完成，进行模型预测
        if completed_flow:
            self._process_completed_flow(completed_flow)
        
        # 标记包已处理
        self.packet_cache.mark_processed(packet_id)
        
        # 可选：删除已处理的包（或保留一段时间）
        # self.packet_cache.delete_packet(packet_id)
    
    def _process_completed_flow(self, flow: FlowStats):
        """
        处理完成的流
        
        Args:
            flow: 完成的流统计
        """
        try:
            # 1. 提取特征
            features = self.feature_extractor.extract_features(flow)
            
            if not features:
                print(f"[WARNING] Failed to extract features for flow: {flow.key}")
                return
            
            # 2. 添加全局统计特征（ct_srv_src等）
            features = self._add_global_stats(features, flow)
            
            # 3. 模型预测
            result = self.model_predictor.predict_with_confidence(features)
            
            probability = result['probability']
            verdict = result['verdict']
            
            print(f"[DEBUG] Flow {flow.key}: prob={probability:.3f}, verdict={verdict}")
            
            # 4. 如果判定为威胁，写入告警
            if verdict == 'malicious' or (verdict == 'uncertain' and probability >= 0.5):
                alert_id = self.alert_repo.save_model_alert(
                    src_ip=flow.key.src_ip,
                    src_port=flow.key.src_port,
                    dst_ip=flow.key.dst_ip,
                    dst_port=flow.key.dst_port,
                    protocol=flow.key.protocol,
                    probability=probability,
                    prediction=result['prediction'],
                    payload_preview=flow.get_payload_preview()
                )
                
                print(f"[ALERT] Model detected threat: flow={flow.key}, "
                      f"prob={probability:.3f}, alert_id={alert_id}")
            
            # 5. 更新全局统计
            self._update_global_stats(flow)
            
        except Exception as e:
            print(f"[ERROR] Failed to process completed flow: {e}")
    
    def _add_global_stats(self, features: Dict, flow: FlowStats) -> Dict:
        """添加全局统计特征"""
        service = features.get('service', '-')
        src_ip = flow.key.src_ip
        dst_ip = flow.key.dst_ip
        
        # 更新特征字典
        features['ct_srv_src'] = self._global_stats.get(f'srv_src_{src_ip}_{service}', 0)
        features['ct_srv_dst'] = self._global_stats.get(f'srv_dst_{dst_ip}_{service}', 0)
        features['ct_src_ltm'] = self._global_stats.get(f'src_ltm_{src_ip}', 0)
        features['ct_dst_ltm'] = self._global_stats.get(f'dst_ltm_{dst_ip}', 0)
        
        return features
    
    def _update_global_stats(self, flow: FlowStats):
        """更新全局统计"""
        src_ip = flow.key.src_ip
        dst_ip = flow.key.dst_ip
        service = flow.get_service()
        
        # 增加计数
        self._global_stats[f'srv_src_{src_ip}_{service}'] += 1
        self._global_stats[f'srv_dst_{dst_ip}_{service}'] += 1
        self._global_stats[f'src_ltm_{src_ip}'] += 1
        self._global_stats[f'dst_ltm_{dst_ip}'] += 1
        
        # 简单的时间窗口清理（可选）
        # 这里略，可以使用deque + timestamp实现
    
    def get_queue_size(self) -> int:
        """获取队列大小"""
        return self.task_queue.qsize()
    
    def stop(self):
            """停止异步处理器"""
            print("[INFO] Stopping AsyncProcessor...")
            self._stop_event.set()
            
            # 等待所有工作线程结束
            for worker in getattr(self, '_workers', []):
                worker.join(timeout=5)
            
            # 刷新所有流
            remaining_flows = self.flow_aggregator.flush_all()
            for flow in remaining_flows:
                self._process_completed_flow(flow)
            
            self.packet_cache.shutdown()
            print("[INFO] AsyncProcessor stopped")