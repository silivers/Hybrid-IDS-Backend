# worker/async_processor.py
"""异步处理器 - 从缓存读取包，提取特征，模型预测"""
import threading
import time
import queue
from typing import Optional, Dict, List, Set
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
        
        self._workers = []
        self._stop_event = threading.Event()
        self._lock = threading.RLock()
        
        # 全局统计特征（用于ct_srv_src等）
        self._global_stats = defaultdict(int)
        
        # 流处理去重缓存
        # key: 流的唯一标识, value: 处理时间戳
        self._processed_flows: Dict[str, float] = {}
        self._flow_cache_ttl = 300  # 5分钟内不重复处理同一流
        
        # 统计信息
        self._stats = {
            'flows_processed': 0,
            'alerts_generated': 0,
            'duplicates_skipped': 0,
            'errors': 0
        }
        
        print("[INFO] AsyncProcessor initialized with flow deduplication")
    
    def _get_flow_unique_key(self, flow: FlowStats) -> str:
        """生成流的唯一键（双向，不考虑方向）"""
        # 排序IP和端口，使双向流使用同一个key
        ips = sorted([flow.key.src_ip, flow.key.dst_ip])
        ports = sorted([flow.key.src_port, flow.key.dst_port])
        return f"{ips[0]}:{ports[0]}-{ips[1]}:{ports[1]}-{flow.key.protocol}"
    
    def _is_flow_already_processed(self, flow: FlowStats) -> bool:
        """检查流是否已经处理过"""
        key = self._get_flow_unique_key(flow)
        now = time.time()
        
        # 清理过期缓存
        expired_keys = [
            k for k, ts in self._processed_flows.items()
            if now - ts > self._flow_cache_ttl
        ]
        for k in expired_keys:
            del self._processed_flows[k]
        
        # 检查是否已处理
        if key in self._processed_flows:
            self._stats['duplicates_skipped'] += 1
            return True
        
        return False
    
    def _mark_flow_processed(self, flow: FlowStats):
        """标记流已处理"""
        key = self._get_flow_unique_key(flow)
        self._processed_flows[key] = time.time()
        
        # 定期清理（如果缓存过大）
        if len(self._processed_flows) > 10000:
            with self._lock:
                # 保留最近5000条
                sorted_items = sorted(
                    self._processed_flows.items(), 
                    key=lambda x: x[1], 
                    reverse=True
                )[:5000]
                self._processed_flows = dict(sorted_items)
    
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
        
        # 启动统计打印线程（可选）
        self._start_stats_thread()
        
        print(f"[INFO] AsyncProcessor started with {num_workers} workers")
    
    def _start_stats_thread(self):
        """启动统计信息打印线程"""
        def stats_loop():
            while not self._stop_event.is_set():
                time.sleep(60)  # 每分钟打印一次
                if self._stats['flows_processed'] > 0:
                    print(f"[STATS] AsyncProcessor: flows_processed={self._stats['flows_processed']}, "
                          f"alerts={self._stats['alerts_generated']}, "
                          f"duplicates={self._stats['duplicates_skipped']}, "
                          f"queue_size={self.task_queue.qsize()}")
        
        stats_thread = threading.Thread(target=stats_loop, daemon=True)
        stats_thread.start()
    
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
                self._stats['errors'] += 1
    
    def _process_packet(self, packet_id: str, packet):
        """
        处理单个数据包
        
        流程：
        1. 添加到流聚合器
        2. 如果流完成，提取特征并预测
        """
        try:
            # 添加到流聚合器
            completed_flow = self.flow_aggregator.add_packet(packet)
            
            # 如果流完成，进行模型预测
            if completed_flow:
                self._process_completed_flow(completed_flow)
            
            # 标记包已处理
            self.packet_cache.mark_processed(packet_id)
            
            # 可选：删除已处理的包（保留一段时间用于调试）
            # self.packet_cache.delete_packet(packet_id)
            
        except Exception as e:
            print(f"[ERROR] Failed to process packet {packet_id}: {e}")
            self._stats['errors'] += 1
    
    def _process_completed_flow(self, flow: FlowStats):
        """
        处理完成的流（带去重）
        
        Args:
            flow: 完成的流统计
        """
        # 检查是否已经处理过这个流
        if self._is_flow_already_processed(flow):
            # 静默跳过重复流，不打印日志避免刷屏
            return
        
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
            
            # 只在非正常流量时打印（可选，避免刷屏）
            if verdict != 'normal':
                print(f"[INFO] Flow {flow.key.src_ip}:{flow.key.src_port} -> "
                      f"{flow.key.dst_ip}:{flow.key.dst_port}, "
                      f"prob={probability:.3f}, verdict={verdict}")
            
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
                
                if alert_id > 0:
                    self._stats['alerts_generated'] += 1
                    print(f"[ALERT] Model detected threat: {flow.key.src_ip}:{flow.key.src_port} -> "
                          f"{flow.key.dst_ip}:{flow.key.dst_port}, "
                          f"prob={probability:.3f}, alert_id={alert_id}")
            
            # 5. 标记流已处理
            self._mark_flow_processed(flow)
            self._stats['flows_processed'] += 1
            
            # 6. 更新全局统计
            self._update_global_stats(flow)
            
        except Exception as e:
            print(f"[ERROR] Failed to process completed flow: {e}")
            self._stats['errors'] += 1
    
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
        
        # 简单的时间窗口清理（可选，保留最近1000条）
        if len(self._global_stats) > 10000:
            with self._lock:
                # 清理一半
                keys = list(self._global_stats.keys())
                for key in keys[:5000]:
                    del self._global_stats[key]
    
    def get_queue_size(self) -> int:
        """获取队列大小"""
        return self.task_queue.qsize()
    
    def get_stats(self) -> Dict:
        """获取统计信息"""
        return {
            **self._stats,
            'queue_size': self.task_queue.qsize(),
            'processed_flows_cache_size': len(self._processed_flows),
            'global_stats_size': len(self._global_stats)
        }
    
    def flush_all_flows(self) -> int:
        """
        强制刷新所有未完成的流
        Returns:
            刷新的流数量
        """
        remaining_flows = self.flow_aggregator.flush_all()
        for flow in remaining_flows:
            self._process_completed_flow(flow)
        return len(remaining_flows)
    
    def stop(self):
        """停止异步处理器"""
        print("[INFO] Stopping AsyncProcessor...")
        self._stop_event.set()
        
        # 等待所有工作线程结束
        for worker in self._workers:
            worker.join(timeout=5)
        
        # 刷新所有未完成的流
        print("[INFO] Flushing remaining flows...")
        flushed_count = self.flush_all_flows()
        print(f"[INFO] Flushed {flushed_count} remaining flows")
        
        # 关闭缓存
        self.packet_cache.shutdown()
        
        # 打印最终统计
        print(f"[INFO] AsyncProcessor stopped. Final stats: {self._stats}")
    
    def reset_stats(self):
        """重置统计信息"""
        self._stats = {
            'flows_processed': 0,
            'alerts_generated': 0,
            'duplicates_skipped': 0,
            'errors': 0
        }
    
    def clear_flow_cache(self):
        """清空流处理缓存"""
        with self._lock:
            self._processed_flows.clear()
        print("[INFO] Flow processing cache cleared")