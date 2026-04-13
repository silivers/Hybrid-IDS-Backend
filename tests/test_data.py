"""
数据采集与预处理模块测试脚本

测试所有核心模块：
1. 数据包捕获模块
2. 流聚合模块
3. 特征提取模块
4. 数据预处理模块
5. 完整流程集成测试
"""

import sys
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

# 添加项目根目录到路径（当前文件在 tests/ 下，所以 parent 是项目根目录）
sys.path.insert(0, str(Path(__file__).parent.parent))

from data.packet_capture import PacketCapturer, CapturedPacket
from data.flow_aggregator import FlowAggregator, FlowKey, FlowStats, FlowState
from data.feature_extractor import FeatureExtractor
from data.preprocessor import DataPreprocessor
from config import DB_CONFIG, MODEL_CONFIG, DETECTION_CONFIG, FEATURE_CONFIG


class TestConfig(unittest.TestCase):
    """测试配置模块"""
    
    def test_db_config(self):
        """测试数据库配置"""
        self.assertIn('host', DB_CONFIG)
        self.assertIn('database', DB_CONFIG)
        self.assertEqual(DB_CONFIG['database'], 'snort_db')
        self.assertEqual(DB_CONFIG['charset'], 'utf8mb4')
    
    def test_model_config(self):
        """测试模型配置"""
        self.assertIn('model_path', MODEL_CONFIG)
        self.assertTrue(str(MODEL_CONFIG['model_path']).endswith('xgboost.pkl'))
        self.assertIn('encoder_path', MODEL_CONFIG)
        self.assertIn('scaler_path', MODEL_CONFIG)
    
    def test_detection_config(self):
        """测试检测配置"""
        self.assertIn('threat_threshold', DETECTION_CONFIG)
        self.assertIn('flow_timeout', DETECTION_CONFIG)
        self.assertEqual(DETECTION_CONFIG['threat_threshold'], 0.5)
        self.assertEqual(DETECTION_CONFIG['uncertain_threshold'], 0.3)
    
    def test_feature_config(self):
        """测试特征配置"""
        self.assertIn('feature_columns', FEATURE_CONFIG)
        self.assertEqual(len(FEATURE_CONFIG['feature_columns']), 24)
        self.assertIn('proto', FEATURE_CONFIG['feature_columns'])
        self.assertIn('state', FEATURE_CONFIG['feature_columns'])
        self.assertIn('categorical_columns', FEATURE_CONFIG)


class TestPacketCapture(unittest.TestCase):
    """测试数据包捕获模块"""
    
    def setUp(self):
        """测试前准备"""
        self.capturer = PacketCapturer(
            interface=None,
            filter_str='ip',
            packet_count=10
        )
    
    def test_capturer_initialization(self):
        """测试捕获器初始化"""
        self.assertIsNotNone(self.capturer)
        self.assertEqual(self.capturer.filter_str, 'ip')
        self.assertEqual(self.capturer.packet_count, 10)
        self.assertFalse(self.capturer.is_running)
    
    def test_captured_packet_creation(self):
        """测试数据包对象创建"""
        packet = CapturedPacket(
            timestamp=time.time(),
            src_ip='192.168.1.100',
            dst_ip='8.8.8.8',
            src_port=12345,
            dst_port=443,
            protocol='tcp',
            payload=b'GET / HTTP/1.1',
            ttl=64,
            length=1500
        )
        
        self.assertEqual(packet.src_ip, '192.168.1.100')
        self.assertEqual(packet.dst_ip, '8.8.8.8')
        self.assertEqual(packet.protocol, 'tcp')
        self.assertEqual(packet.ttl, 64)
        self.assertEqual(packet.length, 1500)
    
    def test_packet_payload_preview(self):
        """测试数据包负载预览"""
        packet = CapturedPacket(
            timestamp=time.time(),
            src_ip='192.168.1.1',
            dst_ip='192.168.1.2',
            src_port=80,
            dst_port=54321,
            protocol='tcp',
            payload=b'Hello World'
        )
        self.assertIsNotNone(packet.payload_preview)
    
    def test_capturer_start_stop(self):
        """测试捕获器启动和停止"""
        # 使用 mock 避免实际捕获
        with patch('data.packet_capture.sniff') as mock_sniff:
            mock_sniff.side_effect = lambda **kwargs: None
            
            self.capturer.start()
            time.sleep(0.1)
            self.capturer.stop()
            
            # 验证停止事件被设置
            self.assertTrue(self.capturer._stop_event.is_set())


class TestFlowAggregator(unittest.TestCase):
    """测试流聚合模块"""
    
    def setUp(self):
        """测试前准备"""
        self.aggregator = FlowAggregator(flow_timeout=30)
    
    def test_flow_key_creation(self):
        """测试流键创建"""
        key = FlowKey(
            src_ip='192.168.1.1',
            dst_ip='192.168.1.2',
            src_port=12345,
            dst_port=80,
            protocol='tcp'
        )
        
        self.assertEqual(key.src_ip, '192.168.1.1')
        self.assertEqual(key.dst_ip, '192.168.1.2')
        self.assertEqual(key.src_port, 12345)
        self.assertEqual(key.dst_port, 80)
        self.assertEqual(key.protocol, 'tcp')
    
    def test_flow_key_hash(self):
        """测试流键哈希"""
        key1 = FlowKey('192.168.1.1', '192.168.1.2', 12345, 80, 'tcp')
        key2 = FlowKey('192.168.1.1', '192.168.1.2', 12345, 80, 'tcp')
        key3 = FlowKey('192.168.1.2', '192.168.1.1', 12345, 80, 'tcp')
        
        self.assertEqual(hash(key1), hash(key2))
        self.assertNotEqual(hash(key1), hash(key3))
    
    def test_flow_key_reverse(self):
        """测试流键反向"""
        key = FlowKey('192.168.1.1', '192.168.1.2', 12345, 80, 'tcp')
        reverse = key.reverse()
        
        self.assertEqual(reverse.src_ip, '192.168.1.2')
        self.assertEqual(reverse.dst_ip, '192.168.1.1')
        self.assertEqual(reverse.src_port, 80)
        self.assertEqual(reverse.dst_port, 12345)
    
    def test_flow_stats_initialization(self):
        """测试流统计初始化"""
        key = FlowKey('10.0.0.1', '10.0.0.2', 12345, 80, 'tcp')
        flow = FlowStats(key=key)
        
        self.assertEqual(flow.forward_packets, 0)
        self.assertEqual(flow.backward_packets, 0)
        self.assertEqual(flow.forward_bytes, 0)
        self.assertEqual(flow.backward_bytes, 0)
        self.assertEqual(flow.state, FlowState.NEW)
    
    def test_flow_stats_update_forward(self):
        """测试前向流更新"""
        key = FlowKey('10.0.0.1', '10.0.0.2', 12345, 80, 'tcp')
        flow = FlowStats(key=key)
        
        packet = CapturedPacket(
            timestamp=time.time(),
            src_ip='10.0.0.1',
            dst_ip='10.0.0.2',
            src_port=12345,
            dst_port=80,
            protocol='tcp',
            ttl=64,
            length=100
        )
        
        flow.update_forward(packet)
        
        self.assertEqual(flow.forward_packets, 1)
        self.assertEqual(flow.forward_bytes, 100)
        self.assertEqual(flow.forward_ttl_count, 1)
        self.assertEqual(flow.forward_ttl, 64)
    
    def test_flow_stats_jitter_calculation(self):
        """测试抖动计算"""
        key = FlowKey('10.0.0.1', '10.0.0.2', 12345, 80, 'tcp')
        flow = FlowStats(key=key)
        
        base_time = time.time()
        
        for i in range(3):
            packet = CapturedPacket(
                timestamp=base_time + i * 0.1,
                src_ip='10.0.0.1',
                dst_ip='10.0.0.2',
                src_port=12345,
                dst_port=80,
                protocol='tcp',
                ttl=64,
                length=100
            )
            flow.update_forward(packet)
        
        # 抖动应该接近0.1
        jitter = flow.forward_jitter
        self.assertAlmostEqual(jitter, 0.0, places=1)
    
    def test_aggregator_add_packet(self):
        """测试聚合器添加数据包"""
        packet = CapturedPacket(
            timestamp=time.time(),
            src_ip='192.168.1.100',
            dst_ip='8.8.8.8',
            src_port=54321,
            dst_port=53,
            protocol='udp',
            ttl=64,
            length=100
        )
        
        result = self.aggregator.add_packet(packet)
        
        # 新流不应该立即返回
        self.assertIsNone(result)
        self.assertEqual(self.aggregator.get_flow_count(), 1)
    
    def test_aggregator_multiple_packets_same_flow(self):
        """测试同一流多个数据包"""
        base_time = time.time()
        
        for i in range(5):
            packet = CapturedPacket(
                timestamp=base_time + i * 0.1,
                src_ip='192.168.1.100',
                dst_ip='8.8.8.8',
                src_port=54321,
                dst_port=53,
                protocol='udp',
                ttl=64,
                length=100 + i * 10
            )
            self.aggregator.add_packet(packet)
        
        self.assertEqual(self.aggregator.get_flow_count(), 1)
    
    def test_aggregator_flush_all(self):
        """测试刷新所有流"""
        # 添加多个流
        for i in range(3):
            packet = CapturedPacket(
                timestamp=time.time(),
                src_ip=f'192.168.1.{i}',
                dst_ip='8.8.8.8',
                src_port=54321 + i,
                dst_port=53,
                protocol='udp',
                ttl=64,
                length=100
            )
            self.aggregator.add_packet(packet)
        
        self.assertEqual(self.aggregator.get_flow_count(), 3)
        
        flows = self.aggregator.flush_all()
        
        self.assertEqual(len(flows), 3)
        self.assertEqual(self.aggregator.get_flow_count(), 0)


class TestFeatureExtractor(unittest.TestCase):
    """测试特征提取模块"""
    
    def setUp(self):
        """测试前准备"""
        self.extractor = FeatureExtractor()
    
    def test_extractor_initialization(self):
        """测试特征提取器初始化"""
        self.assertEqual(len(self.extractor.feature_columns), 24)
        self.assertEqual(self.extractor.categorical_columns, ['proto', 'service', 'state'])
    
    def test_extract_features_from_flow(self):
        """测试从流中提取特征"""
        key = FlowKey('192.168.1.100', '8.8.8.8', 54321, 53, 'udp')
        flow = FlowStats(key=key)
        
        # 添加一些数据包
        for i in range(3):
            packet = CapturedPacket(
                timestamp=time.time() + i * 0.1,
                src_ip='192.168.1.100',
                dst_ip='8.8.8.8',
                src_port=54321,
                dst_port=53,
                protocol='udp',
                ttl=64,
                length=100
            )
            flow.update_forward(packet)
        
        features = self.extractor.extract_features(flow)
        
        self.assertIsNotNone(features)
        self.assertIn('proto', features)
        self.assertIn('state', features)
        self.assertIn('sbytes', features)
        self.assertIn('dbytes', features)
        self.assertIn('spkts', features)
        self.assertIn('dpkts', features)
    
    def test_all_features_present(self):
        """测试所有必需特征都存在"""
        key = FlowKey('192.168.1.1', '192.168.1.2', 12345, 80, 'tcp')
        flow = FlowStats(key=key)
        
        # 模拟一个HTTP请求
        packet = CapturedPacket(
            timestamp=time.time(),
            src_ip='192.168.1.1',
            dst_ip='192.168.1.2',
            src_port=12345,
            dst_port=80,
            protocol='tcp',
            payload=b'GET /index.html HTTP/1.1',
            ttl=64,
            length=500
        )
        flow.update_forward(packet)
        
        features = self.extractor.extract_features(flow)
        
        # 检查所有24个特征
        for feature in self.extractor.feature_columns:
            self.assertIn(feature, features, f"Missing feature: {feature}")
    
    def test_service_detection(self):
        """测试服务类型检测"""
        # HTTP 服务
        key_http = FlowKey('10.0.0.1', '10.0.0.2', 12345, 80, 'tcp')
        flow_http = FlowStats(key=key_http)
        features_http = self.extractor.extract_features(flow_http)
        self.assertEqual(features_http['service'], 'http')
        
        # HTTPS 服务
        key_https = FlowKey('10.0.0.1', '10.0.0.2', 12345, 443, 'tcp')
        flow_https = FlowStats(key=key_https)
        features_https = self.extractor.extract_features(flow_https)
        self.assertEqual(features_https['service'], 'https')
        
        # DNS 服务
        key_dns = FlowKey('10.0.0.1', '10.0.0.2', 12345, 53, 'udp')
        flow_dns = FlowStats(key=key_dns)
        features_dns = self.extractor.extract_features(flow_dns)
        self.assertEqual(features_dns['service'], 'dns')
    
    def test_extract_features_batch(self):
        """测试批量特征提取"""
        flows = []
        
        for i in range(5):
            key = FlowKey(f'192.168.1.{i}', '8.8.8.8', 54321 + i, 80, 'tcp')
            flow = FlowStats(key=key)
            flows.append(flow)
        
        features_list = self.extractor.extract_features_batch(flows)
        
        self.assertEqual(len(features_list), 5)
    
    def test_feature_validation(self):
        """测试特征验证"""
        key = FlowKey('10.0.0.1', '10.0.0.2', 12345, 80, 'tcp')
        flow = FlowStats(key=key)
        features = self.extractor.extract_features(flow)
        
        is_valid = self.extractor.validate_features(features)
        self.assertTrue(is_valid)
    
    def test_reset_global_stats(self):
        """测试重置全局统计"""
        # 先处理一些流
        key1 = FlowKey('192.168.1.1', '8.8.8.8', 12345, 80, 'tcp')
        flow1 = FlowStats(key=key1)
        self.extractor.extract_features(flow1)
        
        key2 = FlowKey('192.168.1.2', '8.8.8.8', 12346, 80, 'tcp')
        flow2 = FlowStats(key=key2)
        self.extractor.extract_features(flow2)
        
        # 重置
        self.extractor.reset()
        
        # 验证内部计数器已重置
        self.assertEqual(len(self.extractor._srv_src_count), 0)
        self.assertEqual(len(self.extractor._srv_dst_count), 0)


class TestDataPreprocessor(unittest.TestCase):
    """测试数据预处理器模块"""
    
    def setUp(self):
        """测试前准备"""
        # 创建模拟的模型文件
        self.test_model_dir = Path(__file__).parent / 'test_models'
        self.test_model_dir.mkdir(exist_ok=True)
        
        # 创建模拟的编码器文件
        import joblib
        import numpy as np
        from sklearn.preprocessing import LabelEncoder, StandardScaler
        
        # 创建模拟编码器
        encoders = {
            'proto': LabelEncoder().fit(['tcp', 'udp', 'icmp']),
            'service': LabelEncoder().fit(['http', 'https', 'dns', 'ssh', '-']),
            'state': LabelEncoder().fit(['CON', 'FIN', 'INT', 'no'])
        }
        joblib.dump(encoders, self.test_model_dir / 'xgboost_label_encoders.pkl')
        
        # 创建正确的模拟标准化器
        scaler = StandardScaler()
        # 模拟24个特征的数据
        n_features = 24
        # 生成一些随机数据来拟合 scaler
        sample_data = np.random.randn(100, n_features)
        scaler.fit(sample_data)
        joblib.dump(scaler, self.test_model_dir / 'xgboost_scaler.pkl')
        
        # 创建特征名文件
        with open(self.test_model_dir / 'xgboost_feature_names.txt', 'w') as f:
            for col in FEATURE_CONFIG['feature_columns']:
                f.write(f"{col}\n")
        
        self.preprocessor = DataPreprocessor(model_dir=self.test_model_dir)
    
    def tearDown(self):
        """测试后清理"""
        import shutil
        if self.test_model_dir.exists():
            shutil.rmtree(self.test_model_dir)
    
    def test_preprocessor_initialization(self):
        """测试预处理器初始化"""
        self.assertIsNotNone(self.preprocessor)
        self.assertEqual(self.preprocessor.get_feature_count(), 24)
    
    def test_preprocess_single_features(self):
        """测试单条特征预处理"""
        features = {
            'proto': 'tcp',
            'state': 'CON',
            'sbytes': 1000,
            'dbytes': 500,
            'sttl': 64,
            'dttl': 128,
            'sloss': 0,
            'dloss': 0,
            'spkts': 10,
            'dpkts': 8,
            'sjit': 0.1,
            'djit': 0.05,
            'tcprtt': 0.02,
            'synack': 0.01,
            'ackdat': 0.01,
            'service': 'http',
            'ct_srv_src': 5,
            'ct_srv_dst': 3,
            'ct_dst_ltm': 10,
            'ct_src_ltm': 8,
            'trans_depth': 1,
            'is_sm_ips_ports': 1,
            'ct_flw_http_mthd': 2,
            'is_ftp_login': 0
        }
        
        result = self.preprocessor.preprocess(features)
        
        self.assertIsNotNone(result)
        self.assertEqual(result.shape[1], 24)
    
    def test_preprocess_batch(self):
        """测试批量特征预处理"""
        features_list = []
        
        for i in range(10):
            features = {
                'proto': 'tcp' if i % 2 == 0 else 'udp',
                'state': 'CON',
                'sbytes': 1000 + i * 100,
                'dbytes': 500 + i * 50,
                'sttl': 64,
                'dttl': 128,
                'sloss': 0,
                'dloss': 0,
                'spkts': 10 + i,
                'dpkts': 8 + i,
                'sjit': 0.1,
                'djit': 0.05,
                'tcprtt': 0.02,
                'synack': 0.01,
                'ackdat': 0.01,
                'service': 'http',
                'ct_srv_src': 5,
                'ct_srv_dst': 3,
                'ct_dst_ltm': 10,
                'ct_src_ltm': 8,
                'trans_depth': 1,
                'is_sm_ips_ports': 1,
                'ct_flw_http_mthd': 2,
                'is_ftp_login': 0
            }
            features_list.append(features)
        
        result = self.preprocessor.preprocess_batch(features_list)
        
        self.assertIsNotNone(result)
        self.assertEqual(result.shape[0], 10)
        self.assertEqual(result.shape[1], 24)
    
    def test_missing_features_handling(self):
        """测试缺失特征处理"""
        # 只提供部分特征
        features = {
            'proto': 'tcp',
            'state': 'CON',
            'sbytes': 1000,
            'spkts': 10,
        }
        
        result = self.preprocessor.preprocess(features)
        
        self.assertIsNotNone(result)
        self.assertEqual(result.shape[1], 24)
    
    def test_unknown_category_handling(self):
        """测试未知类别处理"""
        features = {
            'proto': 'unknown_protocol',
            'state': 'unknown_state',
            'sbytes': 1000,
            'dbytes': 500,
            'sttl': 64,
            'dttl': 128,
            'sloss': 0,
            'dloss': 0,
            'spkts': 10,
            'dpkts': 8,
            'sjit': 0.1,
            'djit': 0.05,
            'tcprtt': 0.02,
            'synack': 0.01,
            'ackdat': 0.01,
            'service': 'unknown_service',
            'ct_srv_src': 5,
            'ct_srv_dst': 3,
            'ct_dst_ltm': 10,
            'ct_src_ltm': 8,
            'trans_depth': 1,
            'is_sm_ips_ports': 1,
            'ct_flw_http_mthd': 2,
            'is_ftp_login': 0
        }
        
        result = self.preprocessor.preprocess(features)
        
        self.assertIsNotNone(result)
        self.assertEqual(result.shape[1], 24)
    
    def test_is_ready(self):
        """测试预处理器就绪状态"""
        # 现在应该返回 True，因为 scaler 正确加载了
        self.assertTrue(self.preprocessor.is_ready())


class TestIntegration(unittest.TestCase):
    """集成测试"""
    
    def setUp(self):
        """测试前准备"""
        self.aggregator = FlowAggregator(flow_timeout=10)
        self.extractor = FeatureExtractor()
        
        # 创建模拟的预处理器
        self.test_model_dir = Path(__file__).parent / 'test_models'
        self.test_model_dir.mkdir(exist_ok=True)
        
        import joblib
        import numpy as np
        from sklearn.preprocessing import LabelEncoder, StandardScaler
        
        encoders = {
            'proto': LabelEncoder().fit(['tcp', 'udp', 'icmp']),
            'service': LabelEncoder().fit(['http', 'https', 'dns', 'ssh', '-']),
            'state': LabelEncoder().fit(['CON', 'FIN', 'INT', 'no'])
        }
        joblib.dump(encoders, self.test_model_dir / 'xgboost_label_encoders.pkl')
        
        # 创建正确的标准化器
        scaler = StandardScaler()
        n_features = 24
        sample_data = np.random.randn(100, n_features)
        scaler.fit(sample_data)
        joblib.dump(scaler, self.test_model_dir / 'xgboost_scaler.pkl')
        
        with open(self.test_model_dir / 'xgboost_feature_names.txt', 'w') as f:
            for col in FEATURE_CONFIG['feature_columns']:
                f.write(f"{col}\n")
        
        self.preprocessor = DataPreprocessor(model_dir=self.test_model_dir)
    
    def tearDown(self):
        """测试后清理"""
        import shutil
        if self.test_model_dir.exists():
            shutil.rmtree(self.test_model_dir)
    
    def test_full_pipeline_single_packet(self):
        """测试完整流水线 - 单数据包"""
        # 创建测试数据包
        packet = CapturedPacket(
            timestamp=time.time(),
            src_ip='192.168.1.100',
            dst_ip='8.8.8.8',
            src_port=54321,
            dst_port=80,
            protocol='tcp',
            payload=b'GET / HTTP/1.1',
            ttl=64,
            length=500
        )
        
        # 添加到聚合器
        flow = self.aggregator.add_packet(packet)
        
        # 由于流未完成，应该返回 None
        self.assertIsNone(flow)
    
    def test_full_pipeline_multiple_packets(self):
        """测试完整流水线 - 多数据包"""
        base_time = time.time()
        flow_key = None
        
        # 模拟一个完整的HTTP请求-响应
        for i in range(10):
            if i < 5:
                # 请求方向
                packet = CapturedPacket(
                    timestamp=base_time + i * 0.01,
                    src_ip='192.168.1.100',
                    dst_ip='8.8.8.8',
                    src_port=54321,
                    dst_port=80,
                    protocol='tcp',
                    payload=f'GET /page{i} HTTP/1.1'.encode(),
                    ttl=64,
                    length=500
                )
            else:
                # 响应方向
                packet = CapturedPacket(
                    timestamp=base_time + i * 0.01,
                    src_ip='8.8.8.8',
                    dst_ip='192.168.1.100',
                    src_port=80,
                    dst_port=54321,
                    protocol='tcp',
                    payload=b'HTTP/1.1 200 OK',
                    ttl=128,
                    length=1000
                )
            
            flow = self.aggregator.add_packet(packet)
            
            if flow:
                flow_key = flow.key
        
        # 检查是否有完成的流
        active_flows = self.aggregator.get_active_flows()
        
        # 提取特征
        for flow in active_flows:
            features = self.extractor.extract_features(flow)
            
            if features:
                # 预处理
                processed = self.preprocessor.preprocess(features)
                
                self.assertIsNotNone(processed)
                self.assertEqual(processed.shape[1], 24)
                
                # 输出特征信息
                print(f"\n[Integration Test] Extracted features from flow {flow.key}")
                for key, value in list(features.items())[:10]:
                    print(f"  {key}: {value}")
    
    def test_multiple_flows_processing(self):
        """测试多流处理"""
        flows_created = 0
        
        # 创建多个不同的流
        for flow_id in range(5):
            base_time = time.time()
            
            # 为每个流添加几个数据包
            for pkt_id in range(3):
                packet = CapturedPacket(
                    timestamp=base_time + pkt_id * 0.1,
                    src_ip=f'192.168.1.{flow_id}',
                    dst_ip='8.8.8.8',
                    src_port=54321 + flow_id,
                    dst_port=80 + (flow_id % 3),
                    protocol='tcp' if flow_id % 2 == 0 else 'udp',
                    payload=b'Test data',
                    ttl=64,
                    length=100
                )
                self.aggregator.add_packet(packet)
            
            flows_created += 1
        
        # 获取活跃流
        active_flows = self.aggregator.get_active_flows()
        self.assertEqual(len(active_flows), flows_created)
        
        # 为每个流提取特征
        for flow in active_flows:
            features = self.extractor.extract_features(flow)
            self.assertIsNotNone(features)
            self.assertEqual(features['proto'], flow.key.protocol)


def run_performance_test():
    """性能测试"""
    print("\n" + "="*60)
    print("性能测试")
    print("="*60)
    
    aggregator = FlowAggregator(flow_timeout=60)
    extractor = FeatureExtractor()
    
    # 模拟大量数据包
    num_packets = 1000
    start_time = time.time()
    
    for i in range(num_packets):
        packet = CapturedPacket(
            timestamp=time.time(),
            src_ip=f'192.168.1.{i % 100}',
            dst_ip='8.8.8.8',
            src_port=54321 + (i % 1000),
            dst_port=80,
            protocol='tcp',
            payload=b'X' * 100,
            ttl=64,
            length=100
        )
        aggregator.add_packet(packet)
    
    add_time = time.time() - start_time
    print(f"添加 {num_packets} 个数据包耗时: {add_time:.3f} 秒")
    print(f"平均每个数据包: {add_time/num_packets*1000:.3f} 毫秒")
    
    # 特征提取性能
    flows = aggregator.get_active_flows()
    start_time = time.time()
    
    for flow in flows:
        features = extractor.extract_features(flow)
    
    extract_time = time.time() - start_time
    print(f"提取 {len(flows)} 个流的特征耗时: {extract_time:.3f} 秒")
    print(f"平均每个流: {extract_time/len(flows)*1000:.3f} 毫秒")


def print_test_summary():
    """打印测试总结"""
    print("\n" + "="*60)
    print("入侵检测系统测试总结")
    print("="*60)
    
    print("\n[配置信息]")
    print(f"  数据库: {DB_CONFIG['database']}")
    print(f"  特征数量: {len(FEATURE_CONFIG['feature_columns'])}")
    print(f"  类别特征: {FEATURE_CONFIG['categorical_columns']}")
    print(f"  威胁阈值: {DETECTION_CONFIG['threat_threshold']}")
    print(f"  流超时: {DETECTION_CONFIG['flow_timeout']} 秒")
    
    print("\n[模型文件]")
    print(f"  模型路径: {MODEL_CONFIG['model_path']}")
    print(f"  编码器路径: {MODEL_CONFIG['encoder_path']}")
    print(f"  标准化器路径: {MODEL_CONFIG['scaler_path']}")


if __name__ == '__main__':
    print("="*60)
    print("入侵检测系统测试")
    print("="*60)
    print(f"测试时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # 创建测试套件
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # 添加测试
    suite.addTests(loader.loadTestsFromTestCase(TestConfig))
    suite.addTests(loader.loadTestsFromTestCase(TestPacketCapture))
    suite.addTests(loader.loadTestsFromTestCase(TestFlowAggregator))
    suite.addTests(loader.loadTestsFromTestCase(TestFeatureExtractor))
    suite.addTests(loader.loadTestsFromTestCase(TestDataPreprocessor))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    # 运行测试
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # 运行性能测试
    if result.wasSuccessful():
        run_performance_test()
        print_test_summary()
    
    # 输出测试结果
    print("\n" + "="*60)
    print("测试结果")
    print("="*60)
    print(f"运行测试: {result.testsRun}")
    print(f"成功: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"失败: {len(result.failures)}")
    print(f"错误: {len(result.errors)}")
    
    if result.wasSuccessful():
        print("\n✅ 所有测试通过！")
    else:
        print("\n❌ 部分测试失败")
        if result.failures:
            print("\n失败详情:")
            for test, traceback in result.failures:
                # 只显示前200个字符
                error_msg = traceback.split('\n')[-1] if traceback else 'Unknown error'
                print(f"  - {test}: {error_msg[:200]}")