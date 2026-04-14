# storage/alert_repo.py
"""告警仓库 - MySQL告警写入"""
import mysql.connector
from typing import Optional, Dict, Any
from datetime import datetime
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import DB_CONFIG


class AlertRepository:
    """告警仓库"""
    
    def __init__(self):
        self._init_connection_pool()
    
    def _init_connection_pool(self):
        try:
            from mysql.connector import pooling
            self.pool = pooling.MySQLConnectionPool(
                pool_name="alert_pool",
                pool_size=DB_CONFIG.get('pool_size', 5),
                **{k: v for k, v in DB_CONFIG.items() if k not in ['pool_size', 'pool_recycle']}
            )
            print("[INFO] AlertRepository connection pool initialized")
        except Exception as e:
            print(f"[ERROR] Failed to initialize alert pool: {e}")
            self.pool = None
    
    def get_connection(self):
        if self.pool:
            return self.pool.get_connection()
        import mysql.connector
        return mysql.connector.connect(**{k: v for k, v in DB_CONFIG.items() 
                                          if k not in ['pool_size', 'pool_recycle']})
    
    def save_alert(self, sid: int, src_ip: str, src_port: int,
                   dst_ip: str, dst_port: int, protocol: str,
                   severity: int, matched_content: Optional[str] = None,
                   payload_preview: Optional[str] = None,
                   msg: Optional[str] = None) -> int:
        """
        保存告警记录
        
        Returns:
            alert_id: 插入的告警ID
        """
        conn = None
        cursor = None
        
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            query = """
                INSERT INTO snort_alerts 
                (sid, timestamp, src_ip, src_port, dst_ip, dst_port, 
                 protocol, severity, payload_preview, matched_content, processed)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            
            now = datetime.now()
            cursor.execute(query, (
                sid, now, src_ip, src_port, dst_ip, dst_port,
                protocol, severity, payload_preview, matched_content, 0
            ))
            
            conn.commit()
            alert_id = cursor.lastrowid
            
            print(f"[ALERT] sid={sid}, src={src_ip}:{src_port} -> dst={dst_ip}:{dst_port}, "
                  f"severity={severity}, content={matched_content}")
            
            return alert_id
            
        except Exception as e:
            print(f"[ERROR] save_alert failed: {e}")
            if conn:
                conn.rollback()
            return -1
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def save_model_alert(self, src_ip: str, src_port: int, dst_ip: str, 
                         dst_port: int, protocol: str, probability: float,
                         prediction: int, payload_preview: Optional[str] = None) -> int:
        """
        保存模型检测的告警（sid=0表示模型检测）
        """
        # 根据概率确定严重程度
        if probability >= 0.7:
            severity = 1  # 高
        elif probability >= 0.5:
            severity = 2  # 中
        else:
            severity = 3  # 低
        
        matched_content = f"model_prediction={prediction},prob={probability:.3f}"
        
        return self.save_alert(
            sid=0,  # 0表示模型检测
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            severity=severity,
            matched_content=matched_content,
            payload_preview=payload_preview,
            msg=f"Model detected threat (prob={probability:.3f})"
        )