# storage/rule_repo.py
"""规则仓库 - MySQL规则查询"""
import mysql.connector
from mysql.connector import pooling
from typing import Optional, Dict, List, Any
from datetime import datetime
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import DB_CONFIG


class RuleRepository:
    """规则仓库"""
    
    def __init__(self):
        """初始化数据库连接池"""
        self._init_connection_pool()
        self._rule_cache = {}
        self._content_cache = {}
        
    def _init_connection_pool(self):
        """初始化连接池"""
        try:
            self.pool = pooling.MySQLConnectionPool(
                pool_name="rule_pool",
                pool_size=DB_CONFIG.get('pool_size', 5),
                pool_reset_session=True,
                **{k: v for k, v in DB_CONFIG.items() if k not in ['pool_size', 'pool_recycle']}
            )
            print("[INFO] RuleRepository connection pool initialized")
        except Exception as e:
            print(f"[ERROR] Failed to initialize connection pool: {e}")
            self.pool = None
    
    def get_connection(self):
        """获取数据库连接"""
        if self.pool:
            return self.pool.get_connection()
        import mysql.connector
        return mysql.connector.connect(**{k: v for k, v in DB_CONFIG.items() 
                                          if k not in ['pool_size', 'pool_recycle']})
    
    def find_rule_by_5tuple(self, protocol: str, src_ip: str, src_port: int,
                            dst_ip: str, dst_port: int) -> Optional[Dict]:
        """
        根据五元组查找匹配的规则
        
        注意：这是一个简化的匹配逻辑，实际Snort规则匹配更复杂
        """
        conn = None
        cursor = None
        
        try:
            conn = self.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            # 查询启用的规则
            # 简化：匹配协议和端口（实际应包含IP范围匹配）
            query = """
                SELECT sid, msg, classtype, severity, protocol, 
                       source_ip, source_port, dest_ip, dest_port, 
                       flow, rule_text
                FROM snort_rules
                WHERE enabled = 1
                AND protocol = %s
                AND (source_port = %s OR source_port = 'any' OR source_port = '')
                AND (dest_port = %s OR dest_port = 'any' OR dest_port = '')
            """
            
            cursor.execute(query, (protocol, str(src_port), str(dst_port)))
            rules = cursor.fetchall()
            
            # 进一步匹配IP（简化处理）
            for rule in rules:
                if self._match_ip(rule.get('source_ip'), src_ip) and \
                   self._match_ip(rule.get('dest_ip'), dst_ip):
                    return rule
            
            return None
            
        except Exception as e:
            print(f"[ERROR] find_rule_by_5tuple failed: {e}")
            return None
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def _match_ip(self, rule_ip: Optional[str], actual_ip: str) -> bool:
        """匹配IP地址（支持CIDR和变量）"""
        if not rule_ip or rule_ip == 'any' or rule_ip == '':
            return True
        
        # 简化：精确匹配
        # TODO: 实现CIDR匹配和变量替换
        return rule_ip == actual_ip or rule_ip == '$HOME_NET' or rule_ip == '$EXTERNAL_NET'
    
    def get_rule_contents(self, sid: int) -> List[Dict]:
        """获取规则的content匹配条件"""
        # 检查缓存
        if sid in self._content_cache:
            return self._content_cache[sid]
        
        conn = None
        cursor = None
        
        try:
            conn = self.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            query = """
                SELECT content_pattern, content_type, offset_val, depth_val,
                       within_val, distance_val, is_negated, position_order
                FROM rule_contents
                WHERE sid = %s
                ORDER BY position_order
            """
            
            cursor.execute(query, (sid,))
            contents = cursor.fetchall()
            
            # 缓存
            self._content_cache[sid] = contents
            return contents
            
        except Exception as e:
            print(f"[ERROR] get_rule_contents failed for sid {sid}: {e}")
            return []
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def reload(self):
        """重新加载规则（清除缓存）"""
        self._rule_cache.clear()
        self._content_cache.clear()
        print("[INFO] RuleRepository cache cleared")