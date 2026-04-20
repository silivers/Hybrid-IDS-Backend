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
        """根据五元组查找匹配的规则"""
        conn = None
        cursor = None
        
        try:
            conn = self.get_connection()
            cursor = conn.cursor(dictionary=True)
            
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
        """匹配IP地址"""
        if not rule_ip or rule_ip == 'any' or rule_ip == '':
            return True
        return rule_ip == actual_ip or rule_ip == '$HOME_NET' or rule_ip == '$EXTERNAL_NET'
    
    def get_rule_contents(self, sid: int) -> List[Dict]:
        """获取规则的content匹配条件"""
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
    
    # ========== API扩展新增方法 ==========
    
    def get_rules_with_filters(self, filters: dict = None, page: int = 1, 
                               page_size: int = 20) -> tuple:
        """
        获取规则列表（支持分页、筛选）
        
        Args:
            filters: 筛选条件 {'sid', 'msg_keyword', 'classtype', 'protocol', 'severity', 'enabled'}
            page: 页码
            page_size: 每页数量
        
        Returns:
            (total_count, rules_list)
        """
        conn = None
        cursor = None
        
        try:
            conn = self.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            # 构建基础查询
            base_query = """
                SELECT sid, msg, classtype, protocol, 
                       source_ip, source_port, dest_ip, dest_port,
                       severity, enabled, rev, reference, rule_text
                FROM snort_rules
                WHERE 1=1
            """
            count_query = "SELECT COUNT(*) as total FROM snort_rules WHERE 1=1"
            params = []
            
            # 应用筛选条件
            if filters:
                if 'sid' in filters and filters['sid']:
                    base_query += " AND sid = %s"
                    count_query += " AND sid = %s"
                    params.append(filters['sid'])
                
                if 'msg_keyword' in filters and filters['msg_keyword']:
                    base_query += " AND msg LIKE %s"
                    count_query += " AND msg LIKE %s"
                    params.append(f'%{filters["msg_keyword"]}%')
                
                if 'classtype' in filters and filters['classtype']:
                    base_query += " AND classtype = %s"
                    count_query += " AND classtype = %s"
                    params.append(filters['classtype'])
                
                if 'protocol' in filters and filters['protocol']:
                    base_query += " AND protocol = %s"
                    count_query += " AND protocol = %s"
                    params.append(filters['protocol'])
                
                if 'severity' in filters and filters['severity']:
                    base_query += " AND severity = %s"
                    count_query += " AND severity = %s"
                    params.append(filters['severity'])
                
                if 'enabled' in filters and filters['enabled'] is not None:
                    base_query += " AND enabled = %s"
                    count_query += " AND enabled = %s"
                    params.append(filters['enabled'])
            
            # 获取总数
            cursor.execute(count_query, params)
            total = cursor.fetchone()['total']
            
            # 分页
            offset = (page - 1) * page_size
            base_query += " ORDER BY sid ASC LIMIT %s OFFSET %s"
            params.extend([page_size, offset])
            
            cursor.execute(base_query, params)
            rules = cursor.fetchall()
            
            return total, rules
            
        except Exception as e:
            print(f"[ERROR] get_rules_with_filters: {e}")
            return 0, []
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_rule_by_id_with_contents(self, sid: int) -> Optional[Dict]:
        """
        获取规则详情（包含所有content条件）
        
        Args:
            sid: 规则ID
        
        Returns:
            规则字典，包含contents列表
        """
        conn = None
        cursor = None
        
        try:
            conn = self.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            # 获取规则基本信息
            cursor.execute("""
                SELECT sid, msg, classtype, protocol, 
                       source_ip, source_port, dest_ip, dest_port,
                       severity, enabled, rev, reference, rule_text
                FROM snort_rules
                WHERE sid = %s
            """, (sid,))
            rule = cursor.fetchone()
            
            if rule:
                # 获取关联的content条件
                cursor.execute("""
                    SELECT content_pattern, content_type, offset_val, depth_val,
                           within_val, distance_val, is_negated, position_order
                    FROM rule_contents
                    WHERE sid = %s
                    ORDER BY position_order
                """, (sid,))
                rule['contents'] = cursor.fetchall()
            
            return rule
            
        except Exception as e:
            print(f"[ERROR] get_rule_by_id_with_contents for sid {sid}: {e}")
            return None
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def update_rule_enabled(self, sid: int, enabled: int) -> bool:
        """
        更新规则的启用状态
        
        Args:
            sid: 规则ID
            enabled: 启用状态 (0/1)
        
        Returns:
            是否成功
        """
        conn = None
        cursor = None
        
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE snort_rules 
                SET enabled = %s 
                WHERE sid = %s
            """, (enabled, sid))
            
            conn.commit()
            affected = cursor.rowcount
            
            # 清除缓存
            if sid in self._rule_cache:
                del self._rule_cache[sid]
            
            return affected > 0
            
        except Exception as e:
            print(f"[ERROR] update_rule_enabled for sid {sid}: {e}")
            if conn:
                conn.rollback()
            return False
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_classtype_stats(self) -> List[Dict]:
        """
        获取规则分类统计
        
        Returns:
            分类统计列表 [{'classtype': 'xxx', 'rule_count': 10, 'avg_severity': 2.5}]
        """
        conn = None
        cursor = None
        
        try:
            conn = self.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("""
                SELECT 
                    classtype,
                    COUNT(*) as rule_count,
                    ROUND(AVG(severity), 2) as avg_severity
                FROM snort_rules
                WHERE classtype IS NOT NULL AND classtype != ''
                GROUP BY classtype
                ORDER BY rule_count DESC
            """)
            stats = cursor.fetchall()
            
            return stats
            
        except Exception as e:
            print(f"[ERROR] get_classtype_stats: {e}")
            return []
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_all_classtypes(self) -> List[str]:
        """
        获取所有可用的规则分类
        
        Returns:
            分类名称列表
        """
        conn = None
        cursor = None
        
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT DISTINCT classtype
                FROM snort_rules
                WHERE classtype IS NOT NULL AND classtype != ''
                ORDER BY classtype
            """)
            classtypes = [row[0] for row in cursor.fetchall()]
            
            return classtypes
            
        except Exception as e:
            print(f"[ERROR] get_all_classtypes: {e}")
            return []
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_rule_type_distribution_for_asset(self, dst_ip: str) -> List[Dict]:
        """
        获取某资产受到的攻击类型分布
        
        Args:
            dst_ip: 目标IP地址
        
        Returns:
            攻击类型分布列表
        """
        conn = None
        cursor = None
        
        try:
            conn = self.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("""
                SELECT 
                    r.classtype,
                    COUNT(*) as alert_count,
                    AVG(r.severity) as avg_severity
                FROM snort_alerts a
                JOIN snort_rules r ON a.sid = r.sid
                WHERE a.dst_ip = %s AND r.classtype IS NOT NULL
                GROUP BY r.classtype
                ORDER BY alert_count DESC
                LIMIT 20
            """, (dst_ip,))
            distribution = cursor.fetchall()
            
            return distribution
            
        except Exception as e:
            print(f"[ERROR] get_rule_type_distribution_for_asset: {e}")
            return []
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_rules_by_sids(self, sids: List[int]) -> List[Dict]:
        """
        批量获取规则信息
        
        Args:
            sids: 规则ID列表
        
        Returns:
            规则信息列表
        """
        if not sids:
            return []
        
        conn = None
        cursor = None
        
        try:
            conn = self.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            placeholders = ','.join(['%s'] * len(sids))
            query = f"""
                SELECT sid, msg, classtype, protocol, severity, enabled, reference
                FROM snort_rules
                WHERE sid IN ({placeholders})
            """
            
            cursor.execute(query, sids)
            rules = cursor.fetchall()
            
            return rules
            
        except Exception as e:
            print(f"[ERROR] get_rules_by_sids: {e}")
            return []
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_content_patterns_for_rule(self, sid: int) -> List[Dict]:
        """
        获取规则的content模式
        
        Args:
            sid: 规则ID
        
        Returns:
            content模式列表
        """
        return self.get_rule_contents(sid)
    
    def get_rule_statistics(self) -> Dict:
        """
        获取规则统计信息
        
        Returns:
            统计信息字典
        """
        conn = None
        cursor = None
        
        try:
            conn = self.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            # 总规则数
            cursor.execute("SELECT COUNT(*) as total FROM snort_rules")
            total = cursor.fetchone()['total']
            
            # 启用规则数
            cursor.execute("SELECT COUNT(*) as enabled FROM snort_rules WHERE enabled = 1")
            enabled = cursor.fetchone()['enabled']
            
            # 按严重程度分布
            cursor.execute("""
                SELECT severity, COUNT(*) as count 
                FROM snort_rules 
                GROUP BY severity
            """)
            severity_dist = cursor.fetchall()
            
            # 按协议分布
            cursor.execute("""
                SELECT protocol, COUNT(*) as count 
                FROM snort_rules 
                WHERE protocol IS NOT NULL
                GROUP BY protocol
                ORDER BY count DESC
                LIMIT 10
            """)
            protocol_dist = cursor.fetchall()
            
            return {
                'total_rules': total,
                'enabled_rules': enabled,
                'disabled_rules': total - enabled,
                'severity_distribution': severity_dist,
                'protocol_distribution': protocol_dist
            }
            
        except Exception as e:
            print(f"[ERROR] get_rule_statistics: {e}")
            return {}
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