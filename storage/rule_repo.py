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
    """规则仓库 - 管理Snort规则的查询、缓存和统计"""
    
    def __init__(self):
        """初始化数据库连接池和缓存"""
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
        self._rule_cache = {}
        self._content_cache = {}
    
    def _get_conn(self):
        """获取数据库连接
        
        Returns:
            MySQL连接对象
        """
        if self.pool:
            return self.pool.get_connection()
        import mysql.connector
        return mysql.connector.connect(**{k: v for k, v in DB_CONFIG.items() 
                                          if k not in ['pool_size', 'pool_recycle']})
    
    def _execute_query(self, query: str, params: tuple = None, fetch_one=False, fetch_all=False):
        """执行查询的通用方法
        
        Args:
            query: SQL查询语句
            params: 查询参数元组
            fetch_one: 是否返回单条记录
            fetch_all: 是否返回所有记录
        
        Returns:
            根据参数返回单条记录、多条记录、影响行数或None
        """
        conn = self._get_conn()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute(query, params or ())
            if fetch_one:
                return cursor.fetchone()
            if fetch_all:
                return cursor.fetchall()
            conn.commit()
            return cursor.rowcount
        finally:
            cursor.close()
            conn.close()
    
    def find_rule_by_5tuple(self, protocol: str, src_ip: str, src_port: int,
                            dst_ip: str, dst_port: int) -> Optional[Dict]:
        """根据五元组查找匹配的规则
        
        Args:
            protocol: 协议类型 (tcp/udp/icmp等)
            src_ip: 源IP地址
            src_port: 源端口
            dst_ip: 目的IP地址
            dst_port: 目的端口
        
        Returns:
            匹配的规则字典，包含sid、msg、classtype等字段，未找到返回None
        """
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
        rules = self._execute_query(query, (protocol, str(src_port), str(dst_port)), fetch_all=True)
        
        for rule in rules or []:
            if self._match_ip(rule.get('source_ip'), src_ip) and \
               self._match_ip(rule.get('dest_ip'), dst_ip):
                return rule
        return None
    
    def _match_ip(self, rule_ip: Optional[str], actual_ip: str) -> bool:
        """匹配IP地址（支持通配符和变量）
        
        Args:
            rule_ip: 规则中的IP地址（可为any、$HOME_NET、$EXTERNAL_NET或具体IP）
            actual_ip: 实际的IP地址
        
        Returns:
            True表示匹配，False表示不匹配
        """
        if not rule_ip or rule_ip == 'any' or rule_ip == '':
            return True
        return rule_ip == actual_ip or rule_ip == '$HOME_NET' or rule_ip == '$EXTERNAL_NET'
    
    def get_rule_contents(self, sid: int) -> List[Dict]:
        """获取规则的content匹配条件
        
        Args:
            sid: 规则ID
        
        Returns:
            content条件列表，每个元素包含content_pattern、offset_val、depth_val等字段
        """
        if sid in self._content_cache:
            return self._content_cache[sid]
        
        contents = self._execute_query("""
            SELECT content_pattern, content_type, offset_val, depth_val,
                   within_val, distance_val, is_negated, position_order
            FROM rule_contents
            WHERE sid = %s
            ORDER BY position_order
        """, (sid,), fetch_all=True) or []
        
        self._content_cache[sid] = contents
        return contents
    
    # ========== API扩展新增方法 ==========
    
    def get_rules_with_filters(self, filters: dict = None, page: int = 1, 
                               page_size: int = 20) -> tuple:
        """获取规则列表（支持分页和筛选）
        
        Args:
            filters: 筛选条件字典，支持sid、msg_keyword、classtype、protocol、severity、enabled
            page: 页码，从1开始
            page_size: 每页数量
        
        Returns:
            (total_count, rules_list) 元组，total_count为总记录数，rules_list为规则列表
        """
        where = []
        params = []
        
        if filters:
            for key, val in filters.items():
                if val is not None:
                    if key == 'sid':
                        where.append("sid = %s")
                        params.append(val)
                    elif key == 'msg_keyword':
                        where.append("msg LIKE %s")
                        params.append(f'%{val}%')
                    elif key == 'enabled':
                        where.append("enabled = %s")
                        params.append(val)
                    else:
                        where.append(f"{key} = %s")
                        params.append(val)
        
        where_clause = " AND " + " AND ".join(where) if where else ""
        
        total = self._execute_query(
            f"SELECT COUNT(*) as total FROM snort_rules WHERE 1=1{where_clause}",
            params, fetch_one=True
        )['total']
        
        offset = (page - 1) * page_size
        rules = self._execute_query(f"""
            SELECT sid, msg, classtype, protocol, source_ip, source_port,
                   dest_ip, dest_port, severity, enabled, rev, reference, rule_text
            FROM snort_rules WHERE 1=1{where_clause}
            ORDER BY sid ASC LIMIT %s OFFSET %s
        """, params + [page_size, offset], fetch_all=True) or []
        
        return total, rules
    
    def get_rule_by_id_with_contents(self, sid: int) -> Optional[Dict]:
        """获取规则详情（包含所有content条件）
        
        Args:
            sid: 规则ID
        
        Returns:
            规则字典，包含contents字段（content条件列表），未找到返回None
        """
        rule = self._execute_query("""
            SELECT sid, msg, classtype, protocol, source_ip, source_port,
                   dest_ip, dest_port, severity, enabled, rev, reference, rule_text
            FROM snort_rules WHERE sid = %s
        """, (sid,), fetch_one=True)
        
        if rule:
            rule['contents'] = self.get_rule_contents(sid)
        return rule
    
    def update_rule_enabled(self, sid: int, enabled: int) -> bool:
        """更新规则的启用状态
        
        Args:
            sid: 规则ID
            enabled: 启用状态，1表示启用，0表示禁用
        
        Returns:
            True表示更新成功，False表示失败
        """
        result = self._execute_query(
            "UPDATE snort_rules SET enabled = %s WHERE sid = %s",
            (enabled, sid)
        )
        if sid in self._rule_cache:
            del self._rule_cache[sid]
        return result > 0
    
    def get_classtype_stats(self) -> List[Dict]:
        """获取规则分类统计
        
        Returns:
            分类统计列表，每个元素包含classtype、rule_count、avg_severity字段
        """
        return self._execute_query("""
            SELECT classtype, COUNT(*) as rule_count, ROUND(AVG(severity), 2) as avg_severity
            FROM snort_rules
            WHERE classtype IS NOT NULL AND classtype != ''
            GROUP BY classtype ORDER BY rule_count DESC
        """, fetch_all=True) or []
    
    def get_all_classtypes(self) -> List[str]:
        """获取所有可用的规则分类
        
        Returns:
            分类名称列表
        """
        rows = self._execute_query("""
            SELECT DISTINCT classtype FROM snort_rules
            WHERE classtype IS NOT NULL AND classtype != '' ORDER BY classtype
        """, fetch_all=True) or []
        return [row['classtype'] for row in rows]
    
    def get_rule_type_distribution_for_asset(self, dst_ip: str) -> List[Dict]:
        """获取某资产受到的攻击类型分布
        
        Args:
            dst_ip: 目标IP地址（受保护的资产）
        
        Returns:
            攻击类型分布列表，每个元素包含classtype、alert_count、avg_severity字段
        """
        return self._execute_query("""
            SELECT r.classtype, COUNT(*) as alert_count, AVG(r.severity) as avg_severity
            FROM snort_alerts a JOIN snort_rules r ON a.sid = r.sid
            WHERE a.dst_ip = %s AND r.classtype IS NOT NULL
            GROUP BY r.classtype ORDER BY alert_count DESC LIMIT 20
        """, (dst_ip,), fetch_all=True) or []
    
    def get_rules_by_sids(self, sids: List[int]) -> List[Dict]:
        """批量获取规则信息
        
        Args:
            sids: 规则ID列表
        
        Returns:
            规则信息列表，每个元素包含sid、msg、classtype、protocol、severity、enabled、reference字段
        """
        if not sids:
            return []
        placeholders = ','.join(['%s'] * len(sids))
        return self._execute_query(f"""
            SELECT sid, msg, classtype, protocol, severity, enabled, reference
            FROM snort_rules WHERE sid IN ({placeholders})
        """, tuple(sids), fetch_all=True) or []
    
    def get_content_patterns_for_rule(self, sid: int) -> List[Dict]:
        """获取规则的content模式
        
        Args:
            sid: 规则ID
        
        Returns:
            content模式列表
        """
        return self.get_rule_contents(sid)
    
    def get_rule_statistics(self) -> Dict:
        """获取规则统计信息
        
        Returns:
            统计信息字典，包含total_rules、enabled_rules、disabled_rules、
            severity_distribution、protocol_distribution字段
        """
        total = self._execute_query("SELECT COUNT(*) as total FROM snort_rules", fetch_one=True)['total']
        enabled = self._execute_query("SELECT COUNT(*) as enabled FROM snort_rules WHERE enabled = 1", fetch_one=True)['enabled']
        
        return {
            'total_rules': total,
            'enabled_rules': enabled,
            'disabled_rules': total - enabled,
            'severity_distribution': self._execute_query(
                "SELECT severity, COUNT(*) as count FROM snort_rules GROUP BY severity", fetch_all=True) or [],
            'protocol_distribution': self._execute_query(
                "SELECT protocol, COUNT(*) as count FROM snort_rules WHERE protocol IS NOT NULL GROUP BY protocol ORDER BY count DESC LIMIT 10", fetch_all=True) or []
        }
    
    def reload(self):
        """重新加载规则（清除所有缓存）"""
        self._rule_cache.clear()
        self._content_cache.clear()
        print("[INFO] RuleRepository cache cleared")