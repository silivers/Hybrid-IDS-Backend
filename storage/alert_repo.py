"""告警仓库 - MySQL告警写入"""
import mysql.connector
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, date
import sys, os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import DB_CONFIG


class AlertRepository:
    """告警仓库 - 管理告警的写入、查询、统计和报表功能"""
    
    def __init__(self):
        """初始化数据库连接池"""
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
    
    def _execute(self, query: str, params: tuple = None, fetch_one=False, fetch_all=False):
        """统一执行SQL方法
        
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
    
    def save_alert(self, sid: int, src_ip: str, src_port: int,
                   dst_ip: str, dst_port: int, protocol: str,
                   severity: int, matched_content: Optional[str] = None,
                   payload_preview: Optional[str] = None,
                   msg: Optional[str] = None) -> int:
        """保存告警记录
        
        Args:
            sid: 规则ID（0表示模型检测）
            src_ip: 源IP地址
            src_port: 源端口
            dst_ip: 目的IP地址
            dst_port: 目的端口
            protocol: 协议类型
            severity: 严重程度（1=高，2=中，3=低）
            matched_content: 匹配到的content内容或模型预测信息
            payload_preview: payload预览（十六进制）
            msg: 告警消息（可选）
        
        Returns:
            alert_id: 插入的告警ID，失败返回-1
        """
        alert_id = self._execute("""
            INSERT INTO snort_alerts 
            (sid, timestamp, src_ip, src_port, dst_ip, dst_port, 
             protocol, severity, payload_preview, matched_content, processed)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (sid, datetime.now(), src_ip, src_port, dst_ip, dst_port,
              protocol, severity, payload_preview, matched_content, 0))
        
        print(f"[ALERT] sid={sid}, src={src_ip}:{src_port} -> dst={dst_ip}:{dst_port}, "
              f"severity={severity}, content={matched_content}")
        return alert_id
    
    def save_model_alert(self, src_ip: str, src_port: int, dst_ip: str, 
                         dst_port: int, protocol: str, probability: float,
                         prediction: int, payload_preview: Optional[str] = None) -> int:
        """保存模型检测的告警（sid=0表示模型检测）
        
        Args:
            src_ip: 源IP地址
            src_port: 源端口
            dst_ip: 目的IP地址
            dst_port: 目的端口
            protocol: 协议类型
            probability: 模型预测概率（0-1）
            prediction: 模型预测结果（0=正常，1=恶意）
            payload_preview: payload预览（可选）
        
        Returns:
            alert_id: 插入的告警ID
        """
        severity = 1 if probability >= 0.7 else (2 if probability >= 0.5 else 3)
        matched_content = f"model_prediction={prediction},prob={probability:.3f}"
        return self.save_alert(
            sid=0, src_ip=src_ip, src_port=src_port,
            dst_ip=dst_ip, dst_port=dst_port, protocol=protocol,
            severity=severity, matched_content=matched_content,
            payload_preview=payload_preview, msg=f"Model detected threat (prob={probability:.3f})"
        )

    # ========== API扩展方法 ==========
    
    def get_dashboard_metrics(self, days: int = 7) -> dict:
        """获取仪表盘核心指标
        
        Args:
            days: 统计天数，默认7天
        
        Returns:
            包含total_alerts、high_severity、unprocessed、affected_assets的字典
        """
        result = self._execute("""
            SELECT 
                COUNT(*) as total_alerts,
                SUM(CASE WHEN severity = 1 THEN 1 ELSE 0 END) as high_severity,
                SUM(CASE WHEN processed = 0 THEN 1 ELSE 0 END) as unprocessed,
                COUNT(DISTINCT dst_ip) as affected_assets
            FROM snort_alerts
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL %s DAY)
        """, (days,), fetch_one=True) or {}
        return {k: int(v) if v is not None else 0 for k, v in result.items()}
    
    def get_alert_trend(self, hours: int = 24) -> dict:
        """获取告警趋势（最近N小时和最近N天）
        
        Args:
            hours: 最近小时数，默认24小时
        
        Returns:
            包含last_24h和last_7d两个趋势列表的字典
        """
        return {
            'last_24h': self._execute("""
                SELECT DATE_FORMAT(timestamp, '%%Y-%%m-%%d %%H:00:00') as time_bucket, COUNT(*) as count
                FROM snort_alerts WHERE timestamp >= DATE_SUB(NOW(), INTERVAL %s HOUR)
                GROUP BY DATE_FORMAT(timestamp, '%%Y%%m%%d%%H') ORDER BY time_bucket
            """, (hours,), fetch_all=True) or [],
            'last_7d': self._execute("""
                SELECT DATE(timestamp) as date, COUNT(*) as count
                FROM snort_alerts WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                GROUP BY DATE(timestamp) ORDER BY date
            """, fetch_all=True) or []
        }
    
    def get_severity_distribution(self, days: int = 7) -> list:
        """获取严重程度分布
        
        Args:
            days: 统计天数，默认7天
        
        Returns:
            包含severity、count、level的列表
        """
        return self._execute("""
            SELECT severity, COUNT(*) as count,
                   CASE severity WHEN 1 THEN '高' WHEN 2 THEN '中' WHEN 3 THEN '低' ELSE '未知' END as level
            FROM snort_alerts WHERE timestamp >= DATE_SUB(NOW(), INTERVAL %s DAY)
            GROUP BY severity ORDER BY severity
        """, (days,), fetch_all=True) or []
    
    def get_top_src_ips(self, limit: int = 10, days: int = 7) -> list:
        """获取TOP攻击源IP
        
        Args:
            limit: 返回数量，默认10
            days: 统计天数，默认7天
        
        Returns:
            包含src_ip、count、high_count的列表
        """
        return self._execute("""
            SELECT src_ip, COUNT(*) as count, SUM(CASE WHEN severity = 1 THEN 1 ELSE 0 END) as high_count
            FROM snort_alerts WHERE timestamp >= DATE_SUB(NOW(), INTERVAL %s DAY)
            GROUP BY src_ip ORDER BY count DESC LIMIT %s
        """, (days, limit), fetch_all=True) or []
    
    def get_top_dst_ips(self, limit: int = 10, days: int = 7) -> list:
        """获取TOP目标IP（受害资产）
        
        Args:
            limit: 返回数量，默认10
            days: 统计天数，默认7天
        
        Returns:
            包含dst_ip、count、high_count的列表
        """
        return self._execute("""
            SELECT dst_ip, COUNT(*) as count, SUM(CASE WHEN severity = 1 THEN 1 ELSE 0 END) as high_count
            FROM snort_alerts WHERE timestamp >= DATE_SUB(NOW(), INTERVAL %s DAY)
            GROUP BY dst_ip ORDER BY count DESC LIMIT %s
        """, (days, limit), fetch_all=True) or []
    
    def get_top_alert_types(self, limit: int = 10, days: int = 7) -> list:
        """获取TOP告警类型
        
        Args:
            limit: 返回数量，默认10
            days: 统计天数，默认7天
        
        Returns:
            包含sid、msg、count的列表（排除模型告警sid=0）
        """
        return self._execute("""
            SELECT a.sid, r.msg, COUNT(*) as count
            FROM snort_alerts a INNER JOIN snort_rules r ON a.sid = r.sid
            WHERE a.timestamp >= DATE_SUB(NOW(), INTERVAL %s DAY) AND a.sid != 0
            GROUP BY a.sid, r.msg ORDER BY count DESC LIMIT %s
        """, (days, limit), fetch_all=True) or []
    
    def get_top_rules(self, limit: int = 10, days: int = 7) -> list:
        """获取TOP触发规则（与get_top_alert_types相同，保持API兼容）
        
        Args:
            limit: 返回数量，默认10
            days: 统计天数，默认7天
        
        Returns:
            包含sid、msg、count的列表
        """
        return self.get_top_alert_types(limit, days)
    
    def get_alerts_with_filters(self, filters: dict, page: int = 1, 
                                page_size: int = 20, sort_by: str = 'timestamp', 
                                sort_order: str = 'DESC') -> Tuple[int, List[Dict]]:
        """获取告警列表（支持分页、筛选、排序）
        
        Args:
            filters: 筛选条件字典，支持start_time、end_time、severity、src_ip、
                     dst_ip、protocol、processed、sid
            page: 页码，从1开始
            page_size: 每页数量
            sort_by: 排序字段（timestamp、severity、src_ip、dst_ip、alert_id）
            sort_order: 排序方向（DESC/ASC）
        
        Returns:
            (total_count, alerts_list) 元组
        """
        where = []
        params = []
        
        filter_map = {
            'start_time': ("timestamp >= %s", lambda v: v),
            'end_time': ("timestamp <= %s", lambda v: v),
            'severity': ("severity = %s", int),
            'src_ip': ("src_ip = %s", str),
            'dst_ip': ("dst_ip = %s", str),
            'protocol': ("protocol = %s", str),
            'processed': ("processed = %s", int),
            'sid': ("sid = %s", int)
        }
        for key, (clause, converter) in filter_map.items():
            if filters.get(key) is not None:
                where.append(clause)
                params.append(converter(filters[key]))
        
        where_sql = " AND ".join(where) if where else "1=1"
        
        allowed_sort = {'timestamp', 'severity', 'src_ip', 'dst_ip', 'alert_id'}
        sort_by = sort_by if sort_by in allowed_sort else 'timestamp'
        sort_order = 'DESC' if sort_order.upper() == 'DESC' else 'ASC'
        
        total = self._execute(f"SELECT COUNT(*) as total FROM snort_alerts WHERE {where_sql}", 
                              tuple(params), fetch_one=True)['total']
        
        offset = (page - 1) * page_size
        alerts = self._execute(f"""
            SELECT alert_id, sid, timestamp, src_ip, src_port, dst_ip, dst_port,
                   protocol, severity, payload_preview, matched_content, processed
            FROM snort_alerts WHERE {where_sql}
            ORDER BY {sort_by} {sort_order} LIMIT %s OFFSET %s
        """, tuple(params + [page_size, offset]), fetch_all=True) or []
        
        for alert in alerts:
            if alert.get('timestamp'):
                alert['timestamp'] = alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        
        return total, alerts
    
    def get_alert_by_id_with_rule(self, alert_id: int) -> Optional[Dict]:
        """获取告警详情
        
        Args:
            alert_id: 告警ID
        
        Returns:
            告警详情字典，包含所有字段，未找到返回None
        """
        alert = self._execute("""
            SELECT alert_id, sid, timestamp, src_ip, src_port, dst_ip, dst_port,
                   protocol, severity, payload_preview, matched_content, processed
            FROM snort_alerts WHERE alert_id = %s
        """, (alert_id,), fetch_one=True)
        if alert and alert.get('timestamp'):
            alert['timestamp'] = alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        return alert
    
    def batch_update_processed(self, alert_ids: List[int], processed: int = 1) -> int:
        """批量更新告警处理状态
        
        Args:
            alert_ids: 告警ID列表
            processed: 处理状态（1=已处理，0=未处理）
        
        Returns:
            更新的记录数
        """
        if not alert_ids:
            return 0
        placeholders = ','.join(['%s'] * len(alert_ids))
        return self._execute(f"UPDATE snort_alerts SET processed = %s WHERE alert_id IN ({placeholders})",
                            tuple([processed] + alert_ids))
    
    def get_alerts_by_src_ip(self, src_ip: str, start_time: datetime = None,
                             end_time: datetime = None, limit: int = 100) -> List[Dict]:
        """按源IP聚合查询所有告警
        
        Args:
            src_ip: 源IP地址
            start_time: 开始时间（可选）
            end_time: 结束时间（可选）
            limit: 返回数量限制，默认100
        
        Returns:
            告警列表
        """
        where = ["src_ip = %s"]
        params = [src_ip]
        if start_time:
            where.append("timestamp >= %s")
            params.append(start_time)
        if end_time:
            where.append("timestamp <= %s")
            params.append(end_time)
        
        alerts = self._execute(f"""
            SELECT alert_id, sid, timestamp, dst_ip, dst_port, protocol,
                   severity, matched_content, processed
            FROM snort_alerts WHERE {' AND '.join(where)}
            ORDER BY timestamp DESC LIMIT %s
        """, tuple(params + [limit]), fetch_all=True) or []
        
        for alert in alerts:
            if alert.get('timestamp'):
                alert['timestamp'] = alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        return alerts
    
    def get_conversation_alerts(self, src_ip: str, dst_ip: str,
                                start_time: datetime = None, 
                                end_time: datetime = None) -> List[Dict]:
        """查询两个IP之间的所有告警
        
        Args:
            src_ip: 源IP地址
            dst_ip: 目的IP地址
            start_time: 开始时间（可选）
            end_time: 结束时间（可选）
        
        Returns:
            告警列表
        """
        where = ["src_ip = %s", "dst_ip = %s"]
        params = [src_ip, dst_ip]
        if start_time:
            where.append("timestamp >= %s")
            params.append(start_time)
        if end_time:
            where.append("timestamp <= %s")
            params.append(end_time)
        
        alerts = self._execute(f"""
            SELECT alert_id, sid, timestamp, src_port, dst_port, protocol,
                   severity, matched_content, processed
            FROM snort_alerts WHERE {' AND '.join(where)} ORDER BY timestamp
        """, tuple(params), fetch_all=True) or []
        
        for alert in alerts:
            if alert.get('timestamp'):
                alert['timestamp'] = alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        return alerts
    
    def get_asset_context(self, dst_ip: str) -> Dict:
        """获取资产上下文统计信息
        
        Args:
            dst_ip: 目标IP地址（受保护的资产）
        
        Returns:
            包含total_alerts、max_severity、first_alert、last_alert、
            unique_attackers、unique_rules的字典
        """
        result = self._execute("""
            SELECT COUNT(*) as total_alerts, MAX(severity) as max_severity,
                   MIN(timestamp) as first_alert, MAX(timestamp) as last_alert,
                   COUNT(DISTINCT src_ip) as unique_attackers, COUNT(DISTINCT sid) as unique_rules
            FROM snort_alerts WHERE dst_ip = %s
        """, (dst_ip,), fetch_one=True) or {}
        
        for field in ['first_alert', 'last_alert']:
            if result.get(field):
                result[field] = result[field].strftime('%Y-%m-%d %H:%M:%S')
        return result
    
    def get_attacker_summary(self, dst_ip: str, limit: int = 10) -> List[Dict]:
        """获取攻击某资产的所有源IP汇总
        
        Args:
            dst_ip: 目标IP地址
            limit: 返回数量限制，默认10
        
        Returns:
            包含src_ip、alert_count、high_count、last_alert的列表
        """
        results = self._execute("""
            SELECT src_ip, COUNT(*) as alert_count, SUM(CASE WHEN severity = 1 THEN 1 ELSE 0 END) as high_count,
                   MAX(timestamp) as last_alert
            FROM snort_alerts WHERE dst_ip = %s
            GROUP BY src_ip ORDER BY alert_count DESC LIMIT %s
        """, (dst_ip, limit), fetch_all=True) or []
        
        for r in results:
            if r.get('last_alert'):
                r['last_alert'] = r['last_alert'].strftime('%Y-%m-%d %H:%M:%S')
        return results
    
    def get_asset_timeline(self, dst_ip: str, days: int = 7) -> List[Dict]:
        """获取资产的告警时间线
        
        Args:
            dst_ip: 目标IP地址
            days: 天数，默认7天
        
        Returns:
            包含date、count、high_count的列表
        """
        results = self._execute("""
            SELECT DATE(timestamp) as date, COUNT(*) as count,
                   SUM(CASE WHEN severity = 1 THEN 1 ELSE 0 END) as high_count
            FROM snort_alerts WHERE dst_ip = %s AND timestamp >= DATE_SUB(NOW(), INTERVAL %s DAY)
            GROUP BY DATE(timestamp) ORDER BY date
        """, (dst_ip, days), fetch_all=True) or []
        
        for r in results:
            if r.get('date'):
                r['date'] = r['date'].strftime('%Y-%m-%d')
        return results
    
    def get_all_assets(self, severity_threshold: int = None, 
                       has_unprocessed: bool = None,
                       sort_by: str = 'total_alerts', 
                       limit: int = 50) -> List[Dict]:
        """获取所有受监控资产列表
        
        Args:
            severity_threshold: 严重程度阈值（1=高，2=中，3=低）
            has_unprocessed: 是否只返回有未处理告警的资产
            sort_by: 排序字段（total_alerts、max_severity、last_alert、unprocessed_count）
            limit: 返回数量限制，默认50
        
        Returns:
            包含dst_ip、total_alerts、max_severity、last_alert、unprocessed_count的列表
        """
        having = []
        params = []
        if severity_threshold is not None:
            having.append("max_severity <= %s")
            params.append(severity_threshold)
        if has_unprocessed:
            having.append("unprocessed_count > 0")
        
        allowed_sort = {'total_alerts', 'max_severity', 'last_alert', 'unprocessed_count'}
        sort_by = sort_by if sort_by in allowed_sort else 'total_alerts'
        
        results = self._execute(f"""
            SELECT dst_ip, COUNT(*) as total_alerts, MAX(severity) as max_severity,
                   MAX(timestamp) as last_alert, SUM(CASE WHEN processed = 0 THEN 1 ELSE 0 END) as unprocessed_count
            FROM snort_alerts GROUP BY dst_ip
            {f'HAVING {" AND ".join(having)}' if having else ''}
            ORDER BY {sort_by} DESC LIMIT %s
        """, tuple(params + [limit]), fetch_all=True) or []
        
        for r in results:
            if r.get('last_alert'):
                r['last_alert'] = r['last_alert'].strftime('%Y-%m-%d %H:%M:%S')
            r['max_severity_level'] = {1: '高', 2: '中', 3: '低'}.get(r.get('max_severity'), '未知')
        return results
    
    def get_asset_risk_score(self, dst_ip: str) -> float:
        """计算资产风险分数（0-100）
        
        评分算法：
        - 告警数量贡献：最多30分
        - 严重程度贡献：高严重度每+0.5分，中严重度每+0.2分，最多30分
        - 攻击源多样性：每个独特源+2分，最多20分
        - 新鲜度贡献：最近告警越近分数越高，最多20分
        
        Args:
            dst_ip: 目标IP地址
        
        Returns:
            风险分数（0-100）
        """
        stats = self._execute("""
            SELECT COUNT(*) as total_alerts, 
                   SUM(CASE WHEN severity = 1 THEN 1 ELSE 0 END) as high_count,
                   SUM(CASE WHEN severity = 2 THEN 1 ELSE 0 END) as medium_count,
                   COUNT(DISTINCT src_ip) as unique_attackers,
                   DATEDIFF(NOW(), MAX(timestamp)) as days_since_last_alert
            FROM snort_alerts WHERE dst_ip = %s
        """, (dst_ip,), fetch_one=True)
        
        if not stats or stats.get('total_alerts', 0) == 0:
            return 0.0
        
        # 将 Decimal 转换为 float 或 int 以支持数学运算
        total_alerts = float(stats.get('total_alerts', 0))
        high_count = float(stats.get('high_count', 0))
        medium_count = float(stats.get('medium_count', 0))
        unique_attackers = float(stats.get('unique_attackers', 0))
        days_since = float(stats.get('days_since_last_alert') or 999)
        
        alert_score = min(30, total_alerts / 10)
        severity_score = min(30, high_count * 0.5 + medium_count * 0.2)
        attacker_score = min(20, unique_attackers * 2)
        freshness_score = max(0, 20 - days_since)
        
        return min(100, alert_score + severity_score + attacker_score + freshness_score)
    
    def get_asset_alert_trend(self, dst_ip: str, days: int = 7) -> List[Dict]:
        """获取单个资产的告警趋势
        
        Args:
            dst_ip: 目标IP地址
            days: 天数，默认7天
        
        Returns:
            包含date、count、high_count的列表
        """
        return self.get_asset_timeline(dst_ip, days)
    
    def get_attack_sources_for_asset(self, dst_ip: str, limit: int = 20) -> List[Dict]:
        """获取攻击某资产的所有源IP详情
        
        Args:
            dst_ip: 目标IP地址
            limit: 返回数量限制，默认20
        
        Returns:
            包含src_ip、alert_count、high_count、last_alert的列表
        """
        return self.get_attacker_summary(dst_ip, limit)
    
    def get_report_summary(self, start_date: date, end_date: date, group_by: str = 'day') -> Dict:
        """获取报表摘要数据
        
        Args:
            start_date: 开始日期
            end_date: 结束日期
            group_by: 分组粒度（day或hour）
        
        Returns:
            包含summary和trend的字典
        """
        time_field = "DATE_FORMAT(timestamp, '%Y-%m-%d %H:00:00')" if group_by == 'hour' else "DATE(timestamp)"
        
        trend = self._execute(f"""
            SELECT COUNT(*) as total_alerts, SUM(CASE WHEN severity = 1 THEN 1 ELSE 0 END) as high_count,
                   SUM(CASE WHEN severity = 2 THEN 1 ELSE 0 END) as medium_count,
                   SUM(CASE WHEN severity = 3 THEN 1 ELSE 0 END) as low_count,
                   COUNT(DISTINCT src_ip) as unique_sources, COUNT(DISTINCT dst_ip) as unique_targets,
                   COUNT(DISTINCT sid) as unique_rules, {time_field} as time_bucket
            FROM snort_alerts WHERE DATE(timestamp) >= %s AND DATE(timestamp) <= %s
            GROUP BY time_bucket ORDER BY time_bucket
        """, (start_date, end_date), fetch_all=True) or []
        
        for item in trend:
            if item.get('time_bucket'):
                item['time_bucket'] = item['time_bucket'].strftime('%Y-%m-%d %H:%M:%S') if hasattr(item['time_bucket'], 'strftime') else str(item['time_bucket'])
        
        summary = self._execute("""
            SELECT COUNT(*) as total_alerts, SUM(CASE WHEN severity = 1 THEN 1 ELSE 0 END) as high_count,
                   SUM(CASE WHEN severity = 2 THEN 1 ELSE 0 END) as medium_count,
                   SUM(CASE WHEN severity = 3 THEN 1 ELSE 0 END) as low_count,
                   COUNT(DISTINCT src_ip) as unique_sources, COUNT(DISTINCT dst_ip) as unique_targets,
                   COUNT(DISTINCT sid) as unique_rules
            FROM snort_alerts WHERE DATE(timestamp) >= %s AND DATE(timestamp) <= %s
        """, (start_date, end_date), fetch_one=True) or {}
        
        return {'summary': summary, 'trend': trend}
    
    def get_top_sources_report(self, start_date: date, end_date: date, limit: int = 10) -> List[Dict]:
        """获取TOP攻击源报表
        
        Args:
            start_date: 开始日期
            end_date: 结束日期
            limit: 返回数量限制，默认10
        
        Returns:
            包含src_ip、alert_count、high_count、medium_count、low_count、
            target_count、first_seen、last_seen的列表
        """
        results = self._execute("""
            SELECT src_ip, COUNT(*) as alert_count, SUM(CASE WHEN severity = 1 THEN 1 ELSE 0 END) as high_count,
                   SUM(CASE WHEN severity = 2 THEN 1 ELSE 0 END) as medium_count,
                   SUM(CASE WHEN severity = 3 THEN 1 ELSE 0 END) as low_count,
                   COUNT(DISTINCT dst_ip) as target_count, MIN(timestamp) as first_seen, MAX(timestamp) as last_seen
            FROM snort_alerts WHERE DATE(timestamp) >= %s AND DATE(timestamp) <= %s
            GROUP BY src_ip ORDER BY alert_count DESC LIMIT %s
        """, (start_date, end_date, limit), fetch_all=True) or []
        
        for r in results:
            for field in ['first_seen', 'last_seen']:
                if r.get(field):
                    r[field] = r[field].strftime('%Y-%m-%d %H:%M:%S')
        return results
    
    def get_top_rules_report(self, start_date: date, end_date: date, limit: int = 10) -> List[Dict]:
        """获取TOP规则命中报表
        
        Args:
            start_date: 开始日期
            end_date: 结束日期
            limit: 返回数量限制，默认10
        
        Returns:
            包含sid、msg、classtype、rule_severity、hit_count、
            unique_sources、unique_targets的列表
        """
        return self._execute("""
            SELECT a.sid, r.msg, r.classtype, r.severity as rule_severity,
                   COUNT(*) as hit_count, COUNT(DISTINCT a.src_ip) as unique_sources,
                   COUNT(DISTINCT a.dst_ip) as unique_targets
            FROM snort_alerts a INNER JOIN snort_rules r ON a.sid = r.sid
            WHERE DATE(a.timestamp) >= %s AND DATE(a.timestamp) <= %s AND a.sid != 0
            GROUP BY a.sid, r.msg, r.classtype, r.severity ORDER BY hit_count DESC LIMIT %s
        """, (start_date, end_date, limit), fetch_all=True) or []
    
    def get_classtype_breakdown(self, start_date: date, end_date: date) -> List[Dict]:
        """获取告警的分类分布（用于报表）
        
        Args:
            start_date: 开始日期
            end_date: 结束日期
        
        Returns:
            包含classtype、count、percentage的列表
        """
        return self._execute("""
            SELECT r.classtype, COUNT(*) as count,
                   ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER(), 2) as percentage
            FROM snort_alerts a INNER JOIN snort_rules r ON a.sid = r.sid
            WHERE DATE(a.timestamp) >= %s AND DATE(a.timestamp) <= %s AND a.sid != 0 AND r.classtype IS NOT NULL
            GROUP BY r.classtype ORDER BY count DESC
        """, (start_date, end_date), fetch_all=True) or []
    
    def get_filter_options(self) -> Dict:
        """获取所有筛选器选项（动态生成前端下拉框）
        
        Returns:
            包含protocols、severities、processed_status、classtypes的字典
        """
        return {
            'protocols': self._execute("SELECT DISTINCT protocol, COUNT(*) as count FROM snort_alerts GROUP BY protocol", fetch_all=True) or [],
            'severities': self._execute("""
                SELECT severity, COUNT(*) as count, 
                       CASE severity WHEN 1 THEN '高' WHEN 2 THEN '中' WHEN 3 THEN '低' END as label 
                FROM snort_alerts GROUP BY severity ORDER BY severity
            """, fetch_all=True) or [],
            'processed_status': self._execute("""
                SELECT processed, COUNT(*) as count,
                       CASE processed WHEN 0 THEN '未处理' WHEN 1 THEN '已处理' END as label 
                FROM snort_alerts GROUP BY processed
            """, fetch_all=True) or [],
            'classtypes': self._execute("""
                SELECT DISTINCT classtype, COUNT(*) as count 
                FROM snort_rules WHERE classtype IS NOT NULL 
                GROUP BY classtype ORDER BY classtype
            """, fetch_all=True) or []
        }
