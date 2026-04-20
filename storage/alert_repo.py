# storage/alert_repo.py
"""告警仓库 - MySQL告警写入"""
import mysql.connector
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, date
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

    # ========== 以下为API扩展新增方法 ==========
    
    def get_dashboard_metrics(self, days: int = 7) -> dict:
        """获取仪表盘核心指标"""
        conn = None
        cursor = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            query = """
                SELECT 
                    COUNT(*) as total_alerts,
                    SUM(CASE WHEN severity = 1 THEN 1 ELSE 0 END) as high_severity,
                    SUM(CASE WHEN processed = 0 THEN 1 ELSE 0 END) as unprocessed,
                    COUNT(DISTINCT dst_ip) as affected_assets
                FROM snort_alerts
                WHERE timestamp >= DATE_SUB(NOW(), INTERVAL %s DAY)
            """
            
            cursor.execute(query, (days,))
            result = cursor.fetchone()
            
            return {
                'total_alerts': result['total_alerts'] or 0,
                'high_severity': result['high_severity'] or 0,
                'unprocessed': result['unprocessed'] or 0,
                'affected_assets': result['affected_assets'] or 0
            }
        except Exception as e:
            print(f"[ERROR] get_dashboard_metrics failed: {e}")
            return {
                'total_alerts': 0,
                'high_severity': 0,
                'unprocessed': 0,
                'affected_assets': 0
            }
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_alert_trend(self, hours: int = 24) -> dict:
        """获取告警趋势（最近N小时和最近N天）"""
        conn = None
        cursor = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            # 最近24小时趋势（按小时）
            query_24h = """
                SELECT 
                    DATE_FORMAT(timestamp, '%%Y-%%m-%%d %%H:00:00') as time_bucket,
                    COUNT(*) as count
                FROM snort_alerts
                WHERE timestamp >= DATE_SUB(NOW(), INTERVAL %s HOUR)
                GROUP BY DATE_FORMAT(timestamp, '%%Y%%m%%d%%H')
                ORDER BY time_bucket
            """
            cursor.execute(query_24h, (hours,))
            last_24h = cursor.fetchall()
            
            # 最近7天趋势（按天）
            query_7d = """
                SELECT 
                    DATE(timestamp) as date,
                    COUNT(*) as count
                FROM snort_alerts
                WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                GROUP BY DATE(timestamp)
                ORDER BY date
            """
            cursor.execute(query_7d)
            last_7d = cursor.fetchall()
            
            return {
                'last_24h': last_24h,
                'last_7d': last_7d
            }
        except Exception as e:
            print(f"[ERROR] get_alert_trend failed: {e}")
            return {'last_24h': [], 'last_7d': []}
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_severity_distribution(self, days: int = 7) -> list:
        """获取严重程度分布"""
        conn = None
        cursor = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            query = """
                SELECT 
                    severity,
                    CASE severity
                        WHEN 1 THEN '高'
                        WHEN 2 THEN '中'
                        WHEN 3 THEN '低'
                        ELSE '未知'
                    END as level,
                    COUNT(*) as count
                FROM snort_alerts
                WHERE timestamp >= DATE_SUB(NOW(), INTERVAL %s DAY)
                GROUP BY severity
                ORDER BY severity
            """
            
            cursor.execute(query, (days,))
            return cursor.fetchall()
        except Exception as e:
            print(f"[ERROR] get_severity_distribution failed: {e}")
            return []
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_top_src_ips(self, limit: int = 10, days: int = 7) -> list:
        """获取TOP攻击源IP"""
        conn = None
        cursor = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            query = """
                SELECT 
                    src_ip,
                    COUNT(*) as count,
                    SUM(CASE WHEN severity = 1 THEN 1 ELSE 0 END) as high_count
                FROM snort_alerts
                WHERE timestamp >= DATE_SUB(NOW(), INTERVAL %s DAY)
                GROUP BY src_ip
                ORDER BY count DESC
                LIMIT %s
            """
            
            cursor.execute(query, (days, limit))
            return cursor.fetchall()
        except Exception as e:
            print(f"[ERROR] get_top_src_ips failed: {e}")
            return []
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_top_dst_ips(self, limit: int = 10, days: int = 7) -> list:
        """获取TOP目标IP"""
        conn = None
        cursor = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            query = """
                SELECT 
                    dst_ip,
                    COUNT(*) as count,
                    SUM(CASE WHEN severity = 1 THEN 1 ELSE 0 END) as high_count
                FROM snort_alerts
                WHERE timestamp >= DATE_SUB(NOW(), INTERVAL %s DAY)
                GROUP BY dst_ip
                ORDER BY count DESC
                LIMIT %s
            """
            
            cursor.execute(query, (days, limit))
            return cursor.fetchall()
        except Exception as e:
            print(f"[ERROR] get_top_dst_ips failed: {e}")
            return []
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_top_alert_types(self, limit: int = 10, days: int = 7) -> list:
        """获取TOP告警类型（关联snort_rules.msg）"""
        conn = None
        cursor = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            query = """
                SELECT 
                    a.sid,
                    r.msg,
                    COUNT(*) as count
                FROM snort_alerts a
                INNER JOIN snort_rules r ON a.sid = r.sid
                WHERE a.timestamp >= DATE_SUB(NOW(), INTERVAL %s DAY)
                AND a.sid != 0
                GROUP BY a.sid, r.msg
                ORDER BY count DESC
                LIMIT %s
            """
            
            cursor.execute(query, (days, limit))
            return cursor.fetchall()
        except Exception as e:
            print(f"[ERROR] get_top_alert_types failed: {e}")
            return []
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_top_rules(self, limit: int = 10, days: int = 7) -> list:
        """获取TOP触发规则"""
        # 与 get_top_alert_types 相同，但保留方法名以符合API设计
        return self.get_top_alert_types(limit, days)
    
    def get_alerts_with_filters(self, filters: dict, page: int = 1, 
                                page_size: int = 20, sort_by: str = 'timestamp', 
                                sort_order: str = 'DESC') -> Tuple[int, List[Dict]]:
        """获取告警列表（支持分页、筛选、排序）
        
        Returns:
            (total_count, alerts_list)
        """
        conn = None
        cursor = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            # 构建WHERE条件
            where_clauses = []
            params = []
            
            if filters.get('start_time'):
                where_clauses.append("timestamp >= %s")
                params.append(filters['start_time'])
            
            if filters.get('end_time'):
                where_clauses.append("timestamp <= %s")
                params.append(filters['end_time'])
            
            if filters.get('severity'):
                where_clauses.append("severity = %s")
                params.append(filters['severity'])
            
            if filters.get('src_ip'):
                where_clauses.append("src_ip = %s")
                params.append(filters['src_ip'])
            
            if filters.get('dst_ip'):
                where_clauses.append("dst_ip = %s")
                params.append(filters['dst_ip'])
            
            if filters.get('protocol'):
                where_clauses.append("protocol = %s")
                params.append(filters['protocol'])
            
            if filters.get('processed') is not None:
                where_clauses.append("processed = %s")
                params.append(filters['processed'])
            
            if filters.get('sid'):
                where_clauses.append("sid = %s")
                params.append(filters['sid'])
            
            where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"
            
            # 验证排序字段（防止SQL注入）
            allowed_sort_fields = {'timestamp', 'severity', 'src_ip', 'dst_ip', 'alert_id'}
            if sort_by not in allowed_sort_fields:
                sort_by = 'timestamp'
            
            sort_order = 'DESC' if sort_order.upper() == 'DESC' else 'ASC'
            
            # 查询总数
            count_query = f"SELECT COUNT(*) as total FROM snort_alerts WHERE {where_sql}"
            cursor.execute(count_query, params)
            total = cursor.fetchone()['total']
            
            # 查询数据
            offset = (page - 1) * page_size
            data_query = f"""
                SELECT 
                    alert_id, sid, timestamp, src_ip, src_port, dst_ip, dst_port,
                    protocol, severity, payload_preview, matched_content, processed
                FROM snort_alerts
                WHERE {where_sql}
                ORDER BY {sort_by} {sort_order}
                LIMIT %s OFFSET %s
            """
            cursor.execute(data_query, params + [page_size, offset])
            alerts = cursor.fetchall()
            
            # 格式化时间
            for alert in alerts:
                if alert['timestamp']:
                    alert['timestamp'] = alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            
            return total, alerts
            
        except Exception as e:
            print(f"[ERROR] get_alerts_with_filters failed: {e}")
            return 0, []
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_alert_by_id_with_rule(self, alert_id: int) -> Optional[Dict]:
        """获取告警详情（包含规则完整信息）"""
        conn = None
        cursor = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            query = """
                SELECT 
                    alert_id, sid, timestamp, src_ip, src_port, dst_ip, dst_port,
                    protocol, severity, payload_preview, matched_content, processed
                FROM snort_alerts
                WHERE alert_id = %s
            """
            
            cursor.execute(query, (alert_id,))
            alert = cursor.fetchone()
            
            if alert and alert['timestamp']:
                alert['timestamp'] = alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            
            return alert
            
        except Exception as e:
            print(f"[ERROR] get_alert_by_id_with_rule failed: {e}")
            return None
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def batch_update_processed(self, alert_ids: List[int], processed: int = 1) -> int:
        """批量更新告警处理状态
        
        Returns:
            更新的记录数
        """
        if not alert_ids:
            return 0
        
        conn = None
        cursor = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            placeholders = ','.join(['%s'] * len(alert_ids))
            query = f"""
                UPDATE snort_alerts 
                SET processed = %s 
                WHERE alert_id IN ({placeholders})
            """
            
            cursor.execute(query, [processed] + alert_ids)
            conn.commit()
            
            return cursor.rowcount
            
        except Exception as e:
            print(f"[ERROR] batch_update_processed failed: {e}")
            if conn:
                conn.rollback()
            return 0
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_alerts_by_src_ip(self, src_ip: str, start_time: datetime = None,
                             end_time: datetime = None, limit: int = 100) -> List[Dict]:
        """按源IP聚合查询所有告警"""
        conn = None
        cursor = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            where_clauses = ["src_ip = %s"]
            params = [src_ip]
            
            if start_time:
                where_clauses.append("timestamp >= %s")
                params.append(start_time)
            
            if end_time:
                where_clauses.append("timestamp <= %s")
                params.append(end_time)
            
            where_sql = " AND ".join(where_clauses)
            
            query = f"""
                SELECT 
                    alert_id, sid, timestamp, dst_ip, dst_port, protocol,
                    severity, matched_content, processed
                FROM snort_alerts
                WHERE {where_sql}
                ORDER BY timestamp DESC
                LIMIT %s
            """
            
            cursor.execute(query, params + [limit])
            alerts = cursor.fetchall()
            
            for alert in alerts:
                if alert['timestamp']:
                    alert['timestamp'] = alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            
            return alerts
            
        except Exception as e:
            print(f"[ERROR] get_alerts_by_src_ip failed: {e}")
            return []
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_conversation_alerts(self, src_ip: str, dst_ip: str,
                                start_time: datetime = None, 
                                end_time: datetime = None) -> List[Dict]:
        """查询两个IP之间的所有告警"""
        conn = None
        cursor = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            where_clauses = ["src_ip = %s", "dst_ip = %s"]
            params = [src_ip, dst_ip]
            
            if start_time:
                where_clauses.append("timestamp >= %s")
                params.append(start_time)
            
            if end_time:
                where_clauses.append("timestamp <= %s")
                params.append(end_time)
            
            where_sql = " AND ".join(where_clauses)
            
            query = f"""
                SELECT 
                    alert_id, sid, timestamp, src_port, dst_port, protocol,
                    severity, matched_content, processed
                FROM snort_alerts
                WHERE {where_sql}
                ORDER BY timestamp
            """
            
            cursor.execute(query, params)
            alerts = cursor.fetchall()
            
            for alert in alerts:
                if alert['timestamp']:
                    alert['timestamp'] = alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            
            return alerts
            
        except Exception as e:
            print(f"[ERROR] get_conversation_alerts failed: {e}")
            return []
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_asset_context(self, dst_ip: str) -> Dict:
        """获取资产上下文统计信息"""
        conn = None
        cursor = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            query = """
                SELECT 
                    COUNT(*) as total_alerts,
                    MAX(severity) as max_severity,
                    MIN(timestamp) as first_alert,
                    MAX(timestamp) as last_alert,
                    COUNT(DISTINCT src_ip) as unique_attackers,
                    COUNT(DISTINCT sid) as unique_rules
                FROM snort_alerts
                WHERE dst_ip = %s
            """
            
            cursor.execute(query, (dst_ip,))
            result = cursor.fetchone()
            
            if result:
                if result['first_alert']:
                    result['first_alert'] = result['first_alert'].strftime('%Y-%m-%d %H:%M:%S')
                if result['last_alert']:
                    result['last_alert'] = result['last_alert'].strftime('%Y-%m-%d %H:%M:%S')
            
            return result or {}
            
        except Exception as e:
            print(f"[ERROR] get_asset_context failed: {e}")
            return {}
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_attacker_summary(self, dst_ip: str, limit: int = 10) -> List[Dict]:
        """获取攻击某资产的所有源IP汇总"""
        conn = None
        cursor = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            query = """
                SELECT 
                    src_ip,
                    COUNT(*) as alert_count,
                    SUM(CASE WHEN severity = 1 THEN 1 ELSE 0 END) as high_count,
                    MAX(timestamp) as last_alert
                FROM snort_alerts
                WHERE dst_ip = %s
                GROUP BY src_ip
                ORDER BY alert_count DESC
                LIMIT %s
            """
            
            cursor.execute(query, (dst_ip, limit))
            results = cursor.fetchall()
            
            for result in results:
                if result['last_alert']:
                    result['last_alert'] = result['last_alert'].strftime('%Y-%m-%d %H:%M:%S')
            
            return results
            
        except Exception as e:
            print(f"[ERROR] get_attacker_summary failed: {e}")
            return []
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_asset_timeline(self, dst_ip: str, days: int = 7) -> List[Dict]:
        """获取资产的告警时间线"""
        conn = None
        cursor = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            query = """
                SELECT 
                    DATE(timestamp) as date,
                    COUNT(*) as count,
                    SUM(CASE WHEN severity = 1 THEN 1 ELSE 0 END) as high_count
                FROM snort_alerts
                WHERE dst_ip = %s AND timestamp >= DATE_SUB(NOW(), INTERVAL %s DAY)
                GROUP BY DATE(timestamp)
                ORDER BY date
            """
            
            cursor.execute(query, (dst_ip, days))
            results = cursor.fetchall()
            
            # 格式化日期
            for result in results:
                if result['date']:
                    result['date'] = result['date'].strftime('%Y-%m-%d')
            
            return results
            
        except Exception as e:
            print(f"[ERROR] get_asset_timeline failed: {e}")
            return []
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_all_assets(self, severity_threshold: int = None, 
                       has_unprocessed: bool = None,
                       sort_by: str = 'total_alerts', 
                       limit: int = 50) -> List[Dict]:
        """获取所有受监控资产列表"""
        conn = None
        cursor = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            # 构建HAVING条件
            having_clauses = []
            params = []
            
            if severity_threshold:
                having_clauses.append("max_severity <= %s")
                params.append(severity_threshold)
            
            if has_unprocessed:
                having_clauses.append("unprocessed_count > 0")
            
            having_sql = " AND ".join(having_clauses) if having_clauses else ""
            having_sql = f"HAVING {having_sql}" if having_sql else ""
            
            # 验证排序字段
            allowed_sort = {'total_alerts', 'max_severity', 'last_alert', 'unprocessed_count'}
            if sort_by not in allowed_sort:
                sort_by = 'total_alerts'
            
            query = f"""
                SELECT 
                    dst_ip,
                    COUNT(*) as total_alerts,
                    MAX(severity) as max_severity,
                    MAX(timestamp) as last_alert,
                    SUM(CASE WHEN processed = 0 THEN 1 ELSE 0 END) as unprocessed_count
                FROM snort_alerts
                GROUP BY dst_ip
                {having_sql}
                ORDER BY {sort_by} DESC
                LIMIT %s
            """
            
            cursor.execute(query, params + [limit])
            results = cursor.fetchall()
            
            for result in results:
                if result['last_alert']:
                    result['last_alert'] = result['last_alert'].strftime('%Y-%m-%d %H:%M:%S')
                # 转换severity为等级名称
                if result['max_severity'] == 1:
                    result['max_severity_level'] = '高'
                elif result['max_severity'] == 2:
                    result['max_severity_level'] = '中'
                elif result['max_severity'] == 3:
                    result['max_severity_level'] = '低'
            
            return results
            
        except Exception as e:
            print(f"[ERROR] get_all_assets failed: {e}")
            return []
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_asset_risk_score(self, dst_ip: str) -> float:
        """计算资产风险分数（0-100）"""
        conn = None
        cursor = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            query = """
                SELECT 
                    COUNT(*) as total_alerts,
                    SUM(CASE WHEN severity = 1 THEN 1 ELSE 0 END) as high_count,
                    SUM(CASE WHEN severity = 2 THEN 1 ELSE 0 END) as medium_count,
                    COUNT(DISTINCT src_ip) as unique_attackers,
                    DATEDIFF(NOW(), MAX(timestamp)) as days_since_last_alert
                FROM snort_alerts
                WHERE dst_ip = %s
            """
            
            cursor.execute(query, (dst_ip,))
            stats = cursor.fetchone()
            
            if not stats or stats['total_alerts'] == 0:
                return 0.0
            
            # 风险评分算法
            # 基础分：告警数量贡献（最多30分）
            alert_score = min(30, stats['total_alerts'] / 10)
            
            # 严重程度贡献（高：每高严重度+0.5分，最多30分）
            severity_score = min(30, stats['high_count'] * 0.5 + stats['medium_count'] * 0.2)
            
            # 攻击源多样性贡献（每个独特源+2分，最多20分）
            attacker_score = min(20, stats['unique_attackers'] * 2)
            
            # 新鲜度贡献（最近告警越近分数越高，最多20分）
            days_since = stats['days_since_last_alert'] or 999
            freshness_score = max(0, 20 - days_since)
            
            total_score = alert_score + severity_score + attacker_score + freshness_score
            return min(100, total_score)
            
        except Exception as e:
            print(f"[ERROR] get_asset_risk_score failed: {e}")
            return 0.0
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_asset_alert_trend(self, dst_ip: str, days: int = 7) -> List[Dict]:
        """获取单个资产的告警趋势"""
        return self.get_asset_timeline(dst_ip, days)
    
    def get_attack_sources_for_asset(self, dst_ip: str, limit: int = 20) -> List[Dict]:
        """获取攻击某资产的所有源IP详情"""
        return self.get_attacker_summary(dst_ip, limit)
    
    def get_report_summary(self, start_date: date, end_date: date, 
                           group_by: str = 'day') -> Dict:
        """获取报表摘要数据"""
        conn = None
        cursor = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            # 根据group_by选择时间格式
            if group_by == 'hour':
                time_format = '%Y-%m-%d %H:00:00'
                time_field = f"DATE_FORMAT(timestamp, '{time_format}')"
            else:  # day
                time_field = "DATE(timestamp)"
            
            query = f"""
                SELECT 
                    COUNT(*) as total_alerts,
                    SUM(CASE WHEN severity = 1 THEN 1 ELSE 0 END) as high_count,
                    SUM(CASE WHEN severity = 2 THEN 1 ELSE 0 END) as medium_count,
                    SUM(CASE WHEN severity = 3 THEN 1 ELSE 0 END) as low_count,
                    COUNT(DISTINCT src_ip) as unique_sources,
                    COUNT(DISTINCT dst_ip) as unique_targets,
                    COUNT(DISTINCT sid) as unique_rules,
                    {time_field} as time_bucket
                FROM snort_alerts
                WHERE DATE(timestamp) >= %s AND DATE(timestamp) <= %s
                GROUP BY time_bucket
                ORDER BY time_bucket
            """
            
            cursor.execute(query, (start_date, end_date))
            trend = cursor.fetchall()
            
            # 格式化结果
            for item in trend:
                if isinstance(item['time_bucket'], datetime):
                    item['time_bucket'] = item['time_bucket'].strftime('%Y-%m-%d %H:%M:%S')
                elif isinstance(item['time_bucket'], date):
                    item['time_bucket'] = item['time_bucket'].strftime('%Y-%m-%d')
            
            # 获取总体统计
            summary_query = """
                SELECT 
                    COUNT(*) as total_alerts,
                    SUM(CASE WHEN severity = 1 THEN 1 ELSE 0 END) as high_count,
                    SUM(CASE WHEN severity = 2 THEN 1 ELSE 0 END) as medium_count,
                    SUM(CASE WHEN severity = 3 THEN 1 ELSE 0 END) as low_count,
                    COUNT(DISTINCT src_ip) as unique_sources,
                    COUNT(DISTINCT dst_ip) as unique_targets,
                    COUNT(DISTINCT sid) as unique_rules
                FROM snort_alerts
                WHERE DATE(timestamp) >= %s AND DATE(timestamp) <= %s
            """
            
            cursor.execute(summary_query, (start_date, end_date))
            summary = cursor.fetchone()
            
            return {
                'summary': summary or {},
                'trend': trend
            }
            
        except Exception as e:
            print(f"[ERROR] get_report_summary failed: {e}")
            return {'summary': {}, 'trend': []}
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_top_sources_report(self, start_date: date, end_date: date, 
                               limit: int = 10) -> List[Dict]:
        """获取TOP攻击源报表"""
        conn = None
        cursor = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            query = """
                SELECT 
                    src_ip,
                    COUNT(*) as alert_count,
                    SUM(CASE WHEN severity = 1 THEN 1 ELSE 0 END) as high_count,
                    SUM(CASE WHEN severity = 2 THEN 1 ELSE 0 END) as medium_count,
                    SUM(CASE WHEN severity = 3 THEN 1 ELSE 0 END) as low_count,
                    COUNT(DISTINCT dst_ip) as target_count,
                    MIN(timestamp) as first_seen,
                    MAX(timestamp) as last_seen
                FROM snort_alerts
                WHERE DATE(timestamp) >= %s AND DATE(timestamp) <= %s
                GROUP BY src_ip
                ORDER BY alert_count DESC
                LIMIT %s
            """
            
            cursor.execute(query, (start_date, end_date, limit))
            results = cursor.fetchall()
            
            for result in results:
                if result['first_seen']:
                    result['first_seen'] = result['first_seen'].strftime('%Y-%m-%d %H:%M:%S')
                if result['last_seen']:
                    result['last_seen'] = result['last_seen'].strftime('%Y-%m-%d %H:%M:%S')
            
            return results
            
        except Exception as e:
            print(f"[ERROR] get_top_sources_report failed: {e}")
            return []
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_top_rules_report(self, start_date: date, end_date: date, 
                             limit: int = 10) -> List[Dict]:
        """获取TOP规则命中报表"""
        conn = None
        cursor = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            query = """
                SELECT 
                    a.sid,
                    r.msg,
                    r.classtype,
                    r.severity as rule_severity,
                    COUNT(*) as hit_count,
                    COUNT(DISTINCT a.src_ip) as unique_sources,
                    COUNT(DISTINCT a.dst_ip) as unique_targets
                FROM snort_alerts a
                INNER JOIN snort_rules r ON a.sid = r.sid
                WHERE DATE(a.timestamp) >= %s AND DATE(a.timestamp) <= %s
                AND a.sid != 0
                GROUP BY a.sid, r.msg, r.classtype, r.severity
                ORDER BY hit_count DESC
                LIMIT %s
            """
            
            cursor.execute(query, (start_date, end_date, limit))
            return cursor.fetchall()
            
        except Exception as e:
            print(f"[ERROR] get_top_rules_report failed: {e}")
            return []
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_classtype_breakdown(self, start_date: date, end_date: date) -> List[Dict]:
        """获取告警的分类分布（用于报表）"""
        conn = None
        cursor = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            query = """
                SELECT 
                    r.classtype,
                    COUNT(*) as count,
                    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER(), 2) as percentage
                FROM snort_alerts a
                INNER JOIN snort_rules r ON a.sid = r.sid
                WHERE DATE(a.timestamp) >= %s AND DATE(a.timestamp) <= %s
                AND a.sid != 0 AND r.classtype IS NOT NULL
                GROUP BY r.classtype
                ORDER BY count DESC
            """
            
            cursor.execute(query, (start_date, end_date))
            return cursor.fetchall()
            
        except Exception as e:
            print(f"[ERROR] get_classtype_breakdown failed: {e}")
            return []
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    def get_filter_options(self) -> Dict:
        """获取所有筛选器选项（动态生成前端下拉框）"""
        conn = None
        cursor = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            # 获取协议选项
            cursor.execute("""
                SELECT DISTINCT protocol, COUNT(*) as count 
                FROM snort_alerts 
                GROUP BY protocol
            """)
            protocols = cursor.fetchall()
            
            # 获取严重程度选项
            cursor.execute("""
                SELECT 
                    severity,
                    CASE severity
                        WHEN 1 THEN '高'
                        WHEN 2 THEN '中'
                        WHEN 3 THEN '低'
                    END as label,
                    COUNT(*) as count
                FROM snort_alerts
                GROUP BY severity
                ORDER BY severity
            """)
            severities = cursor.fetchall()
            
            # 获取处理状态选项
            cursor.execute("""
                SELECT 
                    processed,
                    CASE processed
                        WHEN 0 THEN '未处理'
                        WHEN 1 THEN '已处理'
                    END as label,
                    COUNT(*) as count
                FROM snort_alerts
                GROUP BY processed
            """)
            processed_status = cursor.fetchall()
            
            # 获取规则分类选项
            cursor.execute("""
                SELECT DISTINCT classtype, COUNT(*) as count
                FROM snort_rules
                WHERE classtype IS NOT NULL
                GROUP BY classtype
                ORDER BY classtype
            """)
            classtypes = cursor.fetchall()
            
            return {
                'protocols': protocols,
                'severities': severities,
                'processed_status': processed_status,
                'classtypes': classtypes
            }
            
        except Exception as e:
            print(f"[ERROR] get_filter_options failed: {e}")
            return {}
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()