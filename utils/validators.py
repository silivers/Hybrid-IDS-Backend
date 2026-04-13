# utils/validators.py
"""
数据校验工具模块
提供IP、端口、协议等数据验证功能
"""
import re
import ipaddress
from typing import Tuple, Optional


class Validators:
    """数据校验工具类"""
    
    # 常见协议列表
    COMMON_PROTOCOLS = {'tcp', 'udp', 'icmp', 'ip', 'arp', 'igmp'}
    
    # 端口范围
    PORT_MIN = 0
    PORT_MAX = 65535
    
    @classmethod
    def validate_ip(cls, ip: str) -> bool:
        """
        验证IP地址是否有效
        
        Args:
            ip: IP地址字符串
            
        Returns:
            是否有效
        """
        if not ip or not isinstance(ip, str):
            return False
        
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @classmethod
    def validate_port(cls, port: int) -> bool:
        """
        验证端口号是否有效
        
        Args:
            port: 端口号
            
        Returns:
            是否有效
        """
        if not isinstance(port, int):
            try:
                port = int(port)
            except (ValueError, TypeError):
                return False
        
        return cls.PORT_MIN <= port <= cls.PORT_MAX
    
    @classmethod
    def validate_protocol(cls, protocol: str) -> bool:
        """
        验证协议是否有效
        
        Args:
            protocol: 协议名称
            
        Returns:
            是否有效
        """
        if not protocol or not isinstance(protocol, str):
            return False
        
        return protocol.lower() in cls.COMMON_PROTOCOLS
    
    @classmethod
    def validate_payload(cls, payload: bytes, max_size: int = 65535) -> bool:
        """
        验证payload是否有效
        
        Args:
            payload: 数据负载
            max_size: 最大大小
            
        Returns:
            是否有效
        """
        if payload is None:
            return False
        
        if not isinstance(payload, bytes):
            try:
                payload = bytes(payload)
            except Exception:
                return False
        
        return 0 <= len(payload) <= max_size
    
    @classmethod
    def normalize_ip(cls, ip: str) -> Optional[str]:
        """
        标准化IP地址格式
        
        Args:
            ip: IP地址字符串
            
        Returns:
            标准化后的IP地址，无效则返回None
        """
        if not cls.validate_ip(ip):
            return None
        
        try:
            return str(ipaddress.ip_address(ip))
        except ValueError:
            return None
    
    @classmethod
    def normalize_protocol(cls, protocol: str) -> Optional[str]:
        """
        标准化协议名称
        
        Args:
            protocol: 协议名称
            
        Returns:
            标准化后的协议名称，无效则返回None
        """
        if not protocol:
            return None
        
        protocol_lower = protocol.lower()
        
        # 协议名称映射
        protocol_map = {
            'tcp': 'tcp',
            'udp': 'udp',
            'icmp': 'icmp',
            'ip': 'ip',
            'ipv4': 'ip',
            'ipv6': 'ip',
            'arp': 'arp',
            'igmp': 'igmp',
        }
        
        return protocol_map.get(protocol_lower, None)
    
    @classmethod
    def is_private_ip(cls, ip: str) -> bool:
        """
        检查是否为私有IP地址
        
        Args:
            ip: IP地址字符串
            
        Returns:
            是否为私有IP
        """
        if not cls.validate_ip(ip):
            return False
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False
    
    @classmethod
    def is_multicast_ip(cls, ip: str) -> bool:
        """
        检查是否为组播IP地址
        
        Args:
            ip: IP地址字符串
            
        Returns:
            是否为组播IP
        """
        if not cls.validate_ip(ip):
            return False
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_multicast
        except ValueError:
            return False
    
    @classmethod
    def extract_ports_from_string(cls, port_str: str) -> list:
        """
        从端口字符串中提取端口列表
        支持格式: "80", "80,443", "80-90", "[80,443,8080]"
        
        Args:
            port_str: 端口字符串
            
        Returns:
            端口列表
        """
        if not port_str or not isinstance(port_str, str):
            return []
        
        ports = []
        
        # 处理 [port1,port2] 格式
        if port_str.startswith('[') and port_str.endswith(']'):
            port_str = port_str[1:-1]
        
        # 分割逗号
        for part in port_str.split(','):
            part = part.strip()
            if not part:
                continue
            
            # 处理范围 80-90
            if '-' in part:
                try:
                    start, end = part.split('-')
                    start = int(start)
                    end = int(end)
                    ports.extend(range(start, end + 1))
                except ValueError:
                    pass
            else:
                try:
                    ports.append(int(part))
                except ValueError:
                    pass
        
        # 去重并排序
        ports = sorted(set(ports))
        
        # 过滤有效端口
        ports = [p for p in ports if cls.validate_port(p)]
        
        return ports
    
    @classmethod
    def is_safe_string(cls, s: str, max_length: int = 1000) -> bool:
        """
        检查字符串是否安全（不包含危险字符）
        
        Args:
            s: 待检查的字符串
            max_length: 最大长度
            
        Returns:
            是否安全
        """
        if not s or not isinstance(s, str):
            return False
        
        if len(s) > max_length:
            return False
        
        # 危险字符检查（可根据需要扩展）
        dangerous_chars = ['\x00', '\n', '\r', '\t', '\b']
        for char in dangerous_chars:
            if char in s:
                return False
        
        return True


# 便捷函数
validate_ip = Validators.validate_ip
validate_port = Validators.validate_port
validate_protocol = Validators.validate_protocol
is_private_ip = Validators.is_private_ip
normalize_ip = Validators.normalize_ip