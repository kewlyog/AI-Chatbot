import os
from datetime import datetime, timedelta
import hashlib
import secrets

class SecurityConfig:
    # Rate limiting configuration
    RATE_LIMITS = {
        'chat_per_minute': 10,
        'chat_per_hour': 20,
        'chat_per_day': 30,
        'global_per_minute': 50,
        'global_per_hour': 100
    }
    
    # Content filtering
    FORBIDDEN_PATTERNS = [
        # SQL Injection patterns
        r'(?i)(union|select|insert|update|delete|drop|create|alter)\s+',
        r'(?i)(or|and)\s+\d+\s*=\s*\d+',
        r'(?i)(union|select).*from',
        
        # XSS patterns
        r'(?i)<script[^>]*>',
        r'(?i)javascript:',
        r'(?i)on\w+\s*=',
        r'(?i)<iframe[^>]*>',
        r'(?i)<object[^>]*>',
        r'(?i)<embed[^>]*>',
        
        # Command injection
        r'(?i)(exec|eval|system|shell|subprocess)',
        r'(?i)(cmd|command|powershell)',
        
        # File operations
        r'(?i)(file://|ftp://|http://|https://)',
        r'(?i)(\.\./|\.\.\\)',
        
        # Sensitive data patterns
        r'(?i)(password|api[_-]?key|token|secret|private[_-]?key)',
        r'(?i)(credit[_-]?card|ssn|social[_-]?security)',
        
        # Malicious patterns
        r'(?i)(virus|malware|trojan|backdoor)',
        r'(?i)(hack|crack|exploit|vulnerability)',
    ]
    
    # Message validation rules
    MESSAGE_RULES = {
        'max_length': 500,
        'min_length': 1,
        'allowed_chars': r'^[a-zA-Z0-9\s\.,!?@#$%^&*()_+\-=\[\]{}|;:"\'<>\/\\]+$',
        'max_words': 100,
        'forbidden_words': [
            'spam', 'advertisement', 'promote', 'buy now', 'click here',
            'free money', 'lottery', 'winner', 'urgent', 'limited time'
        ]
    }
    
    # Session security
    SESSION_CONFIG = {
        'max_age': timedelta(hours=1),
        'secure': True,
        'httponly': True,
        'samesite': 'Strict'
    }
    
    # API security
    API_CONFIG = {
        'max_tokens': 150,
        'temperature': 0.7,
        'timeout': 30,
        'retry_attempts': 3
    }
    
    @staticmethod
    def generate_request_id():
        """Generate a unique request ID for tracking."""
        return hashlib.sha256(
            f"{datetime.now().isoformat()}{secrets.token_hex(8)}".encode()
        ).hexdigest()[:16]
    
    @staticmethod
    def sanitize_input(text):
        """Sanitize user input to prevent XSS."""
        if not text:
            return ""
        
        # Remove HTML tags
        import re
        text = re.sub(r'<[^>]+>', '', text)
        
        # Escape special characters
        text = text.replace('&', '&amp;')
        text = text.replace('<', '&lt;')
        text = text.replace('>', '&gt;')
        text = text.replace('"', '&quot;')
        text = text.replace("'", '&#x27;')
        
        return text.strip()
    
    @staticmethod
    def validate_ip(ip_address):
        """Validate and sanitize IP address."""
        import re
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return bool(re.match(ip_pattern, ip_address)) 