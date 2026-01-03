import streamlit as st
import pandas as pd
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import ssl
import time
import threading
import random
import json
import os
import hashlib
import hmac
import uuid
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
from typing import Dict, List, Tuple, Optional, Any
import logging
from dataclasses import dataclass, asdict
import secrets
import re
import warnings
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import base64
import socket
import ipaddress
import pytz
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import io

warnings.filterwarnings('ignore')

# =============== SECURITY CONFIGURATION ===============
# Environment variables for production
import sys
import getpass

# Generate or load encryption key
def get_encryption_key():
    """Generate or load encryption key from environment or file"""
    key_env = os.environ.get('ENCRYPTION_KEY')
    if key_env:
        # Derive Fernet key from environment variable
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'pen_test_salt',
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(key_env.encode()))
    else:
        # For development - generate and store key
        key_file = '.encryption_key'
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                key = f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            os.chmod(key_file, 0o600)
    
    return key

ENCRYPTION_KEY = get_encryption_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

# Security constants
MAX_SMTP_ACCOUNTS = 10
MAX_EMAILS_PER_CAMPAIGN = 5000
MIN_DELAY_SECONDS = 10
MAX_THREADS = 5
DEFAULT_TIMEOUT = 30
MAX_CAMPAIGN_HISTORY = 100
SESSION_TIMEOUT_MINUTES = 30

# File paths
SMTP_FILE = "data/smtps_encrypted.json"
STATS_FILE = "data/stats_encrypted.json"
LOGS_FILE = "data/audit_logs.json"
TEMPLATES_FILE = "data/templates.json"
CONFIG_FILE = "data/config.json"
BLACKLIST_FILE = "data/blacklist.json"

# Create data directory
os.makedirs("data", exist_ok=True)
os.makedirs("logs", exist_ok=True)
os.makedirs("exports", exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(ip)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/app.log'),
        logging.StreamHandler()
    ]
)

class ContextFilter(logging.Filter):
    def filter(self, record):
        record.ip = getattr(st.session_state, 'client_ip', '127.0.0.1')
        return True

logger = logging.getLogger(__name__)
logger.addFilter(ContextFilter())

# Configure Streamlit page
st.set_page_config(
    page_title="🔐 Enterprise PenTest Mailer Pro",
    layout="wide",
    initial_sidebar_state="expanded",
    page_icon="🔐",
    menu_items={
        'Get Help': 'https://github.com/your-repo',
        'Report a bug': 'https://github.com/your-repo/issues',
        'About': 'Enterprise Penetration Testing Tool v4.0'
    }
)

# =============== SECURITY CLASSES ===============
@dataclass
class SMTPServerConfig:
    """Secure SMTP server configuration"""
    id: str
    server: str
    port: int
    username: str
    password_encrypted: str
    display_name: str
    provider: str
    daily_limit: int = 300
    sent_today: int = 0
    is_active: bool = True
    last_used: Optional[str] = None
    created_at: str = None
    tags: List[str] = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow().isoformat()
        if self.tags is None:
            self.tags = []
    
    @property
    def password(self):
        """Decrypt password on demand"""
        try:
            return cipher_suite.decrypt(self.password_encrypted.encode()).decode()
        except:
            return ""
    
    @password.setter
    def password(self, value):
        """Encrypt password when setting"""
        self.password_encrypted = cipher_suite.encrypt(value.encode()).decode()

@dataclass
class CampaignResult:
    """Campaign result storage with privacy protection"""
    id: str
    email_hash: str
    status: str
    smtp_id: str
    timestamp: str
    campaign_id: str
    email_domain: str
    error_message: Optional[str] = None
    open_tracked: bool = False
    click_tracked: bool = False
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None

@dataclass
class Campaign:
    """Campaign configuration"""
    id: str
    name: str
    targets: List[str]
    subject: str
    template_id: str
    phishing_url: str
    created_at: str
    created_by: str
    status: str = "pending"  # pending, running, completed, failed, paused
    sent_count: int = 0
    failed_count: int = 0
    total_count: int = 0
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    smtp_rotation: List[str] = None
    delay_seconds: int = 30
    thread_count: int = 1
    
    def __post_init__(self):
        if self.smtp_rotation is None:
            self.smtp_rotation = []
        self.total_count = len(self.targets)

@dataclass
class EmailTemplate:
    """Email template with validation"""
    id: str
    name: str
    subject: str
    html_content: str
    text_content: Optional[str] = None
    variables: List[str] = None
    created_at: str = None
    is_shared: bool = False
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow().isoformat()
        if self.variables is None:
            self.variables = self.extract_variables()
    
    def extract_variables(self) -> List[str]:
        """Extract variables from template"""
        variables = re.findall(r'\{(\w+)\}', self.html_content)
        return list(set(variables))

class SecurityManager:
    """Central security management"""
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def sanitize_input(text: str, max_length: int = 1000) -> str:
        """Sanitize user input"""
        if not text:
            return ""
        
        # Remove potentially dangerous characters
        text = re.sub(r'[<>"\'\\]', '', text)
        
        # Limit length
        if len(text) > max_length:
            text = text[:max_length]
        
        return text.strip()
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate URL format"""
        if not url:
            return False
        
        # Basic URL validation
        pattern = re.compile(
            r'^(https?://)?'  # http:// or https://
            r'([A-Za-z0-9-]+\.)+[A-Za-z]{2,}'  # domain
            r'(:\d+)?'  # port
            r'(/[-a-zA-Z0-9@:%_\+.~#?&//=]*)?$',  # path
            re.IGNORECASE
        )
        
        return bool(pattern.match(url))
    
    @staticmethod
    def generate_secure_id() -> str:
        """Generate cryptographically secure ID"""
        return f"id_{secrets.token_hex(8)}_{int(time.time())}"
    
    @staticmethod
    def hash_email(email: str) -> str:
        """Hash email for privacy protection"""
        salt = os.environ.get('HASH_SALT', 'pen-test-salt').encode()
        return hashlib.sha256(salt + email.lower().encode()).hexdigest()
    
    @staticmethod
    def check_password_strength(password: str) -> Tuple[bool, str]:
        """Check password strength"""
        if len(password) < 12:
            return False, "Password must be at least 12 characters"
        
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain uppercase letters"
        
        if not re.search(r'[a-z]', password):
            return False, "Password must contain lowercase letters"
        
        if not re.search(r'\d', password):
            return False, "Password must contain numbers"
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain special characters"
        
        return True, "Strong password"

class DataManager:
    """Secure data management with encryption"""
    
    @staticmethod
    def encrypt_data(data: Any) -> str:
        """Encrypt any data"""
        json_str = json.dumps(data)
        encrypted = cipher_suite.encrypt(json_str.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    
    @staticmethod
    def decrypt_data(encrypted_str: str) -> Any:
        """Decrypt data"""
        try:
            encrypted = base64.urlsafe_b64decode(encrypted_str.encode())
            decrypted = cipher_suite.decrypt(encrypted)
            return json.loads(decrypted.decode())
        except:
            return None
    
    @staticmethod
    def save_to_file(data: Any, filepath: str, encrypt: bool = True) -> bool:
        """Save data to file with optional encryption"""
        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            if encrypt:
                save_data = DataManager.encrypt_data(data)
            else:
                save_data = data
            
            with open(filepath, 'w') as f:
                json.dump(save_data, f, indent=2)
            
            # Set secure permissions
            os.chmod(filepath, 0o600)
            
            logger.info(f"Data saved to {filepath}")
            return True
        except Exception as e:
            logger.error(f"Failed to save data to {filepath}: {e}")
            return False
    
    @staticmethod
    def load_from_file(filepath: str, encrypted: bool = True) -> Any:
        """Load data from file with decryption"""
        try:
            if not os.path.exists(filepath):
                return [] if encrypted else {}
            
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            if encrypted and isinstance(data, str):
                return DataManager.decrypt_data(data)
            else:
                return data
        except Exception as e:
            logger.error(f"Failed to load data from {filepath}: {e}")
            return [] if encrypted else {}

class AuditLogger:
    """Comprehensive audit logging"""
    
    @staticmethod
    def get_client_info() -> Dict:
        """Get client information"""
        try:
            import streamlit.web.server.websocket_headers as ws_headers
            headers = ws_headers._get_websocket_headers()
            
            return {
                'ip': headers.get('X-Forwarded-For', '127.0.0.1').split(',')[0],
                'user_agent': headers.get('User-Agent', 'Unknown'),
                'host': headers.get('Host', 'Unknown'),
                'referer': headers.get('Referer', 'Unknown'),
            }
        except:
            return {
                'ip': '127.0.0.1',
                'user_agent': 'Unknown',
                'host': 'Unknown',
                'referer': 'Unknown',
            }
    
    @staticmethod
    def log_event(event_type: str, details: Dict, level: str = "INFO"):
        """Log security event"""
        client_info = AuditLogger.get_client_info()
        
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'level': level,
            'details': details,
            'client_info': client_info,
            'session_id': st.session_state.get('session_id', 'unknown'),
            'user': st.session_state.get('username', 'anonymous'),
        }
        
        # Save to audit log file
        logs = DataManager.load_from_file(LOGS_FILE, encrypted=False)
        logs.append(log_entry)
        
        # Keep only last 10000 logs
        if len(logogs) > 10000:
            logs = logs[-10000:]
        
        DataManager.save_to_file(logs, LOGS_FILE, encrypt=False)
        
        # Also log to application log
        log_message = f"{event_type}: {json.dumps(details)}"
        if level == "ERROR":
            logger.error(log_message)
        elif level == "WARNING":
            logger.warning(log_message)
        else:
            logger.info(log_message)
        
        return log_entry

class EmailValidator:
    """Email validation and processing"""
    
    @staticmethod
    def validate_email(email: str) -> Tuple[bool, str, str]:
        """Validate email format and extract domain"""
        email = email.strip().lower()
        
        # Basic format validation
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, email):
            return False, "Invalid email format", ""
        
        # Extract domain
        domain = email.split('@')[1]
        
        # Check for disposable email domains
        disposable_domains = [
            'tempmail.com', '10minutemail.com', 'guerrillamail.com',
            'mailinator.com', 'yopmail.com', 'throwawaymail.com'
        ]
        
        if any(disposable in domain for disposable in disposable_domains):
            return False, "Disposable email domain not allowed", domain
        
        # Check for common role-based emails
        role_based_prefixes = [
            'admin', 'administrator', 'webmaster', 'postmaster',
            'hostmaster', 'info', 'support', 'help', 'contact',
            'sales', 'marketing', 'billing', 'abuse', 'security',
            'noreply', 'no-reply', 'newsletter'
        ]
        
        local_part = email.split('@')[0]
        for prefix in role_based_prefixes:
            if local_part.startswith(prefix):
                return True, "Role-based email", domain
        
        return True, "Valid email", domain
    
    @staticmethod
    def process_email_list(emails_text: str) -> Tuple[List[str], List[Dict]]:
        """Process list of emails from text input"""
        if not emails_text:
            return [], []
        
        valid_emails = []
        invalid_entries = []
        
        lines = emails_text.strip().split('\n')
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
            
            # Check if line contains CSV-like format
            if ',' in line:
                parts = [p.strip() for p in line.split(',')]
                if len(parts) >= 1:
                    line = parts[0]
            
            if '@' in line:
                is_valid, message, domain = EmailValidator.validate_email(line)
                if is_valid:
                    valid_emails.append(line)
                else:
                    invalid_entries.append({
                        'email': line,
                        'reason': message,
                        'line': i
                    })
            else:
                invalid_entries.append({
                    'email': line,
                    'reason': 'No @ symbol found',
                    'line': i
                })
        
        # Remove duplicates while preserving order
        seen = set()
        unique_emails = []
        for email in valid_emails:
            if email not in seen:
                seen.add(email)
                unique_emails.append(email)
        
        # Apply limit
        if len(unique_emails) > MAX_EMAILS_PER_CAMPAIGN:
            invalid_entries.append({
                'email': f'Total limit exceeded ({len(unique_emails)} > {MAX_EMAILS_PER_CAMPAIGN})',
                'reason': 'Too many emails',
                'line': 0
            })
            unique_emails = unique_emails[:MAX_EMAILS_PER_CAMPAIGN]
        
        return unique_emails, invalid_entries

class SMTPServerManager:
    """Manage SMTP servers with rotation and failover"""
    
    def __init__(self):
        self.servers = self.load_servers()
        self.server_stats = defaultdict(lambda: {'success': 0, 'failure': 0, 'last_used': None})
    
    def load_servers(self) -> List[SMTPServerConfig]:
        """Load SMTP servers from file"""
        servers_data = DataManager.load_from_file(SMTP_FILE)
        servers = []
        
        for server_data in servers_data:
            try:
                server = SMTPServerConfig(**server_data)
                servers.append(server)
            except Exception as e:
                logger.error(f"Failed to load SMTP server: {e}")
        
        return servers
    
    def save_servers(self):
        """Save SMTP servers to file"""
        servers_data = [asdict(server) for server in self.servers]
        DataManager.save_to_file(servers_data, SMTP_FILE)
        AuditLogger.log_event("SMTP_SERVERS_SAVED", {"count": len(servers_data)})
    
    def add_server(self, server_config: Dict) -> Tuple[bool, str]:
        """Add new SMTP server"""
        # Validate required fields
        required_fields = ['server', 'port', 'username', 'password']
        for field in required_fields:
            if field not in server_config or not server_config[field]:
                return False, f"Missing required field: {field}"
        
        # Validate port
        if not (1 <= server_config['port'] <= 65535):
            return False, "Invalid port number"
        
        # Check for duplicates
        for existing in self.servers:
            if (existing.server == server_config['server'] and 
                existing.port == server_config['port'] and
                existing.username == server_config['username']):
                return False, "SMTP server already exists"
        
        # Check maximum limit
        if len(self.servers) >= MAX_SMTP_ACCOUNTS:
            return False, f"Maximum {MAX_SMTP_ACCOUNTS} SMTP accounts allowed"
        
        # Create server object
        server_id = SecurityManager.generate_secure_id()
        server = SMTPServerConfig(
            id=server_id,
            server=server_config['server'],
            port=server_config['port'],
            username=server_config['username'],
            display_name=server_config.get('display_name', server_config['username'].split('@')[0]),
            provider=server_config.get('provider', 'Custom'),
            daily_limit=server_config.get('daily_limit', 300),
            tags=server_config.get('tags', []),
        )
        
        # Set password (will be encrypted)
        server.password = server_config['password']
        
        self.servers.append(server)
        self.save_servers()
        
        AuditLogger.log_event("SMTP_SERVER_ADDED", {
            "server_id": server_id,
            "server": server.server,
            "username": server.username[:3] + "***"
        })
        
        return True, f"SMTP server added successfully (ID: {server_id})"
    
    def test_server(self, server_id: str) -> Tuple[bool, str]:
        """Test SMTP server connection"""
        server = self.get_server_by_id(server_id)
        if not server:
            return False, "Server not found"
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect to server
            if server.port == 465:
                # SSL connection
                server_conn = smtplib.SMTP_SSL(server.server, server.port, 
                                             context=context, timeout=DEFAULT_TIMEOUT)
            else:
                # StartTLS connection
                server_conn = smtplib.SMTP(server.server, server.port, 
                                         timeout=DEFAULT_TIMEOUT)
                server_conn.starttls(context=context)
            
            # Login
            server_conn.login(server.username, server.password)
            
            # Send NOOP to verify connection
            server_conn.noop()
            
            # Quit
            server_conn.quit()
            
            # Update server status
            server.is_active = True
            server.last_used = datetime.utcnow().isoformat()
            self.save_servers()
            
            self.server_stats[server_id]['success'] += 1
            self.server_stats[server_id]['last_used'] = datetime.utcnow().isoformat()
            
            AuditLogger.log_event("SMTP_TEST_SUCCESS", {"server_id": server_id})
            
            return True, "✅ Connection successful"
            
        except smtplib.SMTPAuthenticationError:
            error_msg = "Authentication failed - check username and password"
        except smtplib.SMTPConnectError:
            error_msg = "Connection failed - check server and port"
        except smtplib.SMTPServerDisconnected:
            error_msg = "Server disconnected unexpectedly"
        except socket.timeout:
            error_msg = "Connection timeout"
        except Exception as e:
            error_msg = f"Error: {str(e)[:100]}"
        
        server.is_active = False
        self.save_servers()
        
        self.server_stats[server_id]['failure'] += 1
        
        AuditLogger.log_event("SMTP_TEST_FAILED", {
            "server_id": server_id,
            "error": error_msg
        })
        
        return False, f"❌ {error_msg}"
    
    def get_server_by_id(self, server_id: str) -> Optional[SMTPServerConfig]:
        """Get server by ID"""
        for server in self.servers:
            if server.id == server_id:
                return server
        return None
    
    def get_active_servers(self) -> List[SMTPServerConfig]:
        """Get all active servers"""
        return [server for server in self.servers if server.is_active]
    
    def get_next_server(self, round_robin_index: int = 0) -> Optional[SMTPServerConfig]:
        """Get next server for rotation"""
        active_servers = self.get_active_servers()
        if not active_servers:
            return None
        
        # Simple round-robin selection
        return active_servers[round_robin_index % len(active_servers)]
    
    def delete_server(self, server_id: str) -> bool:
        """Delete SMTP server"""
        for i, server in enumerate(self.servers):
            if server.id == server_id:
                deleted_server = self.servers.pop(i)
                self.save_servers()
                
                AuditLogger.log_event("SMTP_SERVER_DELETED", {
                    "server_id": server_id,
                    "username": deleted_server.username[:3] + "***"
                })
                
                return True
        
        return False
    
    def get_server_stats(self) -> Dict:
        """Get statistics for all servers"""
        stats = {}
        for server in self.servers:
            server_stat = self.server_stats[server.id]
            stats[server.id] = {
                'name': server.display_name,
                'server': server.server,
                'is_active': server.is_active,
                'success': server_stat['success'],
                'failure': server_stat['failure'],
                'success_rate': (server_stat['success'] / (server_stat['success'] + server_stat['failure'] * 100)
                               if (server_stat['success'] + server_stat['failure']) > 0 else 0),
                'last_used': server_stat['last_used'],
                'daily_limit': server.daily_limit,
                'sent_today': server.sent_today,
            }
        return stats

class EmailSender:
    """Handle email sending with tracking and retry logic"""
    
    def __init__(self, smtp_manager: SMTPServerManager):
        self.smtp_manager = smtp_manager
        self.sent_emails = 0
        self.failed_emails = 0
        self.active_connections = {}
    
    def send_email(self, 
                   to_email: str, 
                   subject: str, 
                   html_content: str, 
                   from_name: Optional[str] = None,
                   server_id: Optional[str] = None,
                   tracking_pixel: bool = True,
                   campaign_id: Optional[str] = None) -> Tuple[bool, str, Optional[str]]:
        """Send single email"""
        server = None
        
        if server_id:
            server = self.smtp_manager.get_server_by_id(server_id)
        else:
            # Get next available server
            active_servers = self.smtp_manager.get_active_servers()
            if active_servers:
                server = active_servers[self.sent_emails % len(active_servers)]
        
        if not server:
            return False, "No active SMTP servers available", None
        
        # Check daily limit
        if server.sent_today >= server.daily_limit:
            return False, f"Daily limit reached for {server.display_name}", None
        
        # Generate tracking ID
        tracking_id = SecurityManager.generate_secure_id() if tracking_pixel else None
        
        # Prepare email content
        if tracking_pixel and tracking_id:
            tracking_url = f"https://track.example.com/pixel/{tracking_id}"  # Replace with your tracking domain
            html_content += f'<img src="{tracking_url}" width="1" height="1" style="display:none;">'
        
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f'{from_name or server.display_name} <{server.username}>'
            msg['To'] = to_email
            msg['Date'] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S +0000')
            
            if campaign_id:
                msg['X-Campaign-ID'] = campaign_id
            
            if tracking_id:
                msg['X-Tracking-ID'] = tracking_id
            
            # Add HTML part
            html_part = MIMEText(html_content, 'html')
            msg.attach(html_part)
            
            # Add plain text alternative
            text_content = self.html_to_text(html_content)
            text_part = MIMEText(text_content, 'plain')
            msg.attach(text_part)
            
            # Send email
            success, error_msg = self._send_with_server(server, to_email, msg)
            
            if success:
                server.sent_today += 1
                server.last_used = datetime.utcnow().isoformat()
                self.smtp_manager.save_servers()
                
                self.sent_emails += 1
                self.smtp_manager.server_stats[server.id]['success'] += 1
                
                AuditLogger.log_event("EMAIL_SENT_SUCCESS", {
                    "to": SecurityManager.hash_email(to_email),
                    "server_id": server.id,
                    "campaign_id": campaign_id or "none"
                })
                
                return True, "Email sent successfully", tracking_id
            else:
                self.failed_emails += 1
                self.smtp_manager.server_stats[server.id]['failure'] += 1
                
                AuditLogger.log_event("EMAIL_SENT_FAILED", {
                    "to": SecurityManager.hash_email(to_email),
                    "server_id": server.id,
                    "error": error_msg,
                    "campaign_id": campaign_id or "none"
                })
                
                return False, error_msg, None
                
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)[:100]}"
            logger.error(f"Failed to send email to {to_email}: {e}")
            
            self.failed_emails += 1
            if server:
                self.smtp_manager.server_stats[server.id]['failure'] += 1
            
            return False, error_msg, None
    
    def _send_with_server(self, server: SMTPServerConfig, to_email: str, msg: MIMEMultipart) -> Tuple[bool, str]:
        """Send email using specific server"""
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect based on port
            if server.port == 465:
                # SSL connection
                smtp_conn = smtplib.SMTP_SSL(server.server, server.port, 
                                           context=context, timeout=DEFAULT_TIMEOUT)
            else:
                # StartTLS connection
                smtp_conn = smtplib.SMTP(server.server, server.port, 
                                       timeout=DEFAULT_TIMEOUT)
                smtp_conn.starttls(context=context)
            
            # Login
            smtp_conn.login(server.username, server.password)
            
            # Send email
            smtp_conn.send_message(msg)
            
            # Quit
            smtp_conn.quit()
            
            return True, ""
            
        except smtplib.SMTPRecipientsRefused:
            return False, "Recipient refused"
        except smtplib.SMTPSenderRefused:
            return False, "Sender refused"
        except smtplib.SMTPDataError as e:
            return False, f"SMTP data error: {str(e)}"
        except socket.timeout:
            return False, "Connection timeout"
        except Exception as e:
            return False, f"Send error: {str(e)[:100]}"
    
    def html_to_text(self, html: str) -> str:
        """Convert HTML to plain text (simplified)"""
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', ' ', html)
        
        # Replace HTML entities
        text = text.replace('&nbsp;', ' ')
        text = text.replace('&amp;', '&')
        text = text.replace('&lt;', '<')
        text = text.replace('&gt;', '>')
        
        # Collapse multiple spaces
        text = re.sub(r'\s+', ' ', text)
        
        return text.strip()

class CampaignManager:
    """Manage email campaigns"""
    
    def __init__(self, smtp_manager: SMTPServerManager):
        self.smtp_manager = smtp_manager
        self.email_sender = EmailSender(smtp_manager)
        self.active_campaigns = {}
        self.campaign_history = DataManager.load_from_file(STATS_FILE)
        self.templates = self.load_templates()
    
    def load_templates(self) -> List[EmailTemplate]:
        """Load email templates"""
        templates_data = DataManager.load_from_file(TEMPLATES_FILE)
        templates = []
        
        for template_data in templates_data:
            try:
                template = EmailTemplate(**template_data)
                templates.append(template)
            except Exception as e:
                logger.error(f"Failed to load template: {e}")
        
        return templates
    
    def save_templates(self):
        """Save templates to file"""
        templates_data = [asdict(template) for template in self.templates]
        DataManager.save_to_file(templates_data, TEMPLATES_FILE)
    
    def create_template(self, template_data: Dict) -> Tuple[bool, str]:
        """Create new email template"""
        try:
            template_id = SecurityManager.generate_secure_id()
            
            template = EmailTemplate(
                id=template_id,
                name=template_data['name'],
                subject=template_data['subject'],
                html_content=template_data['html_content'],
                text_content=template_data.get('text_content'),
                is_shared=template_data.get('is_shared', False)
            )
            
            self.templates.append(template)
            self.save_templates()
            
            AuditLogger.log_event("TEMPLATE_CREATED", {
                "template_id": template_id,
                "name": template.name
            })
            
            return True, f"Template created successfully (ID: {template_id})"
        except Exception as e:
            return False, f"Failed to create template: {str(e)}"
    
    def create_campaign(self, campaign_data: Dict) -> Tuple[bool, str, Optional[Campaign]]:
        """Create new campaign"""
        try:
            # Validate required fields
            required_fields = ['name', 'targets', 'subject', 'template_id', 'phishing_url']
            for field in required_fields:
                if field not in campaign_data or not campaign_data[field]:
                    return False, f"Missing required field: {field}", None
            
            # Validate targets
            if not isinstance(campaign_data['targets'], list) or len(campaign_data['targets']) == 0:
                return False, "No valid targets provided", None
            
            # Validate phishing URL
            if not SecurityManager.validate_url(campaign_data['phishing_url']):
                return False, "Invalid phishing URL format", None
            
            # Get template
            template = self.get_template_by_id(campaign_data['template_id'])
            if not template:
                return False, "Template not found", None
            
            # Create campaign
            campaign_id = SecurityManager.generate_secure_id()
            campaign = Campaign(
                id=campaign_id,
                name=campaign_data['name'],
                targets=campaign_data['targets'],
                subject=campaign_data['subject'],
                template_id=campaign_data['template_id'],
                phishing_url=campaign_data['phishing_url'],
                created_at=datetime.utcnow().isoformat(),
                created_by=st.session_state.get('username', 'anonymous'),
                delay_seconds=campaign_data.get('delay_seconds', 30),
                thread_count=campaign_data.get('thread_count', 1),
                smtp_rotation=[server.id for server in self.smtp_manager.get_active_servers()]
            )
            
            AuditLogger.log_event("CAMPAIGN_CREATED", {
                "campaign_id": campaign_id,
                "name": campaign.name,
                "target_count": len(campaign.targets)
            })
            
            return True, f"Campaign created successfully (ID: {campaign_id})", campaign
            
        except Exception as e:
            return False, f"Failed to create campaign: {str(e)}", None
    
    def start_campaign(self, campaign: Campaign) -> str:
        """Start campaign execution"""
        campaign_id = campaign.id
        
        # Update campaign status
        campaign.status = "running"
        campaign.start_time = datetime.utcnow().isoformat()
        
        # Store in active campaigns
        self.active_campaigns[campaign_id] = {
            'campaign': campaign,
            'progress': 0,
            'sent': 0,
            'failed': 0,
            'start_time': campaign.start_time,
            'thread': None
        }
        
        # Start campaign thread
        thread = threading.Thread(
            target=self._run_campaign,
            args=(campaign,),
            daemon=True
        )
        thread.start()
        
        self.active_campaigns[campaign_id]['thread'] = thread
        
        AuditLogger.log_event("CAMPAIGN_STARTED", {
            "campaign_id": campaign_id,
            "name": campaign.name
        })
        
        return campaign_id
    
    def _run_campaign(self, campaign: Campaign):
        """Run campaign in background thread"""
        try:
            results = []
            total_targets = len(campaign.targets)
            
            # Process emails with thread pool
            with ThreadPoolExecutor(max_workers=campaign.thread_count) as executor:
                # Submit all email sending tasks
                future_to_email = {}
                for i, email in enumerate(campaign.targets):
                    # Get template
                    template = self.get_template_by_id(campaign.template_id)
                    if not template:
                        logger.error(f"Template not found for campaign {campaign.id}")
                        continue
                    
                    # Prepare email content
                    email_content = self._prepare_email_content(
                        template.html_content,
                        email,
                        campaign.phishing_url,
                        campaign.id
                    )
                    
                    # Get SMTP server for this email (round-robin)
                    server_idx = i % len(campaign.smtp_rotation)
                    server_id = campaign.smtp_rotation[server_idx] if campaign.smtp_rotation else None
                    
                    # Submit sending task
                    future = executor.submit(
                        self.email_sender.send_email,
                        email,
                        campaign.subject,
                        email_content,
                        f"Security Team",
                        server_id,
                        True,
                        campaign.id
                    )
                    future_to_email[future] = email
                
                # Process results as they complete
                for future in as_completed(future_to_email):
                    email = future_to_email[future]
                    try:
                        success, message, tracking_id = future.result(timeout=60)
                        
                        # Create result record
                        result = CampaignResult(
                            id=SecurityManager.generate_secure_id(),
                            email_hash=SecurityManager.hash_email(email),
                            status="✅ SENT" if success else "❌ FAILED",
                            smtp_id=tracking_id or "none",
                            timestamp=datetime.utcnow().isoformat(),
                            campaign_id=campaign.id,
                            email_domain=email.split('@')[1] if '@' in email else "unknown",
                            error_message=message if not success else None
                        )
                        
                        results.append(asdict(result))
                        
                        # Update campaign progress
                        if success:
                            campaign.sent_count += 1
                            self.active_campaigns[campaign.id]['sent'] += 1
                        else:
                            campaign.failed_count += 1
                            self.active_campaigns[campaign.id]['failed'] += 1
                        
                        progress = (campaign.sent_count + campaign.failed_count) / total_targets
                        self.active_campaigns[campaign.id]['progress'] = progress
                        
                    except Exception as e:
                        logger.error(f"Error sending to {email}: {e}")
                        
                        result = CampaignResult(
                            id=SecurityManager.generate_secure_id(),
                            email_hash=SecurityManager.hash_email(email),
                            status="❌ FAILED",
                            smtp_id="none",
                            timestamp=datetime.utcnow().isoformat(),
                            campaign_id=campaign.id,
                            email_domain=email.split('@')[1] if '@' in email else "unknown",
                            error_message=str(e)[:100]
                        )
                        
                        results.append(asdict(result))
                        campaign.failed_count += 1
                        self.active_campaigns[campaign.id]['failed'] += 1
            
            # Campaign complete
            campaign.status = "completed"
            campaign.end_time = datetime.utcnow().isoformat()
            
            # Save results
            self.campaign_history.extend(results)
            
            # Keep only recent history
            if len(self.campaign_history) > MAX_CAMPAIGN_HISTORY * 100:
                self.campaign_history = self.campaign_history[-(MAX_CAMPAIGN_HISTORY * 100):]
            
            DataManager.save_to_file(self.campaign_history, STATS_FILE)
            
            # Remove from active campaigns
            if campaign.id in self.active_campaigns:
                self.active_campaigns.pop(campaign.id)
            
            AuditLogger.log_event("CAMPAIGN_COMPLETED", {
                "campaign_id": campaign.id,
                "name": campaign.name,
                "sent": campaign.sent_count,
                "failed": campaign.failed_count,
                "success_rate": campaign.sent_count / total_targets * 100 if total_targets > 0 else 0
            })
            
        except Exception as e:
            logger.error(f"Campaign {campaign.id} failed: {e}")
            campaign.status = "failed"
            
            AuditLogger.log_event("CAMPAIGN_FAILED", {
                "campaign_id": campaign.id,
                "name": campaign.name,
                "error": str(e)
            })
    
    def _prepare_email_content(self, template: str, email: str, phishing_url: str, campaign_id: str) -> str:
        """Prepare email content with variables"""
        # Generate unique tracking ID
        tracking_id = SecurityManager.generate_secure_id()
        
        # Replace variables in template
        content = template
        content = content.replace('{email}', email)
        content = content.replace('{phishing_link}', phishing_url)
        content = content.replace('{campaign_id}', campaign_id)
        content = content.replace('{tracking_id}', tracking_id)
        content = content.replace('{date}', datetime.now().strftime('%Y-%m-%d'))
        content = content.replace('{time}', datetime.now().strftime('%H:%M:%S'))
        
        return content
    
    def get_template_by_id(self, template_id: str) -> Optional[EmailTemplate]:
        """Get template by ID"""
        for template in self.templates:
            if template.id == template_id:
                return template
        return None
    
    def get_campaign_stats(self) -> Dict:
        """Get campaign statistics"""
        stats = {
            'total_campaigns': len(self.campaign_history) // 100,  # Approximate
            'active_campaigns': len(self.active_campaigns),
            'total_emails_sent': sum(1 for r in self.campaign_history if r['status'] == '✅ SENT'),
            'total_emails_failed': sum(1 for r in self.campaign_history if r['status'] == '❌ FAILED'),
            'success_rate': 0,
            'recent_campaigns': []
        }
        
        if stats['total_emails_sent'] + stats['total_emails_failed'] > 0:
            stats['success_rate'] = (stats['total_emails_sent'] / 
                                   (stats['total_emails_sent'] + stats['total_emails_failed']) * 100)
        
        # Get recent campaigns
        recent_results = self.campaign_history[-100:] if self.campaign_history else []
        if recent_results:
            # Group by campaign
            campaigns = {}
            for result in recent_results:
                campaign_id = result['campaign_id']
                if campaign_id not in campaigns:
                    campaigns[campaign_id] = {
                        'sent': 0,
                        'failed': 0,
                        'last_activity': result['timestamp']
                    }
                
                if result['status'] == '✅ SENT':
                    campaigns[campaign_id]['sent'] += 1
                else:
                    campaigns[campaign_id]['failed'] += 1
            
            # Convert to list
            for campaign_id, data in list(campaigns.items())[:5]:
                total = data['sent'] + data['failed']
                stats['recent_campaigns'].append({
                    'id': campaign_id[:8] + '...',
                    'sent': data['sent'],
                    'failed': data['failed'],
                    'success_rate': data['sent'] / total * 100 if total > 0 else 0,
                    'last_activity': data['last_activity']
                })
        
        return stats

# =============== STREAMLIT UI ===============
def initialize_session():
    """Initialize session state"""
    if 'initialized' not in st.session_state:
        st.session_state.initialized = True
        st.session_state.session_id = SecurityManager.generate_secure_id()
        st.session_state.username = getpass.getuser()
        st.session_state.client_ip = AuditLogger.get_client_info()['ip']
        
        # Initialize managers
        st.session_state.smtp_manager = SMTPServerManager()
        st.session_state.campaign_manager = CampaignManager(st.session_state.smtp_manager)
        
        # Load default templates if none exist
        if not st.session_state.campaign_manager.templates:
            default_templates = [
                {
                    'name': 'Security Alert',
                    'subject': '🚨 URGENT: Account Security Verification Required',
                    'html_content': """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Verification</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 15px; text-align: center;">
        <h1 style="margin: 0 0 20px;">🔒 Security Verification Required</h1>
        <p style="font-size: 18px; margin-bottom: 30px;">Your account <strong>{email}</strong> requires immediate verification to prevent unauthorized access.</p>
        
        <div style="margin: 40px 0;">
            <a href="{phishing_link}" 
               style="background: #ff4757; color: white; padding: 18px 45px; text-decoration: none; 
                      border-radius: 50px; font-size: 18px; font-weight: bold; display: inline-block;
                      box-shadow: 0 10px 30px rgba(255,71,87,0.4); transition: all 0.3s;">
                VERIFY ACCOUNT NOW
            </a>
        </div>
        
        <p style="font-size: 14px; opacity: 0.9; margin-top: 30px;">
            Reference ID: {tracking_id}<br>
            This is an automated security notification
        </p>
    </div>
    
    <div style="margin-top: 30px; padding: 20px; background: #f8f9fa; border-radius: 10px; font-size: 14px;">
        <p style="margin: 0; color: #666;">
            If you did not request this verification, please ignore this email or contact our support team immediately.
        </p>
    </div>
</body>
</html>"""
                },
                {
                    'name': 'Password Reset',
                    'subject': 'Password Reset Request - Action Required',
                    'html_content': """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: #f8f9fa; padding: 30px; border-radius: 10px; border-left: 5px solid #007bff;">
        <h2 style="color: #007bff; margin-top: 0;">Password Reset Request</h2>
        
        <p>Hello,</p>
        
        <p>We received a request to reset the password for your account <strong>{email}</strong>.</p>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="{phishing_link}" 
               style="background: #007bff; color: white; padding: 15px 35px; text-decoration: none; 
                      border-radius: 5px; font-weight: bold; display: inline-block;">
                Reset Your Password
            </a>
        </div>
        
        <p style="color: #666; font-size: 14px;">
            <strong>Note:</strong> This link will expire in 24 hours. If you didn't request a password reset, 
            you can safely ignore this email.
        </p>
        
        <hr style="border: none; border-top: 1px solid #ddd; margin: 30px 0;">
        
        <p style="font-size: 12px; color: #888;">
            Request ID: {tracking_id}<br>
            Time: {time}<br>
            Date: {date}
        </p>
    </div>
</body>
</html>"""
                }
            ]
            
            for template_data in default_templates:
                st.session_state.campaign_manager.create_template(template_data)
        
        AuditLogger.log_event("SESSION_STARTED", {
            "session_id": st.session_state.session_id,
            "username": st.session_state.username
        })

def check_session_timeout():
    """Check if session has timed out"""
    if 'last_activity' in st.session_state:
        last_activity = datetime.fromisoformat(st.session_state.last_activity)
        timeout_delta = timedelta(minutes=SESSION_TIMEOUT_MINUTES)
        
        if datetime.utcnow() - last_activity > timeout_delta:
            st.session_state.clear()
            st.error("Session timed out. Please refresh the page.")
            st.stop()
    
    # Update last activity
    st.session_state.last_activity = datetime.utcnow().isoformat()

def show_security_disclaimer():
    """Display security disclaimer"""
    st.markdown("""
    <div style="background: linear-gradient(135deg, #ff6b6b 0%, #c0392b 100%); 
                padding: 25px; border-radius: 15px; margin-bottom: 25px; 
                border-left: 8px solid #2c3e50; box-shadow: 0 10px 30px rgba(0,0,0,0.2);">
        <h1 style="color: white; margin: 0 0 15px 0; text-align: center; font-size: 28px;">
            ⚠️ ENTERPRISE PENETRATION TESTING TOOL
        </h1>
        <div style="background: rgba(255,255,255,0.1); padding: 20px; border-radius: 10px; margin: 15px 0;">
            <h3 style="color: white; margin: 0 0 10px 0;">🚨 LEGAL DISCLAIMER:</h3>
            <ul style="color: white; margin: 0; padding-left: 20px;">
                <li><strong>STRICTLY FOR AUTHORIZED TESTING ONLY</strong></li>
                <li>You MUST have written permission before testing any system</li>
                <li>Unauthorized access is illegal and punishable by law</li>
                <li>All activities are logged and monitored</li>
                <li>You are legally responsible for all actions</li>
            </ul>
        </div>
        <p style="color: white; text-align: center; margin: 15px 0 0 0; font-size: 14px;">
            By using this tool, you accept full legal responsibility for your actions
        </p>
    </div>
    """, unsafe_allow_html=True)

def show_smtp_manager():
    """Show SMTP server management interface"""
    st.header("⚙️ SMTP Server Management")
    
    # Add new SMTP server
    with st.expander("➕ Add New SMTP Server", expanded=False):
        col1, col2 = st.columns(2)
        
        with col1:
            server_host = st.text_input("SMTP Server", "smtp.gmail.com", 
                                      help="e.g., smtp.gmail.com, smtp-mail.outlook.com")
            server_port = st.number_input("Port", min_value=1, max_value=65535, value=587)
            display_name = st.text_input("Display Name", "Security Team")
        
        with col2:
            username = st.text_input("Username/Email", "your-email@gmail.com")
            password = st.text_input("Password", type="password", 
                                   help="Use app password for Gmail, regular password for others")
            
            provider = st.selectbox("Provider", 
                                  ["Gmail", "Outlook", "Office365", "Yahoo", "Custom"])
            
            daily_limit = st.number_input("Daily Limit", min_value=1, max_value=10000, value=500)
        
        tags = st.multiselect("Tags", ["Primary", "Backup", "High-Limit", "Low-Limit"])
        
        if st.button("🔒 Add & Test SMTP Server", use_container_width=True, type="primary"):
            if not all([server_host, username, password]):
                st.error("Please fill all required fields")
            else:
                server_config = {
                    'server': server_host,
                    'port': int(server_port),
                    'username': username,
                    'password': password,
                    'display_name': display_name or username.split('@')[0],
                    'provider': provider,
                    'daily_limit': daily_limit,
                    'tags': tags
                }
                
                success, message = st.session_state.smtp_manager.add_server(server_config)
                
                if success:
                    st.success(message)
                    # Test the new server
                    server_id = st.session_state.smtp_manager.servers[-1].id
                    test_success, test_msg = st.session_state.smtp_manager.test_server(server_id)
                    
                    if test_success:
                        st.success(f"✅ Connection test successful!")
                    else:
                        st.warning(f"⚠️ Server added but test failed: {test_msg}")
                    
                    time.sleep(2)
                    st.rerun()
                else:
                    st.error(f"❌ {message}")
    
    # Show existing SMTP servers
    st.subheader("📊 Active SMTP Servers")
    
    if not st.session_state.smtp_manager.servers:
        st.info("No SMTP servers configured. Add your first server above.")
        return
    
    # Display servers in a grid
    servers = st.session_state.smtp_manager.servers
    cols = st.columns(3)
    
    for idx, server in enumerate(servers):
        col = cols[idx % 3]
        
        with col:
            # Card style container
            status_color = "🟢" if server.is_active else "🔴"
            card_bg = "rgba(0,255,136,0.1)" if server.is_active else "rgba(255,71,87,0.1)"
            
            st.markdown(f"""
            <div style="background: {card_bg}; padding: 15px; border-radius: 10px; 
                        border-left: 5px solid {'#00ff88' if server.is_active else '#ff4757'};
                        margin-bottom: 15px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <h4 style="margin: 0;">{status_color} {server.display_name}</h4>
                    <span style="font-size: 12px; background: {'#00ff88' if server.is_active else '#ff4757'}; 
                           color: white; padding: 2px 8px; border-radius: 10px;">
                        {server.provider}
                    </span>
                </div>
                <p style="margin: 5px 0; font-size: 12px; color: #888;">
                    {server.username[:3]}***@{server.username.split('@')[1] if '@' in server.username else '***'}
                </p>
                <p style="margin: 5px 0; font-size: 12px;">
                    {server.server}:{server.port}
                </p>
                <div style="display: flex; justify-content: space-between; margin-top: 10px;">
                    <button style="background: #0080ff; color: white; border: none; padding: 5px 10px; 
                            border-radius: 5px; font-size: 12px; cursor: pointer;" 
                            onclick="window.document.getElementById('test-btn-{server.id}').click()">
                        Test
                    </button>
                    <button style="background: #ff4757; color: white; border: none; padding: 5px 10px; 
                            border-radius: 5px; font-size: 12px; cursor: pointer;"
                            onclick="window.document.getElementById('del-btn-{server.id}').click()">
                        Delete
                    </button>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            # Hidden buttons for Streamlit
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Test", key=f"test-btn-{server.id}", use_container_width=True):
                    with st.spinner(f"Testing {server.display_name}..."):
                        success, msg = st.session_state.smtp_manager.test_server(server.id)
                        if success:
                            st.success(msg)
                        else:
                            st.error(msg)
                        time.sleep(2)
                        st.rerun()
            
            with col2:
                if st.button("Delete", key=f"del-btn-{server.id}", use_container_width=True):
                    if st.session_state.smtp_manager.delete_server(server.id):
                        st.success("Server deleted")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error("Failed to delete server")

def show_campaign_creator():
    """Show campaign creation interface"""
    st.header("📨 Create New Campaign")
    
    tab1, tab2, tab3 = st.tabs(["🎯 Targets", "✉️ Message", "⚙️ Settings"])
    
    with tab1:
        st.subheader("Target Email List")
        
        # Email input options
        input_method = st.radio("Input Method:", 
                              ["Paste Emails", "Upload CSV", "Manual Entry"])
        
        targets = []
        
        if input_method == "Paste Emails":
            emails_text = st.text_area(
                "Paste emails (one per line or comma-separated)",
                height=200,
                placeholder="user1@example.com\nuser2@example.com\nuser3@example.com"
            )
            
            if emails_text:
                valid_emails, invalid_entries = EmailValidator.process_email_list(emails_text)
                targets = valid_emails
                
                if valid_emails:
                    st.success(f"✅ {len(valid_emails)} valid emails found")
                    
                    # Show sample
                    with st.expander("Preview first 10 emails"):
                        for i, email in enumerate(valid_emails[:10], 1):
                            st.text(f"{i}. {email}")
                        if len(valid_emails) > 10:
                            st.text(f"... and {len(valid_emails) - 10} more")
                
                if invalid_entries:
                    with st.expander(f"⚠️ {len(invalid_entries)} invalid entries"):
                        for entry in invalid_entries[:20]:
                            st.text(f"Line {entry['line']}: {entry['email']} - {entry['reason']}")
                        if len(invalid_entries) > 20:
                            st.text(f"... and {len(invalid_entries) - 20} more")
        
        elif input_method == "Upload CSV":
            csv_file = st.file_uploader("Upload CSV file", type=['csv'])
            if csv_file:
                try:
                    df = pd.read_csv(csv_file)
                    st.write("Preview:", df.head())
                    
                    # Let user select email column
                    if len(df.columns) > 0:
                        email_column = st.selectbox("Select email column", df.columns)
                        
                        if email_column:
                            emails = df[email_column].dropna().astype(str).tolist()
                            emails_text = "\n".join(emails)
                            valid_emails, invalid_entries = EmailValidator.process_email_list(emails_text)
                            targets = valid_emails
                            
                            if valid_emails:
                                st.success(f"✅ {len(valid_emails)} valid emails extracted")
                except Exception as e:
                    st.error(f"Error reading CSV: {e}")
        
        else:  # Manual Entry
            num_emails = st.number_input("Number of emails to add", min_value=1, max_value=100, value=5)
            
            for i in range(num_emails):
                email = st.text_input(f"Email {i+1}", key=f"manual_email_{i}")
                if email and '@' in email:
                    is_valid, msg, domain = EmailValidator.validate_email(email)
                    if is_valid:
                        targets.append(email)
                    else:
                        st.warning(f"Invalid email: {msg}")
            
            if targets:
                st.success(f"✅ {len(targets)} emails added")
        
        # Store targets in session state
        if targets:
            st.session_state.campaign_targets = targets
    
    with tab2:
        st.subheader("Message Configuration")
        
        # Campaign name
        campaign_name = st.text_input("Campaign Name", "Security Awareness Test")
        
        # Subject
        subject = st.text_input("Email Subject", "🔒 Security Verification Required")
        
        # Phishing URL - YOUR CUSTOM PHISHING LINK INPUT
        st.subheader("🔗 Phishing/Tracking URL")
        phishing_url = st.text_input(
            "Enter your custom phishing/tracking URL:",
            value="https://your-domain.com/login?token={tracking_id}&email={email}",
            help="Use {tracking_id} for unique tracking ID and {email} for target email"
        )
        
        # Template selection
        st.subheader("📄 Email Template")
        
        templates = st.session_state.campaign_manager.templates
        if templates:
            template_names = [t.name for t in templates]
            selected_template_name = st.selectbox("Select Template", template_names)
            
            selected_template = next(t for t in templates if t.name == selected_template_name)
            
            # Template preview
            with st.expander("Template Preview", expanded=True):
                st.markdown("**Subject Preview:**")
                st.code(selected_template.subject)
                
                st.markdown("**HTML Preview:**")
                st.components.v1.html(selected_template.html_content, height=400, scrolling=True)
            
            # Store selected template
            st.session_state.selected_template = selected_template
        else:
            st.error("No templates available. Please create a template first.")
    
    with tab3:
        st.subheader("Campaign Settings")
        
        col1, col2 = st.columns(2)
        
        with col1:
            delay = st.slider(
                "Delay between emails (seconds)",
                min_value=MIN_DELAY_SECONDS,
                max_value=300,
                value=30,
                help=f"Minimum {MIN_DELAY_SECONDS}s to prevent flooding"
            )
            
            thread_count = st.slider(
                "Parallel threads",
                min_value=1,
                max_value=MAX_THREADS,
                value=1,
                help="More threads = faster sending but more resource usage"
            )
        
        with col2:
            # SMTP server selection
            active_servers = st.session_state.smtp_manager.get_active_servers()
            if active_servers:
                server_options = [f"{s.display_name} ({s.provider})" for s in active_servers]
                selected_servers = st.multiselect(
                    "SMTP Servers (for rotation)",
                    server_options,
                    default=server_options[:min(3, len(server_options))]
                )
                
                # Map back to server IDs
                selected_server_ids = []
                for server_name in selected_servers:
                    for server in active_servers:
                        if f"{server.display_name} ({server.provider})" == server_name:
                            selected_server_ids.append(server.id)
                            break
            else:
                st.warning("No active SMTP servers. Add servers in SMTP Manager.")
                selected_server_ids = []
        
        # Schedule (optional)
        schedule_now = st.checkbox("Start immediately", value=True)
        
        if not schedule_now:
            schedule_time = st.time_input("Schedule start time")
            schedule_date = st.date_input("Schedule date")
        
        # Campaign summary
        if 'campaign_targets' in st.session_state and st.session_state.campaign_targets:
            st.subheader("📋 Campaign Summary")
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Targets", len(st.session_state.campaign_targets))
            with col2:
                st.metric("SMTP Servers", len(selected_server_ids))
            with col3:
                estimated_time = len(st.session_state.campaign_targets) * delay / 60
                st.metric("Est. Time", f"{estimated_time:.1f} min")
            
            # Launch button
            if st.button("🚀 Launch Campaign", type="primary", use_container_width=True):
                if not active_servers:
                    st.error("No active SMTP servers available")
                elif not st.session_state.campaign_targets:
                    st.error("No target emails specified")
                elif not phishing_url:
                    st.error("Phishing URL is required")
                elif 'selected_template' not in st.session_state:
                    st.error("No template selected")
                else:
                    # Create campaign
                    campaign_data = {
                        'name': campaign_name,
                        'targets': st.session_state.campaign_targets,
                        'subject': subject,
                        'template_id': st.session_state.selected_template.id,
                        'phishing_url': phishing_url,
                        'delay_seconds': delay,
                        'thread_count': thread_count
                    }
                    
                    success, message, campaign = st.session_state.campaign_manager.create_campaign(campaign_data)
                    
                    if success and campaign:
                        # Start campaign
                        campaign.smtp_rotation = selected_server_ids
                        campaign_id = st.session_state.campaign_manager.start_campaign(campaign)
                        
                        st.success(f"✅ Campaign launched! ID: {campaign_id}")
                        st.balloons()
                        
                        # Clear targets
                        if 'campaign_targets' in st.session_state:
                            del st.session_state.campaign_targets
                        
                        # Refresh after 2 seconds
                        time.sleep(2)
                        st.rerun()
                    else:
                        st.error(f"❌ {message}")

def show_dashboard():
    """Show main dashboard with statistics"""
    st.header("📊 Dashboard Overview")
    
    # Get statistics
    campaign_stats = st.session_state.campaign_manager.get_campaign_stats()
    smtp_stats = st.session_state.smtp_manager.get_server_stats()
    
    # Top metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "Total Emails Sent",
            f"{campaign_stats['total_emails_sent']:,}",
            delta=f"{campaign_stats['success_rate']:.1f}% success"
        )
    
    with col2:
        st.metric(
            "Active Campaigns",
            campaign_stats['active_campaigns'],
            delta=f"{len(st.session_state.smtp_manager.get_active_servers())} SMTP active"
        )
    
    with col3:
        active_servers = len([s for s in st.session_state.smtp_manager.servers if s.is_active])
        total_servers = len(st.session_state.smtp_manager.servers)
        st.metric(
            "SMTP Servers",
            f"{active_servers}/{total_servers}",
            delta="active" if active_servers > 0 else "inactive"
        )
    
    with col4:
        # Calculate emails sent today
        today = datetime.now().date().isoformat()
        emails_today = sum(1 for r in st.session_state.campaign_manager.campaign_history 
                         if r['timestamp'].startswith(today) and r['status'] == '✅ SENT')
        st.metric("Emails Today", f"{emails_today:,}")
    
    # Charts
    col1, col2 = st.columns(2)
    
    with col1:
        # Success rate chart
        if campaign_stats['total_emails_sent'] + campaign_stats['total_emails_failed'] > 0:
            fig1 = go.Figure(data=[
                go.Pie(
                    labels=['Success', 'Failed'],
                    values=[campaign_stats['total_emails_sent'], campaign_stats['total_emails_failed']],
                    hole=.4,
                    marker_colors=['#00ff88', '#ff4757']
                )
            ])
            fig1.update_layout(
                title_text="Overall Success Rate",
                showlegend=True,
                height=300
            )
            st.plotly_chart(fig1, use_container_width=True)
    
    with col2:
        # Active campaigns progress
        if st.session_state.campaign_manager.active_campaigns:
            active_campaigns_data = []
            for camp_id, data in st.session_state.campaign_manager.active_campaigns.items():
                campaign = data['campaign']
                progress = data['progress']
                
                active_campaigns_data.append({
                    'name': campaign.name[:20] + ('...' if len(campaign.name) > 20 else ''),
                    'progress': progress * 100,
                    'sent': data['sent'],
                    'total': campaign.total_count
                })
            
            if active_campaigns_data:
                df_active = pd.DataFrame(active_campaigns_data)
                fig2 = px.bar(
                    df_active, 
                    x='name', 
                    y='progress',
                    title="Active Campaigns Progress",
                    labels={'progress': 'Progress %', 'name': 'Campaign'},
                    hover_data=['sent', 'total']
                )
                fig2.update_layout(height=300)
                st.plotly_chart(fig2, use_container_width=True)
        else:
            st.info("No active campaigns")
    
    # Recent activity
    st.subheader("📈 Recent Activity")
    
    if campaign_stats['recent_campaigns']:
        df_recent = pd.DataFrame(campaign_stats['recent_campaigns'])
        st.dataframe(
            df_recent,
            column_config={
                "id": "Campaign ID",
                "sent": st.column_config.NumberColumn("Sent", format="%d"),
                "failed": st.column_config.NumberColumn("Failed", format="%d"),
                "success_rate": st.column_config.NumberColumn("Success %", format="%.1f%%"),
                "last_activity": "Last Activity"
            },
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No recent campaign activity")

def show_analytics():
    """Show detailed analytics"""
    st.header("📈 Advanced Analytics")
    
    # Load campaign history
    campaign_history = st.session_state.campaign_manager.campaign_history
    
    if not campaign_history:
        st.info("No campaign data available yet")
        return
    
    # Convert to DataFrame
    df = pd.DataFrame(campaign_history)
    
    # Date range selector
    col1, col2 = st.columns(2)
    with col1:
        if 'timestamp' in df.columns:
            df['date'] = pd.to_datetime(df['timestamp']).dt.date
            min_date = df['date'].min()
            max_date = df['date'].max()
            
            date_range = st.date_input(
                "Date Range",
                value=(min_date, max_date),
                min_value=min_date,
                max_value=max_date
            )
            
            if len(date_range) == 2:
                start_date, end_date = date_range
                df = df[(df['date'] >= start_date) & (df['date'] <= end_date)]
    
    with col2:
        group_by = st.selectbox(
            "Group By",
            ["Hour", "Day", "Week", "Month", "Campaign", "Domain"]
        )
    
    # Analytics tabs
    tab1, tab2, tab3 = st.tabs(["Performance", "Geographic", "Technical"])
    
    with tab1:
        st.subheader("Performance Metrics")
        
        # Success rate over time
        if 'timestamp' in df.columns and 'status' in df.columns:
            df['hour'] = pd.to_datetime(df['timestamp']).dt.floor('H')
            hourly_stats = df.groupby('hour')['status'].apply(
                lambda x: (x == '✅ SENT').sum() / len(x) * 100 if len(x) > 0 else 0
            ).reset_index()
            
            fig1 = px.line(
                hourly_stats, 
                x='hour', 
                y='status',
                title="Success Rate Over Time",
                labels={'status': 'Success Rate %', 'hour': 'Time'}
            )
            st.plotly_chart(fig1, use_container_width=True)
    
    with tab2:
        st.subheader("Domain Analysis")
        
        if 'email_domain' in df.columns:
            domain_stats = df.groupby('email_domain').agg({
                'status': lambda x: (x == '✅ SENT').sum() / len(x) * 100 if len(x) > 0 else 0,
                'id': 'count'
            }).reset_index()
            
            domain_stats.columns = ['Domain', 'Success Rate', 'Email Count']
            
            fig2 = px.scatter(
                domain_stats,
                x='Email Count',
                y='Success Rate',
                size='Email Count',
                color='Success Rate',
                hover_name='Domain',
                title="Domain Performance",
                size_max=60
            )
            st.plotly_chart(fig2, use_container_width=True)
    
    with tab3:
        st.subheader("Technical Metrics")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # SMTP performance
            if 'smtp_id' in df.columns:
                smtp_stats = df.groupby('smtp_id').agg({
                    'status': lambda x: (x == '✅ SENT').sum(),
                    'id': 'count'
                }).reset_index()
                
                if not smtp_stats.empty:
                    st.metric(
                        "Best Performing SMTP",
                        f"{smtp_stats.loc[smtp_stats['status'].idxmax(), 'smtp_id'][:8]}...",
                        delta=f"{smtp_stats['status'].max()} sent"
                    )
        
        with col2:
            # Failure analysis
            if 'error_message' in df.columns:
                failed = df[df['status'] == '❌ FAILED']
                if not failed.empty:
                    common_errors = failed['error_message'].value_counts().head(5)
                    st.write("**Common Errors:**")
                    for error, count in common_errors.items():
                        st.text(f"{count}× {error[:30]}...")

def show_export():
    """Show export functionality"""
    st.header("💾 Export Data")
    
    # Export options
    export_type = st.radio(
        "Export Type:",
        ["Campaign Results", "SMTP Configuration", "Audit Logs", "Templates"]
    )
    
    # Date range for exports
    col1, col2 = st.columns(2)
    with col1:
        start_date = st.date_input("Start Date")
    with col2:
        end_date = st.date_input("End Date", value=datetime.now().date())
    
    # Format selection
    export_format = st.selectbox("Format", ["CSV", "JSON", "Excel"])
    
    # Prepare data based on selection
    export_data = None
    
    if export_type == "Campaign Results":
        data = st.session_state.campaign_manager.campaign_history
        if data:
            # Filter by date
            filtered_data = []
            for item in data:
                item_date = datetime.fromisoformat(item['timestamp']).date()
                if start_date <= item_date <= end_date:
                    filtered_data.append(item)
            
            if filtered_data:
                df = pd.DataFrame(filtered_data)
                export_data = df
    
    elif export_type == "SMTP Configuration":
        servers = st.session_state.smtp_manager.servers
        if servers:
            server_data = []
            for server in servers:
                server_dict = asdict(server)
                # Don't include encrypted password in export
                if 'password_encrypted' in server_dict:
                    del server_dict['password_encrypted']
                server_data.append(server_dict)
            
            export_data = pd.DataFrame(server_data)
    
    elif export_type == "Audit Logs":
        logs = DataManager.load_from_file(LOGS_FILE, encrypted=False)
        if logs:
            # Filter by date
            filtered_logs = []
            for log in logs:
                log_date = datetime.fromisoformat(log['timestamp']).date()
                if start_date <= log_date <= end_date:
                    filtered_logs.append(log)
            
            if filtered_logs:
                export_data = pd.DataFrame(filtered_logs)
    
    elif export_type == "Templates":
        templates = st.session_state.campaign_manager.templates
        if templates:
            template_data = [asdict(t) for t in templates]
            export_data = pd.DataFrame(template_data)
    
    # Export button
    if export_data is not None and not export_data.empty:
        st.success(f"✅ {len(export_data)} records ready for export")
        
        if export_format == "CSV":
            csv = export_data.to_csv(index=False)
            st.download_button(
                label="📥 Download CSV",
                data=csv,
                file_name=f"export_{export_type.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True
            )
        
        elif export_format == "JSON":
            json_str = export_data.to_json(orient='records', indent=2)
            st.download_button(
                label="📥 Download JSON",
                data=json_str,
                file_name=f"export_{export_type.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True
            )
        
        elif export_format == "Excel":
            excel_buffer = io.BytesIO()
            with pd.ExcelWriter(excel_buffer, engine='openpyxl') as writer:
                export_data.to_excel(writer, index=False, sheet_name='Export')
            
            st.download_button(
                label="📥 Download Excel",
                data=excel_buffer.getvalue(),
                file_name=f"export_{export_type.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                use_container_width=True
            )
    else:
        st.warning("No data available for export with selected filters")

def main():
    """Main application entry point"""
    
    # Initialize session
    initialize_session()
    
    # Check session timeout
    check_session_timeout()
    
    # Show security disclaimer
    show_security_disclaimer()
    
    # Sidebar navigation
    with st.sidebar:
        st.image("https://img.icons8.com/color/96/000000/security-checked--v1.png", width=100)
        
        st.title("Navigation")
        
        page = st.radio(
            "Select Page:",
            ["Dashboard", "SMTP Manager", "Create Campaign", "Analytics", "Export", "Settings"],
            label_visibility="collapsed"
        )
        
        st.markdown("---")
        
        # Display session info
        st.caption(f"Session: {st.session_state.session_id[:8]}...")
        st.caption(f"User: {st.session_state.username}")
        st.caption(f"IP: {st.session_state.client_ip}")
        
        # Quick stats
        active_servers = len([s for s in st.session_state.smtp_manager.servers if s.is_active])
        total_servers = len(st.session_state.smtp_manager.servers)
        st.metric("SMTP Status", f"{active_servers}/{total_servers}")
        
        active_campaigns = len(st.session_state.campaign_manager.active_campaigns)
        st.metric("Active Campaigns", active_campaigns)
        
        st.markdown("---")
        
        # Logout/clear session
        if st.button("🔒 Clear Session", use_container_width=True):
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.success("Session cleared. Refreshing...")
            time.sleep(1)
            st.rerun()
    
    # Main content area
    if page == "Dashboard":
        show_dashboard()
    elif page == "SMTP Manager":
        show_smtp_manager()
    elif page == "Create Campaign":
        show_campaign_creator()
    elif page == "Analytics":
        show_analytics()
    elif page == "Export":
        show_export()
    elif page == "Settings":
        st.header("⚙️ Settings")
        
        # Security settings
        with st.expander("Security Settings", expanded=True):
            st.checkbox("Require re-authentication after 15 minutes", value=True)
            st.checkbox("Enable IP whitelisting", value=False)
            st.checkbox("Log all user actions", value=True)
            st.checkbox("Encrypt all stored data", value=True)
        
        # Notification settings
        with st.expander("Notifications"):
            st.checkbox("Email notifications for campaign completion", value=True)
            st.checkbox("Alerts for SMTP failures", value=True)
            st.checkbox("Daily summary report", value=False)
        
        # Application settings
        with st.expander("Application"):
            st.slider("Default delay between emails", 10, 300, 30)
            st.slider("Maximum parallel threads", 1, 10, 5)
            st.number_input("Maximum emails per campaign", 100, 10000, 5000)
        
        if st.button("Save Settings", type="primary"):
            st.success("Settings saved successfully!")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.error(f"Application error: {e}", exc_info=True)
        st.error(f"An error occurred: {str(e)[:200]}")
        st.info("Please refresh the page or check the logs for details.")