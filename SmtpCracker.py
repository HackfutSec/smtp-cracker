import sys
import socket
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import threading
from datetime import datetime
import os
import re
import logging
import json
import hashlib
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import time

from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QTextEdit, QLineEdit, QPushButton, 
                             QLabel, QProgressBar, QListWidget, QSplitter,
                             QMessageBox, QFileDialog, QFrame, QCheckBox, 
                             QListWidgetItem, QDialog, QScrollArea)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QPalette, QColor, QTextCursor, QIcon

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('smtp_checker.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

class ConfigManager:
    """Persistent configuration manager"""
    
    def __init__(self):
        self.config_file = Path("smtp_checker_config.json")
        self.default_config = {
            "last_email": "",
            "window_geometry": None,
            "auto_save": True,
            "max_workers": 5,
            "timeout": 30,
            "last_directory": ""
        }
    
    def load_config(self) -> dict:
        """Load configuration from file"""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    loaded_config = json.load(f)
                    config = self.default_config.copy()
                    config.update(loaded_config)
                    return config
        except Exception as e:
            logging.error(f"Config loading error: {e}")
        return self.default_config.copy()
    
    def save_config(self, config: dict):
        """Save configuration"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logging.error(f"Config save error: {e}")

class InputValidator:
    """User input validator"""
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate an email address"""
        if not email:
            return False
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_smtp_line(line: str) -> Tuple[bool, str]:
        """Validate an SMTP configuration line"""
        line = line.strip()
        if not line:
            return False, "Empty line"
        
        # Ignore comment lines
        if line.startswith('#') or line.startswith('//') or line.startswith(';'):
            return False, "Comment line ignored"
        
        parts = line.split('|')
        if len(parts) < 4:
            return False, "Invalid format - Expected: server|port|username|password"
        
        server, port_str, username, password = parts[:4]
        
        # Clean spaces
        server = server.strip()
        port_str = port_str.strip()
        username = username.strip()
        password = password.strip()
        
        # Server validation
        if not server or len(server) < 3:
            return False, "Invalid server name"
        
        # Port validation
        try:
            port = int(port_str)
            if not (1 <= port <= 65535):
                return False, "Invalid port (1-65535)"
        except ValueError:
            return False, "Port must be a number"
        
        # Username validation
        if not username:
            return False, "Empty username"
        
        # Password validation
        if not password:
            return False, "Empty password"
        
        return True, "Valid"
    
    @staticmethod
    def filter_valid_lines(lines: List[str]) -> Tuple[List[str], List[Tuple[str, str]]]:
        """Filter valid lines and return invalid ones with their errors"""
        valid_lines = []
        invalid_lines = []
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            is_valid, message = InputValidator.validate_smtp_line(line)
            if is_valid:
                valid_lines.append(line)
            else:
                invalid_lines.append((line, message))
        
        return valid_lines, invalid_lines
    
    @staticmethod
    def remove_duplicates(lines: List[str]) -> List[str]:
        """Remove duplicates based on MD5 hash"""
        seen_hashes = set()
        unique_lines = []
        
        for line in lines:
            line_hash = hashlib.md5(line.encode('utf-8')).hexdigest()
            if line_hash not in seen_hashes:
                seen_hashes.add(line_hash)
                unique_lines.append(line)
        
        return unique_lines

class SecurityManager:
    """Security manager"""
    
    @staticmethod
    def mask_password(password: str) -> str:
        """Mask a password for display"""
        if not password:
            return ""
        if len(password) <= 4:
            return "*" * len(password)
        return password[:2] + "*" * (len(password) - 4) + password[-2:]
    
    @staticmethod
    def calculate_hash(data: str) -> str:
        """Calculate a hash to identify duplicates"""
        return hashlib.md5(data.encode('utf-8')).hexdigest()

class InvalidLinesDialog(QDialog):
    """Dialog to display invalid lines"""
    
    def __init__(self, invalid_lines: List[Tuple[str, str]], parent=None):
        super().__init__(parent)
        self.invalid_lines = invalid_lines
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle("📋 Invalid Lines Report")
        self.setGeometry(300, 300, 900, 600)
        self.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #1a0a1a, stop:0.5 #2a0a2a, stop:1 #1a0a2a);
                color: #ff00ff;
            }
        """)
        
        layout = QVBoxLayout()
        
        # Title
        title = QLabel(f"🚫 {len(self.invalid_lines)} Invalid Lines Detected")
        title.setStyleSheet("""
            QLabel {
                font-size: 16px;
                font-weight: bold;
                color: #ff4444;
                padding: 10px;
                background: rgba(255, 0, 0, 0.1);
                border: 1px solid #ff4444;
                border-radius: 5px;
                text-align: center;
            }
        """)
        layout.addWidget(title)
        
        # Text area for report
        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setStyleSheet("""
            QTextEdit {
                background: rgba(30, 0, 0, 0.8);
                border: 2px solid #ff0000;
                border-radius: 8px;
                padding: 10px;
                color: #ff8888;
                font-family: 'Courier New', monospace;
                font-size: 10px;
                selection-background-color: rgba(255, 0, 0, 0.3);
            }
        """)
        
        # Generate report
        report = self.generate_report()
        self.text_edit.setPlainText(report)
        layout.addWidget(self.text_edit)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.copy_btn = QPushButton("📋 Copy Report")
        self.copy_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #ffaa00, stop:1 #000000);
                color: white;
                border: 2px solid #ffaa00;
                border-radius: 8px;
                padding: 8px 15px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #ffaa00, stop:1 #111111);
                border: 2px solid #ffffff;
            }
        """)
        self.copy_btn.clicked.connect(self.copy_report)
        button_layout.addWidget(self.copy_btn)
        
        self.close_btn = QPushButton("❌ Close")
        self.close_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #ff4444, stop:1 #000000);
                color: white;
                border: 2px solid #ff4444;
                border-radius: 8px;
                padding: 8px 15px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #ff4444, stop:1 #111111);
                border: 2px solid #ffffff;
            }
        """)
        self.close_btn.clicked.connect(self.close)
        button_layout.addWidget(self.close_btn)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
    
    def generate_report(self) -> str:
        """Generate invalid lines report"""
        report = "=" * 80 + "\n"
        report += "INVALID LINES REPORT - " + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "\n"
        report += "=" * 80 + "\n\n"
        
        for i, (line, error) in enumerate(self.invalid_lines, 1):
            report += f"{i:03d}. ERROR: {error}\n"
            report += f"     LINE: {line}\n"
            report += "-" * 80 + "\n"
        
        report += f"\nTotal: {len(self.invalid_lines)} invalid lines detected\n"
        return report
    
    def copy_report(self):
        """Copy report to clipboard"""
        clipboard = QApplication.clipboard()
        clipboard.setText(self.text_edit.toPlainText())
        # Use parent's styled message box if available
        if self.parent():
            self.parent().styled_message_box(
                QMessageBox.Information,
                "Success", 
                "Report copied to clipboard!"
            )
        else:
            # Fallback to standard message box
            msg = QMessageBox()
            msg.setWindowTitle("Success")
            msg.setText("Report copied to clipboard!")
            msg.setIcon(QMessageBox.Information)
            msg.setStyleSheet("""
                QMessageBox {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                        stop:0 #0a0a2a, stop:0.5 #1a1a4a, stop:1 #2a0a2a);
                    color: #00ffff;
                    font-family: 'Courier New';
                    border: 2px solid #00ffff;
                    border-radius: 10px;
                }
                QMessageBox QLabel {
                    color: #00ffff;
                    font-size: 12px;
                }
                QMessageBox QPushButton {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 #00ffff, stop:1 #000000);
                    color: #000000;
                    border: 2px solid #00ffff;
                    border-radius: 8px;
                    padding: 8px 15px;
                    font-weight: bold;
                    min-width: 80px;
                }
                QMessageBox QPushButton:hover {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 #00ffff, stop:1 #111111);
                    border: 2px solid #ffffff;
                }
            """)
            msg.exec_()

class SMTPTester(QThread):
    update_signal = pyqtSignal(str, str)
    progress_signal = pyqtSignal(int)
    finished_signal = pyqtSignal()
    error_signal = pyqtSignal(str)
    stats_signal = pyqtSignal(int, int)  # success, failures
    
    def __init__(self, smtp_data: List[str], notification_email: str, timeout: int = 30):
        super().__init__()
        self.smtp_data = smtp_data
        self.notification_email = notification_email
        self.timeout = timeout
        self.results = []
        self.is_running = True
        self.validator = InputValidator()
        self.security = SecurityManager()
        self.processed_lines = 0
        self.success_count = 0
        self.failure_count = 0
        
    def stop_test(self):
        """Stop current test"""
        self.is_running = False
        
    def run(self):
        """Execute SMTP tests"""
        total = len(self.smtp_data)
        
        for i, data in enumerate(self.smtp_data):
            if not self.is_running:
                break
                
            try:
                self.processed_lines += 1
                
                # Line validation (double check)
                is_valid, validation_msg = self.validator.validate_smtp_line(data)
                if not is_valid:
                    self.update_signal.emit(f"❌ INVALID - {self.truncate_data(data)}", validation_msg)
                    self.failure_count += 1
                    self.stats_signal.emit(self.success_count, self.failure_count)
                    continue  # Skip invalid lines
                
                # Parse data
                server, port, username, password = self.parse_smtp_data(data)
                if server and port and username and password:
                    success, message = self.test_smtp_connection(server, port, username, password)
                    self.results.append({
                        'server': server,
                        'port': port,
                        'username': username,
                        'success': success,
                        'message': message,
                        'timestamp': datetime.now().isoformat()
                    })
                    
                    status = "✅ SUCCESS" if success else "❌ FAILED"
                    masked_password = self.security.mask_password(password)
                    display_data = f"{server}:{port} - {username} - {masked_password}"
                    
                    self.update_signal.emit(f"{status} - {display_data}", message)
                    
                    if success:
                        self.success_count += 1
                        self.save_successful_connection(server, port, username, password)
                    else:
                        self.failure_count += 1
                else:
                    self.update_signal.emit(f"❌ PARSING ERROR - {self.truncate_data(data)}", "Unable to parse SMTP data")
                    self.failure_count += 1
                    
            except Exception as e:
                logging.error(f"SMTP test error: {e}")
                self.update_signal.emit(f"❌ ERROR - {self.truncate_data(data)}", f"Internal error: {str(e)}")
                self.failure_count += 1
            
            # Emit statistics
            self.stats_signal.emit(self.success_count, self.failure_count)
            
            # Emit progress
            progress = int((i + 1) / total * 100)
            self.progress_signal.emit(progress)
            
            # Short pause to avoid overload
            time.sleep(0.1)
        
        # Finished signal
        self.finished_signal.emit()
        logging.info(f"Tests completed: {self.success_count} success, {self.failure_count} failures")
    
    def truncate_data(self, data: str, max_length: int = 50) -> str:
        """Truncate data for display"""
        if len(data) <= max_length:
            return data
        return data[:max_length] + "..."
    
    def parse_smtp_data(self, data: str) -> Tuple[Optional[str], Optional[int], Optional[str], Optional[str]]:
        """Parse SMTP data with improved error handling"""
        try:
            parts = data.strip().split('|')
            if len(parts) >= 4:
                server = parts[0].strip()
                port = int(parts[1].strip())
                username = parts[2].strip()
                password = parts[3].strip()
                
                # Additional cleaning
                if server and port and username and password:
                    return server, port, username, password
                    
        except ValueError as e:
            logging.error(f"Port conversion error: {e}")
        except Exception as e:
            logging.error(f"SMTP data parsing error: {e}")
            
        return None, None, None, None
    
    def test_smtp_connection(self, server: str, port: int, username: str, password: str) -> Tuple[bool, str]:
        """Test SMTP connection with timeout and complete error handling"""
        try:
            # Timeout configuration
            socket.setdefaulttimeout(self.timeout)
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            if port == 465:
                # SSL connection
                with smtplib.SMTP_SSL(server, port, context=context, timeout=self.timeout) as smtp:
                    smtp.login(username, password)
                    if self.send_confirmation_email(smtp, username):
                        return True, "SSL connection successful and confirmation email sent"
                    return True, "SSL connection successful (email confirmation failed)"
                    
            elif port == 587:
                # STARTTLS connection
                with smtplib.SMTP(server, port, timeout=self.timeout) as smtp:
                    smtp.starttls(context=context)
                    smtp.login(username, password)
                    if self.send_confirmation_email(smtp, username):
                        return True, "STARTTLS connection successful and confirmation email sent"
                    return True, "STARTTLS connection successful (email confirmation failed)"
                    
            else:
                # Try both methods
                try:
                    with smtplib.SMTP_SSL(server, port, context=context, timeout=self.timeout) as smtp:
                        smtp.login(username, password)
                        if self.send_confirmation_email(smtp, username):
                            return True, "SSL connection successful and confirmation email sent"
                        return True, "SSL connection successful (email confirmation failed)"
                except:
                    with smtplib.SMTP(server, port, timeout=self.timeout) as smtp:
                        smtp.starttls(context=context)
                        smtp.login(username, password)
                        if self.send_confirmation_email(smtp, username):
                            return True, "STARTTLS connection successful and confirmation email sent"
                        return True, "STARTTLS connection successful (email confirmation failed)"
                        
        except smtplib.SMTPAuthenticationError:
            return False, "Authentication failed - Bad credentials"
        except smtplib.SMTPConnectError:
            return False, "Connection to server failed"
        except smtplib.SMTPServerDisconnected:
            return False, "Server disconnected"
        except socket.timeout:
            return False, f"Timeout after {self.timeout} seconds"
        except socket.gaierror:
            return False, "Unable to resolve server name"
        except ssl.SSLError as e:
            return False, f"SSL error: {str(e)}"
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def send_confirmation_email(self, smtp, from_addr: str) -> bool:
        """Send confirmation email"""
        try:
            if not self.notification_email or not self.validator.validate_email(self.notification_email):
                return False
            
            msg = MIMEMultipart()
            msg['From'] = from_addr
            msg['To'] = self.notification_email
            msg['Subject'] = "✅ SMTP Connection Successful Confirmation"
            
            # Récupérer les informations de connexion SMTP de manière sécurisée
            server_info = ""
            
            try:
                # Essayer d'obtenir le host de différentes manières selon le type de connexion
                if hasattr(smtp, '_host'):
                    server_info = f"<p><strong>SMTP Server:</strong> {smtp._host}</p>"
                
                elif hasattr(smtp, 'sock') and smtp.sock:
                    server_info = f"<p><strong>SMTP Server:</strong> Connected via socket</p>"
                    
                else:
                    server_info = f"<p><strong>SMTP Server:</strong> Information unavailable</p>"
                
            except:
                server_info = f"<p><strong>SMTP Server:</strong> Information unavailable</p>"
                port_info = ""
                
            try:
                if hasattr(smtp, 'port'):
                    port_info = f"<p><strong>Port:</strong> {smtp.port}</p>"
                
                else:
                    port_info = f"<p><strong>Port:</strong> Information unavailable</p>"
            
            except:
                port_info = f"<p><strong>Port:</strong> Information unavailable</p>"
                
                body = f"""
                <html>
                <body style="font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px;">
                <div style="max-width: 600px; margin: 0 auto; background: rgba(0,0,0,0.8); padding: 30px; border-radius: 15px; border: 2px solid #00ffff; box-shadow: 0 0 20px rgba(0,255,255,0.5);">
                <h1 style="text-align: center; color: #00ffff; text-shadow: 0 0 10px rgba(0,255,255,0.8);">✅ SMTP CONNECTION SUCCESSFUL</h1>
                <div style="background: rgba(0,255,255,0.1); padding: 20px; border-radius: 10px; margin: 20px 0;">
                    {server_info}
                    {port_info}
                    <p><strong>Tested account:</strong> {from_addr}</p>
                    <p><strong>Date and time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                <p style="text-align: center; font-size: 12px; color: #888;">
                    This email confirms that the SMTP connection was established successfully.
                </p>
            </div>
        </body>
        </html>
        """
                msg.attach(MIMEText(body, 'html'))
                smtp.send_message(msg)
                return True
            
        except Exception as e:
            logging.warning(f"Confirmation email sending failed: {e}")
            return False
    
    def save_successful_connection(self, server: str, port: int, username: str, password: str):
        """Save successful connections"""
        try:
            filename = "smtp_success.txt"
            backup_dir = Path("backups")
            backup_dir.mkdir(exist_ok=True)
            
            # Main save
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with open(filename, 'a', encoding='utf-8') as f:
                f.write(f"{server}|{port}|{username}|{password}\n")
            
            # Timestamped backup
            backup_file = backup_dir / f"smtp_success_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(backup_file, 'w', encoding='utf-8') as f:
                f.write(f"# Backup created on {timestamp}\n")
                f.write(f"# Total: {self.success_count} successful connections\n")
                f.write(f"{server}|{port}|{username}|{password}\n")
                
        except Exception as e:
            logging.error(f"Connection save error: {e}")

class CyberPunkSMTPChecker(QMainWindow):
    def __init__(self):
        super().__init__()
        self.config_manager = ConfigManager()
        self.validator = InputValidator()
        self.security = SecurityManager()
        self.smtp_tester = None
        self.config = {}
        self.invalid_lines_cache = []
        self.load_config()
        self.init_ui()
        
    def load_config(self):
        """Load configuration"""
        self.config = self.config_manager.load_config()
        
    def save_config(self):
        """Save configuration"""
        self.config_manager.save_config(self.config)
        
    def styled_message_box(self, icon, title, text, buttons=QMessageBox.Ok, default_button=QMessageBox.Ok):
        """Create a styled message box with cyberpunk theme"""
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle(title)
        msg_box.setText(text)
        msg_box.setIcon(icon)
        msg_box.setStandardButtons(buttons)
        msg_box.setDefaultButton(default_button)
        
        # Apply cyberpunk style
        msg_box.setStyleSheet("""
            QMessageBox {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0a0a2a, stop:0.5 #1a1a4a, stop:1 #2a0a2a);
                color: #00ffff;
                font-family: 'Courier New';
                border: 2px solid #00ffff;
                border-radius: 10px;
            }
            QMessageBox QLabel {
                color: #00ffff;
                font-size: 12px;
            }
            QMessageBox QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #00ffff, stop:1 #000000);
                color: #000000;
                border: 2px solid #00ffff;
                border-radius: 8px;
                padding: 8px 15px;
                font-weight: bold;
                min-width: 80px;
            }
            QMessageBox QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #00ffff, stop:1 #111111);
                border: 2px solid #ffffff;
            }
        """)
        
        return msg_box.exec_()
        
    def closeEvent(self, event):
        """Handle application closure"""
        if self.smtp_tester and self.smtp_tester.isRunning():
            reply = self.styled_message_box(
                QMessageBox.Question,
                'Confirmation',
                'A test is in progress. Do you really want to quit?',
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                self.smtp_tester.stop_test()
                self.smtp_tester.wait(5000)  # Wait max 5 seconds
            else:
                event.ignore()
                return
        
        # Save configuration
        self.config['last_email'] = self.email_input.text()
        self.config['window_geometry'] = self.saveGeometry().data().hex()
        self.save_config()
        
        event.accept()
        
    def init_ui(self):
        self.setWindowTitle("🔮SMTP Cracker")
        self.setGeometry(100, 100, 1200, 800)
        
        # Restore geometry
        if self.config.get('window_geometry'):
            try:
                self.restoreGeometry(bytes.fromhex(self.config['window_geometry']))
            except:
                pass
                
        self.setStyleSheet(self.get_cyberpunk_style())
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Title
        title = QLabel("🔮 SMTP Cracker")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("""
            QLabel {
                font-size: 28px;
                font-weight: bold;
                color: #00ffff;
                text-shadow: 0 0 10px rgba(0, 255, 255, 0.8), 
                             0 0 20px rgba(0, 255, 255, 0.6),
                             0 0 30px rgba(0, 255, 255, 0.4);
                padding: 20px;
                background: rgba(0, 0, 0, 0.7);
                border: 2px solid #00ffff;
                border-radius: 15px;
                margin: 10px;
            }
        """)
        layout.addWidget(title)
        
        # Configuration panel
        config_layout = QHBoxLayout()
        
        # Email input
        email_layout = QVBoxLayout()
        email_layout.addWidget(QLabel("📧 Notification email:"))
        self.email_input = QLineEdit()
        self.email_input.setText(self.config.get('last_email', ''))
        self.email_input.setPlaceholderText("your.Hackfut_email@domain.com")
        self.email_input.textChanged.connect(self.validate_email)
        self.email_input.setStyleSheet("""
            QLineEdit {
                background: rgba(0, 20, 30, 0.8);
                border: 2px solid #00ffff;
                border-radius: 8px;
                padding: 10px;
                color: #00ffff;
                font-size: 14px;
                selection-background-color: rgba(0, 255, 255, 0.3);
            }
            QLineEdit:focus {
                border: 2px solid #ff00ff;
                box-shadow: 0 0 15px rgba(255, 0, 255, 0.5);
            }
        """)
        email_layout.addWidget(self.email_input)
        config_layout.addLayout(email_layout)
        
        # Timeout setting
        timeout_layout = QVBoxLayout()
        timeout_layout.addWidget(QLabel("⏱️ Timeout (seconds):"))
        self.timeout_input = QLineEdit()
        self.timeout_input.setText(str(self.config.get('timeout', 30)))
        self.timeout_input.setStyleSheet("""
            QLineEdit {
                background: rgba(0, 20, 30, 0.8);
                border: 2px solid #00ff00;
                border-radius: 8px;
                padding: 10px;
                color: #00ff00;
                font-size: 14px;
                selection-background-color: rgba(0, 255, 0, 0.3);
            }
        """)
        timeout_layout.addWidget(self.timeout_input)
        config_layout.addLayout(timeout_layout)
        
        layout.addLayout(config_layout)
        
        # Splitter for main content
        splitter = QSplitter(Qt.Horizontal)
        
        # Left panel - Input
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        
        input_label = QLabel("📝 Enter SMTP configurations (format: smtp.server.com|port|username|password):")
        input_label.setStyleSheet("color: #00ff00; font-weight: bold; margin: 10px 0;")
        left_layout.addWidget(input_label)
        
        self.smtp_input = QTextEdit()
        self.smtp_input.setPlaceholderText("smtp.gmail.com|587|username|password\nsmtp.office365.com|587|username|password\n# Comment lines ignored\n// Other comment\n...")
        self.smtp_input.textChanged.connect(self.validate_input)
        self.smtp_input.setStyleSheet("""
            QTextEdit {
                background: rgba(0, 20, 30, 0.8);
                border: 2px solid #00ff00;
                border-radius: 8px;
                padding: 10px;
                color: #00ff00;
                font-family: 'Courier New', monospace;
                font-size: 12px;
                selection-background-color: rgba(0, 255, 0, 0.3);
            }
        """)
        left_layout.addWidget(self.smtp_input)
        
        # Stats label
        self.stats_label = QLabel("0 valid lines | 0 invalid lines")
        self.stats_label.setStyleSheet("color: #ff00ff; font-weight: bold;")
        left_layout.addWidget(self.stats_label)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.load_btn = QPushButton("📂 Load from file")
        self.load_btn.setStyleSheet(self.get_button_style("#ff00ff"))
        self.load_btn.clicked.connect(self.load_from_file)
        button_layout.addWidget(self.load_btn)
        
        self.invalid_btn = QPushButton("🚫 View invalid lines")
        self.invalid_btn.setStyleSheet(self.get_button_style("#ff4444"))
        self.invalid_btn.clicked.connect(self.show_invalid_lines)
        self.invalid_btn.setEnabled(False)
        button_layout.addWidget(self.invalid_btn)
        
        self.start_btn = QPushButton("🚀 Start verification")
        self.start_btn.setStyleSheet(self.get_button_style("#00ffff"))
        self.start_btn.clicked.connect(self.start_verification)
        button_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("⏹️ Stop")
        self.stop_btn.setStyleSheet(self.get_button_style("#ff4444"))
        self.stop_btn.clicked.connect(self.stop_verification)
        self.stop_btn.setEnabled(False)
        button_layout.addWidget(self.stop_btn)
        
        self.clear_btn = QPushButton("🗑️ Clear")
        self.clear_btn.setStyleSheet(self.get_button_style("#ffaa00"))
        self.clear_btn.clicked.connect(self.clear_all)
        button_layout.addWidget(self.clear_btn)
        
        left_layout.addLayout(button_layout)
        
        # Right panel - Output
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        
        output_label = QLabel("📊 Real-time results:")
        output_label.setStyleSheet("color: #ff00ff; font-weight: bold; margin: 10px 0;")
        right_layout.addWidget(output_label)
        
        self.results_list = QListWidget()
        self.results_list.setStyleSheet("""
            QListWidget {
                background: rgba(20, 0, 30, 0.8);
                border: 2px solid #ff00ff;
                border-radius: 8px;
                padding: 10px;
                color: #ff00ff;
                font-family: 'Courier New', monospace;
                font-size: 11px;
                outline: none;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid rgba(255, 0, 255, 0.3);
                background: rgba(255, 0, 255, 0.1);
                margin: 2px;
                border-radius: 5px;
            }
            QListWidget::item:selected {
                background: rgba(255, 0, 255, 0.3);
                border: 1px solid #ff00ff;
            }
        """)
        right_layout.addWidget(self.results_list)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #00ffff;
                border-radius: 10px;
                text-align: center;
                color: #00ffff;
                font-weight: bold;
                background: rgba(0, 20, 30, 0.8);
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00ffff, stop:0.5 #ff00ff, stop:1 #00ffff);
                border-radius: 8px;
            }
        """)
        right_layout.addWidget(self.progress_bar)
        
        # Results summary
        self.results_summary = QLabel("Ready")
        self.results_summary.setStyleSheet("color: #00ff00; font-weight: bold;")
        right_layout.addWidget(self.results_summary)
        
        # Add widgets to splitter
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setSizes([500, 700])
        
        layout.addWidget(splitter)
        
        # Status bar
        self.statusBar().showMessage("Ready - Enter SMTP configurations and notification email")
        self.statusBar().setStyleSheet("""
            QStatusBar {
                background: rgba(0, 0, 0, 0.8);
                color: #00ff00;
                border-top: 1px solid #00ffff;
            }
        """)
        
        # Initial validation
        self.validate_email()
        self.validate_input()
    
    def get_cyberpunk_style(self):
        return """
            QMainWindow {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0a0a2a, stop:0.5 #1a1a4a, stop:1 #2a0a2a);
                color: #00ffff;
            }
            QWidget {
                background: transparent;
            }
        """
    
    def get_button_style(self, color):
        return f"""
            QPushButton {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 {color}, stop:1 #000000);
                color: white;
                border: 2px solid {color};
                border-radius: 10px;
                padding: 12px 20px;
                font-weight: bold;
                font-size: 12px;
                text-shadow: 0 0 5px rgba(255, 255, 255, 0.8);
            }}
            QPushButton:hover {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 {color}, stop:1 #111111);
                border: 2px solid #ffffff;
                box-shadow: 0 0 15px {color};
            }}
            QPushButton:pressed {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #000000, stop:1 {color});
            }}
            QPushButton:disabled {{
                background: #333333;
                border: 2px solid #666666;
                color: #666666;
            }}
        """
    
    def validate_email(self):
        """Validate email in real-time"""
        email = self.email_input.text().strip()
        if self.validator.validate_email(email):
            self.email_input.setStyleSheet("""
                QLineEdit {
                    background: rgba(0, 30, 0, 0.8);
                    border: 2px solid #00ff00;
                    border-radius: 8px;
                    padding: 10px;
                    color: #00ff00;
                    font-size: 14px;
                }
            """)
            return True
        else:
            self.email_input.setStyleSheet("""
                QLineEdit {
                    background: rgba(30, 0, 0, 0.8);
                    border: 2px solid #ff0000;
                    border-radius: 8px;
                    padding: 10px;
                    color: #ff0000;
                    font-size: 14px;
                }
            """)
            return False
    
    def validate_input(self):
        """Validate SMTP input in real-time with invalid lines handling"""
        content = self.smtp_input.toPlainText()
        lines = [line.strip() for line in content.split('\n') if line.strip()]
        
        valid_lines, invalid_lines = self.validator.filter_valid_lines(lines)
        
        # Update statistics
        valid_count = len(valid_lines)
        invalid_count = len(invalid_lines)
        
        self.stats_label.setText(f"{valid_count} valid lines | {invalid_count} invalid lines")
        
        # Save invalid lines for display
        self.invalid_lines_cache = invalid_lines
        
        # Enable/disable invalid lines view button
        self.invalid_btn.setEnabled(invalid_count > 0)
    
    def show_invalid_lines(self):
        """Show invalid lines dialog"""
        if self.invalid_lines_cache:
            dialog = InvalidLinesDialog(self.invalid_lines_cache, self)
            dialog.exec_()
    
    def load_from_file(self):
        """Load configurations from file"""
        last_dir = self.config.get('last_directory', '')
        filename, _ = QFileDialog.getOpenFileName(
            self, 
            "Load SMTP configurations", 
            last_dir, 
            "Text Files (*.txt);;All Files (*)"
        )
        
        if filename:
            try:
                # Save directory
                self.config['last_directory'] = os.path.dirname(filename)
                self.save_config()
                
                with open(filename, 'r', encoding='utf-8') as f:
                    content = f.read()
                    self.smtp_input.setPlainText(content)
                
                self.statusBar().showMessage(f"File loaded: {filename}")
                logging.info(f"File loaded: {filename}")
                
            except UnicodeDecodeError:
                # Try with different encodings
                encodings = ['latin-1', 'cp1252', 'iso-8859-1', 'utf-16']
                for encoding in encodings:
                    try:
                        with open(filename, 'r', encoding=encoding) as f:
                            content = f.read()
                            self.smtp_input.setPlainText(content)
                        self.statusBar().showMessage(f"File loaded (encoding: {encoding}): {filename}")
                        logging.info(f"File loaded with encoding {encoding}: {filename}")
                        break
                    except:
                        continue
                else:
                    self.styled_message_box(
                        QMessageBox.Critical,
                        "Error", 
                        "Unable to decode file with standard encodings"
                    )
                    logging.error(f"Unable to decode file: {filename}")
                    
            except Exception as e:
                self.styled_message_box(
                    QMessageBox.Critical,
                    "Error", 
                    f"Unable to load file: {str(e)}"
                )
                logging.error(f"File loading error: {e}")
    
    def start_verification(self):
        """Start SMTP verification"""
        # Email validation
        email = self.email_input.text().strip()
        if not self.validator.validate_email(email):
            self.styled_message_box(
                QMessageBox.Warning,
                "Warning", 
                "Please enter a valid email address for notifications"
            )
            return
        
        # SMTP data validation
        smtp_data = self.smtp_input.toPlainText().strip()
        if not smtp_data:
            self.styled_message_box(
                QMessageBox.Warning,
                "Warning",
                "Please enter SMTP configurations to test"
            )
            return
        
        # Parse and validate lines
        lines = [line.strip() for line in smtp_data.split('\n') if line.strip()]
        valid_lines, invalid_lines = self.validator.filter_valid_lines(lines)
        
        # Remove duplicates
        valid_lines = self.validator.remove_duplicates(valid_lines)
        
        if not valid_lines:
            self.styled_message_box(
                QMessageBox.Warning,
                "Warning",
                "No valid SMTP configuration found"
            )
            return
        
        # Show invalid lines
        if invalid_lines:
            invalid_msg = f"{len(invalid_lines)} invalid lines detected and will be ignored."
            reply = self.styled_message_box(
                QMessageBox.Question,
                "Invalid lines detected", 
                f"{invalid_msg}\n\nDo you want to see invalid lines details?",
                QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel
            )
            
            if reply == QMessageBox.Yes:
                self.show_invalid_lines()
                # Ask for confirmation again after display
                reply2 = self.styled_message_box(
                    QMessageBox.Question,
                    "Confirmation",
                    f"{len(valid_lines)} unique valid lines will be tested.\n\nDo you want to continue?",
                    QMessageBox.Yes | QMessageBox.No
                )
                if reply2 == QMessageBox.No:
                    return
            elif reply == QMessageBox.Cancel:
                return
        
        # Timeout configuration
        try:
            timeout = int(self.timeout_input.text())
            if timeout < 5 or timeout > 300:
                raise ValueError
        except:
            timeout = 30
            self.timeout_input.setText("30")
        
        # Disable UI during tests
        self.start_btn.setEnabled(False)
        self.load_btn.setEnabled(False)
        self.clear_btn.setEnabled(False)
        self.invalid_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        
        # Clear previous results
        self.results_list.clear()
        self.progress_bar.setValue(0)
        
        # Start tests
        self.smtp_tester = SMTPTester(valid_lines, email, timeout)
        self.smtp_tester.update_signal.connect(self.update_results)
        self.smtp_tester.progress_signal.connect(self.progress_bar.setValue)
        self.smtp_tester.finished_signal.connect(self.verification_finished)
        self.smtp_tester.error_signal.connect(self.handle_error)
        self.smtp_tester.stats_signal.connect(self.update_real_time_stats)
        self.smtp_tester.start()
        
        self.statusBar().showMessage(f"Verification in progress... {len(valid_lines)} configurations to test")
        self.results_summary.setText("Tests in progress...")
    
    def update_real_time_stats(self, success_count: int, failure_count: int):
        """Update real-time statistics"""
        total = success_count + failure_count
        if total > 0:
            percentage = (success_count / total) * 100
            self.results_summary.setText(f"In progress... Success: {success_count} | Failures: {failure_count} | Total: {total} ({percentage:.1f}%)")
    
    def stop_verification(self):
        """Stop current verification"""
        if self.smtp_tester and self.smtp_tester.isRunning():
            reply = self.styled_message_box(
                QMessageBox.Question,
                "Confirmation",
                "Do you really want to stop the current verification?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                self.smtp_tester.stop_test()
                self.statusBar().showMessage("Stop requested...")
                self.stop_btn.setEnabled(False)
    
    def update_results(self, status: str, message: str):
        """Update real-time results"""
        item_text = f"{status}\n   📋 {message}"
        self.results_list.addItem(item_text)
        self.results_list.scrollToBottom()
    
    def verification_finished(self):
        """Called when verification is completed"""
        # Reactivate UI
        self.start_btn.setEnabled(True)
        self.load_btn.setEnabled(True)
        self.clear_btn.setEnabled(True)
        self.invalid_btn.setEnabled(len(self.invalid_lines_cache) > 0)
        self.stop_btn.setEnabled(False)
        
        # Calculate final statistics
        total_items = self.results_list.count()
        success_count = sum(1 for i in range(total_items) if "✅ SUCCESS" in self.results_list.item(i).text())
        failure_count = total_items - success_count
        
        self.statusBar().showMessage("Verification completed - Results saved in smtp_success.txt")
        
        if total_items > 0:
            percentage = (success_count / total_items) * 100
            self.results_summary.setText(f"COMPLETED - Success: {success_count}/{total_items} ({percentage:.1f}%)")
        else:
            self.results_summary.setText("COMPLETED - No tests performed")
        
        # Completion message
        self.styled_message_box(
            QMessageBox.Information,
            "Completed", 
            f"SMTP verification completed!\n\n" 
            f"Results: {success_count} success out of {total_items} tests\n"
            f"Success rate: {percentage:.1f}%\n\n"
            f"Successful connections saved in 'smtp_success.txt'\n"
            f"Confirmation emails sent to the specified address."
        )
        
        # Save configuration
        self.config['last_email'] = self.email_input.text()
        self.save_config()
    
    def handle_error(self, error_message: str):
        """Handle errors reported by thread"""
        self.styled_message_box(
            QMessageBox.Critical,
            "Error", 
            f"An error occurred:\n{error_message}"
        )
        logging.error(f"Reported error: {error_message}")
    
    def clear_all(self):
        """Clear all fields"""
        reply = self.styled_message_box(
            QMessageBox.Question,
            "Confirmation", 
            "Do you really want to clear all fields?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.smtp_input.clear()
            self.results_list.clear()
            self.progress_bar.setValue(0)
            self.email_input.clear()
            self.stats_label.setText("0 valid lines | 0 invalid lines")
            self.results_summary.setText("Ready")
            self.statusBar().showMessage("Fields cleared")
            self.invalid_lines_cache = []
            self.invalid_btn.setEnabled(False)

def main():
    app = QApplication(sys.argv)
    
    # Logging configuration
    logging.info("Starting SMTP Verifier application")
    
    # Uncaught exception handling
    def exception_handler(exctype, value, traceback):
        logging.critical("Uncaught exception", exc_info=(exctype, value, traceback))
        msg = QMessageBox()
        msg.setWindowTitle("Critical Error")
        msg.setText(f"A critical error occurred:\n{str(value)}")
        msg.setIcon(QMessageBox.Critical)
        msg.setStyleSheet("""
            QMessageBox {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0a0a2a, stop:0.5 #1a1a4a, stop:1 #2a0a2a);
                color: #00ffff;
                font-family: 'Courier New';
                border: 2px solid #00ffff;
                border-radius: 10px;
            }
            QMessageBox QLabel {
                color: #00ffff;
                font-size: 12px;
            }
            QMessageBox QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #00ffff, stop:1 #000000);
                color: #000000;
                border: 2px solid #00ffff;
                border-radius: 8px;
                padding: 8px 15px;
                font-weight: bold;
                min-width: 80px;
            }
        """)
        msg.exec_()
    
    sys.excepthook = exception_handler
    
    # Cyberpunk font
    font = QFont("Courier New", 10)
    app.setFont(font)
    
    # Create and show window
    window = CyberPunkSMTPChecker()
    window.show()
    
    try:
        sys.exit(app.exec_())
    except Exception as e:
        logging.critical(f"Error during execution: {e}")
        raise

if __name__ == '__main__':
    main()