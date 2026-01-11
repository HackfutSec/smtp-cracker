# 🔮 SMTP Cracker - Professional SMTP Verification Tool

![SMTP Cracker Interface](https://ibb.co/bjCBfZMg)

## 📌 Table of Contents
- [✨ Features](#-features)
- [🎯 Purpose](#-purpose)
- [📦 Installation](#-installation)
- [🚀 Usage](#-usage)
- [⚙️ Configuration](#️-configuration)
- [🔒 Security](#-security)
- [📁 Project Structure](#-project-structure)
- [🤝 Contributing](#-contributing)
- [⚠️ Disclaimer](#️-disclaimer)
- [📄 License](#-license)

## ✨ Features

### 🎨 **Cyberpunk Interface**
- Modern dark theme with neon colors
- Real-time visual feedback
- Responsive and intuitive design
- Gradient effects and custom styling

### 🔧 **Core Functionality**
- **Multi-protocol SMTP testing** (SSL/TLS, STARTTLS)
- **Batch processing** of SMTP configurations
- **Real-time validation** with instant feedback
- **Duplicate detection** using MD5 hashing
- **Automatic backup** of successful connections

### 📊 **Advanced Features**
- **Smart input validation** with detailed error reporting
- **Email confirmation** on successful connections
- **Progress tracking** with detailed statistics
- **Configuration persistence** between sessions
- **Logging system** with file and console output

### 🛡️ **Security**
- Password masking for display
- Secure connection handling
- Configurable timeouts
- Input sanitization and validation

## 🎯 Purpose

SMTP Cracker is a professional tool designed for **legitimate testing** of SMTP server configurations. It helps system administrators, developers, and security professionals to:

- ✅ Verify SMTP server accessibility
- ✅ Test authentication credentials
- ✅ Validate email sending capabilities
- ✅ Audit SMTP configurations
- ✅ Identify working email servers

## 📦 Installation

### Prerequisites
- Python 3.7 or higher
- PyQt5 library

### Installation Steps

```bash
# Clone the repository
git clone https://github.com/HackfutSec/smtp-cracker.git
cd smtp-cracker

# Install dependencies
pip install PyQt5

# Run the application
python smtpCracker.py
```

### Optional: Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows
pip install -r requirements.txt
```

## 🚀 Usage

### 1. **Input Format**
Enter SMTP configurations in the following format:
```
smtp.server.com|port|username|password
```

**Example:**
```
smtp.gmail.com|587|user@gmail.com|password123
smtp.office365.com|465|user@company.com|securepass
smtp-mail.outlook.com|587|contact@outlook.com|mypassword
```

### 2. **Basic Workflow**

1. **Enter notification email** for confirmation messages
2. **Paste SMTP configurations** or load from file
3. **Adjust timeout** if needed (default: 30 seconds)
4. **Click "Start verification"** to begin testing
5. **Monitor real-time results** in the output panel
6. **Review successful connections** in `smtp_success.txt`

### 3. **File Loading**
- Supports multiple encodings (UTF-8, Latin-1, etc.)
- Automatic comment filtering (#, //, ;)
- Duplicate removal
- Invalid line detection

## ⚙️ Configuration

### Application Settings
The application automatically saves configuration in `smtp_checker_config.json`:
```json
{
    "last_email": "your@email.com",
    "window_geometry": "window_size_data",
    "auto_save": true,
    "max_workers": 5,
    "timeout": 30,
    "last_directory": "/path/to/last/folder"
}
```

### Timeout Settings
- **Default**: 30 seconds
- **Range**: 5 to 300 seconds
- **Recommended**: 30-60 seconds for reliable testing

## 🔒 Security Features

### Password Protection
- Passwords are **never displayed in plain text**
- Masking format: `pa****rd`
- Secure storage in memory during processing
- Encrypted logging (optional)

### Connection Security
- SSL/TLS certificate validation
- STARTTLS upgrade support
- Safe timeout handling
- Graceful error recovery

### Data Management
- Automatic backup of successful connections
- Log rotation and management
- Secure temporary file handling
- Memory cleanup after processing

## 📁 Project Structure

```
smtp-cracker/
├── smtpCracker.py          # Main application file
├── smtp_checker_config.json # User configuration
├── smtp_success.txt        # Successful connections
├── backups/                # Automatic backups
│   └── smtp_success_backup_*.txt
├── smtp_checker.log       # Application logs
└── README.md              # This file
```

### Key Components

1. **`ConfigManager`** - Persistent configuration handling
2. **`InputValidator`** - Comprehensive input validation
3. **`SecurityManager`** - Security and data protection
4. **`SMTPTester`** - Core SMTP testing logic
5. **`CyberPunkSMTPChecker`** - Main GUI application

## 🤝 Contributing

We welcome contributions! Here's how to help:

### Bug Reports
1. Check existing issues
2. Create detailed bug report
3. Include steps to reproduce

### Feature Requests
1. Describe the feature
2. Explain use case
3. Suggest implementation

### Code Contributions
1. Fork the repository
2. Create feature branch
3. Follow PEP 8 style guide
4. Add tests if applicable
5. Submit pull request

### Coding Standards
- Use type hints
- Add docstrings
- Follow PyQt5 patterns
- Include logging statements

## ⚠️ Disclaimer

**IMPORTANT LEGAL NOTICE**

This tool is designed for **LEGITIMATE PURPOSES ONLY**, including:

- ✅ Testing your own email servers
- ✅ Educational purposes
- ✅ Authorized security audits
- ✅ System administration tasks

**PROHIBITED USES:**
- ❌ Unauthorized access to systems
- ❌ Spamming or harassment
- ❌ Credential theft
- ❌ Illegal activities

The developers are **NOT RESPONSIBLE** for misuse of this tool. Users must comply with all applicable laws and regulations.

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

### Key Permissions
- Commercial use
- Modification
- Distribution
- Private use

### Requirements
- Include original copyright notice
- Include license copy
- State changes made

### No Warranty
This software is provided "as is", without warranty of any kind.

---

## 🚨 Support

### Common Issues
1. **Connection timeouts**: Increase timeout value
2. **Authentication failures**: Verify credentials
3. **SSL errors**: Check server certificates
4. **Memory issues**: Reduce batch size

### Troubleshooting
- Check `smtp_checker.log` for errors
- Verify network connectivity
- Test with single configuration first
- Ensure firewall allows SMTP traffic

### Getting Help
- Open GitHub issue
- Check existing documentation
- Review error logs

---

**🔧 Built with PyQt5 | 🐍 Python 3 | 🔒 Security First**

---
*Last Updated: January 2024 | Version: 1.0.0*

---

<div align="center">
  <img src="https://img.shields.io/badge/Python-3.7%2B-blue" alt="Python">
  <img src="https://img.shields.io/badge/PyQt5-5.15%2B-green" alt="PyQt5">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="License">
  <img src="https://img.shields.io/badge/Status-Active-success" alt="Status">
</div>

<div align="center">
  <sub>Built with ❤️ by <a href="https://github.com/HackfutSec">HackfutSec</a></sub>
</div>
