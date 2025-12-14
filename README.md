# 🛡️ Phishing URL Detector

A powerful, heuristic-based URL phishing detector with both **CLI** and **GUI** interfaces. Analyze URLs for potential phishing threats with detailed threat breakdowns, domain analysis, and visual risk assessments.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)

---

## ✨ Features

### 🔍 Comprehensive URL Analysis
- **Threat Percentage Scoring** - Calculate risk as a percentage (0-100%)
- **Domain Breakdown** - Extract and analyze subdomains, base domain, TLD
- **Brand Impersonation Detection** - Detect fake PayPal, Google, Microsoft, etc.
- **Suspicious TLD Detection** - Flag high-risk top-level domains
- **URL Shortener Detection** - Identify bit.ly, tinyurl, and other shorteners

### 🎯 Threat Categories
| Category | Description |
|----------|-------------|
| **Domain Trust** | IP addresses, suspicious TLDs, URL shorteners |
| **URL Structure** | Excessive subdomains, hyphens, length |
| **Brand Safety** | Brand impersonation attempts |
| **Encoding** | Punycode, percent-encoding, non-ASCII chars |
| **Protocol Security** | HTTP vs HTTPS, unusual ports |

### 📊 Threat Levels
| Level | Score Range | Description |
|-------|-------------|-------------|
| 🟢 **SAFE** | 0-10% | No significant threats detected |
| 🔵 **LOW** | 10-25% | Minor concerns |
| 🟡 **MEDIUM** | 25-40% | Suspicious characteristics |
| 🟠 **HIGH** | 40-60% | Likely phishing attempt |
| 🔴 **CRITICAL** | 60-100% | High probability of phishing |

---

## 🖥️ Screenshots

### GUI Interface
The modern GUI features:
- Dark theme design
- Animated threat gauge
- Color-coded risk categories
- Detailed threat indicators

### CLI Interface
The CLI provides:
- Colored terminal output
- ASCII threat gauge
- Detailed domain breakdown
- Risk category overview

---

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- tkinter (included with Python on Windows)

### Clone the Repository
```bash
git clone https://github.com/DHANUSH630/Phishing-URL-Detector.git
cd Phishing-URL-Detector
```

### No External Dependencies Required!
This project uses only Python standard library modules.

---

## 📖 Usage

### GUI Mode (Recommended)
```bash
python phishing_detector_gui.py
```
1. Enter a URL in the input field
2. Click "🔍 Analyze URL" or press Enter
3. View the comprehensive threat analysis

### CLI Mode
```bash
python index.py
```
Then enter the URL when prompted.

### Programmatic Usage
```python
from index import analyze_url, is_phishing

# Full analysis
result = analyze_url("https://suspicious-site.xyz/login")
print(f"Threat Level: {result.threat_level}")
print(f"Threat %: {result.threat_percentage}%")

# Simple check
if is_phishing("https://paypal-secure.tk/verify"):
    print("⚠️ This URL is likely a phishing attempt!")
```

---

## 🔬 Detection Techniques

### Heuristic Checks Performed:
1. **IP Address Usage** - Legitimate sites rarely use IP addresses
2. **URL Shorteners** - Often used to hide malicious destinations
3. **Punycode/IDN** - Homograph attacks using similar-looking characters
4. **Suspicious TLDs** - .tk, .ml, .xyz often used in phishing
5. **@ Symbol** - Credential injection technique
6. **Excessive Length** - Long URLs hide suspicious content
7. **Multiple Subdomains** - Fake legitimacy (e.g., paypal.secure.login.xyz)
8. **Sensitive Keywords** - login, password, verify, bank, etc.
9. **Brand Impersonation** - paypal-secure.com vs paypal.com
10. **Non-standard Ports** - Unusual ports indicate unofficial services
11. **HTTP Protocol** - Lack of HTTPS encryption
12. **Heavy Encoding** - Percent-encoding to obfuscate content

---

## 📁 Project Structure

```
Phishing-URL-Detector/
├── index.py                    # CLI version with colored output
├── phishing_detector_gui.py    # Modern GUI application
├── README.md                   # This file
└── LICENSE                     # MIT License
```

---

## 🧪 Example Analysis

**Testing URL:** `http://paypal-secure-login.xyz/verify?token=123`

**Results:**
- **Threat Level:** MEDIUM (36.5%)
- **Indicators Found:**
  - 🔴 Brand Impersonation (PayPal) - +30 pts
  - 🔴 Suspicious TLD (.xyz) - +15 pts  
  - 🟡 Sensitive Keywords (verify, token) - +12 pts
  - 🟡 No HTTPS - +10 pts

---

## 🤝 Contributing

Contributions are welcome! Feel free to:
- Report bugs
- Suggest new features
- Add more brand domains
- Improve detection heuristics

---

## ⚠️ Disclaimer

This tool provides heuristic-based analysis and should be used as one of many security measures. It may produce false positives or miss sophisticated phishing attempts. Always exercise caution when clicking on unknown URLs.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**DHANUSH630**

---

## 🌟 Star this repo if you find it useful!
