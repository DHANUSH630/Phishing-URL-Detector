import re
import sys
import os
from urllib.parse import urlparse, parse_qs
from dataclasses import dataclass
from typing import Optional, List, Dict, Set
from datetime import datetime

# Fix Windows console encoding
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    os.system('')  # Enable ANSI escape codes on Windows

# ============================================================
# Enhanced URL Phishing Detector
# - Detailed threat analysis with percentage scoring
# - Subdomain & domain breakdown
# - Color-coded terminal output
# - Comprehensive risk assessment
# ============================================================

# ANSI Color codes for terminal output
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    
    # Foreground colors
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    
    # Background colors
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'

# Known URL shorteners
SHORTENERS = {
    'bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'shorturl.at', 'cutt.ly', 'rb.gy', 'lnkd.in',
    'rebrand.ly', 's.id', 'shorte.st', 'v.gd', 'bl.ink', 't.ly',
    'tiny.cc', 'clck.ru', 'short.io', 'bitly.com', 'soo.gd'
}

# Suspicious TLDs often used in phishing
SUSPICIOUS_TLDS = {
    'xyz': 15, 'top': 15, 'gq': 20, 'work': 12, 'tk': 25, 'ml': 25, 'cf': 25,
    'fit': 15, 'cam': 18, 'party': 12, 'click': 18, 'link': 10, 'review': 12,
    'date': 10, 'zip': 20, 'mom': 15, 'country': 12, 'stream': 12, 'download': 15,
    'ru': 8, 'cn': 8, 'pw': 20, 'cc': 12, 'buzz': 10, 'best': 10
}

# Multi-level domain suffixes
MULTI_LEVEL_SUFFIXES = {
    'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'net.uk',
    'com.au', 'net.au', 'org.au', 'edu.au',
    'co.jp', 'ne.jp', 'or.jp', 'ac.jp',
    'co.in', 'net.in', 'org.in', 'ac.in',
    'com.br', 'net.br', 'org.br',
    'co.nz', 'net.nz', 'org.nz',
    'co.za', 'net.za', 'org.za',
}

# Sensitive keywords indicating credential harvesting
SENSITIVE_KEYWORDS = {
    'login': 15, 'verify': 12, 'update': 10, 'confirm': 12, 'secure': 10,
    'account': 12, 'password': 18, 'bank': 20, 'invoice': 15, 'payment': 18,
    'token': 10, 'session': 8, 'signin': 15, 'wallet': 18, 'credit': 15,
    'ssn': 25, 'social-security': 25, 'reset': 10, 'expire': 12, 'suspend': 15,
    'unlock': 12, 'reactivate': 12, 'authenticate': 10
}

# Known brand domains for impersonation detection
BRAND_DOMAINS = {
    'paypal': {'paypal.com', 'paypal.me'},
    'apple': {'apple.com', 'icloud.com', 'apple.co'},
    'google': {'google.com', 'gmail.com', 'google.co', 'accounts.google.com'},
    'microsoft': {'microsoft.com', 'live.com', 'office.com', 'outlook.com', 'onedrive.com'},
    'dropbox': {'dropbox.com'},
    'amazon': {'amazon.com', 'amazon.co.uk', 'aws.amazon.com'},
    'chase': {'chase.com'},
    'bankofamerica': {'bankofamerica.com', 'bofa.com'},
    'facebook': {'facebook.com', 'fb.com', 'fb.me'},
    'instagram': {'instagram.com'},
    'twitter': {'twitter.com', 'x.com'},
    'netflix': {'netflix.com'},
    'spotify': {'spotify.com'},
    'linkedin': {'linkedin.com'},
    'whatsapp': {'whatsapp.com', 'wa.me'},
}


@dataclass
class DomainInfo:
    """Structured domain information"""
    full_host: str
    tld: str
    base_domain: str
    subdomain: str
    subdomain_levels: int
    is_ip_address: bool
    is_punycode: bool


@dataclass
class ThreatIndicator:
    """Individual threat indicator with severity"""
    name: str
    severity: str  # 'critical', 'high', 'medium', 'low', 'info'
    score: int
    description: str


@dataclass
class AnalysisResult:
    """Complete analysis result"""
    url: str
    domain_info: DomainInfo
    threat_percentage: float
    threat_level: str
    threat_indicators: List[ThreatIndicator]
    total_score: int
    max_score: int
    protocol: str
    path: str
    query_params: Dict[str, List[str]]
    analysis_time: str


def is_ip(host: str) -> bool:
    """Check if host is an IP address"""
    if not host:
        return False
    ipv4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    ipv6 = re.compile(r"^\[?[0-9a-fA-F:]+\]?$")
    if ipv4.match(host):
        parts = host.split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    return bool(ipv6.match(host))


def is_punycode(host: str) -> bool:
    """Check for internationalized domain names (IDN)"""
    return host.lower().startswith('xn--') or 'xn--' in host.lower()


def has_non_ascii(text: str) -> bool:
    """Check for non-ASCII characters (homograph attacks)"""
    return any(ord(c) > 127 for c in text)


def percent_encoding_count(url: str) -> int:
    """Count percent-encoded sequences"""
    return len(re.findall(r"%[0-9A-Fa-f]{2}", url))


def extract_domain_info(host: str) -> DomainInfo:
    """Extract detailed domain information"""
    if not host:
        return DomainInfo('', '', '', '', 0, False, False)
    
    is_ip_addr = is_ip(host)
    is_puny = is_punycode(host)
    
    if is_ip_addr:
        return DomainInfo(host, '', host, '', 0, True, False)
    
    parts = host.lower().split('.')
    
    # Get TLD
    tld = parts[-1] if parts else ''
    
    # Determine base domain
    if len(parts) < 2:
        return DomainInfo(host, tld, host, '', 0, False, is_puny)
    
    maybe_suffix = '.'.join(parts[-2:])
    if maybe_suffix in MULTI_LEVEL_SUFFIXES and len(parts) >= 3:
        base = '.'.join(parts[-3:])
        subdomain = '.'.join(parts[:-3])
        subdomain_levels = len(parts) - 3
    else:
        base = '.'.join(parts[-2:])
        subdomain = '.'.join(parts[:-2])
        subdomain_levels = len(parts) - 2
    
    return DomainInfo(
        full_host=host,
        tld=tld,
        base_domain=base,
        subdomain=subdomain,
        subdomain_levels=subdomain_levels,
        is_ip_address=is_ip_addr,
        is_punycode=is_puny
    )


def analyze_url(url: str) -> AnalysisResult:
    """Perform comprehensive URL analysis"""
    indicators: List[ThreatIndicator] = []
    total_score = 0
    max_possible_score = 200  # Maximum threat score
    
    # Parse URL
    try:
        parsed = urlparse(url)
    except Exception:
        return AnalysisResult(
            url=url,
            domain_info=DomainInfo('', '', '', '', 0, False, False),
            threat_percentage=100.0,
            threat_level='CRITICAL',
            threat_indicators=[ThreatIndicator('Invalid URL', 'critical', 100, 'URL parsing failed completely')],
            total_score=100,
            max_score=100,
            protocol='unknown',
            path='',
            query_params={},
            analysis_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )
    
    host = (parsed.hostname or '').lower()
    path = parsed.path or ''
    query = parsed.query or ''
    protocol = parsed.scheme or 'unknown'
    
    # Extract domain info
    domain_info = extract_domain_info(host)
    
    # Parse query parameters
    try:
        query_params = parse_qs(query)
    except:
        query_params = {}
    
    # ==================== THREAT ANALYSIS ====================
    
    # 1. IP Address Check
    if domain_info.is_ip_address:
        score = 30
        total_score += score
        indicators.append(ThreatIndicator(
            'IP Address Used',
            'critical',
            score,
            'URL uses IP address instead of domain name - common phishing technique'
        ))
    
    # 2. URL Shortener
    if host in SHORTENERS:
        score = 25
        total_score += score
        indicators.append(ThreatIndicator(
            'URL Shortener',
            'high',
            score,
            f'Uses known URL shortener ({host}) to hide destination'
        ))
    
    # 3. Punycode/IDN Check
    if domain_info.is_punycode:
        score = 20
        total_score += score
        indicators.append(ThreatIndicator(
            'Punycode/IDN Domain',
            'high',
            score,
            'Internationalized domain name - potential homograph attack'
        ))
    
    # 4. Non-ASCII Characters
    if has_non_ascii(url):
        score = 18
        total_score += score
        indicators.append(ThreatIndicator(
            'Non-ASCII Characters',
            'high',
            score,
            'URL contains non-ASCII characters - possible obfuscation'
        ))
    
    # 5. @ Symbol (credential injection)
    if '@' in url:
        score = 25
        total_score += score
        indicators.append(ThreatIndicator(
            '@ Symbol Present',
            'critical',
            score,
            'Contains @ symbol - credential injection/URL spoofing technique'
        ))
    
    # 6. Suspicious TLD
    tld = domain_info.tld.lower()
    if tld in SUSPICIOUS_TLDS:
        score = SUSPICIOUS_TLDS[tld]
        total_score += score
        indicators.append(ThreatIndicator(
            f'Suspicious TLD (.{tld})',
            'medium' if score < 15 else 'high',
            score,
            f'TLD ".{tld}" is commonly associated with malicious domains'
        ))
    
    # 7. URL Length
    url_len = len(url)
    if url_len >= 200:
        score = 20
        total_score += score
        indicators.append(ThreatIndicator(
            'Extremely Long URL',
            'high',
            score,
            f'URL is {url_len} characters - often used to hide suspicious content'
        ))
    elif url_len >= 100:
        score = 10
        total_score += score
        indicators.append(ThreatIndicator(
            'Long URL',
            'medium',
            score,
            f'URL is {url_len} characters - moderately suspicious length'
        ))
    
    # 8. Subdomain Analysis
    if domain_info.subdomain_levels >= 4:
        score = 20
        total_score += score
        indicators.append(ThreatIndicator(
            'Excessive Subdomains',
            'high',
            score,
            f'{domain_info.subdomain_levels} subdomain levels - commonly used to fake legitimacy'
        ))
    elif domain_info.subdomain_levels >= 3:
        score = 12
        total_score += score
        indicators.append(ThreatIndicator(
            'Multiple Subdomains',
            'medium',
            score,
            f'{domain_info.subdomain_levels} subdomain levels - moderately suspicious'
        ))
    
    # 9. Hyphen Count
    hyphen_count = host.count('-') if host else 0
    if hyphen_count >= 4:
        score = 15
        total_score += score
        indicators.append(ThreatIndicator(
            'Many Hyphens',
            'medium',
            score,
            f'{hyphen_count} hyphens in domain - often used to mimic legitimate domains'
        ))
    elif hyphen_count >= 3:
        score = 8
        total_score += score
        indicators.append(ThreatIndicator(
            'Multiple Hyphens',
            'low',
            score,
            f'{hyphen_count} hyphens in domain'
        ))
    
    # 10. Excessive Digits
    digit_count = sum(ch.isdigit() for ch in host)
    if digit_count >= 7:
        score = 12
        total_score += score
        indicators.append(ThreatIndicator(
            'Excessive Digits',
            'medium',
            score,
            f'{digit_count} digits in domain - unusual for legitimate sites'
        ))
    
    # 11. Sensitive Keywords
    text_to_check = (path + ' ' + query).lower()
    found_keywords = [k for k in SENSITIVE_KEYWORDS if k in text_to_check]
    if found_keywords:
        keyword_score = max(SENSITIVE_KEYWORDS[k] for k in found_keywords)
        total_score += keyword_score
        indicators.append(ThreatIndicator(
            'Sensitive Keywords',
            'high' if keyword_score >= 15 else 'medium',
            keyword_score,
            f'Contains sensitive terms: {", ".join(found_keywords[:3])}'
        ))
    
    # 12. Unusual Port
    if parsed.port and parsed.port not in (80, 443):
        score = 15
        total_score += score
        indicators.append(ThreatIndicator(
            f'Unusual Port (:{parsed.port})',
            'medium',
            score,
            f'Non-standard port {parsed.port} - may indicate unofficial service'
        ))
    
    # 13. Heavy Percent Encoding
    pct_count = percent_encoding_count(url)
    if pct_count >= 8:
        score = 15
        total_score += score
        indicators.append(ThreatIndicator(
            'Heavy Encoding',
            'high',
            score,
            f'{pct_count} percent-encoded sequences - URL obfuscation'
        ))
    elif pct_count >= 5:
        score = 8
        total_score += score
        indicators.append(ThreatIndicator(
            'Notable Encoding',
            'low',
            score,
            f'{pct_count} percent-encoded sequences'
        ))
    
    # 14. Brand Impersonation
    base = domain_info.base_domain.lower()
    for brand, allowed_domains in BRAND_DOMAINS.items():
        if brand in host:
            if base not in allowed_domains:
                score = 30
                total_score += score
                indicators.append(ThreatIndicator(
                    f'Brand Impersonation ({brand.title()})',
                    'critical',
                    score,
                    f'Contains "{brand}" but domain "{base}" is not official'
                ))
                break
    
    # 15. HTTP (No HTTPS)
    if protocol == 'http':
        score = 10
        total_score += score
        indicators.append(ThreatIndicator(
            'No HTTPS',
            'medium',
            score,
            'Uses insecure HTTP protocol'
        ))
    
    # 16. Double Extension
    if re.search(r'\.(html|php|asp|htm)\.[a-z]{2,4}$', path.lower()):
        score = 20
        total_score += score
        indicators.append(ThreatIndicator(
            'Double Extension',
            'high',
            score,
            'File has double extension - potential malware technique'
        ))
    
    # Calculate threat percentage
    threat_percentage = min((total_score / max_possible_score) * 100, 100)
    
    # Determine threat level
    if threat_percentage >= 60:
        threat_level = 'CRITICAL'
    elif threat_percentage >= 40:
        threat_level = 'HIGH'
    elif threat_percentage >= 25:
        threat_level = 'MEDIUM'
    elif threat_percentage >= 10:
        threat_level = 'LOW'
    else:
        threat_level = 'SAFE'
    
    return AnalysisResult(
        url=url,
        domain_info=domain_info,
        threat_percentage=round(threat_percentage, 1),
        threat_level=threat_level,
        threat_indicators=indicators,
        total_score=total_score,
        max_score=max_possible_score,
        protocol=protocol,
        path=path,
        query_params=query_params,
        analysis_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )


def get_threat_color(level: str) -> str:
    """Get color code based on threat level"""
    colors = {
        'CRITICAL': Colors.RED + Colors.BOLD,
        'HIGH': Colors.RED,
        'MEDIUM': Colors.YELLOW,
        'LOW': Colors.CYAN,
        'SAFE': Colors.GREEN,
    }
    return colors.get(level, Colors.WHITE)


def get_severity_color(severity: str) -> str:
    """Get color code based on indicator severity"""
    colors = {
        'critical': Colors.RED + Colors.BOLD,
        'high': Colors.RED,
        'medium': Colors.YELLOW,
        'low': Colors.CYAN,
        'info': Colors.DIM,
    }
    return colors.get(severity, Colors.WHITE)


def print_separator(char: str = '═', width: int = 70):
    """Print a separator line"""
    print(f"{Colors.DIM}{char * width}{Colors.RESET}")


def print_header(text: str, width: int = 70):
    """Print a centered header"""
    padding = (width - len(text) - 2) // 2
    print(f"{Colors.BOLD}{Colors.BLUE}{'═' * padding} {text} {'═' * padding}{Colors.RESET}")


def draw_threat_gauge(percentage: float, level: str):
    """Draw a visual threat level gauge/graph"""
    width = 60
    
    # Define zones with their ranges and colors
    zones = [
        (0, 10, 'SAFE', Colors.GREEN),
        (10, 25, 'LOW', Colors.CYAN),
        (25, 40, 'MEDIUM', Colors.YELLOW),
        (40, 60, 'HIGH', Colors.RED),
        (60, 100, 'CRITICAL', Colors.RED + Colors.BOLD),
    ]
    
    print(f"\n{Colors.BOLD}📈 THREAT LEVEL GAUGE:{Colors.RESET}")
    print()
    
    # Top border
    print(f"   ╔{'═' * (width + 2)}╗")
    
    # Draw the gauge bar
    bar = ""
    for i in range(width):
        pos_pct = (i / width) * 100
        for start, end, name, color in zones:
            if start <= pos_pct < end:
                bar += f"{color}█{Colors.RESET}"
                break
    
    print(f"   ║ {bar} ║")
    
    # Draw the pointer
    pointer_pos = int((percentage / 100) * width)
    pointer_pos = min(pointer_pos, width - 1)
    pointer_line = " " * pointer_pos + "▲"
    threat_color = get_threat_color(level)
    print(f"   ║ {threat_color}{pointer_line}{Colors.RESET}{' ' * (width - pointer_pos - 1)} ║")
    
    # Draw percentage markers
    print(f"   ╟{'─' * (width + 2)}╢")
    markers = "0%       10%      25%      40%      60%           100%"
    print(f"   ║ {Colors.DIM}{markers}{Colors.RESET} ║")
    
    # Draw zone labels
    print(f"   ╟{'─' * (width + 2)}╢")
    zone_labels = f"{Colors.GREEN}SAFE{Colors.RESET}  {Colors.CYAN}LOW{Colors.RESET}   {Colors.YELLOW}MEDIUM{Colors.RESET}   {Colors.RED}HIGH{Colors.RESET}    {Colors.RED}{Colors.BOLD}CRITICAL{Colors.RESET}"
    print(f"   ║ {zone_labels}         ║")
    
    # Bottom border
    print(f"   ╚{'═' * (width + 2)}╝")
    
    # Current position indicator
    print()
    print(f"   {threat_color}► Current Threat: {percentage:.1f}% ({level}){Colors.RESET}")


def draw_threat_breakdown_chart(indicators: List[ThreatIndicator], max_score: int):
    """Draw a horizontal bar chart showing threat breakdown by category"""
    if not indicators:
        return
    
    print(f"\n{Colors.BOLD}📊 THREAT BREAKDOWN CHART:{Colors.RESET}")
    print()
    
    # Group by severity
    severity_scores = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for ind in indicators:
        severity_scores[ind.severity] = severity_scores.get(ind.severity, 0) + ind.score
    
    max_bar = 40
    total_score = sum(severity_scores.values())
    
    severity_info = [
        ('critical', 'CRITICAL', Colors.RED + Colors.BOLD),
        ('high', 'HIGH', Colors.RED),
        ('medium', 'MEDIUM', Colors.YELLOW),
        ('low', 'LOW', Colors.CYAN),
    ]
    
    for sev_key, sev_label, sev_color in severity_info:
        score = severity_scores.get(sev_key, 0)
        if score > 0:
            bar_len = int((score / max_score) * max_bar)
            bar_len = max(1, bar_len)
            bar = '█' * bar_len
            pct = (score / max_score) * 100
            print(f"   {sev_label:>10} │ {sev_color}{bar}{Colors.RESET} {score} pts ({pct:.1f}%)")
    
    print(f"   {'─' * 12}┼{'─' * 50}")
    print(f"   {'TOTAL':>10} │ {total_score} / {max_score} points")


def draw_risk_radar(result):
    """Draw a simplified risk radar showing different risk categories"""
    print(f"\n{Colors.BOLD}🎯 RISK CATEGORY OVERVIEW:{Colors.RESET}")
    print()
    
    # Define risk categories
    categories = {
        'Domain Trust': 0,
        'URL Structure': 0,
        'Brand Safety': 0,
        'Encoding/Obfuscation': 0,
        'Protocol Security': 0,
    }
    
    # Map indicators to categories
    category_mapping = {
        'IP Address Used': 'Domain Trust',
        'URL Shortener': 'Domain Trust',
        'Punycode/IDN Domain': 'Domain Trust',
        'Suspicious TLD': 'Domain Trust',
        'Non-ASCII Characters': 'Encoding/Obfuscation',
        '@ Symbol Present': 'URL Structure',
        'Extremely Long URL': 'URL Structure',
        'Long URL': 'URL Structure',
        'Excessive Subdomains': 'URL Structure',
        'Multiple Subdomains': 'URL Structure',
        'Many Hyphens': 'URL Structure',
        'Multiple Hyphens': 'URL Structure',
        'Excessive Digits': 'URL Structure',
        'Sensitive Keywords': 'URL Structure',
        'Heavy Encoding': 'Encoding/Obfuscation',
        'Notable Encoding': 'Encoding/Obfuscation',
        'No HTTPS': 'Protocol Security',
        'Double Extension': 'Encoding/Obfuscation',
    }
    
    # Calculate category scores
    for indicator in result.threat_indicators:
        name = indicator.name
        # Check for brand impersonation
        if 'Brand Impersonation' in name:
            categories['Brand Safety'] += indicator.score
        elif 'Unusual Port' in name:
            categories['Protocol Security'] += indicator.score
        elif 'Suspicious TLD' in name:
            categories['Domain Trust'] += indicator.score
        else:
            for key, cat in category_mapping.items():
                if key in name:
                    categories[cat] += indicator.score
                    break
    
    # Draw the overview
    max_cat_score = 50  # Max score per category for visualization
    bar_width = 30
    
    for cat_name, cat_score in categories.items():
        if cat_score > 0:
            fill = min(int((cat_score / max_cat_score) * bar_width), bar_width)
            
            if cat_score >= 25:
                color = Colors.RED
                status = "HIGH"
            elif cat_score >= 15:
                color = Colors.YELLOW
                status = "MED"
            elif cat_score >= 5:
                color = Colors.CYAN
                status = "LOW"
            else:
                color = Colors.GREEN
                status = "OK"
            
            bar = '▓' * fill + '░' * (bar_width - fill)
            print(f"   {cat_name:>22} │ {color}{bar}{Colors.RESET} [{status}]")
        else:
            bar = '░' * bar_width
            print(f"   {cat_name:>22} │ {Colors.GREEN}{bar}{Colors.RESET} [OK]")


def display_results(result: AnalysisResult):
    """Display analysis results with formatting"""
    print()
    print_separator('═')
    print_header('🔍 URL THREAT ANALYSIS REPORT')
    print_separator('═')
    
    # URL Display
    print(f"\n{Colors.BOLD}📎 URL:{Colors.RESET}")
    print(f"   {Colors.CYAN}{result.url}{Colors.RESET}")
    
    # Threat Level Banner
    threat_color = get_threat_color(result.threat_level)
    print(f"\n{Colors.BOLD}⚠️  THREAT ASSESSMENT:{Colors.RESET}")
    print(f"   {threat_color}┌{'─' * 40}┐{Colors.RESET}")
    print(f"   {threat_color}│{' ' * 10}THREAT LEVEL: {result.threat_level:^14}│{Colors.RESET}")
    print(f"   {threat_color}│{' ' * 10}THREAT SCORE: {result.threat_percentage:>5.1f}%{' ' * 8}│{Colors.RESET}")
    print(f"   {threat_color}└{'─' * 40}┘{Colors.RESET}")
    
    # Progress Bar
    bar_width = 40
    filled = int((result.threat_percentage / 100) * bar_width)
    bar = '█' * filled + '░' * (bar_width - filled)
    print(f"\n   {Colors.DIM}Risk:{Colors.RESET} [{threat_color}{bar}{Colors.RESET}] {result.threat_percentage}%")
    
    # Domain Information
    print(f"\n{Colors.BOLD}🌐 DOMAIN BREAKDOWN:{Colors.RESET}")
    print_separator('─')
    di = result.domain_info
    
    print(f"   {'Full Host:':<18} {Colors.WHITE}{di.full_host or 'N/A'}{Colors.RESET}")
    print(f"   {'Base Domain:':<18} {Colors.GREEN}{di.base_domain or 'N/A'}{Colors.RESET}")
    print(f"   {'Subdomain:':<18} {Colors.YELLOW}{di.subdomain or '(none)'}{Colors.RESET}")
    print(f"   {'Subdomain Levels:':<18} {Colors.CYAN}{di.subdomain_levels}{Colors.RESET}")
    print(f"   {'TLD:':<18} {Colors.MAGENTA}.{di.tld or 'N/A'}{Colors.RESET}")
    print(f"   {'Protocol:':<18} {Colors.BLUE}{result.protocol}{Colors.RESET}")
    
    if di.is_ip_address:
        print(f"   {'Type:':<18} {Colors.RED}IP Address{Colors.RESET}")
    if di.is_punycode:
        print(f"   {'Encoding:':<18} {Colors.RED}Punycode/IDN{Colors.RESET}")
    
    # Path and Query
    if result.path and result.path != '/':
        print(f"\n{Colors.BOLD}📁 PATH:{Colors.RESET}")
        print(f"   {Colors.DIM}{result.path}{Colors.RESET}")
    
    if result.query_params:
        print(f"\n{Colors.BOLD}🔑 QUERY PARAMETERS:{Colors.RESET}")
        for key, values in list(result.query_params.items())[:5]:
            val_str = ', '.join(values)[:50]
            print(f"   {Colors.CYAN}{key}{Colors.RESET} = {Colors.DIM}{val_str}{Colors.RESET}")
    
    # Threat Indicators
    if result.threat_indicators:
        print(f"\n{Colors.BOLD}🚨 THREAT INDICATORS ({len(result.threat_indicators)}):{Colors.RESET}")
        print_separator('─')
        
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_indicators = sorted(result.threat_indicators, 
                                   key=lambda x: severity_order.get(x.severity, 5))
        
        for idx, indicator in enumerate(sorted_indicators, 1):
            sev_color = get_severity_color(indicator.severity)
            severity_label = f"[{indicator.severity.upper():^8}]"
            print(f"\n   {sev_color}{severity_label}{Colors.RESET} {Colors.BOLD}{indicator.name}{Colors.RESET}")
            print(f"   {'Score:':<10} +{indicator.score} points")
            print(f"   {'Detail:':<10} {Colors.DIM}{indicator.description}{Colors.RESET}")
    else:
        print(f"\n{Colors.GREEN}✅ No significant threat indicators detected{Colors.RESET}")
    
    # ==================== VISUAL GRAPHS ====================
    
    # Draw the threat level gauge
    draw_threat_gauge(result.threat_percentage, result.threat_level)
    
    # Draw threat breakdown chart
    draw_threat_breakdown_chart(result.threat_indicators, result.max_score)
    
    # Draw risk category overview
    draw_risk_radar(result)
    
    # Summary
    print()
    print_separator('═')
    print(f"{Colors.BOLD}📊 SCORE BREAKDOWN:{Colors.RESET}")
    print(f"   Total Score:     {result.total_score} / {result.max_score}")
    print(f"   Threat %:        {result.threat_percentage}%")
    print(f"   Analysis Time:   {result.analysis_time}")
    print_separator('═')
    
    # Final Verdict
    print()
    if result.threat_level == 'CRITICAL':
        print(f"   {Colors.BG_RED}{Colors.WHITE}{Colors.BOLD} ⛔ DANGEROUS - HIGH PROBABILITY OF PHISHING {Colors.RESET}")
    elif result.threat_level == 'HIGH':
        print(f"   {Colors.RED}{Colors.BOLD} ⚠️  WARNING - LIKELY PHISHING ATTEMPT {Colors.RESET}")
    elif result.threat_level == 'MEDIUM':
        print(f"   {Colors.YELLOW}{Colors.BOLD} ⚡ CAUTION - SUSPICIOUS CHARACTERISTICS DETECTED {Colors.RESET}")
    elif result.threat_level == 'LOW':
        print(f"   {Colors.CYAN}{Colors.BOLD} 🔵 LOW RISK - SOME MINOR CONCERNS {Colors.RESET}")
    else:
        print(f"   {Colors.GREEN}{Colors.BOLD} ✅ SAFE - NO SIGNIFICANT THREATS DETECTED {Colors.RESET}")
    print()


def is_phishing(url: str) -> bool:
    """Simple check if URL is likely phishing"""
    result = analyze_url(url)
    return result.threat_level in ('CRITICAL', 'HIGH')


def main():
    """Main entry point"""
    print()
    print(f"{Colors.BOLD}{Colors.BLUE}╔════════════════════════════════════════════════════════════╗{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}║     🛡️  ADVANCED URL PHISHING DETECTOR v2.0  🛡️           ║{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}╚════════════════════════════════════════════════════════════╝{Colors.RESET}")
    print()
    
    try:
        url = input(f'{Colors.BOLD}Enter URL to analyze:{Colors.RESET} ').strip()
    except (EOFError, KeyboardInterrupt):
        print(f"\n{Colors.DIM}Exiting...{Colors.RESET}")
        return
    
    if not url:
        print(f"{Colors.YELLOW}No URL provided. Exiting.{Colors.RESET}")
        return
    
    # Add protocol if missing
    if not url.startswith(('http://', 'https://', 'ftp://')):
        url = 'https://' + url
    
    print(f"\n{Colors.DIM}Analyzing URL...{Colors.RESET}")
    
    result = analyze_url(url)
    display_results(result)
    
    # Return code based on threat level
    if result.threat_level == 'CRITICAL':
        sys.exit(3)
    elif result.threat_level == 'HIGH':
        sys.exit(2)
    elif result.threat_level == 'MEDIUM':
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()