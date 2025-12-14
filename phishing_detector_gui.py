"""
Advanced URL Phishing Detector - Modern GUI
A premium, visually stunning interface for URL threat analysis
"""

import re
import tkinter as tk
from tkinter import ttk, messagebox
from urllib.parse import urlparse, parse_qs
from dataclasses import dataclass
from typing import List, Dict
from datetime import datetime
import math

# ============================================================
# CONFIGURATION & CONSTANTS
# ============================================================

# Modern Dark Theme Colors
COLORS = {
    'bg_dark': '#0d1117',
    'bg_card': '#161b22',
    'bg_card_hover': '#1c2128',
    'bg_input': '#21262d',
    'border': '#30363d',
    'border_light': '#484f58',
    'text_primary': '#f0f6fc',
    'text_secondary': '#8b949e',
    'text_muted': '#6e7681',
    'accent_blue': '#58a6ff',
    'accent_purple': '#a371f7',
    'accent_cyan': '#39d353',
    'safe': '#3fb950',
    'low': '#58a6ff',
    'medium': '#d29922',
    'high': '#f85149',
    'critical': '#ff7b72',
    'gradient_start': '#238636',
    'gradient_end': '#da3633',
}

# Known URL shorteners
SHORTENERS = {
    'bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'shorturl.at', 'cutt.ly', 'rb.gy', 'lnkd.in',
    'rebrand.ly', 's.id', 'shorte.st', 'v.gd', 'bl.ink', 't.ly',
    'tiny.cc', 'clck.ru', 'short.io', 'bitly.com', 'soo.gd'
}

# Suspicious TLDs with risk scores
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
}

# Sensitive keywords
SENSITIVE_KEYWORDS = {
    'login': 15, 'verify': 12, 'update': 10, 'confirm': 12, 'secure': 10,
    'account': 12, 'password': 18, 'bank': 20, 'invoice': 15, 'payment': 18,
    'token': 10, 'session': 8, 'signin': 15, 'wallet': 18, 'credit': 15,
    'ssn': 25, 'social-security': 25, 'reset': 10, 'expire': 12, 'suspend': 15,
}

# Known brand domains
BRAND_DOMAINS = {
    'paypal': {'paypal.com', 'paypal.me'},
    'apple': {'apple.com', 'icloud.com', 'apple.co'},
    'google': {'google.com', 'gmail.com', 'google.co', 'accounts.google.com'},
    'microsoft': {'microsoft.com', 'live.com', 'office.com', 'outlook.com'},
    'amazon': {'amazon.com', 'amazon.co.uk', 'aws.amazon.com'},
    'facebook': {'facebook.com', 'fb.com', 'fb.me'},
    'netflix': {'netflix.com'},
    'twitter': {'twitter.com', 'x.com'},
}


# ============================================================
# DATA CLASSES
# ============================================================

@dataclass
class DomainInfo:
    full_host: str
    tld: str
    base_domain: str
    subdomain: str
    subdomain_levels: int
    is_ip_address: bool
    is_punycode: bool


@dataclass
class ThreatIndicator:
    name: str
    severity: str
    score: int
    description: str


@dataclass
class AnalysisResult:
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


# ============================================================
# ANALYSIS FUNCTIONS
# ============================================================

def is_ip(host: str) -> bool:
    if not host:
        return False
    ipv4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    if ipv4.match(host):
        parts = host.split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    return False


def is_punycode(host: str) -> bool:
    return host.lower().startswith('xn--') or 'xn--' in host.lower()


def has_non_ascii(text: str) -> bool:
    return any(ord(c) > 127 for c in text)


def percent_encoding_count(url: str) -> int:
    return len(re.findall(r"%[0-9A-Fa-f]{2}", url))


def extract_domain_info(host: str) -> DomainInfo:
    if not host:
        return DomainInfo('', '', '', '', 0, False, False)
    
    is_ip_addr = is_ip(host)
    is_puny = is_punycode(host)
    
    if is_ip_addr:
        return DomainInfo(host, '', host, '', 0, True, False)
    
    parts = host.lower().split('.')
    tld = parts[-1] if parts else ''
    
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
    
    return DomainInfo(host, tld, base, subdomain, subdomain_levels, is_ip_addr, is_puny)


def analyze_url(url: str) -> AnalysisResult:
    indicators: List[ThreatIndicator] = []
    total_score = 0
    max_possible_score = 200
    
    try:
        parsed = urlparse(url)
    except Exception:
        return AnalysisResult(
            url=url,
            domain_info=DomainInfo('', '', '', '', 0, False, False),
            threat_percentage=100.0,
            threat_level='CRITICAL',
            threat_indicators=[ThreatIndicator('Invalid URL', 'critical', 100, 'URL parsing failed')],
            total_score=100, max_score=100, protocol='unknown', path='', query_params={},
            analysis_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )
    
    host = (parsed.hostname or '').lower()
    path = parsed.path or ''
    query = parsed.query or ''
    protocol = parsed.scheme or 'unknown'
    domain_info = extract_domain_info(host)
    
    try:
        query_params = parse_qs(query)
    except:
        query_params = {}
    
    # Analysis checks
    if domain_info.is_ip_address:
        total_score += 30
        indicators.append(ThreatIndicator('IP Address Used', 'critical', 30,
            'Uses IP address instead of domain - common phishing technique'))
    
    if host in SHORTENERS:
        total_score += 25
        indicators.append(ThreatIndicator('URL Shortener', 'high', 25,
            f'Uses URL shortener ({host}) to hide destination'))
    
    if domain_info.is_punycode:
        total_score += 20
        indicators.append(ThreatIndicator('Punycode Domain', 'high', 20,
            'Internationalized domain - potential homograph attack'))
    
    if has_non_ascii(url):
        total_score += 18
        indicators.append(ThreatIndicator('Non-ASCII Characters', 'high', 18,
            'Contains non-ASCII characters - possible obfuscation'))
    
    if '@' in url:
        total_score += 25
        indicators.append(ThreatIndicator('@ Symbol Present', 'critical', 25,
            'Contains @ symbol - credential injection technique'))
    
    tld = domain_info.tld.lower()
    if tld in SUSPICIOUS_TLDS:
        score = SUSPICIOUS_TLDS[tld]
        total_score += score
        indicators.append(ThreatIndicator(f'Suspicious TLD (.{tld})', 
            'medium' if score < 15 else 'high', score,
            f'TLD ".{tld}" is commonly associated with malicious domains'))
    
    url_len = len(url)
    if url_len >= 200:
        total_score += 20
        indicators.append(ThreatIndicator('Extremely Long URL', 'high', 20,
            f'URL is {url_len} characters - used to hide suspicious content'))
    elif url_len >= 100:
        total_score += 10
        indicators.append(ThreatIndicator('Long URL', 'medium', 10,
            f'URL is {url_len} characters - moderately suspicious'))
    
    if domain_info.subdomain_levels >= 4:
        total_score += 20
        indicators.append(ThreatIndicator('Excessive Subdomains', 'high', 20,
            f'{domain_info.subdomain_levels} subdomain levels detected'))
    elif domain_info.subdomain_levels >= 3:
        total_score += 12
        indicators.append(ThreatIndicator('Multiple Subdomains', 'medium', 12,
            f'{domain_info.subdomain_levels} subdomain levels'))
    
    hyphen_count = host.count('-') if host else 0
    if hyphen_count >= 4:
        total_score += 15
        indicators.append(ThreatIndicator('Many Hyphens', 'medium', 15,
            f'{hyphen_count} hyphens in domain'))
    
    digit_count = sum(ch.isdigit() for ch in host)
    if digit_count >= 7:
        total_score += 12
        indicators.append(ThreatIndicator('Excessive Digits', 'medium', 12,
            f'{digit_count} digits in domain'))
    
    text_check = (path + ' ' + query).lower()
    found_keywords = [k for k in SENSITIVE_KEYWORDS if k in text_check]
    if found_keywords:
        score = max(SENSITIVE_KEYWORDS[k] for k in found_keywords)
        total_score += score
        indicators.append(ThreatIndicator('Sensitive Keywords', 
            'high' if score >= 15 else 'medium', score,
            f'Contains: {", ".join(found_keywords[:3])}'))
    
    if parsed.port and parsed.port not in (80, 443):
        total_score += 15
        indicators.append(ThreatIndicator(f'Unusual Port (:{parsed.port})', 'medium', 15,
            f'Non-standard port {parsed.port}'))
    
    pct_count = percent_encoding_count(url)
    if pct_count >= 8:
        total_score += 15
        indicators.append(ThreatIndicator('Heavy Encoding', 'high', 15,
            f'{pct_count} percent-encoded sequences'))
    
    base = domain_info.base_domain.lower()
    for brand, allowed in BRAND_DOMAINS.items():
        if brand in host and base not in allowed:
            total_score += 30
            indicators.append(ThreatIndicator(f'Brand Impersonation ({brand.title()})', 
                'critical', 30, f'Contains "{brand}" but not official domain'))
            break
    
    if protocol == 'http':
        total_score += 10
        indicators.append(ThreatIndicator('No HTTPS', 'medium', 10,
            'Uses insecure HTTP protocol'))
    
    threat_percentage = min((total_score / max_possible_score) * 100, 100)
    
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
        url=url, domain_info=domain_info, threat_percentage=round(threat_percentage, 1),
        threat_level=threat_level, threat_indicators=indicators, total_score=total_score,
        max_score=max_possible_score, protocol=protocol, path=path, query_params=query_params,
        analysis_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )


# ============================================================
# CUSTOM WIDGETS
# ============================================================

class ThreatGauge(tk.Canvas):
    """Custom circular threat gauge widget"""
    
    def __init__(self, parent, size=200, **kwargs):
        super().__init__(parent, width=size, height=size, bg=COLORS['bg_card'],
                        highlightthickness=0, **kwargs)
        self.size = size
        self.center = size // 2
        self.radius = size // 2 - 20
        self.percentage = 0
        self.target_percentage = 0
        self.level = 'SAFE'
        self.draw_gauge()
    
    def draw_gauge(self):
        self.delete('all')
        
        # Draw background arc segments
        segments = [
            (0, 10, COLORS['safe']),
            (10, 25, COLORS['low']),
            (25, 40, COLORS['medium']),
            (40, 60, COLORS['high']),
            (60, 100, COLORS['critical']),
        ]
        
        for start_pct, end_pct, color in segments:
            start_angle = 180 - (start_pct / 100) * 180
            end_angle = 180 - (end_pct / 100) * 180
            extent = end_angle - start_angle
            
            # Draw arc
            self.create_arc(
                20, 20, self.size - 20, self.size - 20,
                start=start_angle, extent=extent,
                outline=color, width=15, style='arc'
            )
        
        # Draw center circle
        inner_r = self.radius - 30
        self.create_oval(
            self.center - inner_r, self.center - inner_r,
            self.center + inner_r, self.center + inner_r,
            fill=COLORS['bg_dark'], outline=COLORS['border']
        )
        
        # Draw percentage text
        self.create_text(
            self.center, self.center - 10,
            text=f"{self.percentage:.1f}%",
            fill=self.get_level_color(),
            font=('Segoe UI', 24, 'bold')
        )
        
        # Draw level text
        self.create_text(
            self.center, self.center + 25,
            text=self.level,
            fill=self.get_level_color(),
            font=('Segoe UI', 12, 'bold')
        )
        
        # Draw needle
        angle = math.radians(180 - (self.percentage / 100) * 180)
        needle_len = self.radius - 25
        end_x = self.center + needle_len * math.cos(angle)
        end_y = self.center - needle_len * math.sin(angle)
        
        self.create_line(
            self.center, self.center, end_x, end_y,
            fill=COLORS['text_primary'], width=3, arrow=tk.LAST
        )
        
        # Draw center dot
        self.create_oval(
            self.center - 6, self.center - 6,
            self.center + 6, self.center + 6,
            fill=COLORS['text_primary'], outline=''
        )
    
    def get_level_color(self):
        colors = {
            'SAFE': COLORS['safe'],
            'LOW': COLORS['low'],
            'MEDIUM': COLORS['medium'],
            'HIGH': COLORS['high'],
            'CRITICAL': COLORS['critical'],
        }
        return colors.get(self.level, COLORS['text_primary'])
    
    def set_value(self, percentage, level):
        self.target_percentage = percentage
        self.level = level
        self.animate_to_target()
    
    def animate_to_target(self):
        if abs(self.percentage - self.target_percentage) < 0.5:
            self.percentage = self.target_percentage
            self.draw_gauge()
            return
        
        diff = self.target_percentage - self.percentage
        self.percentage += diff * 0.15
        self.draw_gauge()
        self.after(20, self.animate_to_target)


class CategoryBar(tk.Canvas):
    """Horizontal category risk bar"""
    
    def __init__(self, parent, label, **kwargs):
        super().__init__(parent, width=300, height=30, bg=COLORS['bg_card'],
                        highlightthickness=0, **kwargs)
        self.label = label
        self.value = 0
        self.max_value = 50
        self.draw_bar()
    
    def draw_bar(self):
        self.delete('all')
        
        # Draw label
        self.create_text(5, 15, text=self.label, anchor='w',
                        fill=COLORS['text_secondary'], font=('Segoe UI', 9))
        
        # Draw background bar
        bar_x = 130
        bar_width = 150
        bar_height = 12
        
        self.create_rectangle(
            bar_x, 9, bar_x + bar_width, 9 + bar_height,
            fill=COLORS['bg_input'], outline=''
        )
        
        # Draw filled portion
        if self.value > 0:
            fill_width = min((self.value / self.max_value) * bar_width, bar_width)
            color = self.get_color()
            self.create_rectangle(
                bar_x, 9, bar_x + fill_width, 9 + bar_height,
                fill=color, outline=''
            )
        
        # Draw value
        self.create_text(
            bar_x + bar_width + 10, 15,
            text=f"{self.value}",
            anchor='w', fill=COLORS['text_muted'], font=('Segoe UI', 9)
        )
    
    def get_color(self):
        if self.value >= 25:
            return COLORS['high']
        elif self.value >= 15:
            return COLORS['medium']
        elif self.value >= 5:
            return COLORS['low']
        return COLORS['safe']
    
    def set_value(self, value):
        self.value = value
        self.draw_bar()


class IndicatorCard(tk.Frame):
    """Card widget for threat indicators"""
    
    def __init__(self, parent, indicator: ThreatIndicator, **kwargs):
        super().__init__(parent, bg=COLORS['bg_card'], **kwargs)
        
        severity_colors = {
            'critical': COLORS['critical'],
            'high': COLORS['high'],
            'medium': COLORS['medium'],
            'low': COLORS['low'],
        }
        color = severity_colors.get(indicator.severity, COLORS['text_secondary'])
        
        # Severity badge
        badge_frame = tk.Frame(self, bg=color, padx=8, pady=2)
        badge_frame.pack(side='left', padx=(10, 10), pady=10)
        
        tk.Label(badge_frame, text=indicator.severity.upper(),
                bg=color, fg='white', font=('Segoe UI', 8, 'bold')).pack()
        
        # Content
        content_frame = tk.Frame(self, bg=COLORS['bg_card'])
        content_frame.pack(side='left', fill='x', expand=True, pady=10)
        
        tk.Label(content_frame, text=indicator.name,
                bg=COLORS['bg_card'], fg=COLORS['text_primary'],
                font=('Segoe UI', 11, 'bold'), anchor='w').pack(anchor='w')
        
        tk.Label(content_frame, text=indicator.description,
                bg=COLORS['bg_card'], fg=COLORS['text_secondary'],
                font=('Segoe UI', 9), anchor='w').pack(anchor='w')
        
        # Score
        score_frame = tk.Frame(self, bg=COLORS['bg_card'])
        score_frame.pack(side='right', padx=15, pady=10)
        
        tk.Label(score_frame, text=f"+{indicator.score}",
                bg=COLORS['bg_card'], fg=color,
                font=('Segoe UI', 14, 'bold')).pack()
        tk.Label(score_frame, text="pts",
                bg=COLORS['bg_card'], fg=COLORS['text_muted'],
                font=('Segoe UI', 8)).pack()


class ThreatBarChart(tk.Canvas):
    """Vertical bar chart showing threat breakdown by severity"""
    
    def __init__(self, parent, width=350, height=200, **kwargs):
        super().__init__(parent, width=width, height=height, bg=COLORS['bg_card'],
                        highlightthickness=0, **kwargs)
        self.chart_width = width
        self.chart_height = height
        self.data = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        self.max_value = 50
        self.animated_data = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        self.draw_chart()
    
    def draw_chart(self):
        self.delete('all')
        
        # Chart area
        left_margin = 60
        right_margin = 20
        top_margin = 30
        bottom_margin = 50
        
        chart_w = self.chart_width - left_margin - right_margin
        chart_h = self.chart_height - top_margin - bottom_margin
        
        # Title
        self.create_text(self.chart_width // 2, 12, text="Threat Score by Severity",
                        fill=COLORS['text_primary'], font=('Segoe UI', 10, 'bold'))
        
        # Draw grid lines
        for i in range(5):
            y = top_margin + (i * chart_h / 4)
            self.create_line(left_margin, y, self.chart_width - right_margin, y,
                           fill=COLORS['border'], dash=(2, 4))
            value = int(self.max_value - (i * self.max_value / 4))
            self.create_text(left_margin - 10, y, text=str(value),
                           fill=COLORS['text_muted'], font=('Segoe UI', 8), anchor='e')
        
        # Draw bars
        categories = [
            ('critical', 'CRIT', COLORS['critical']),
            ('high', 'HIGH', COLORS['high']),
            ('medium', 'MED', COLORS['medium']),
            ('low', 'LOW', COLORS['low']),
        ]
        
        bar_width = chart_w / len(categories) - 20
        
        for i, (key, label, color) in enumerate(categories):
            x = left_margin + (i * (chart_w / len(categories))) + 10
            value = self.animated_data.get(key, 0)
            bar_height = (value / self.max_value) * chart_h if self.max_value > 0 else 0
            bar_height = min(bar_height, chart_h)
            
            # Bar
            if bar_height > 0:
                self.create_rectangle(
                    x, top_margin + chart_h - bar_height,
                    x + bar_width, top_margin + chart_h,
                    fill=color, outline=''
                )
                
                # Value on top of bar
                if bar_height > 20:
                    self.create_text(
                        x + bar_width / 2, top_margin + chart_h - bar_height - 8,
                        text=str(int(value)), fill=color, font=('Segoe UI', 9, 'bold')
                    )
            
            # Label below
            self.create_text(
                x + bar_width / 2, top_margin + chart_h + 15,
                text=label, fill=COLORS['text_secondary'], font=('Segoe UI', 8, 'bold')
            )
        
        # Y-axis label
        self.create_text(15, self.chart_height // 2, text="Points",
                        fill=COLORS['text_muted'], font=('Segoe UI', 8),
                        angle=90)
    
    def set_data(self, data: dict):
        self.data = data
        # Find max value for scaling
        max_val = max(data.values()) if data.values() else 50
        self.max_value = max(50, max_val + 10)
        self.animate_bars()
    
    def animate_bars(self):
        done = True
        for key in self.data:
            target = self.data[key]
            current = self.animated_data.get(key, 0)
            if abs(current - target) > 0.5:
                self.animated_data[key] = current + (target - current) * 0.2
                done = False
            else:
                self.animated_data[key] = target
        
        self.draw_chart()
        if not done:
            self.after(30, self.animate_bars)


class ThreatLevelGraph(tk.Canvas):
    """Horizontal threat level indicator with zones"""
    
    def __init__(self, parent, width=350, height=80, **kwargs):
        super().__init__(parent, width=width, height=height, bg=COLORS['bg_card'],
                        highlightthickness=0, **kwargs)
        self.graph_width = width
        self.graph_height = height
        self.percentage = 0
        self.target_percentage = 0
        self.level = 'SAFE'
        self.draw_graph()
    
    def draw_graph(self):
        self.delete('all')
        
        margin = 20
        bar_height = 25
        bar_y = 30
        bar_width = self.graph_width - (margin * 2)
        
        # Title
        self.create_text(self.graph_width // 2, 12, text="Threat Level Meter",
                        fill=COLORS['text_primary'], font=('Segoe UI', 10, 'bold'))
        
        # Draw zone backgrounds
        zones = [
            (0, 10, COLORS['safe']),
            (10, 25, COLORS['low']),
            (25, 40, COLORS['medium']),
            (40, 60, COLORS['high']),
            (60, 100, COLORS['critical']),
        ]
        
        for start_pct, end_pct, color in zones:
            x1 = margin + (start_pct / 100) * bar_width
            x2 = margin + (end_pct / 100) * bar_width
            self.create_rectangle(x1, bar_y, x2, bar_y + bar_height,
                                 fill=color, outline='')
        
        # Draw border
        self.create_rectangle(margin, bar_y, margin + bar_width, bar_y + bar_height,
                             outline=COLORS['border'], width=2)
        
        # Draw pointer/marker
        pointer_x = margin + (self.percentage / 100) * bar_width
        pointer_x = max(margin + 5, min(pointer_x, margin + bar_width - 5))
        
        # Pointer triangle
        self.create_polygon(
            pointer_x - 8, bar_y + bar_height + 5,
            pointer_x + 8, bar_y + bar_height + 5,
            pointer_x, bar_y + bar_height - 3,
            fill=COLORS['text_primary'], outline=''
        )
        
        # Percentage label below pointer
        self.create_text(pointer_x, bar_y + bar_height + 20,
                        text=f"{self.percentage:.1f}%",
                        fill=COLORS['text_primary'], font=('Segoe UI', 10, 'bold'))
        
        # Zone labels at bottom
        labels = [("SAFE", 5), ("LOW", 17), ("MED", 32), ("HIGH", 50), ("CRIT", 80)]
        for label, pct in labels:
            x = margin + (pct / 100) * bar_width
            self.create_text(x, bar_y - 8, text=label,
                           fill=COLORS['text_muted'], font=('Segoe UI', 7))
    
    def set_value(self, percentage, level):
        self.target_percentage = percentage
        self.level = level
        self.animate_to_target()
    
    def animate_to_target(self):
        if abs(self.percentage - self.target_percentage) < 0.3:
            self.percentage = self.target_percentage
            self.draw_graph()
            return
        
        diff = self.target_percentage - self.percentage
        self.percentage += diff * 0.15
        self.draw_graph()
        self.after(25, self.animate_to_target)


class RiskRadarChart(tk.Canvas):
    """Spider/Radar chart for risk categories"""
    
    def __init__(self, parent, size=250, **kwargs):
        super().__init__(parent, width=size, height=size, bg=COLORS['bg_card'],
                        highlightthickness=0, **kwargs)
        self.size = size
        self.center = size // 2
        self.radius = size // 2 - 40
        self.categories = {}
        self.animated_categories = {}
        self.draw_radar()
    
    def draw_radar(self):
        self.delete('all')
        
        # Title
        self.create_text(self.center, 15, text="Risk Category Radar",
                        fill=COLORS['text_primary'], font=('Segoe UI', 10, 'bold'))
        
        category_names = ['Domain', 'Structure', 'Brand', 'Encoding', 'Protocol']
        num_categories = len(category_names)
        
        # Draw background circles
        for i in range(1, 5):
            r = self.radius * (i / 4)
            self.create_oval(
                self.center - r, self.center - r + 15,
                self.center + r, self.center + r + 15,
                outline=COLORS['border'], dash=(2, 4)
            )
        
        # Draw axes
        for i in range(num_categories):
            angle = math.radians(90 - (360 / num_categories) * i)
            x = self.center + self.radius * math.cos(angle)
            y = self.center + 15 - self.radius * math.sin(angle)
            
            self.create_line(self.center, self.center + 15, x, y,
                           fill=COLORS['border'])
            
            # Labels
            label_x = self.center + (self.radius + 25) * math.cos(angle)
            label_y = self.center + 15 - (self.radius + 25) * math.sin(angle)
            self.create_text(label_x, label_y, text=category_names[i],
                           fill=COLORS['text_secondary'], font=('Segoe UI', 8))
        
        # Draw data polygon
        if self.animated_categories:
            points = []
            cat_keys = ['Domain Trust', 'URL Structure', 'Brand Safety', 
                       'Encoding', 'Protocol']
            max_val = 50
            
            for i, key in enumerate(cat_keys):
                value = self.animated_categories.get(key, 0)
                ratio = min(value / max_val, 1) if max_val > 0 else 0
                angle = math.radians(90 - (360 / num_categories) * i)
                r = self.radius * ratio
                x = self.center + r * math.cos(angle)
                y = self.center + 15 - r * math.sin(angle)
                points.extend([x, y])
            
            if len(points) >= 6:
                # Fill - use a darker shade since tkinter doesn't support alpha
                self.create_polygon(points, fill='#1a3a5c',
                                   outline=COLORS['accent_blue'], width=2)
                
                # Points
                for i in range(0, len(points), 2):
                    self.create_oval(points[i] - 4, points[i + 1] - 4,
                                   points[i] + 4, points[i + 1] + 4,
                                   fill=COLORS['accent_blue'], outline='')
    
    def set_data(self, categories: dict):
        self.categories = categories
        self.animate_data()
    
    def animate_data(self):
        done = True
        for key in self.categories:
            target = self.categories[key]
            current = self.animated_categories.get(key, 0)
            if abs(current - target) > 0.5:
                self.animated_categories[key] = current + (target - current) * 0.15
                done = False
            else:
                self.animated_categories[key] = target
        
        self.draw_radar()
        if not done:
            self.after(30, self.animate_data)


# ============================================================
# MAIN APPLICATION
# ============================================================

class PhishingDetectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ URL Phishing Detector")
        self.root.geometry("1100x800")
        self.root.configure(bg=COLORS['bg_dark'])
        self.root.minsize(900, 700)
        
        # Configure styles
        self.setup_styles()
        
        # Build UI
        self.build_ui()
        
        # Current result
        self.current_result = None
    
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure scrollbar
        style.configure('Vertical.TScrollbar',
                       background=COLORS['bg_card'],
                       troughcolor=COLORS['bg_dark'],
                       arrowcolor=COLORS['text_secondary'])
    
    def build_ui(self):
        # Main container
        main_container = tk.Frame(self.root, bg=COLORS['bg_dark'])
        main_container.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Header
        self.build_header(main_container)
        
        # Input section
        self.build_input_section(main_container)
        
        # Results section (scrollable)
        self.build_results_section(main_container)
    
    def build_header(self, parent):
        header = tk.Frame(parent, bg=COLORS['bg_dark'])
        header.pack(fill='x', pady=(0, 20))
        
        # Logo and title
        title_frame = tk.Frame(header, bg=COLORS['bg_dark'])
        title_frame.pack(side='left')
        
        tk.Label(title_frame, text="🛡️",
                bg=COLORS['bg_dark'], font=('Segoe UI Emoji', 32)).pack(side='left', padx=(0, 10))
        
        text_frame = tk.Frame(title_frame, bg=COLORS['bg_dark'])
        text_frame.pack(side='left')
        
        tk.Label(text_frame, text="URL Phishing Detector",
                bg=COLORS['bg_dark'], fg=COLORS['text_primary'],
                font=('Segoe UI', 24, 'bold')).pack(anchor='w')
        
        tk.Label(text_frame, text="Advanced threat analysis powered by heuristic detection",
                bg=COLORS['bg_dark'], fg=COLORS['text_secondary'],
                font=('Segoe UI', 10)).pack(anchor='w')
        
        # Version badge
        version_frame = tk.Frame(header, bg=COLORS['accent_purple'], padx=10, pady=3)
        version_frame.pack(side='right', pady=10)
        tk.Label(version_frame, text="v2.0",
                bg=COLORS['accent_purple'], fg='white',
                font=('Segoe UI', 9, 'bold')).pack()
    
    def build_input_section(self, parent):
        input_frame = tk.Frame(parent, bg=COLORS['bg_card'], padx=20, pady=20)
        input_frame.pack(fill='x', pady=(0, 20))
        
        # Add rounded corners effect with border
        input_frame.configure(highlightbackground=COLORS['border'],
                             highlightthickness=1)
        
        # Input label
        tk.Label(input_frame, text="Enter URL to analyze",
                bg=COLORS['bg_card'], fg=COLORS['text_secondary'],
                font=('Segoe UI', 10)).pack(anchor='w', pady=(0, 8))
        
        # Input row
        input_row = tk.Frame(input_frame, bg=COLORS['bg_card'])
        input_row.pack(fill='x')
        
        # URL Entry
        self.url_entry = tk.Entry(input_row, font=('Consolas', 12),
                                 bg=COLORS['bg_input'], fg=COLORS['text_primary'],
                                 insertbackground=COLORS['text_primary'],
                                 relief='flat', bd=0)
        self.url_entry.pack(side='left', fill='x', expand=True, ipady=12, padx=(0, 10))
        self.url_entry.insert(0, "https://example.com")
        self.url_entry.bind('<Return>', lambda e: self.analyze())
        self.url_entry.bind('<FocusIn>', self.on_entry_focus)
        
        # Analyze button
        self.analyze_btn = tk.Button(input_row, text="🔍 Analyze URL",
                                    font=('Segoe UI', 11, 'bold'),
                                    bg=COLORS['accent_blue'], fg='white',
                                    activebackground=COLORS['accent_purple'],
                                    activeforeground='white',
                                    relief='flat', cursor='hand2',
                                    padx=25, pady=10,
                                    command=self.analyze)
        self.analyze_btn.pack(side='right')
        
        # Bind hover effects
        self.analyze_btn.bind('<Enter>', lambda e: self.analyze_btn.configure(bg=COLORS['accent_purple']))
        self.analyze_btn.bind('<Leave>', lambda e: self.analyze_btn.configure(bg=COLORS['accent_blue']))
    
    def on_entry_focus(self, event):
        if self.url_entry.get() == "https://example.com":
            self.url_entry.delete(0, tk.END)
    
    def build_results_section(self, parent):
        # Create scrollable frame
        self.results_container = tk.Frame(parent, bg=COLORS['bg_dark'])
        self.results_container.pack(fill='both', expand=True)
        
        # Canvas for scrolling
        self.canvas = tk.Canvas(self.results_container, bg=COLORS['bg_dark'],
                               highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.results_container, orient='vertical',
                                 command=self.canvas.yview)
        
        self.scrollable_frame = tk.Frame(self.canvas, bg=COLORS['bg_dark'])
        
        self.scrollable_frame.bind('<Configure>',
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox('all')))
        
        self.canvas_frame = self.canvas.create_window((0, 0), window=self.scrollable_frame,
                                                      anchor='nw')
        self.canvas.configure(yscrollcommand=scrollbar.set)
        
        # Bind canvas resize
        self.canvas.bind('<Configure>', self.on_canvas_configure)
        
        # Mouse wheel scrolling
        self.canvas.bind_all('<MouseWheel>', self.on_mousewheel)
        
        self.canvas.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Initial placeholder
        self.show_placeholder()
    
    def on_canvas_configure(self, event):
        self.canvas.itemconfig(self.canvas_frame, width=event.width)
    
    def on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), 'units')
    
    def show_placeholder(self):
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        
        placeholder = tk.Frame(self.scrollable_frame, bg=COLORS['bg_dark'])
        placeholder.pack(fill='both', expand=True, pady=100)
        
        tk.Label(placeholder, text="🔗",
                bg=COLORS['bg_dark'], font=('Segoe UI Emoji', 48)).pack()
        
        tk.Label(placeholder, text="Enter a URL above to analyze",
                bg=COLORS['bg_dark'], fg=COLORS['text_secondary'],
                font=('Segoe UI', 14)).pack(pady=10)
        
        tk.Label(placeholder, text="We'll check for phishing indicators, suspicious patterns, and security risks",
                bg=COLORS['bg_dark'], fg=COLORS['text_muted'],
                font=('Segoe UI', 10)).pack()
    
    def analyze(self):
        url = self.url_entry.get().strip()
        
        if not url or url == "https://example.com":
            messagebox.showwarning("Input Required", "Please enter a URL to analyze.")
            return
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://', 'ftp://')):
            url = 'https://' + url
        
        # Perform analysis
        self.current_result = analyze_url(url)
        
        # Display results
        self.display_results()
    
    def display_results(self):
        result = self.current_result
        if not result:
            return
        
        # Clear previous results
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        
        # Create two-column layout
        main_frame = tk.Frame(self.scrollable_frame, bg=COLORS['bg_dark'])
        main_frame.pack(fill='both', expand=True, pady=10)
        
        # Left column (60%)
        left_col = tk.Frame(main_frame, bg=COLORS['bg_dark'])
        left_col.pack(side='left', fill='both', expand=True, padx=(0, 10))
        
        # Right column (40%)
        right_col = tk.Frame(main_frame, bg=COLORS['bg_dark'])
        right_col.pack(side='right', fill='y', padx=(10, 0))
        
        # === LEFT COLUMN ===
        
        # URL Card
        url_card = tk.Frame(left_col, bg=COLORS['bg_card'], padx=20, pady=15)
        url_card.pack(fill='x', pady=(0, 15))
        url_card.configure(highlightbackground=COLORS['border'], highlightthickness=1)
        
        tk.Label(url_card, text="📎 Analyzed URL",
                bg=COLORS['bg_card'], fg=COLORS['text_secondary'],
                font=('Segoe UI', 10)).pack(anchor='w')
        
        tk.Label(url_card, text=result.url,
                bg=COLORS['bg_card'], fg=COLORS['accent_cyan'],
                font=('Consolas', 11), wraplength=500, justify='left').pack(anchor='w', pady=(5, 0))
        
        # Domain Breakdown Card
        domain_card = tk.Frame(left_col, bg=COLORS['bg_card'], padx=20, pady=15)
        domain_card.pack(fill='x', pady=(0, 15))
        domain_card.configure(highlightbackground=COLORS['border'], highlightthickness=1)
        
        tk.Label(domain_card, text="🌐 Domain Breakdown",
                bg=COLORS['bg_card'], fg=COLORS['text_primary'],
                font=('Segoe UI', 12, 'bold')).pack(anchor='w', pady=(0, 10))
        
        domain_info = [
            ("Full Host", result.domain_info.full_host or "N/A"),
            ("Base Domain", result.domain_info.base_domain or "N/A"),
            ("Subdomain", result.domain_info.subdomain or "(none)"),
            ("Subdomain Levels", str(result.domain_info.subdomain_levels)),
            ("TLD", f".{result.domain_info.tld}" if result.domain_info.tld else "N/A"),
            ("Protocol", result.protocol.upper()),
        ]
        
        for label, value in domain_info:
            row = tk.Frame(domain_card, bg=COLORS['bg_card'])
            row.pack(fill='x', pady=3)
            
            tk.Label(row, text=label, width=18, anchor='w',
                    bg=COLORS['bg_card'], fg=COLORS['text_secondary'],
                    font=('Segoe UI', 10)).pack(side='left')
            
            tk.Label(row, text=value, anchor='w',
                    bg=COLORS['bg_card'], fg=COLORS['text_primary'],
                    font=('Consolas', 10)).pack(side='left')
        
        # Threat Indicators Card
        if result.threat_indicators:
            indicators_card = tk.Frame(left_col, bg=COLORS['bg_card'], padx=20, pady=15)
            indicators_card.pack(fill='x', pady=(0, 15))
            indicators_card.configure(highlightbackground=COLORS['border'], highlightthickness=1)
            
            tk.Label(indicators_card, text=f"🚨 Threat Indicators ({len(result.threat_indicators)})",
                    bg=COLORS['bg_card'], fg=COLORS['text_primary'],
                    font=('Segoe UI', 12, 'bold')).pack(anchor='w', pady=(0, 10))
            
            # Sort by severity
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
            sorted_indicators = sorted(result.threat_indicators,
                                       key=lambda x: severity_order.get(x.severity, 4))
            
            for indicator in sorted_indicators:
                ind_card = IndicatorCard(indicators_card, indicator)
                ind_card.pack(fill='x', pady=3)
                ind_card.configure(highlightbackground=COLORS['border'], highlightthickness=1)
        
        # === RIGHT COLUMN ===
        
        # Threat Gauge
        gauge_card = tk.Frame(right_col, bg=COLORS['bg_card'], padx=20, pady=20)
        gauge_card.pack(fill='x', pady=(0, 15))
        gauge_card.configure(highlightbackground=COLORS['border'], highlightthickness=1)
        
        tk.Label(gauge_card, text="📈 Threat Level",
                bg=COLORS['bg_card'], fg=COLORS['text_primary'],
                font=('Segoe UI', 12, 'bold')).pack(pady=(0, 10))
        
        self.gauge = ThreatGauge(gauge_card, size=200)
        self.gauge.pack()
        self.gauge.set_value(result.threat_percentage, result.threat_level)
        
        # Verdict
        verdict_colors = {
            'SAFE': (COLORS['safe'], "✅ SAFE"),
            'LOW': (COLORS['low'], "🔵 LOW RISK"),
            'MEDIUM': (COLORS['medium'], "⚡ SUSPICIOUS"),
            'HIGH': (COLORS['high'], "⚠️ DANGEROUS"),
            'CRITICAL': (COLORS['critical'], "⛔ PHISHING"),
        }
        color, text = verdict_colors.get(result.threat_level, (COLORS['text_primary'], result.threat_level))
        
        verdict_frame = tk.Frame(gauge_card, bg=color, padx=15, pady=8)
        verdict_frame.pack(fill='x', pady=(15, 0))
        
        tk.Label(verdict_frame, text=text,
                bg=color, fg='white',
                font=('Segoe UI', 11, 'bold')).pack()
        
        # Risk Categories
        categories_card = tk.Frame(right_col, bg=COLORS['bg_card'], padx=20, pady=15)
        categories_card.pack(fill='x', pady=(0, 15))
        categories_card.configure(highlightbackground=COLORS['border'], highlightthickness=1)
        
        tk.Label(categories_card, text="🎯 Risk Categories",
                bg=COLORS['bg_card'], fg=COLORS['text_primary'],
                font=('Segoe UI', 12, 'bold')).pack(anchor='w', pady=(0, 10))
        
        # Calculate category scores
        categories = {
            'Domain Trust': 0,
            'URL Structure': 0,
            'Brand Safety': 0,
            'Encoding': 0,
            'Protocol': 0,
        }
        
        for ind in result.threat_indicators:
            name = ind.name
            if 'Brand' in name:
                categories['Brand Safety'] += ind.score
            elif 'HTTPS' in name or 'Port' in name:
                categories['Protocol'] += ind.score
            elif 'TLD' in name or 'IP' in name or 'Shortener' in name or 'Punycode' in name:
                categories['Domain Trust'] += ind.score
            elif 'Encoding' in name or 'ASCII' in name:
                categories['Encoding'] += ind.score
            else:
                categories['URL Structure'] += ind.score
        
        for cat_name, cat_score in categories.items():
            bar = CategoryBar(categories_card, cat_name)
            bar.pack(fill='x', pady=2)
            bar.set_value(cat_score)
        
        # Score Summary
        summary_card = tk.Frame(right_col, bg=COLORS['bg_card'], padx=20, pady=15)
        summary_card.pack(fill='x')
        summary_card.configure(highlightbackground=COLORS['border'], highlightthickness=1)
        
        tk.Label(summary_card, text="📊 Analysis Summary",
                bg=COLORS['bg_card'], fg=COLORS['text_primary'],
                font=('Segoe UI', 12, 'bold')).pack(anchor='w', pady=(0, 10))
        
        summary_info = [
            ("Total Score", f"{result.total_score} / {result.max_score}"),
            ("Threat %", f"{result.threat_percentage}%"),
            ("Analyzed", result.analysis_time),
        ]
        
        for label, value in summary_info:
            row = tk.Frame(summary_card, bg=COLORS['bg_card'])
            row.pack(fill='x', pady=3)
            
            tk.Label(row, text=label, anchor='w',
                    bg=COLORS['bg_card'], fg=COLORS['text_secondary'],
                    font=('Segoe UI', 10)).pack(side='left')
            
            tk.Label(row, text=value, anchor='e',
                    bg=COLORS['bg_card'], fg=COLORS['text_primary'],
                    font=('Segoe UI', 10, 'bold')).pack(side='right')
        
        # ==================== VISUAL GRAPHS SECTION ====================
        
        # Create a new row for graphs below the main content
        graphs_frame = tk.Frame(self.scrollable_frame, bg=COLORS['bg_dark'])
        graphs_frame.pack(fill='x', pady=(20, 10))
        
        # Graphs header
        tk.Label(graphs_frame, text="📊 Visual Risk Analysis",
                bg=COLORS['bg_dark'], fg=COLORS['text_primary'],
                font=('Segoe UI', 14, 'bold')).pack(anchor='w', pady=(0, 15))
        
        # Container for graphs
        graphs_container = tk.Frame(graphs_frame, bg=COLORS['bg_dark'])
        graphs_container.pack(fill='x')
        
        # Left graphs column
        left_graphs = tk.Frame(graphs_container, bg=COLORS['bg_dark'])
        left_graphs.pack(side='left', fill='both', expand=True, padx=(0, 10))
        
        # Center graphs column  
        center_graphs = tk.Frame(graphs_container, bg=COLORS['bg_dark'])
        center_graphs.pack(side='left', fill='both', expand=True, padx=10)
        
        # Right graphs column
        right_graphs = tk.Frame(graphs_container, bg=COLORS['bg_dark'])
        right_graphs.pack(side='left', fill='both', expand=True, padx=(10, 0))
        
        # === THREAT LEVEL METER ===
        meter_card = tk.Frame(left_graphs, bg=COLORS['bg_card'], padx=15, pady=15)
        meter_card.pack(fill='x', pady=(0, 10))
        meter_card.configure(highlightbackground=COLORS['border'], highlightthickness=1)
        
        self.threat_meter = ThreatLevelGraph(meter_card, width=320, height=80)
        self.threat_meter.pack()
        self.threat_meter.set_value(result.threat_percentage, result.threat_level)
        
        # === BAR CHART ===
        chart_card = tk.Frame(center_graphs, bg=COLORS['bg_card'], padx=15, pady=15)
        chart_card.pack(fill='x', pady=(0, 10))
        chart_card.configure(highlightbackground=COLORS['border'], highlightthickness=1)
        
        # Calculate severity scores for bar chart
        severity_scores = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for ind in result.threat_indicators:
            sev = ind.severity.lower()
            if sev in severity_scores:
                severity_scores[sev] += ind.score
        
        self.bar_chart = ThreatBarChart(chart_card, width=320, height=180)
        self.bar_chart.pack()
        self.bar_chart.set_data(severity_scores)
        
        # === RADAR CHART ===
        radar_card = tk.Frame(right_graphs, bg=COLORS['bg_card'], padx=15, pady=15)
        radar_card.pack(fill='x', pady=(0, 10))
        radar_card.configure(highlightbackground=COLORS['border'], highlightthickness=1)
        
        self.radar_chart = RiskRadarChart(radar_card, size=220)
        self.radar_chart.pack()
        self.radar_chart.set_data(categories)


# ============================================================
# MAIN ENTRY POINT
# ============================================================

def main():
    root = tk.Tk()
    
    # Set window icon (optional)
    try:
        root.iconbitmap(default='')
    except:
        pass
    
    app = PhishingDetectorApp(root)
    
    # Center window
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'+{x}+{y}')
    
    root.mainloop()


if __name__ == '__main__':
    main()
