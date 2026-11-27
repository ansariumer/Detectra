
import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

interface Threat {
  title: string;
  description: string;
  points: number;
}

interface ScanRecord {
  url: string;
  score: number;
  level: string;
  date: string;
}

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './app.html',
  styleUrl: './app.css'
})
export class App implements OnInit {
  url = '';
  loading = false;
  scanned = false;
  error = '';

  score = 0;
  riskLevel = '';
  riskMessage = '';
  threats: Threat[] = [];
  recommendation = '';

  mouseX = 0;
  mouseY = 0;

  history: ScanRecord[] = [];

  private readonly suspiciousWords = [
    'login', 'verify', 'password', 'account', 'secure',
    'banking', 'update', 'wallet', 'free', 'claim',
    'gift', 'prize', 'urgent', 'signin', 'confirm',
    'payment', 'recover', 'suspended', 'unlock'
  ];

  private readonly shorteners = [
    'bit.ly', 'tinyurl.com', 't.co', 'is.gd',
    'cutt.ly', 'shorturl.at', 'rb.gy', 'ow.ly',
    'buff.ly', 'rebrand.ly'
  ];

  private readonly suspiciousTlds = [
    '.zip', '.mov', '.click', '.top', '.work',
    '.gq', '.tk', '.country'
  ];

  private readonly trustedBrandDomains: Record<string, string[]> = {
    google: ['google.com'],
    microsoft: ['microsoft.com', 'live.com', 'outlook.com'],
    paypal: ['paypal.com'],
    amazon: ['amazon.com', 'amazon.in'],
    apple: ['apple.com'],
    netflix: ['netflix.com'],
    facebook: ['facebook.com'],
    instagram: ['instagram.com'],
    whatsapp: ['whatsapp.com'],
    sbi: ['sbi.co.in'],
    flipkart: ['flipkart.com']
  };

  ngOnInit(): void {
    this.loadHistory();
  }

  onMouseMove(event: MouseEvent): void {
    this.mouseX = event.clientX;
    this.mouseY = event.clientY;
  }

  scanUrl(): void {
    this.error = '';
    this.scanned = false;

    if (!this.url.trim()) {
      this.error = 'Please enter a website URL.';
      return;
    }

    let normalizedUrl = this.url.trim();

    if (!/^https?:\/\//i.test(normalizedUrl)) {
      normalizedUrl = 'https://' + normalizedUrl;
    }

    let parsedUrl: URL;

    try {
      parsedUrl = new URL(normalizedUrl);

      if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
        throw new Error('Unsupported protocol');
      }

      const hostname = parsedUrl.hostname;

      if (
        !hostname ||
        hostname.length > 253 ||
        !hostname.includes('.') ||
        hostname.startsWith('.') ||
        hostname.endsWith('.') ||
        hostname.includes('..') ||
        hostname.split('.').some(label =>
          !label ||
          label.length > 63 ||
          !/^[a-z0-9-]+$/i.test(label) ||
          label.startsWith('-') ||
          label.endsWith('-')
        )
      ) {
        throw new Error('Invalid domain');
      }

      if (parsedUrl.port && (
        Number(parsedUrl.port) < 1 ||
        Number(parsedUrl.port) > 65535
      )) {
        throw new Error('Invalid port');
      }

    } catch {
      this.error = 'Invalid URL. Enter a valid domain, such as example.com.';
      return;
    }

    this.loading = true;

    setTimeout(() => {
      this.analyzeUrl(parsedUrl);
      this.loading = false;
      this.scanned = true;
      this.saveScan(parsedUrl.href);
    }, 1000);
  }

  private analyzeUrl(url: URL): void {
    this.score = 0;
    this.threats = [];

    const hostname = url.hostname.toLowerCase();
    const fullUrl = url.href.toLowerCase();

    const addThreat = (
      title: string,
      description: string,
      points: number
    ): void => {
      this.threats.push({ title, description, points });
      this.score += points;
    };

    // 1. Unencrypted connection
    if (url.protocol === 'http:') {
      addThreat(
        'Unsecured HTTP Connection',
        'The website does not use HTTPS encryption.',
        10
      );
    }

    // 2. IP address instead of a domain
    if (
      /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) ||
      hostname.includes(':')
    ) {
      addThreat(
        'IP Address Website',
        'The link uses a direct IP address instead of a regular domain.',
        25
      );
    }

    // 3. Embedded credentials
    if (url.username || url.password) {
      addThreat(
        'Embedded Login Credentials',
        'The URL contains username or password information.',
        25
      );
    }

    // 4. Punycode / internationalized domain
    if (hostname.includes('xn--')) {
      addThreat(
        'Encoded Domain Name',
        'The domain contains encoded characters that may imitate another website.',
        20
      );
    }

    // 5. Suspicious words
    const foundWords = this.suspiciousWords.filter(word =>
      `${url.pathname}${url.search}`.toLowerCase().includes(word)
    );

    if (foundWords.length > 0) {
      addThreat(
        'Suspicious URL Keywords',
        `Potentially deceptive words detected: ${foundWords.join(', ')}.`,
        Math.min(foundWords.length * 4, 20)
      );
    }

    // 6. URL shorteners
    if (this.shorteners.includes(hostname)) {
      addThreat(
        'URL Shortener Detected',
        'Shortened links hide the final destination and should be checked carefully.',
        15
      );
    }

    // 7. Unusually long URL
    if (url.href.length > 150) {
      addThreat(
        'Unusually Long URL',
        'The URL is unusually long and may contain hidden parameters.',
        8
      );
    }

    // 8. Too many subdomains
    if (hostname.split('.').length > 4) {
      addThreat(
        'Excessive Subdomains',
        'The website contains an unusually large number of subdomains.',
        12
      );
    }

    // 9. Multiple hyphens
    if ((hostname.match(/-/g) || []).length >= 3) {
      addThreat(
        'Multiple Domain Hyphens',
        'Multiple hyphens in a domain can be used in deceptive addresses.',
        8
      );
    }

    // 10. Suspicious redirect parameters
    const redirectKeys = [
      'redirect', 'redirect_url', 'return',
      'returnurl', 'next', 'continue'
    ];

    const hasRedirect = redirectKeys.some(key =>
      url.searchParams.has(key)
    );

    if (hasRedirect) {
      addThreat(
        'Redirect Parameters',
        'The URL contains parameters that may redirect visitors.',
        10
      );
    }

    // 11. Too many digits in hostname
    if ((hostname.match(/\d/g) || []).length >= 5) {
      addThreat(
        'Unusual Numeric Domain',
        'The hostname contains an unusually high number of digits.',
        8
      );
    }

    // 12. Suspicious extension
    if (this.suspiciousTlds.some(tld => hostname.endsWith(tld))) {
      addThreat(
        'Uncommon Domain Extension',
        'This domain extension deserves additional verification.',
        10
      );
    }

    // 13. Brand impersonation
    const labels = hostname.split('.');
    const rootDomain = labels.slice(-2).join('.');

    for (const [brand, officialDomains] of Object.entries(this.trustedBrandDomains)) {
      const mentionsBrand = hostname.split('.').some(label =>
        label.includes(brand)
      );

      const isOfficial = officialDomains.some(domain =>
        hostname === domain || hostname.endsWith('.' + domain)
      );

      if (mentionsBrand && !isOfficial) {
        addThreat(
          'Possible Brand Impersonation',
          `The domain mentions ${brand} but does not match its listed official domains.`,
          25
        );
        break;
      }
    }

    // 14. At symbol in URL
    if (url.href.includes('@')) {
      addThreat(
        'Misleading URL Symbol',
        'An @ symbol can make a URL look like it belongs to a different website.',
        15
      );
    }

    // 15. Excessive special characters
    if ((hostname.match(/_/g) || []).length > 0) {
      addThreat(
        'Unusual Domain Characters',
        'The hostname contains underscore characters.',
        10
      );
    }

    this.score = Math.min(this.score, 100);

    this.setRiskResult();
  }

  private setRiskResult(): void {
    if (this.score <= 20) {
      this.riskLevel = 'LOW';
      this.riskMessage = 'Few suspicious URL patterns detected.';
      this.recommendation =
        'No major warning signs were found. Still verify the website before sharing personal information.';
    } else if (this.score <= 50) {
      this.riskLevel = 'MEDIUM';
      this.riskMessage = 'Some suspicious URL patterns detected.';
      this.recommendation =
        'Proceed carefully. Do not share passwords, OTPs or payment details until the domain is verified.';
    } else if (this.score <= 75) {
      this.riskLevel = 'HIGH';
      this.riskMessage = 'Multiple suspicious indicators detected.';
      this.recommendation =
        'Avoid interacting with this link until its source and destination are independently verified.';
    } else {
      this.riskLevel = 'CRITICAL';
      this.riskMessage = 'Several high-risk indicators detected.';
      this.recommendation =
        'Do not enter personal information or payment details. Treat this link as potentially dangerous.';
    }
  }

  private saveScan(url: string): void {
    const record: ScanRecord = {
      url,
      score: this.score,
      level: this.riskLevel,
      date: new Date().toLocaleString()
    };

    this.history.unshift(record);
    this.history = this.history.slice(0, 10);

    localStorage.setItem(
      'detectry-history',
      JSON.stringify(this.history)
    );
  }

  loadHistory(): void {
    try {
      this.history = JSON.parse(
        localStorage.getItem('detectry-history') || '[]'
      );
    } catch {
      this.history = [];
    }
  }

  clearHistory(): void {
    this.history = [];
    localStorage.removeItem('detectry-history');
  }

  scanAgain(item: ScanRecord): void {
    this.url = item.url;
    this.scanUrl();
  }

  get scoreColor(): string {
    if (this.score <= 20) return '#00f5a0';
    if (this.score <= 50) return '#ffd166';
    if (this.score <= 75) return '#ff8c42';
    return '#ff3864';
  }
}
