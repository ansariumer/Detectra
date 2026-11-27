
import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ScanService, ScanResult } from './scan.service';

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

  private scanService = inject(ScanService);

  url = '';
  loading = false;
  scanned = false;
  error = '';

  score = 0;
  riskLevel = '';
  riskMessage = '';
  threats: Threat[] = [];
  recommendation = '';

  domainExists = false;

  mouseX = 0;
  mouseY = 0;

  history: ScanRecord[] = [];

  ngOnInit(): void {
    this.loadHistory();
  }

  onMouseMove(event: MouseEvent): void {
    this.mouseX = event.clientX;
    this.mouseY = event.clientY;
  }

  // MAIN BACKEND SCAN FUNCTION
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
        throw new Error('Invalid protocol');
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

    } catch {
      this.error = 'Invalid URL. Enter a valid domain, such as example.com.';
      return;
    }

    this.loading = true;

    // Send URL to Node.js backend
    this.scanService.scanWebsite(parsedUrl.href).subscribe({

      next: (result: ScanResult) => {

        this.score = result.score;
        this.domainExists = result.domainExists;

        // Convert backend threat strings into frontend objects
        this.threats = (result.threats || []).map(
          (threat: string) => ({
            title: threat,
            description: 'This indicator was detected by the backend security engine.',
            points: 0
          })
        );

        this.setRiskResult();

        if (!result.domainExists) {
          this.recommendation =
            'This domain could not be resolved. Do not enter personal information or payment details.';
        }

        this.loading = false;
        this.scanned = true;

        this.saveScan(parsedUrl.href);

      },

      error: (err) => {

        this.loading = false;
        this.scanned = false;

        this.error =
          err?.error?.error ||
          'Unable to connect to Detectra backend. Make sure your backend is running on port 3000.';

      }

    });
  }

  // RISK CLASSIFICATION
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

  // SAVE SCAN HISTORY
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
