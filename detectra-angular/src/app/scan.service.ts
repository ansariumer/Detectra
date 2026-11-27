
import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface ScanResult {
  success: boolean;
  url: string;
  domain: string;
  domainExists: boolean;
  score: number;
  level: string;
  threats: string[];
  message: string;
}

@Injectable({
  providedIn: 'root'
})
export class ScanService {
  private http = inject(HttpClient);

  private apiUrl = 'http://localhost:3000/api/scan';

  scanWebsite(url: string): Observable<ScanResult> {
    return this.http.post<ScanResult>(this.apiUrl, { url });
  }
}

