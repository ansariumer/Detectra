
const express = require('express');
const cors = require('cors');
const dns = require('dns').promises;
const ipaddr = require('ipaddr.js');

const app = express();

app.use(cors());
app.use(express.json());

function isPublicIP(ip) {
  try {
    const address = ipaddr.parse(ip);
    return address.range() === 'unicast';
  } catch {
    return false;
  }
}

async function checkWebsite(inputUrl) {
  let currentUrl = inputUrl;
  let lastStatus = null;
  let reachable = false;
  let redirectUrl = null;

  for (let i = 0; i < 4; i++) {
    const parsed = new URL(currentUrl);

    if (!['http:', 'https:'].includes(parsed.protocol)) {
      throw new Error('Unsupported protocol');
    }

    const addresses = await dns.lookup(parsed.hostname, {
      all: true,
      verbatim: true
    });

    if (!addresses.length ||
        addresses.some(item => !isPublicIP(item.address))) {
      throw new Error('Website resolves to a restricted IP address');
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

    try {
      const response = await fetch(currentUrl, {
        method: 'HEAD',
        redirect: 'manual',
        signal: controller.signal,
        headers: {
          'User-Agent': 'Detectra-Website-Checker/1.0'
        }
      });

      lastStatus = response.status;

      if ([301, 302, 303, 307, 308].includes(response.status)) {
        const location = response.headers.get('location');

        if (!location) {
          reachable = true;
          break;
        }

        const nextUrl = new URL(location, currentUrl);

        if (!['http:', 'https:'].includes(nextUrl.protocol)) {
          throw new Error('Unsafe redirect protocol');
        }

        redirectUrl = nextUrl.href;
        currentUrl = nextUrl.href;
        reachable = true;
        continue;
      }

      reachable = true;
      break;

    } finally {
      clearTimeout(timeout);
    }
  }

  return {
    reachable,
    statusCode: lastStatus,
    finalUrl: currentUrl,
    redirectUrl
  };
}

app.get('/', (req, res) => {
  res.json({
    message: 'Detectra Backend is Running!'
  });
});

app.post('/api/scan', async (req, res) => {
  try {
    const { url } = req.body;

    if (!url || typeof url !== 'string' || url.length > 2048) {
      return res.status(400).json({
        error: 'Please provide a valid URL'
      });
    }

    let parsed;

    try {
      parsed = new URL(
        /^https?:\/\//i.test(url) ? url : `https://${url}`
      );
    } catch {
      return res.status(400).json({
        error: 'Invalid URL'
      });
    }

    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return res.status(400).json({
        error: 'Only HTTP and HTTPS are allowed'
      });
    }

    const domain = parsed.hostname.toLowerCase();

    if (
      !domain.includes('.') ||
      domain.length > 253 ||
      domain.split('.').some(part =>
        !part || part.length > 63 ||
        !/^[a-z0-9-]+$/i.test(part) ||
        part.startsWith('-') || part.endsWith('-')
      )
    ) {
      return res.status(400).json({
        error: 'Invalid domain'
      });
    }

    let domainExists = false;
    let website = {
      reachable: false,
      statusCode: null,
      finalUrl: null,
      redirectUrl: null
    };

    let dnsError = null;

    try {
      const records = await dns.lookup(domain);
      domainExists = !!records.address;
    } catch {
      dnsError = 'Domain could not be resolved';
    }

    if (domainExists) {
      try {
        website = await checkWebsite(parsed.href);
      } catch (error) {
        website.error = error.name === 'AbortError'
          ? 'Website request timed out'
          : error.message;
      }
    }

    let score = 0;
    const threats = [];

    const addThreat = (message, points) => {
      threats.push(message);
      score += points;
    };

    const suspiciousWords = [
      'scam', 'phishing', 'fraud', 'fake',
      'malware', 'steal', 'hack', 'login',
      'verify', 'password', 'wallet', 'prize'
    ];

    for (const word of suspiciousWords) {
      if (domain.includes(word)) {
        addThreat(`Suspicious keyword: ${word}`,
          ['scam', 'phishing', 'fraud', 'malware', 'steal']
            .includes(word) ? 30 : 10);
      }
    }

    if (parsed.protocol === 'http:') {
      addThreat('Website does not use HTTPS', 15);
    }

    if (domain.split('.').length > 3) {
      addThreat('Unusual subdomain structure', 10);
    }

    if (domain.includes('xn--')) {
      addThreat('Encoded international domain', 25);
    }

    if (!domainExists) {
      addThreat('Domain does not resolve through DNS', 40);
    }

    if (domainExists && !website.reachable) {
      addThreat('Website could not be reached', 15);
    }

    score = Math.min(score, 100);

    let level = 'Safe';

    if (score >= 60) level = 'Dangerous';
    else if (score >= 30) level = 'Suspicious';

    res.json({
      success: true,
      url: parsed.href,
      domain,
      domainExists,
      websiteReachable: website.reachable,
      statusCode: website.statusCode,
      finalUrl: website.finalUrl,
      redirectUrl: website.redirectUrl,
      websiteError: website.error || dnsError,
      score,
      level,
      threats,
      message: 'Website analysis completed'
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});

app.listen(3000, () => {
  console.log('Detectra backend running on port 3000');
});
