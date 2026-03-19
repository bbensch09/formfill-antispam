# @form-gate/server

Server-side validation for Form Gate submissions.

## Installation

```bash
npm install @form-gate/server
```

## Usage

### Express

```javascript
import express from 'express';
import { validateSubmission } from '@form-gate/server';

const app = express();

app.use(express.json());

app.post('/api/contact', 
  validateSubmission({
    secretKey: process.env.FORM_GATE_SECRET,
    maxAge: 300,           // Token expires after 5 minutes
    maxScore: 50,          // Reject submissions with score > 50
    maxLinksInMessage: 3,  // Reject if > 3 URLs
    blockedEmailDomains: ['tempmail.com', '10minutemail.com'],
    suspiciousKeywords: ['viagra', 'casino', 'lottery'],
    rateLimitWindow: 3600, // 1 hour window
    rateLimitMax: 5        // Max 5 submissions per hour per IP
  }),
  (req, res) => {
    // Access validation metadata
    const { score, timestamp } = req.formGate;
    
    // Process legitimate submission
    // req.body has _form_gate_token and _form_gate_meta removed
    
    res.json({ success: true });
  }
);
```

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `secretKey` | string | required | Secret for token validation |
| `maxAge` | number | 300 | Maximum token age in seconds |
| `maxScore` | number | 60 | Maximum allowed suspicion score |
| `maxLinksInMessage` | number | 5 | Max URLs allowed in message |
| `blockedEmailDomains` | string[] | temp mail list | Blocked email domains |
| `suspiciousKeywords` | string[] | spam keywords | Blocked content keywords |
| `rateLimitWindow` | number | 3600 | Rate limit window in seconds |
| `rateLimitMax` | number | 10 | Max submissions per window |

## Error Codes

- `MISSING_TOKEN` - No Form Gate token present
- `INVALID_TOKEN` - Token format invalid
- `TOKEN_EXPIRED` - Token too old
- `INVALID_POW` - Proof of work invalid
- `POW_TOO_FAST` - Proof of work suspiciously fast
- `HIGH_SCORE` - Automation score too high
- `RATE_LIMITED` - Too many submissions
- `TOO_MANY_LINKS` - Excessive URLs in message
- `BLOCKED_DOMAIN` - Email domain on blocklist
- `SUSPICIOUS_CONTENT` - Message contains spam keywords
- `LOW_ENTROPY` - Message appears automated

## License

MIT