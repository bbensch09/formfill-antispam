# Form Gate

Open-source, privacy-first anti-spam form protection. Defeats automated form fillers through behavioral analysis and proof-of-work challenges — no image CAPTCHAs, no tracking, no Google dependencies.

## Quick Start

```bash
npm install @form-gate/client @form-gate/server
```

### Client-side
```javascript
import { FormGuard } from '@form-gate/client';

const guard = new FormGuard({
  endpoint: '/api/contact',
  strictness: 'balanced'
});

guard.attach('#contact-form');
```

### Server-side
```javascript
import { validateSubmission } from '@form-gate/server';

app.post('/api/contact', validateSubmission(), (req, res) => {
  // Process legitimate submission
});
```

## Documentation

- [Architecture](docs/architecture.md)
- [Client API](docs/client-api.md)
- [Server API](docs/server-api.md)
- [Deployment Guide](docs/deployment.md)

## Why Form Gate?

- **Privacy-first**: No persistent tracking, no cookies for legitimate users
- **Frictionless**: Invisible detection where possible; simple challenges when needed
- **Anti-automation**: Proof-of-work increases spammer costs; behavioral challenges defeat AI solvers
- **Open source**: Auditable, self-hosted, no vendor lock-in

## License

MIT