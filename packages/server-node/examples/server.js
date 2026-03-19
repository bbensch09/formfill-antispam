const express = require('express');
const { validateSubmission } = require('@form-gate/server');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Parse JSON bodies
app.use(express.json());

// Serve static files (the demo form)
app.use(express.static(path.join(__dirname, '../vanilla-html')));

// Contact form endpoint with Form Gate protection
app.post('/api/contact',
  validateSubmission({
    secretKey: process.env.FORM_GATE_SECRET || 'demo-secret-change-in-production',
    maxAge: 300,
    maxScore: 50,
    maxLinksInMessage: 3,
    blockedEmailDomains: ['tempmail.com', '10minutemail.com', 'guerrillamail.com'],
    suspiciousKeywords: ['viagra', 'cialis', 'casino', 'lottery', 'winner', 'congratulations you won'],
    rateLimitWindow: 3600,
    rateLimitMax: 5
  }),
  (req, res) => {
    // Access validation metadata
    const { score, timestamp, meta } = req.formGate;
    
    console.log('Legitimate submission received:');
    console.log('  Score:', score);
    console.log('  Form time:', meta.formTime, 'ms');
    console.log('  Mouse path length:', meta.mousePathLength);
    console.log('  Keystrokes:', meta.keystrokeCount);
    console.log('  Body:', req.body);
    
    // Process the submission (send email, save to DB, etc.)
    
    res.json({
      success: true,
      message: 'Message received!',
      meta: {
        score,
        formTime: meta.formTime,
        fieldCount: meta.fieldCount
      }
    });
  }
);

// Error handler
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({
    success: false,
    error: 'Internal server error'
  });
});

app.listen(PORT, () => {
  console.log(`Form Gate demo server running on http://localhost:${PORT}`);
  console.log('Open that URL to test the form protection');
});