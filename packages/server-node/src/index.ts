import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

interface TokenPayload {
  timestamp: number;
  score: number;
  fingerprint: string;
  challenge?: {
    prefix: string;
    nonce: number;
    hash: string;
    duration: number;
  };
  nonce: string;
}

interface ValidationOptions {
  secretKey: string;
  maxAge?: number; // seconds
  maxScore?: number;
  maxLinksInMessage?: number;
  blockedEmailDomains?: string[];
  suspiciousKeywords?: string[];
  rateLimitWindow?: number; // seconds
  rateLimitMax?: number;
}

interface SubmissionMeta {
  score: number;
  timestamp: number;
  formTime: number;
  fieldCount: number;
  mousePathLength: number;
  keystrokeCount: number;
  automationScore: number;
}

// Simple in-memory rate limiting (use Redis in production)
const rateLimitStore = new Map<string, { count: number; resetTime: number }>();

/**
 * Express middleware to validate Form Gate tokens
 */
export function validateSubmission(options: ValidationOptions) {
  const {
    secretKey,
    maxAge = 300, // 5 minutes
    maxScore = 60,
    maxLinksInMessage = 5,
    blockedEmailDomains = ['tempmail.com', '10minutemail.com', 'guerrillamail.com'],
    suspiciousKeywords = ['viagra', 'cialis', 'casino', 'lottery', 'winner', 'congratulations'],
    rateLimitWindow = 3600, // 1 hour
    rateLimitMax = 10
  } = options;

  return (req: Request, res: Response, next: NextFunction) => {
    try {
      // Extract token and metadata
      const token = req.body._form_gate_token;
      const metaStr = req.body._form_gate_meta;

      if (!token || !metaStr) {
        return res.status(400).json({
          error: 'Form protection token missing',
          code: 'MISSING_TOKEN'
        });
      }

      // Parse metadata
      let meta: SubmissionMeta;
      try {
        meta = JSON.parse(metaStr);
      } catch {
        return res.status(400).json({
          error: 'Invalid metadata',
          code: 'INVALID_META'
        });
      }

      // Decode token
      let payload: TokenPayload;
      try {
        payload = JSON.parse(Buffer.from(token, 'base64').toString());
      } catch {
        return res.status(400).json({
          error: 'Invalid token format',
          code: 'INVALID_TOKEN'
        });
      }

      // Verify token age
      const age = (Date.now() - payload.timestamp) / 1000;
      if (age > maxAge) {
        return res.status(400).json({
          error: 'Token expired',
          code: 'TOKEN_EXPIRED'
        });
      }

      // Verify proof of work (if present)
      if (payload.challenge) {
        const { prefix, nonce, hash } = payload.challenge;
        const expectedHash = crypto
          .createHash('sha256')
          .update(prefix + nonce)
          .digest('hex');
        
        if (expectedHash !== hash) {
          return res.status(400).json({
            error: 'Invalid proof of work',
            code: 'INVALID_POW'
          });
        }

        // Verify PoW took reasonable time (anti-replay)
        if (payload.challenge.duration < 100) { // Less than 100ms is suspicious
          return res.status(400).json({
            error: 'Proof of work completed too quickly',
            code: 'POW_TOO_FAST'
          });
        }
      }

      // Verify fingerprint (basic check)
      const expectedFingerprint = generateFingerprint(req);
      if (payload.fingerprint !== expectedFingerprint) {
        // Don't block, just log - fingerprint can change between client/server
        console.warn('Form Gate: Fingerprint mismatch');
      }

      // Check client score against server threshold
      if (payload.score > maxScore) {
        return res.status(400).json({
          error: 'High automation score detected',
          code: 'HIGH_SCORE',
          score: payload.score
        });
      }

      // Rate limiting
      const clientId = getClientId(req);
      if (isRateLimited(clientId, rateLimitWindow, rateLimitMax)) {
        return res.status(429).json({
          error: 'Rate limit exceeded',
          code: 'RATE_LIMITED'
        });
      }

      // Message content analysis
      const message = req.body.message || req.body.content || req.body.body || '';
      const email = req.body.email || req.body.from || '';

      // Check for excessive links
      const linkCount = (message.match(/https?:\/\//g) || []).length;
      if (linkCount > maxLinksInMessage) {
        return res.status(400).json({
          error: 'Too many links in message',
          code: 'TOO_MANY_LINKS'
        });
      }

      // Check email domain
      const emailDomain = email.split('@')[1]?.toLowerCase();
      if (emailDomain && blockedEmailDomains.includes(emailDomain)) {
        return res.status(400).json({
          error: 'Email domain not allowed',
          code: 'BLOCKED_DOMAIN'
        });
      }

      // Check for suspicious keywords
      const messageLower = message.toLowerCase();
      const foundKeywords = suspiciousKeywords.filter(kw => 
        messageLower.includes(kw.toLowerCase())
      );
      if (foundKeywords.length > 0) {
        return res.status(400).json({
          error: 'Message contains suspicious content',
          code: 'SUSPICIOUS_CONTENT',
          keywords: foundKeywords
        });
      }

      // Calculate entropy of message (spam often has low entropy)
      const entropy = calculateEntropy(message);
      if (entropy < 2 && message.length > 50) {
        return res.status(400).json({
          error: 'Message appears to be automated',
          code: 'LOW_ENTROPY'
        });
      }

      // All checks passed - attach metadata to request
      (req as any).formGate = {
        score: payload.score,
        timestamp: payload.timestamp,
        meta
      };

      // Remove form gate fields from body
      delete req.body._form_gate_token;
      delete req.body._form_gate_meta;

      next();
    } catch (error) {
      console.error('Form Gate validation error:', error);
      return res.status(500).json({
        error: 'Validation failed',
        code: 'VALIDATION_ERROR'
      });
    }
  };
}

/**
 * Generate fingerprint from request
 */
function generateFingerprint(req: Request): string {
  const components = [
    req.headers['user-agent'] || '',
    req.headers['accept-language'] || '',
    req.ip
  ];
  
  return crypto
    .createHash('sha256')
    .update(components.join('::'))
    .digest('hex');
}

/**
 * Get client identifier for rate limiting
 */
function getClientId(req: Request): string {
  // Use IP + User Agent hash
  const components = [req.ip, req.headers['user-agent'] || ''];
  return crypto
    .createHash('sha256')
    .update(components.join('::'))
    .digest('hex')
    .slice(0, 16);
}

/**
 * Check if client is rate limited
 */
function isRateLimited(clientId: string, window: number, max: number): boolean {
  const now = Date.now();
  const entry = rateLimitStore.get(clientId);

  if (!entry || now > entry.resetTime) {
    rateLimitStore.set(clientId, {
      count: 1,
      resetTime: now + window * 1000
    });
    return false;
  }

  if (entry.count >= max) {
    return true;
  }

  entry.count++;
  return false;
}

/**
 * Calculate Shannon entropy of a string
 */
function calculateEntropy(str: string): number {
  if (str.length === 0) return 0;
  
  const freq: { [char: string]: number } = {};
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }
  
  let entropy = 0;
  const len = str.length;
  
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  
  return entropy;
}

// Export for TypeScript
export type { ValidationOptions, TokenPayload, SubmissionMeta };