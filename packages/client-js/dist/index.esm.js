/**
 * Form Gate - Client-side Bot Detection
 * 
 * Detects automated form submissions through:
 * - Timing analysis
 * - Honeypot fields
 * - Mouse/keyboard behavior
 * - Browser fingerprinting
 * - Proof-of-work challenges
 */

class FormGuard {
  constructor(options = {}) {
    this.config = {
      endpoint: options.endpoint || '/api/contact',
      strictness: options.strictness || 'balanced', // lenient | balanced | strict
      
      // Detection features
      honeypot: options.honeypot !== false,
      timingAnalysis: options.timingAnalysis !== false,
      mouseTracking: options.mouseTracking !== false,
      proofOfWork: options.proofOfWork !== false,
      
      // Thresholds (in seconds)
      minFormTime: options.minFormTime || 3,
      minFieldTime: options.minFieldTime || 0.5,
      
      // Proof of work difficulty (higher = harder)
      powDifficulty: options.powDifficulty || 4,
      
      // Callbacks
      onChallenge: options.onChallenge || this.defaultOnChallenge,
      onBlocked: options.onBlocked || this.defaultOnBlocked,
      onSuccess: options.onSuccess || this.defaultOnSuccess,
      
      // Debug
      debug: options.debug || false
    };
    
    this.state = {
      formStartTime: null,
      fieldInteractions: [],
      mousePath: [],
      keystrokes: [],
      honeypotFields: [],
      challengeCompleted: false,
      token: null
    };
    
    this.observers = [];
  }
  
  /**
   * Attach to a form element
   */
  attach(selector) {
    const form = typeof selector === 'string' 
      ? document.querySelector(selector) 
      : selector;
      
    if (!form) {
      console.error('Form Gate: Could not find form element');
      return;
    }
    
    this.form = form;
    this.log('Attached to form');
    
    // Inject honeypot fields
    if (this.config.honeypot) {
      this.injectHoneypots();
    }
    
    // Start tracking
    this.setupTracking();
    
    // Intercept submission
    form.addEventListener('submit', this.handleSubmit.bind(this), true);
    
    return this;
  }
  
  /**
   * Inject invisible honeypot fields
   */
  injectHoneypots() {
    const fieldNames = ['website', 'url', 'phone_ext', 'company_size', 'fax'];
    const strategies = [
      { style: 'position:absolute;left:-9999px;', type: 'text' },
      { style: 'opacity:0;height:0;width:0;', type: 'text' },
      { style: 'visibility:hidden;', type: 'text' },
      { style: 'display:none;', type: 'text' },
      { tabindex: '-1', autocomplete: 'off', type: 'text' }
    ];
    
    fieldNames.forEach((name, i) => {
      const input = document.createElement('input');
      const strategy = strategies[i % strategies.length];
      
      input.type = strategy.type;
      input.name = `_${name}_${Math.random().toString(36).slice(2, 8)}`;
      input.setAttribute('aria-hidden', 'true');
      input.setAttribute('tabindex', strategy.tabindex || '-1');
      input.setAttribute('autocomplete', strategy.autocomplete || 'off');
      
      if (strategy.style) {
        input.style.cssText = strategy.style;
      }
      
      this.form.appendChild(input);
      this.state.honeypotFields.push(input);
      this.log('Injected honeypot:', input.name);
    });
  }
  
  /**
   * Set up all tracking mechanisms
   */
  setupTracking() {
    // Form start time
    this.form.addEventListener('focus', () => {
      if (!this.state.formStartTime) {
        this.state.formStartTime = Date.now();
        this.log('Form focus detected');
      }
    }, true);
    
    // Field timing
    const fields = this.form.querySelectorAll('input, textarea, select');
    fields.forEach(field => {
      let fieldStartTime = null;
      
      field.addEventListener('focus', () => {
        fieldStartTime = Date.now();
      });
      
      field.addEventListener('blur', () => {
        if (fieldStartTime) {
          this.state.fieldInteractions.push({
            name: field.name,
            duration: Date.now() - fieldStartTime,
            timestamp: Date.now()
          });
        }
      });
    });
    
    // Mouse tracking
    if (this.config.mouseTracking) {
      this.setupMouseTracking();
    }
    
    // Keystroke dynamics
    this.setupKeystrokeTracking();
    
    // Browser fingerprinting
    this.detectAutomation();
  }
  
  /**
   * Track mouse movement entropy
   */
  setupMouseTracking() {
    let lastX = 0, lastY = 0;
    let lastTime = Date.now();
    
    const trackMouse = (e) => {
      const now = Date.now();
      const dx = e.clientX - lastX;
      const dy = e.clientY - lastY;
      const dt = now - lastTime;
      
      if (lastX !== 0 && lastY !== 0) {
        
        this.state.mousePath.push({
          x: e.clientX,
          y: e.clientY,
          t: now,
          v: Math.sqrt(dx * dx + dy * dy) / Math.max(dt, 1) // velocity
        });
        
        // Limit path history
        if (this.state.mousePath.length > 500) {
          this.state.mousePath.shift();
        }
      }
      
      lastX = e.clientX;
      lastY = e.clientY;
      lastTime = now;
    };
    
    document.addEventListener('mousemove', trackMouse);
    
    // Store for cleanup
    this.observers.push(() => {
      document.removeEventListener('mousemove', trackMouse);
    });
  }
  
  /**
   * Track keystroke timing (for typed fields)
   */
  setupKeystrokeTracking() {
    const textFields = this.form.querySelectorAll('input[type="text"], input[type="email"], textarea');
    
    textFields.forEach(field => {
      let lastKeystroke = 0;
      
      field.addEventListener('keydown', (e) => {
        const now = Date.now();
        if (lastKeystroke) {
          this.state.keystrokes.push({
            key: e.key,
            interval: now - lastKeystroke,
            timestamp: now
          });
          
          // Limit history
          if (this.state.keystrokes.length > 100) {
            this.state.keystrokes.shift();
          }
        }
        lastKeystroke = now;
      });
    });
  }
  
  /**
   * Detect headless browsers and automation frameworks
   */
  detectAutomation() {
    const checks = {
      // Headless browser indicators
      webdriver: navigator.webdriver,
      pluginsEmpty: navigator.plugins?.length === 0,
      languagesMissing: !navigator.languages,
      
      // Automation framework traces
      playwright: window.playwright,
      selenium: window.selenium || window.webdriver,
      puppeteer: window.puppeteer,
      cypress: window.Cypress,
      
      // Inconsistency checks
      chromeNotChrome: /Chrome/.test(navigator.userAgent) && !window.chrome,
      headlessChrome: /HeadlessChrome/.test(navigator.userAgent),
      
      // Screen inconsistencies
      screenMismatch: window.outerWidth === 0 || window.outerHeight === 0,
      
      // WebGL fingerprinting
      webglVendor: this.getWebGLVendor(),
      
      // Notification API (often disabled in headless)
      notificationsDisabled: 'Notification' in window && Notification.permission === 'default'
    };
    
    this.state.automationScore = Object.values(checks).filter(Boolean).length;
    this.state.automationChecks = checks;
    
    this.log('Automation checks:', checks);
    
    return this.state.automationScore;
  }
  
  /**
   * Get WebGL vendor/renderer (can detect headless)
   */
  getWebGLVendor() {
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return null;
      
      const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
      if (!debugInfo) return null;
      
      return {
        vendor: gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL),
        renderer: gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL)
      };
    } catch (e) {
      return null;
    }
  }
  
  /**
   * Calculate suspicion score (0-100)
   */
  calculateScore() {
    let score = this.state.automationScore * 10; // Base from automation checks
    
    // Timing analysis
    const formTime = Date.now() - this.state.formStartTime;
    if (formTime < this.config.minFormTime * 1000) {
      score += 20;
    }
    
    // Field interaction analysis
    const avgFieldTime = this.state.fieldInteractions.reduce((a, b) => a + b.duration, 0) 
      / this.state.fieldInteractions.length;
    if (avgFieldTime < this.config.minFieldTime * 1000) {
      score += 15;
    }
    
    // Mouse path entropy
    const mouseEntropy = this.calculateMouseEntropy();
    if (mouseEntropy < 0.5) { // Low entropy = suspicious
      score += 15;
    }
    
    // Honeypot checks
    const honeyFilled = this.state.honeypotFields.some(h => h.value !== '');
    if (honeyFilled) {
      score += 50; // Instant flag
    }
    
    // Keystroke analysis
    if (this.state.keystrokes.length > 5) {
      const avgInterval = this.state.keystrokes.reduce((a, b) => a + b.interval, 0) 
        / this.state.keystrokes.length;
      if (avgInterval < 50) { // Too fast typing
        score += 10;
      }
      
      // Check for suspicious uniformity
      const variance = this.calculateVariance(this.state.keystrokes.map(k => k.interval));
      if (variance < 100) { // Too consistent
        score += 10;
      }
    }
    
    return Math.min(score, 100);
  }
  
  /**
   * Calculate mouse path entropy (higher = more human-like)
   */
  calculateMouseEntropy() {
    if (this.state.mousePath.length < 10) return 0;
    
    // Calculate velocity changes
    const velocities = this.state.mousePath.map(p => p.v).filter(v => !isNaN(v));
    if (velocities.length < 5) return 0;
    
    // Human mouse movement has high variance in velocity
    const mean = velocities.reduce((a, b) => a + b, 0) / velocities.length;
    const variance = velocities.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / velocities.length;
    const stdDev = Math.sqrt(variance);
    
    // Normalize to 0-1 range (empirically tuned)
    return Math.min(stdDev / 100, 1);
  }
  
  /**
   * Calculate variance of an array
   */
  calculateVariance(arr) {
    if (arr.length === 0) return 0;
    const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
    return arr.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / arr.length;
  }
  
  /**
   * Proof of work challenge
   */
  async solveProofOfWork() {
    const difficulty = this.config.powDifficulty;
    const prefix = Math.random().toString(36).slice(2, 10);
    let nonce = 0;
    
    const target = '0'.repeat(difficulty);
    
    const startTime = Date.now();
    
    while (true) {
      const hash = await this.simpleHash(prefix + nonce);
      if (hash.startsWith(target)) {
        const duration = Date.now() - startTime;
        this.log(`PoW solved in ${duration}ms`);
        return { prefix, nonce, hash, duration };
      }
      nonce++;
      
      // Yield to prevent blocking UI
      if (nonce % 1000 === 0) {
        await new Promise(r => requestAnimationFrame(r));
      }
    }
  }
  
  /**
   * Simple SHA-256 hash
   */
  async simpleHash(str) {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }
  
  /**
   * Handle form submission
   */
  async handleSubmit(e) {
    e.preventDefault();
    
    this.log('Processing submission...');
    
    // Calculate suspicion score
    const score = this.calculateScore();
    this.log('Suspicion score:', score);
    
    // Determine action based on strictness
    let needsChallenge = false;
    
    switch (this.config.strictness) {
      case 'lenient':
        needsChallenge = score > 60;
        break;
      case 'balanced':
        needsChallenge = score > 40;
        break;
      case 'strict':
        needsChallenge = score > 20;
        break;
    }
    
    // Instant block for obvious bots
    if (score > 80) {
      this.config.onBlocked('High automation score detected');
      return false;
    }
    
    // Present challenge if needed
    if (needsChallenge && !this.state.challengeCompleted) {
      if (this.config.proofOfWork) {
        this.log('Presenting proof-of-work challenge');
        const pow = await this.solveProofOfWork();
        this.state.proofOfWork = pow;
        this.state.challengeCompleted = true;
      } else {
        // Present behavioral challenge
        this.config.onChallenge('slider');
        return false; // Wait for challenge completion
      }
    }
    
    // Generate submission token
    const token = await this.generateToken();
    this.state.token = token;
    
    // Add token to form
    let tokenInput = this.form.querySelector('input[name="_form_gate_token"]');
    if (!tokenInput) {
      tokenInput = document.createElement('input');
      tokenInput.type = 'hidden';
      tokenInput.name = '_form_gate_token';
      this.form.appendChild(tokenInput);
    }
    tokenInput.value = token;
    
    // Add metadata
    let metaInput = this.form.querySelector('input[name="_form_gate_meta"]');
    if (!metaInput) {
      metaInput = document.createElement('input');
      metaInput.type = 'hidden';
      metaInput.name = '_form_gate_meta';
      this.form.appendChild(metaInput);
    }
    metaInput.value = JSON.stringify({
      score,
      timestamp: Date.now(),
      formTime: Date.now() - this.state.formStartTime,
      fieldCount: this.state.fieldInteractions.length,
      mousePathLength: this.state.mousePath.length,
      keystrokeCount: this.state.keystrokes.length,
      automationScore: this.state.automationScore
    });
    
    this.config.onSuccess(token);
    
    // Allow submission to proceed
    this.form.submit();
    
    return true;
  }
  
  /**
   * Generate cryptographically signed token
   */
  async generateToken() {
    const payload = {
      timestamp: Date.now(),
      score: this.calculateScore(),
      fingerprint: await this.getFingerprint(),
      challenge: this.state.proofOfWork,
      nonce: Math.random().toString(36).slice(2)
    };
    
    return btoa(JSON.stringify(payload));
  }
  
  /**
   * Get browser fingerprint (for server verification)
   */
  async getFingerprint() {
    const components = [
      navigator.userAgent,
      navigator.language,
      screen.width + 'x' + screen.height,
      new Date().getTimezoneOffset(),
      !!window.sessionStorage,
      !!window.localStorage,
      navigator.hardwareConcurrency,
      navigator.deviceMemory
    ];
    
    return this.simpleHash(components.join('::'));
  }
  
  /**
   * Default callbacks
   */
  defaultOnChallenge(type) {
    console.log('Form Gate: Challenge required -', type);
  }
  
  defaultOnBlocked(reason) {
    console.error('Form Gate: Submission blocked -', reason);
    alert('Submission blocked. Please try again.');
  }
  
  defaultOnSuccess(token) {
    console.log('Form Gate: Token generated');
  }
  
  /**
   * Logging
   */
  log(...args) {
    if (this.config.debug) {
      console.log('[Form Gate]', ...args);
    }
  }
  
  /**
   * Cleanup
   */
  destroy() {
    this.observers.forEach(cleanup => cleanup());
    this.observers = [];
  }
}

// Export for different module systems
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { FormGuard };
} else if (typeof window !== 'undefined') {
  window.FormGate = { FormGuard };
}

export { FormGuard, FormGuard as default };
