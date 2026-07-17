/**
 * Sanitize sensitive information from text before posting publicly
 */

// Phone number patterns (various formats)
const PHONE_PATTERNS = [
  /\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}/g,  // US format
  /\+[0-9]{1,3}[-.\s]?[0-9]{6,14}/g,  // International format
  /\b[0-9]{10,15}\b/g,  // Plain digits (10-15 digits)
];

// API key/token patterns
const SECRET_PATTERNS = [
  /\b(sk|pk|api|key|token|secret|password|pwd|auth)[-_]?[a-zA-Z0-9]{16,}/gi,
  /Bearer\s+[a-zA-Z0-9._-]+/gi,
  /\b[a-f0-9]{32,64}\b/gi,  // Hex strings (API keys, hashes)
  /ghp_[a-zA-Z0-9]{20,}/g,  // GitHub personal access tokens
  /gho_[a-zA-Z0-9]{20,}/g,  // GitHub OAuth tokens
  /github_pat_[a-zA-Z0-9_]{22,}/g,  // GitHub fine-grained PATs
  /xox[baprs]-[a-zA-Z0-9-]+/g,  // Slack tokens
  /sk-[a-zA-Z0-9]{32,}/g,  // OpenAI API keys
  /AKIA[A-Z0-9]{16}/g,  // AWS access key IDs
];

// Email patterns (optional - can be enabled if needed)
const EMAIL_PATTERN = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;

// Credit card patterns
const CC_PATTERNS = [
  /\b[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b/g,
  /\b[0-9]{15,16}\b/g,  // Plain digits
];

// SSN pattern
const SSN_PATTERN = /\b[0-9]{3}[-\s]?[0-9]{2}[-\s]?[0-9]{4}\b/g;

// URL patterns that may reveal infrastructure
const PRIVATE_URL_PATTERNS = [
  /https?:\/\/[a-zA-Z0-9-]+\.tail[a-f0-9]+\.ts\.net[^\s)"]*/gi,  // Tailscale URLs
  /https?:\/\/[a-zA-Z0-9-]+\.ngrok[a-zA-Z0-9-]*\.[a-z]+[^\s)"]*/gi,  // ngrok URLs
  /https?:\/\/localhost[:\d]*[^\s)"]*/gi,  // localhost URLs
  /https?:\/\/127\.0\.0\.1[:\d]*[^\s)"]*/gi,  // 127.0.0.1 URLs
  /https?:\/\/192\.168\.[0-9.]+[:\d]*[^\s)"]*/gi,  // Private network IPs
  /https?:\/\/10\.[0-9.]+[:\d]*[^\s)"]*/gi,  // Private network IPs
];

export interface SanitizeOptions {
  redactPhones?: boolean;
  redactSecrets?: boolean;
  redactEmails?: boolean;
  redactCreditCards?: boolean;
  redactSSN?: boolean;
  redactPrivateUrls?: boolean;
  replacement?: string;
}

const DEFAULT_OPTIONS: SanitizeOptions = {
  redactPhones: true,
  redactSecrets: true,
  redactEmails: false,  // Off by default - emails often appear in git commits
  redactCreditCards: true,
  redactSSN: true,
  redactPrivateUrls: true,
  replacement: "[REDACTED]",
};

/**
 * Sanitize sensitive information from text
 */
export function sanitize(text: string, options: SanitizeOptions = {}): string {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  let result = text;

  if (opts.redactPhones) {
    for (const pattern of PHONE_PATTERNS) {
      result = result.replace(pattern, `[PHONE ${opts.replacement}]`);
    }
  }

  if (opts.redactSecrets) {
    for (const pattern of SECRET_PATTERNS) {
      result = result.replace(pattern, `[SECRET ${opts.replacement}]`);
    }
  }

  if (opts.redactEmails) {
    result = result.replace(EMAIL_PATTERN, `[EMAIL ${opts.replacement}]`);
  }

  if (opts.redactCreditCards) {
    for (const pattern of CC_PATTERNS) {
      result = result.replace(pattern, `[CC ${opts.replacement}]`);
    }
  }

  if (opts.redactSSN) {
    result = result.replace(SSN_PATTERN, `[SSN ${opts.replacement}]`);
  }

  if (opts.redactPrivateUrls) {
    for (const pattern of PRIVATE_URL_PATTERNS) {
      result = result.replace(pattern, `[URL ${opts.replacement}]`);
    }
  }

  return result;
}

/**
 * Check if text contains potentially sensitive information
 */
export function containsSensitiveInfo(text: string): boolean {
  const allPatterns = [
    ...PHONE_PATTERNS,
    ...SECRET_PATTERNS,
    ...CC_PATTERNS,
    ...PRIVATE_URL_PATTERNS,
    SSN_PATTERN,
  ];

  return allPatterns.some(pattern => {
    pattern.lastIndex = 0;  // Reset regex state
    return pattern.test(text);
  });
}
