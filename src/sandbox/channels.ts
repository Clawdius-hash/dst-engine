/**
 * Channel abstraction and HTTP implementation for DST runtime verification sandbox.
 *
 * DST finds vulnerabilities statically and generates ProofCertificates with payloads.
 * The sandbox PROVES them by firing those payloads against running applications.
 * The Channel is the universal delivery mechanism — HTTP for v1, but the interface
 * supports CDP (Electron), UIA (native), and Browser channels in the future.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface DeliveryTarget {
  base_url: string;   // e.g., "https://localhost:8443"
  path: string;       // e.g., "/sqli-00/BenchmarkTest00008"
}

export interface DeliveryParams {
  method: string;     // GET, POST, PUT, DELETE
  param?: string;     // parameter name for form body or query string
  header?: string;    // header name for header-based delivery
  cookie?: string;    // cookie name for cookie-based delivery
  content_type?: string;  // defaults to application/x-www-form-urlencoded
}

export interface DeliveryResult {
  delivered: boolean;
  status_code: number;
  body: string;
  response_time_ms: number;
  headers: Record<string, string>;
  error?: string;
}

export interface ObservationResult {
  signal_detected: boolean;
  signal_type: 'content_match' | 'timing' | 'error_pattern' | 'status_code' | 'none';
  evidence?: string;
  confidence: 'high' | 'medium' | 'low' | 'none';
}

export interface ChannelSnapshot {
  channel_type: string;
  connected: boolean;
  last_request_time?: number;
}

// ---------------------------------------------------------------------------
// Channel interface — universal delivery abstraction
// ---------------------------------------------------------------------------

export interface Channel {
  readonly name: string;

  deliver(
    payload: string,
    target: DeliveryTarget,
    params: DeliveryParams,
  ): Promise<DeliveryResult>;

  observe(
    oracle: { type: string; pattern: string; positive: boolean },
    attackResult: DeliveryResult,
    baselineResult?: DeliveryResult,
  ): ObservationResult;

  snapshot(): ChannelSnapshot;
}

// ---------------------------------------------------------------------------
// HTTPChannel — v1 implementation targeting OWASP Benchmark and similar apps
// ---------------------------------------------------------------------------

/** Timing threshold for blind injection detection (ms) */
const TIMING_THRESHOLD_MS = 2000;

/** Maximum response body size stored in DeliveryResult (chars) */
const MAX_BODY_LENGTH = 10000;

export class HTTPChannel implements Channel {
  readonly name = 'http';
  private timeout_ms: number;
  private last_request_time?: number;

  constructor(options?: { timeout_ms?: number }) {
    this.timeout_ms = options?.timeout_ms ?? 10000;
  }

  // ── Delivery ────────────────────────────────────────────────────────

  async deliver(
    payload: string,
    target: DeliveryTarget,
    params: DeliveryParams,
  ): Promise<DeliveryResult> {
    const url = new URL(target.path, target.base_url);
    const method = params.method.toUpperCase();
    const contentType = params.content_type ?? 'application/x-www-form-urlencoded';

    // Build headers
    const headers: Record<string, string> = {};
    if (params.header) {
      headers[params.header] = payload;
    }
    if (params.cookie) {
      headers['Cookie'] = `${params.cookie}=${payload}`;
    }

    // Build body or query string
    let body: string | undefined;
    if (method === 'GET') {
      if (params.param) {
        url.searchParams.set(params.param, payload);
      }
    } else {
      // POST, PUT, DELETE — send payload in form body
      if (params.param) {
        headers['Content-Type'] = contentType;
        if (contentType === 'application/json') {
          body = JSON.stringify({ [params.param]: payload });
        } else {
          // application/x-www-form-urlencoded (default)
          body = `${encodeURIComponent(params.param)}=${encodeURIComponent(payload)}`;
        }
      }
    }

    // v1: accept self-signed certs for OWASP Benchmark HTTPS.
    // TODO v2: replace with a scoped undici Agent that pins the cert per-target
    //          instead of disabling TLS verification globally.
    const previousTLS = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

    const start = performance.now();
    try {
      const response = await fetch(url.toString(), {
        method,
        headers,
        body,
        signal: AbortSignal.timeout(this.timeout_ms),
        redirect: 'follow',
      });

      const elapsed = performance.now() - start;
      this.last_request_time = Date.now();

      const rawBody = await response.text();
      const truncatedBody = rawBody.length > MAX_BODY_LENGTH
        ? rawBody.slice(0, MAX_BODY_LENGTH)
        : rawBody;

      // Flatten response headers into a plain object
      const responseHeaders: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        responseHeaders[key] = value;
      });

      return {
        delivered: true,
        status_code: response.status,
        body: truncatedBody,
        response_time_ms: Math.round(elapsed),
        headers: responseHeaders,
      };
    } catch (err: unknown) {
      const elapsed = performance.now() - start;
      this.last_request_time = Date.now();

      const message = err instanceof Error ? err.message : String(err);
      return {
        delivered: false,
        status_code: 0,
        body: '',
        response_time_ms: Math.round(elapsed),
        headers: {},
        error: message,
      };
    } finally {
      // Restore previous TLS setting
      if (previousTLS === undefined) {
        delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
      } else {
        process.env.NODE_TLS_REJECT_UNAUTHORIZED = previousTLS;
      }
    }
  }

  // ── Observation / Oracle evaluation ─────────────────────────────────

  observe(
    oracle: { type: string; pattern: string; positive: boolean },
    attackResult: DeliveryResult,
    baselineResult?: DeliveryResult,
  ): ObservationResult {
    switch (oracle.type) {
      case 'content_match':
        return this.observeContentMatch(oracle, attackResult, baselineResult);
      case 'timing':
        return this.observeTiming(oracle, attackResult, baselineResult);
      case 'error_pattern':
        return this.observeErrorPattern(oracle, attackResult, baselineResult);
      case 'status_code':
        return this.observeStatusCode(oracle, attackResult, baselineResult);
      default:
        return {
          signal_detected: false,
          signal_type: 'none',
          evidence: `Unknown oracle type: ${oracle.type}`,
          confidence: 'none',
        };
    }
  }

  // ── Content match ───────────────────────────────────────────────────
  //
  // The pattern may be a canary string (e.g., "DST_CANARY_12345") OR a payload
  // fragment (OWASP Benchmark servlets echo the SQL query string via
  // DatabaseHelper.printResults / outputUpdateComplete).
  //
  // CRITICAL: If the baseline response ALSO contains the pattern, this is NOT
  // a real detection — the string was already present in the normal response.
  // Return signal_detected: false to prevent false proofs.

  private observeContentMatch(
    oracle: { pattern: string; positive: boolean },
    attackResult: DeliveryResult,
    baselineResult?: DeliveryResult,
  ): ObservationResult {
    const patternInAttack = attackResult.body.includes(oracle.pattern);
    const patternInBaseline = baselineResult
      ? baselineResult.body.includes(oracle.pattern)
      : false;

    // Baseline comparison — false proof prevention
    if (patternInAttack && patternInBaseline) {
      return {
        signal_detected: false,
        signal_type: 'content_match',
        evidence: `Pattern "${oracle.pattern}" found in BOTH attack and baseline responses — not a real detection`,
        confidence: 'none',
      };
    }

    const rawSignal = patternInAttack;
    // If oracle.positive is false, invert: signal means the pattern is ABSENT
    const detected = oracle.positive ? rawSignal : !rawSignal;

    if (detected) {
      return {
        signal_detected: true,
        signal_type: 'content_match',
        evidence: oracle.positive
          ? `Pattern "${oracle.pattern}" found in attack response but NOT in baseline`
          : `Pattern "${oracle.pattern}" absent from attack response as expected`,
        confidence: 'high',
      };
    }

    return {
      signal_detected: false,
      signal_type: 'content_match',
      evidence: oracle.positive
        ? `Pattern "${oracle.pattern}" not found in attack response`
        : `Pattern "${oracle.pattern}" unexpectedly present in attack response`,
      confidence: 'none',
    };
  }

  // ── Timing oracle ──────────────────────────────────────────────────
  //
  // Blind injection detection: if the attack response takes significantly
  // longer than baseline, the injected SLEEP/WAITFOR/pg_sleep worked.

  private observeTiming(
    oracle: { pattern: string; positive: boolean },
    attackResult: DeliveryResult,
    baselineResult?: DeliveryResult,
  ): ObservationResult {
    const baselineTime = baselineResult?.response_time_ms ?? 0;
    const delta = attackResult.response_time_ms - baselineTime;
    const threshold = parseInt(oracle.pattern, 10) || TIMING_THRESHOLD_MS;

    const rawSignal = delta >= threshold;
    const detected = oracle.positive ? rawSignal : !rawSignal;

    if (detected) {
      return {
        signal_detected: true,
        signal_type: 'timing',
        evidence: `Timing delta: ${delta}ms (threshold: ${threshold}ms, attack: ${attackResult.response_time_ms}ms, baseline: ${baselineTime}ms)`,
        confidence: delta >= threshold * 2 ? 'high' : 'medium',
      };
    }

    return {
      signal_detected: false,
      signal_type: 'timing',
      evidence: `Timing delta: ${delta}ms below threshold ${threshold}ms`,
      confidence: 'none',
    };
  }

  // ── Error pattern oracle ───────────────────────────────────────────
  //
  // Regex match against response body — catches SQL error messages,
  // stack traces, etc. Baseline comparison: if the error also appears
  // in baseline, it's not caused by the payload.

  private observeErrorPattern(
    oracle: { pattern: string; positive: boolean },
    attackResult: DeliveryResult,
    baselineResult?: DeliveryResult,
  ): ObservationResult {
    let regex: RegExp;
    try {
      regex = new RegExp(oracle.pattern, 'i');
    } catch {
      return {
        signal_detected: false,
        signal_type: 'error_pattern',
        evidence: `Invalid regex pattern: ${oracle.pattern}`,
        confidence: 'none',
      };
    }

    const matchInAttack = regex.test(attackResult.body);
    const matchInBaseline = baselineResult ? regex.test(baselineResult.body) : false;

    // Same baseline comparison logic — if error exists in both, not payload-caused
    if (matchInAttack && matchInBaseline) {
      return {
        signal_detected: false,
        signal_type: 'error_pattern',
        evidence: `Error pattern /${oracle.pattern}/i matched in BOTH attack and baseline — not payload-caused`,
        confidence: 'none',
      };
    }

    const rawSignal = matchInAttack;
    const detected = oracle.positive ? rawSignal : !rawSignal;

    if (detected) {
      const match = attackResult.body.match(regex);
      return {
        signal_detected: true,
        signal_type: 'error_pattern',
        evidence: oracle.positive
          ? `Error pattern matched: "${match?.[0]}" (not in baseline)`
          : `Error pattern absent from attack response as expected`,
        confidence: 'high',
      };
    }

    return {
      signal_detected: false,
      signal_type: 'error_pattern',
      evidence: oracle.positive
        ? `Error pattern /${oracle.pattern}/i not found in attack response`
        : `Error pattern unexpectedly present in attack response`,
      confidence: 'none',
    };
  }

  // ── Status code oracle ─────────────────────────────────────────────
  //
  // If the attack produces a DIFFERENT status code than the baseline,
  // the payload altered server behavior.

  private observeStatusCode(
    oracle: { pattern: string; positive: boolean },
    attackResult: DeliveryResult,
    baselineResult?: DeliveryResult,
  ): ObservationResult {
    if (!baselineResult) {
      // Without a baseline, check if the status matches the pattern directly
      const expectedStatus = parseInt(oracle.pattern, 10);
      if (!isNaN(expectedStatus)) {
        const matches = attackResult.status_code === expectedStatus;
        const detected = oracle.positive ? matches : !matches;
        return {
          signal_detected: detected,
          signal_type: 'status_code',
          evidence: `Attack status: ${attackResult.status_code}, expected: ${expectedStatus}`,
          confidence: detected ? 'medium' : 'none',
        };
      }
      return {
        signal_detected: false,
        signal_type: 'status_code',
        evidence: 'No baseline available for status code comparison',
        confidence: 'none',
      };
    }

    const statusDiffers = attackResult.status_code !== baselineResult.status_code;
    const detected = oracle.positive ? statusDiffers : !statusDiffers;

    if (detected) {
      return {
        signal_detected: true,
        signal_type: 'status_code',
        evidence: `Status code changed: baseline=${baselineResult.status_code}, attack=${attackResult.status_code}`,
        confidence: 'high',
      };
    }

    return {
      signal_detected: false,
      signal_type: 'status_code',
      evidence: `Status codes identical: ${attackResult.status_code}`,
      confidence: 'none',
    };
  }

  // ── Snapshot ────────────────────────────────────────────────────────

  snapshot(): ChannelSnapshot {
    return {
      channel_type: 'http',
      connected: true,
      last_request_time: this.last_request_time,
    };
  }
}
