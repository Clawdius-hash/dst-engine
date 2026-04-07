/**
 * Phoneme expansion: Python Django deep — ORM raw/extra, template engine
 * auto-escaping, middleware, CSRF, DRF serializers, django-allauth
 *
 * Agent-generated for DST phoneme dictionary
 *
 * Coverage gap: The existing Python dictionary covers basic Django ORM CRUD
 * (objects.filter, objects.create, etc.) and Django auth decorators, but has
 * ZERO entries for the most dangerous Django patterns — the ones that bypass
 * Django's built-in protections.
 *
 * django.db.models.expressions.RawSQL (CWE-89 SQL injection):
 *   RawSQL() lets you inject raw SQL fragments into ORM queries via
 *   .annotate(val=RawSQL("select ... where id = %s", [param])). If the SQL
 *   string is constructed from user input rather than using params, it's a
 *   direct SQL injection vector. Unlike objects.raw(), RawSQL is composable
 *   — it can be embedded in otherwise-safe ORM chains, making it sneakier.
 *
 * QuerySet.extra() (CWE-89 SQL injection, deprecated):
 *   .extra(where=["title = %s"], params=[title]) accepts raw SQL fragments.
 *   Officially deprecated since Django 3.x but still present in legacy code.
 *   The where/select/tables params take raw SQL — trivially injectable.
 *
 * django.utils.safestring.mark_safe (CWE-79 XSS):
 *   mark_safe(string) tells Django's template engine "this string is already
 *   HTML-safe, don't escape it." If the string contains user input, this
 *   directly creates XSS. Extremely common in Django codebases — used in
 *   form widgets, admin customizations, template tags. The |safe template
 *   filter does the same thing but at the template level.
 *
 * django.views.decorators.csrf.csrf_exempt (CSRF bypass):
 *   @csrf_exempt disables Django's CSRF protection on a view. Legitimate for
 *   API endpoints that use token auth, but dangerous on views that serve HTML
 *   forms. The scanner should flag every @csrf_exempt for manual review.
 *
 * DRF Request.data / serializer.validated_data (INGRESS):
 *   In Django REST Framework, Request.data is the parsed request body (like
 *   request.POST but for any content type — JSON, multipart, etc.). It's the
 *   primary ingress point for DRF APIs. serializer.validated_data is
 *   post-validation but still user-originated — marking it as INGRESS because
 *   validation != sanitization (validated integers are fine, validated strings
 *   can still contain XSS payloads if the serializer doesn't strip HTML).
 *
 * django-allauth SocialLogin.connect (AUTH/EXTERNAL):
 *   django-allauth's SocialLogin.connect() links a social account (Google,
 *   GitHub, etc.) to a local user. This is a critical auth boundary — if the
 *   social identity isn't properly verified, account takeover is possible.
 *   The social auth callback flow is one of the most bug-prone areas in
 *   any auth system.
 *
 * django.utils.html.format_html (safe TRANSFORM):
 *   format_html() is Django's safe alternative to mark_safe + string formatting.
 *   It auto-escapes its arguments. Marking as TRANSFORM because it's a data
 *   transformation, but it's a SAFE one — the scanner should know about it
 *   to distinguish from the dangerous mark_safe pattern.
 *
 * django.db.connection.cursor (STORAGE — raw DB access):
 *   connection.cursor() gives you a raw database cursor, bypassing the ORM
 *   entirely. Code using this is writing raw SQL and should be audited for
 *   injection. Already have cursor.execute but not the cursor acquisition itself.
 */

import type { CalleePattern } from '../languages/python.js';

export const PHONEMES_PYTHON_DJANGO_DEEP: Record<string, CalleePattern> = {

  // ═══════════════════════════════════════════════════════════════════════════
  // STORAGE — raw SQL injection vectors (CWE-89)
  // ═══════════════════════════════════════════════════════════════════════════

  // STORAGE: RawSQL() injects raw SQL fragments into ORM queries.
  // Used via .annotate(val=RawSQL("select ...", [params])).
  // If the SQL string is built from user input instead of using params, instant SQLi.
  'django.db.models.expressions.RawSQL':  { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },

  // STORAGE: QuerySet.extra() accepts raw SQL in where/select/tables kwargs.
  // Deprecated since Django 3.x but still widely present in legacy codebases.
  // .extra(where=["title = %s"], params=[title]) — SQL injection if string-formatted.
  'objects.extra':                         { nodeType: 'STORAGE', subtype: 'db_read', tainted: false },

  // STORAGE: connection.cursor() acquires a raw database cursor, bypassing the ORM.
  // All subsequent cursor.execute() calls are raw SQL — flag the cursor acquisition itself.
  'django.db.connection.cursor':           { nodeType: 'STORAGE', subtype: 'db_connect', tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // TRANSFORM — HTML/template escaping controls (CWE-79)
  // ═══════════════════════════════════════════════════════════════════════════

  // TRANSFORM: mark_safe() disables Django's auto-escaping for a string.
  // If the string contains ANY user input, this creates XSS.
  // Extremely common in form widgets, admin customizations, and template tags.
  'django.utils.safestring.mark_safe':     { nodeType: 'TRANSFORM', subtype: 'sanitize', tainted: false },

  // TRANSFORM: format_html() is the SAFE alternative to mark_safe + f-strings.
  // It auto-escapes arguments like Django templates do. Marking as TRANSFORM
  // so the scanner can distinguish safe (format_html) from dangerous (mark_safe).
  'django.utils.html.format_html':         { nodeType: 'TRANSFORM', subtype: 'sanitize', tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // AUTH — CSRF and permission controls
  // ═══════════════════════════════════════════════════════════════════════════

  // AUTH: @csrf_exempt disables Django's CSRF middleware on a view.
  // Legitimate for token-auth API endpoints, dangerous on HTML-form views.
  // Every usage should be flagged for manual review.
  'django.views.decorators.csrf.csrf_exempt': { nodeType: 'AUTH', subtype: 'authorize', tainted: false },

  // ═══════════════════════════════════════════════════════════════════════════
  // INGRESS — DRF (Django REST Framework) data entry points
  // ═══════════════════════════════════════════════════════════════════════════

  // NOTE: request.data already existed in the base dictionary (Flask request section).
  // It covers both Flask and DRF since DRF uses the same attribute name.

  // INGRESS: serializer.validated_data is post-validation user input.
  // Validation != sanitization: a CharField passes validation but can contain XSS.
  // Marking tainted because the data originates from the user.
  'serializer.validated_data':             { nodeType: 'INGRESS', subtype: 'http_request', tainted: true },

  // ═══════════════════════════════════════════════════════════════════════════
  // EXTERNAL — django-allauth social authentication
  // ═══════════════════════════════════════════════════════════════════════════

  // EXTERNAL: SocialLogin.connect() links a social identity to a local Django user.
  // This is the critical boundary in OAuth flows — if the social account isn't
  // properly verified, it enables account takeover. django-allauth is the most
  // popular Django social auth library (~8M downloads/month).
  'allauth.socialaccount.models.SocialLogin.connect': { nodeType: 'EXTERNAL', subtype: 'social_auth', tainted: false },

} as const;

// ── Pattern count ─────────────────────────────────────────────────────────

export function getPhonemeCount(): number {
  return Object.keys(PHONEMES_PYTHON_DJANGO_DEEP).length;
}
