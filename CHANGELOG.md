# Changelog

All notable changes to the Cloudflare Gateway Rule Blocking Page project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-07-05

### Added

- **Policy type display** (`cf_filter`) with human-readable label map: `http` → HTTP Policy, `dns` → DNS Policy, `l4` → Network Policy
- **Device name resolution** via `GET /accounts/{id}/devices/registrations?device.id=` using the existing `CLOUDFLARE_API_TOKEN` — no additional credentials required
- **Cloudflare One Client IPv4 and IPv6** display (virtual IPs from the devices/registrations API, cached via Cache API for 2 minutes)
- **Ray ID** display from `cf_ray_id` query param with `CF-Ray` request header as fallback
- All new fields included in the detail table, Contact Administrator email body, and JSON API response (`filter_type`, `device_id`, `device_name`, `cf1client_ipv4`, `cf1client_ipv6`, `ray_id`)
- Cache API (`caches.default`) for Cloudflare One Client IPs with 2-minute TTL
- Generic `getCachedValue` / `setCachedValue` KV helpers (backwards-compatible aliases for existing `getCachedRuleName` / `cacheRuleName`)
- 21 new tests — 34 total, all passing, ≥80% coverage on all metrics
- Updated demo screenshot showing all context fields

### Changed

- All user-facing WARP references renamed to **Cloudflare One Client** (labels, email body, JSON fields, README, tests)
- Device name and Cloudflare One Client IPs resolved in parallel with rule name via `Promise.all` — no added latency
- `Cache-Control` on HTML responses changed from `public, max-age=3600, immutable` to `no-store` (caching HTML with a per-request CSP nonce caused nonce mismatch, breaking all scripts)
- All `onclick=` inline event handlers replaced with `addEventListener` calls inside the nonce-guarded `<script>` block (required for CSP `script-src 'nonce-...'` compliance)
- README fully rewritten with feature table, Gateway context fields table, caching strategy table, security section, and testing guide
- Wrangler updated from `4.28.1` to `4.107.0`
- `baseline-browser-mapping` updated to latest

### Fixed

- **Contact Administrator button broken** — CSP `script-src 'nonce-...'` blocks inline `onclick=` handlers; fixed by moving all event wiring to `addEventListener` inside the nonce-scoped `<script>` block
- **Scripts silently broken after deploy** — HTML was cached at the edge with a stale nonce; the fresh nonce in the CSP header caused every `<script>` tag to be rejected by the browser

### Removed

- `CF_EMAIL` and `CF_API_KEY` secrets (previously added to support the now-replaced `/teamnet/devices/ips` endpoint; the correct `/devices/registrations` endpoint uses the existing Bearer token)

### Security

- Nonce-based CSP now correctly enforced end-to-end — `no-store` prevents cached HTML from carrying stale nonces
- No inline event handlers remain in generated HTML

### Technical

- Uses `GET /devices/registrations?device.id=&status=active` (modern API) instead of the deprecated `/teamnet/devices/ips` endpoint
- Most recently seen active registration selected when a device has multiple registrations
- Cloudflare One Client IPs gracefully omitted when device has no active registration or no virtual IPs assigned

## [1.3.0] - 2026-06-01

### Added

- HTTP cache headers for edge caching optimization (`Cache-Control: public, max-age=3600, immutable`)
- Reduced Worker invocations by ~95% for repeated identical requests

### Technical

- `Cache-Control` headers added to HTML responses (later superseded by `no-store` in v2.0.0 due to CSP nonce conflict)

## [1.2.0] - 2026-05-01

### Changed

- Modernized blocking page UI with improved design and UX
- Cloudflare orange branding tokens, dark/light mode with `localStorage` persistence
- Responsive card layout, animated Blocked badge, CSP with per-request nonce
- Flash-prevention inline script applied before first paint

### Added

- Dark/light mode toggle persisted via `localStorage`
- Contact Administrator modal with pre-filled email body and clipboard copy
- Animated pulsing Blocked badge in top navigation bar

## [1.1.0] - 2026-04-01

### Added

- Gateway context validation — returns `403 Access Denied` if no Gateway query parameters present (prevents direct Worker URL access / SSRF)
- `ALLOWED_ORIGINS` env var for CORS allowlist on JSON API endpoint
- `Accept: application/json` → JSON response with structured block event data
- Exponential backoff retry logic on API 429 and 5xx responses (1s → 2s → 4s, up to 3 retries)
- KV namespace (`RULE_CACHE`) for caching rule names with configurable TTL (`CACHE_TTL`, default 3600s)
- Administrator email link replacing navigation buttons

### Security

- HTML escaping via `escapeHtml()` for all user-supplied values (XSS prevention)
- CORS allowlist — unauthorized origins receive `Access-Control-Allow-Origin: null`

## [1.0.0] - 2026-03-01

### Added

- Initial implementation of Cloudflare Gateway custom blocking page Worker
- Dynamic rule name resolution via `GET /accounts/{id}/gateway/rules/{rule_id}` API
- Displays blocked URL, rule ID, category, and timestamp from Gateway query parameters
- Supports `cf_rule_id`, `cf_site_uri`, `cf_request_category_names`, `cf_user_email` Gateway params
- Semgrep security scanning GitHub Action (weekly + PR-triggered)
- GPL-3.0-or-later license
- Deploy to Cloudflare Workers button
- Architecture diagram in README
