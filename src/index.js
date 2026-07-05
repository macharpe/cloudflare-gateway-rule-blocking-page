/**
 * Cloudflare Worker for Gateway blocking page
 * Dynamically retrieves rule names and displays custom blocking pages
 */

export default {
  async fetch(request, env) {
    return handleRequest(request, env)
  }
}

/**
 * Main request handler
 * @param {Request} request
 * @param {object} env
 */
async function handleRequest(request, env) {
  try {
    const url = new URL(request.url)


    const ruleId = url.searchParams.get('cf_rule_id') || url.searchParams.get('rule_id') || url.searchParams.get('ruleid')
    const blockedUrl = url.searchParams.get('cf_site_uri') || url.searchParams.get('blocked_url') || url.searchParams.get('url')
    const category = url.searchParams.get('cf_request_category_names') || url.searchParams.get('category')
    const timestamp = url.searchParams.get('timestamp')
    const userEmail = url.searchParams.get('cf_user_email')
    const filterType = url.searchParams.get('cf_filter')
    const deviceId = url.searchParams.get('cf_device_id')
    const rayId = url.searchParams.get('cf_ray_id') || request.headers.get('CF-Ray')

    // Validate Gateway context - require at least one Gateway parameter
    const hasGatewayContext = ruleId || blockedUrl || category || userEmail || filterType || deviceId || rayId ||
      url.searchParams.has('cf_rule_id') || url.searchParams.has('cf_site_uri') ||
      url.searchParams.has('cf_request_category_names') || url.searchParams.has('cf_user_email') ||
      url.searchParams.has('cf_filter') || url.searchParams.has('cf_device_id') || url.searchParams.has('cf_ray_id')
    
    if (!hasGatewayContext) {
      return new Response('Access Denied', {
        status: 403,
        headers: {
          'Content-Type': 'text/plain',
          'X-Frame-Options': 'DENY',
          'X-Content-Type-Options': 'nosniff'
        }
      })
    }
    
    // Check for JSON API request
    const acceptHeader = request.headers.get('Accept')
    const isJsonRequest = acceptHeader && acceptHeader.includes('application/json')
    
    if (isJsonRequest) {
      return handleJsonRequest(ruleId, blockedUrl, category, userEmail, filterType, deviceId, rayId, env, request)
    }

    return handleHtmlRequest(ruleId, blockedUrl, category, timestamp, userEmail, filterType, deviceId, rayId, env)
  } catch {
    return new Response('Internal Server Error', { status: 500 })
  }
}

/**
 * Handle JSON API requests
 * @param {string} ruleId 
 * @param {string} blockedUrl 
 * @param {string} category 
 * @param {string} userEmail
 * @param {string} filterType
 * @param {string} deviceId
 * @param {string} rayId
 * @param {object} env
 * @param {Request} request
 */
async function handleJsonRequest(ruleId, blockedUrl, category, userEmail, filterType, deviceId, rayId, env, request) {
  const [ruleName, deviceName, warpIps] = await Promise.all([
    ruleId   ? getRuleName(ruleId, env)     : Promise.resolve('Unknown Rule'),
    deviceId ? getDeviceName(deviceId, env) : Promise.resolve(null),
    deviceId ? getWarpIps(deviceId, env)    : Promise.resolve({ v4: null, v6: null })
  ])
  
  const response = {
    blocked: true,
    rule_id: ruleId,
    rule_name: ruleName,
    blocked_url: blockedUrl,
    category: category,
    filter_type: filterType,
    device_id: deviceId,
    device_name: deviceName,
    cf1client_ipv4: warpIps.v4,
    cf1client_ipv6: warpIps.v6,
    ray_id: rayId,
    timestamp: new Date().toISOString()
  }
  
  // Get allowed origins from environment variable, fallback to none for security
  const allowedOrigins = env.ALLOWED_ORIGINS ? env.ALLOWED_ORIGINS.split(',').map(o => o.trim()) : []
  const origin = request.headers.get('Origin')
  const allowOrigin = allowedOrigins.length > 0 && origin && allowedOrigins.includes(origin) ? origin : 'null'
  
  return new Response(JSON.stringify(response, null, 2), {
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': allowOrigin,
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Vary': 'Origin'
    }
  })
}

/**
 * Handle HTML page requests
 * @param {string} ruleId 
 * @param {string} blockedUrl 
 * @param {string} category 
 * @param {string} timestamp 
 * @param {string} userEmail
 * @param {string} filterType
 * @param {string} deviceId
 * @param {string} rayId
 * @param {object} env
 */
async function handleHtmlRequest(ruleId, blockedUrl, category, timestamp, userEmail, filterType, deviceId, rayId, env) {
  const [ruleName, deviceName, warpIps] = await Promise.all([
    ruleId   ? getRuleName(ruleId, env)     : Promise.resolve('Security Policy'),
    deviceId ? getDeviceName(deviceId, env) : Promise.resolve(null),
    deviceId ? getWarpIps(deviceId, env)    : Promise.resolve({ v4: null, v6: null })
  ])
  const nonce = crypto.randomUUID().replace(/-/g, '')
  const html = generateBlockingPage(ruleName, ruleId, blockedUrl, category, timestamp, filterType, deviceName, warpIps, rayId, env, nonce)
  
  return new Response(html, {
    headers: {
      'Content-Type': 'text/html',
      'Cache-Control': 'no-store',
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Content-Security-Policy': `default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'; font-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none';`
    }
  })
}

/**
 * Retrieve rule name from Cloudflare Gateway API with retry logic
 * @param {string} ruleId 
 * @param {object} env
 * @returns {Promise<string>}
 */
async function getRuleName(ruleId, env) {
  if (!ruleId) {
    return 'Unknown Rule'
  }

  try {
    // Check cache first
    const cached = await getCachedRuleName(ruleId, env)
    if (cached) {
      return cached
    }

    // Fetch from API with retry logic
    const apiToken = env.CLOUDFLARE_API_TOKEN
    const accountId = env.CLOUDFLARE_ACCOUNT_ID


    if (!apiToken || !accountId) {
      return 'Rule ' + ruleId
    }

    const ruleName = await fetchWithRetry(
      `https://api.cloudflare.com/client/v4/accounts/${accountId}/gateway/rules/${ruleId}`,
      {
        headers: {
          'Authorization': `Bearer ${apiToken}`,
          'Content-Type': 'application/json'
        }
      },
      3 // max retries
    )

    // Cache the result
    await cacheRuleName(ruleId, ruleName, env)

    return ruleName
  } catch {
    return 'Rule ' + ruleId
  }
}

/**
 * Retrieve device name from Cloudflare Devices API with retry logic
 * @param {string} deviceId
 * @param {object} env
 * @returns {Promise<string>}
 */
async function getDeviceName(deviceId, env) {
  if (!deviceId) {
    return 'Unknown Device'
  }

  try {
    // Check cache first
    const cacheKey = `device:${deviceId}`
    const cached = await getCachedValue(cacheKey, env)
    if (cached) {
      return cached
    }

    const apiToken = env.CLOUDFLARE_API_TOKEN
    const accountId = env.CLOUDFLARE_ACCOUNT_ID

    if (!apiToken || !accountId) {
      return 'Device ' + deviceId
    }

    const deviceName = await fetchWithRetry(
      `https://api.cloudflare.com/client/v4/accounts/${accountId}/devices/${deviceId}`,
      {
        headers: {
          'Authorization': `Bearer ${apiToken}`,
          'Content-Type': 'application/json'
        }
      },
      3 // max retries
    )

    // Cache the result
    await setCachedValue(cacheKey, deviceName, env)

    return deviceName
  } catch {
    return 'Device ' + deviceId
  }
}

/**
 * Retrieve Cloudflare One Client-assigned IPv4 and IPv6 addresses for a specific device.
 * Uses GET /accounts/{id}/devices/registrations?device.id={deviceId} with Bearer token auth.
 * A device may have multiple registrations (one per user+device pair); we take the most
 * recently seen active one. Results are cached via the Workers Cache API for 2 minutes.
 * @param {string} deviceId
 * @param {object} env  - must have CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID
 * @returns {Promise<{v4: string|null, v6: string|null}>}
 */
async function getWarpIps(deviceId, env) {
  if (!deviceId) return { v4: null, v6: null }

  const apiToken  = env.CLOUDFLARE_API_TOKEN
  const accountId = env.CLOUDFLARE_ACCOUNT_ID

  if (!apiToken || !accountId) return { v4: null, v6: null }

  // Cache API — keyed by account + device, 2-minute TTL
  const cacheKey = `https://cf1client-ips-cache.internal/${accountId}/${deviceId}`
  const cache    = caches.default

  try {
    const cached = await cache.match(cacheKey)
    if (cached) {
      return await cached.json()
    }
  } catch {
    // Cache miss or error — continue to API
  }

  try {
    const response = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${accountId}/devices/registrations?device.id=${encodeURIComponent(deviceId)}&status=active&per_page=10`,
      {
        headers: {
          'Authorization': `Bearer ${apiToken}`,
          'Content-Type':  'application/json'
        }
      }
    )

    if (!response.ok) return { v4: null, v6: null }

    const data = await response.json()
    const registrations = data.result || []

    // Pick the most recently seen registration that has at least one IP
    const match = registrations
      .filter(r => r.virtual_ipv4 || r.virtual_ipv6)
      .sort((a, b) => new Date(b.last_seen_at) - new Date(a.last_seen_at))[0]

    const result = {
      v4: match?.virtual_ipv4 || null,
      v6: match?.virtual_ipv6 || null
    }

    // Store in Cache API with 2-minute TTL
    try {
      await cache.put(cacheKey, new Response(JSON.stringify(result), {
        headers: {
          'Content-Type':  'application/json',
          'Cache-Control': 'max-age=120'
        }
      }))
    } catch {
      // Cache write failure is non-fatal
    }

    return result
  } catch {
    return { v4: null, v6: null }
  }
}

/**
 * Fetch with exponential backoff retry logic
 * @param {string} url 
 * @param {object} options 
 * @param {number} maxRetries 
 * @returns {Promise<string>}
 */
async function fetchWithRetry(url, options, maxRetries) {
  let lastError
  
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const response = await fetch(url, options)

      // Handle rate limiting (429) and server errors (5xx)
      if (response.status === 429 || response.status >= 500) {
        if (attempt === maxRetries) {
          throw new Error(`API request failed after ${maxRetries + 1} attempts: ${response.status} ${response.statusText}`)
        }

        // Exponential backoff: 1s, 2s, 4s, 8s...
        const delay = Math.pow(2, attempt) * 1000
        await new Promise(resolve => setTimeout(resolve, delay))
        continue
      }

      if (!response.ok) {
        throw new Error(`API request failed: ${response.status} ${response.statusText}`)
      }

      const data = await response.json()
      return data.result?.name || ('Rule ' + url.split('/').pop())
      
    } catch (error) {
      lastError = error
      if (attempt === maxRetries) {
        throw lastError
      }
      
      // Wait before retry for non-HTTP errors
      const delay = Math.pow(2, attempt) * 1000
      await new Promise(resolve => setTimeout(resolve, delay))
    }
  }
  
  throw lastError
}

/**
 * Get a cached value from KV storage by full cache key
 * @param {string} cacheKey
 * @param {object} env
 * @returns {Promise<string|null>}
 */
async function getCachedValue(cacheKey, env) {
  try {
    if (env.RULE_CACHE) {
      const cached = await env.RULE_CACHE.get(cacheKey)
      return cached
    }
  } catch {
    // Cache read error - continue without cache
  }
  return null
}

/**
 * Store a value in KV storage by full cache key
 * @param {string} cacheKey
 * @param {string} value
 * @param {object} env
 */
async function setCachedValue(cacheKey, value, env) {
  try {
    if (env.RULE_CACHE) {
      // Cache TTL from environment variable, default to 1 hour
      const cacheTtl = parseInt(env.CACHE_TTL) || 3600
      await env.RULE_CACHE.put(cacheKey, value, { expirationTtl: cacheTtl })
    }
  } catch {
    // Cache write error - continue without cache
  }
}

// Backwards-compatible aliases used by getRuleName
/** @deprecated use getCachedValue directly */
const getCachedRuleName = (ruleId, env) => getCachedValue(`rule:${ruleId}`, env)
/** @deprecated use setCachedValue directly */
const cacheRuleName = (ruleId, value, env) => setCachedValue(`rule:${ruleId}`, value, env)

/**
 * Escape HTML special characters to prevent XSS
 * @param {string} text 
 * @returns {string}
 */
function escapeHtml(text) {
  if (!text) return ''
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

/**
 * Generate formatted email content for contact form
 * @param {string} adminEmail
 * @param {string} ruleName
 * @param {string} ruleId
 * @param {string} blockedUrl
 * @param {string} category
 * @param {string} timestamp
 * @param {string} filterType
 * @param {string} deviceName
 * @param {{v4: string|null, v6: string|null}} warpIps
 * @param {string} rayId
 * @returns {{subject: string, body: string, adminEmail: string}} - Returns subject and body for the email
 */
function generateEmailContent(adminEmail, ruleName, ruleId, blockedUrl, category, timestamp, filterType, deviceName, warpIps, rayId) {
  const subject = 'Security Policy Review Request - Access Blocked'
  
  const body = `Hello,

I was blocked from accessing a resource and would like to request a review of this security policy action.

========================================
INCIDENT DETAILS
========================================

BLOCKED RESOURCE:
${blockedUrl || 'Not specified'}

SECURITY RULE:
Rule Name: ${ruleName}
Rule ID: ${ruleId || 'Not specified'}${category ? `
Category: ${category}` : ''}${filterType ? `
Filter Type: ${filterType}` : ''}

DEVICE:
${deviceName || 'Not specified'}${warpIps?.v4 ? `
CF One Client IPv4: ${warpIps.v4}` : ''}${warpIps?.v6 ? `
CF One Client IPv6: ${warpIps.v6}` : ''}

INCIDENT TIME:
${timestamp ? new Date(timestamp).toLocaleString() : new Date().toLocaleString()}

RAY ID:
${rayId || 'Not specified'}

========================================
REQUEST FOR REVIEW
========================================

I believe this block may have occurred in error. If this is a legitimate business resource that I need access to, please consider:

1. Reviewing the security policy configuration
2. Adding an exception if appropriate
3. Providing guidance on alternative access methods

Please let me know if you need any additional information to process this request.

Thank you for your assistance,
${adminEmail.includes('macharpe.com') ? 'Team Member' : 'User'}`

  return { subject, body, adminEmail }
}

/** @type {Record<string, string>} */
const FILTER_LABELS = {
  http: 'HTTP Policy',
  dns:  'DNS Policy',
  l4:   'Network Policy'
}

/**
 * Generate HTML blocking page
 * @param {string} ruleName 
 * @param {string} ruleId 
 * @param {string} blockedUrl 
 * @param {string} category 
 * @param {string} timestamp
 * @param {string} filterType
 * @param {string} deviceName
 * @param {{v4: string|null, v6: string|null}} warpIps
 * @param {string} rayId
 * @param {object} env
 * @param {string} nonce
 * @returns {string}
 */
function generateBlockingPage(ruleName, ruleId, blockedUrl, category, timestamp, filterType, deviceName, warpIps, rayId, env, nonce) {
  const displayUrl = blockedUrl ? escapeHtml(decodeURIComponent(blockedUrl)) : 'the requested resource'
  const displayCategory = category ? escapeHtml(category) : ''
  const displayFilter = filterType ? escapeHtml(FILTER_LABELS[filterType] || filterType) : ''
  const displayDevice = deviceName ? escapeHtml(deviceName) : ''
  const displayWarpV4 = warpIps?.v4 ? escapeHtml(warpIps.v4) : ''
  const displayWarpV6 = warpIps?.v6 ? escapeHtml(warpIps.v6) : ''
  const displayRayId = rayId ? escapeHtml(rayId) : ''
  const adminEmail = env.ADMIN_EMAIL || 'admin@example.com'
  /** @type {{subject: string, body: string, adminEmail: string}} */
  const emailContent = generateEmailContent(adminEmail, ruleName, ruleId, displayUrl, category, timestamp, filterType, deviceName, warpIps, rayId)
  const displayTime = timestamp ? new Date(timestamp).toLocaleString() : new Date().toLocaleString()

  return `
<!DOCTYPE html>
<html lang="en" data-mode="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Access Blocked — Cloudflare Gateway</title>
  <script nonce="${nonce}">
    /* Flash-prevention: apply stored or system theme before first paint */
    (function(){
      var stored = localStorage.getItem('cf-gw-mode');
      var prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      document.documentElement.setAttribute('data-mode', stored || (prefersDark ? 'dark' : 'light'));
    })();
  </script>
  <style nonce="${nonce}">
    /* ===== Reset ===== */
    *, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }

    /* ===== Design tokens — dark mode (default) ===== */
    :root, [data-mode="dark"] {
      --cf-orange:       #F38020;
      --cf-orange-dim:   #c9631a;

      /* Canvas / surface hierarchy */
      --canvas:          #0B0C0F;
      --base:            #16181D;
      --elevated:        #1E2028;
      --recessed:        #111317;
      --tint:            #1A1C22;

      /* Borders */
      --hairline:        #2D2F36;
      --hairline-strong: #3A3C46;

      /* Text */
      --text-default:    #EDEDED;
      --text-strong:     #FFFFFF;
      --text-subtle:     #8B8D98;
      --text-inactive:   #55575F;

      /* Status */
      --danger:          #EF4444;
      --danger-tint:     rgba(239,68,68,.12);
      --warning:         #F59E0B;
      --warning-tint:    rgba(245,158,11,.10);
      --success:         #22C55E;
      --info:            #3B82F6;

      /* Misc */
      --radius-sm:       6px;
      --radius-md:       10px;
      --radius-lg:       14px;
      --shadow-card:     0 0 0 1px var(--hairline), 0 8px 32px rgba(0,0,0,.45);
      --shadow-modal:    0 0 0 1px var(--hairline-strong), 0 24px 64px rgba(0,0,0,.65);
      --font-mono:       'SF Mono', 'Fira Code', 'IBM Plex Mono', Consolas, monospace;
    }

    /* ===== Light mode token overrides ===== */
    [data-mode="light"] {
      --canvas:          #F8F9FB;
      --base:            #FFFFFF;
      --elevated:        #F3F4F6;
      --recessed:        #F0F1F3;
      --tint:            #ECEEF1;

      --hairline:        #E2E4E9;
      --hairline-strong: #C9CDD6;

      --text-default:    #1A1C23;
      --text-strong:     #000000;
      --text-subtle:     #6B7280;
      --text-inactive:   #9CA3AF;

      --danger-tint:     rgba(239,68,68,.08);
      --warning-tint:    rgba(245,158,11,.08);

      --shadow-card:     0 0 0 1px var(--hairline), 0 4px 20px rgba(0,0,0,.08);
      --shadow-modal:    0 0 0 1px var(--hairline-strong), 0 16px 48px rgba(0,0,0,.15);
    }

    /* ===== Base ===== */
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', Roboto, sans-serif;
      background: var(--canvas);
      background-image:
        radial-gradient(ellipse 900px 500px at 50% -80px, rgba(243,128,32,.07) 0%, transparent 70%);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      color: var(--text-default);
      line-height: 1.6;
      -webkit-font-smoothing: antialiased;
      padding: 24px 16px;
    }

    /* ===== Top nav bar ===== */
    .topbar {
      position: fixed;
      top: 0; left: 0; right: 0;
      height: 48px;
      background: var(--base);
      border-bottom: 1px solid var(--hairline);
      display: flex;
      align-items: center;
      padding: 0 24px;
      gap: 10px;
      z-index: 10;
    }
    .topbar-logo {
      width: 20px;
      height: 20px;
      flex-shrink: 0;
    }
    .topbar-product {
      font-size: 13px;
      font-weight: 600;
      color: var(--text-default);
      letter-spacing: .01em;
    }
    .topbar-sep {
      color: var(--hairline-strong);
      font-size: 18px;
      font-weight: 300;
      line-height: 1;
    }
    .topbar-section {
      font-size: 13px;
      color: var(--text-subtle);
    }
    /* Theme toggle button */
    .theme-toggle {
      margin-left: auto;
      background: none;
      border: 1px solid var(--hairline-strong);
      cursor: pointer;
      color: var(--text-subtle);
      border-radius: var(--radius-sm);
      width: 30px;
      height: 30px;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: color .15s, background .15s, border-color .15s;
      flex-shrink: 0;
    }
    .theme-toggle:hover { color: var(--text-default); background: var(--tint); }
    .theme-toggle svg { width: 15px; height: 15px; }
    /* Show correct icon per mode */
    .icon-sun  { display: none; }
    .icon-moon { display: block; }
    [data-mode="light"] .icon-sun  { display: block; }
    [data-mode="light"] .icon-moon { display: none; }

    .topbar-badge {
      margin-left: 10px;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: var(--danger-tint);
      border: 1px solid rgba(239,68,68,.3);
      border-radius: 99px;
      padding: 2px 10px 2px 8px;
      font-size: 11px;
      font-weight: 600;
      color: var(--danger);
      letter-spacing: .04em;
      text-transform: uppercase;
    }
    .topbar-badge::before {
      content: '';
      width: 6px; height: 6px;
      background: var(--danger);
      border-radius: 50%;
      animation: pulse 2s infinite;
    }

    /* ===== Card ===== */
    .card {
      background: var(--base);
      border-radius: var(--radius-lg);
      box-shadow: var(--shadow-card);
      width: 100%;
      max-width: 600px;
      overflow: hidden;
      margin-top: 12px;
    }

    /* ===== Card header (orange accent strip) ===== */
    .card-header {
      background: linear-gradient(135deg, var(--recessed) 0%, var(--tint) 100%);
      border-bottom: 1px solid var(--hairline);
      padding: 28px 28px 24px;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 12px;
      text-align: center;
      position: relative;
      overflow: hidden;
    }
    .card-header::before {
      content: '';
      position: absolute;
      top: -40px; left: 50%;
      transform: translateX(-50%);
      width: 300px; height: 120px;
      background: radial-gradient(ellipse, rgba(243,128,32,.18) 0%, transparent 70%);
      pointer-events: none;
    }
    .shield-icon {
      width: 52px; height: 52px;
      background: linear-gradient(135deg, rgba(243,128,32,.15) 0%, rgba(243,128,32,.05) 100%);
      border: 1px solid rgba(243,128,32,.3);
      border-radius: var(--radius-md);
      display: flex; align-items: center; justify-content: center;
      position: relative;
      z-index: 1;
    }
    .shield-icon svg { width: 26px; height: 26px; }
    .card-header h1 {
      font-size: 22px;
      font-weight: 700;
      color: var(--text-strong);
      letter-spacing: -.01em;
      position: relative;
      z-index: 1;
    }
    .card-header p {
      font-size: 13px;
      color: var(--text-subtle);
      max-width: 400px;
      position: relative;
      z-index: 1;
    }

    /* ===== Card body ===== */
    .card-body { padding: 24px; display: flex; flex-direction: column; gap: 16px; }

    /* ===== Detail rows (CF-style key-value table) ===== */
    .detail-table {
      background: var(--recessed);
      border: 1px solid var(--hairline);
      border-radius: var(--radius-md);
      overflow: hidden;
    }
    .detail-row {
      display: flex;
      align-items: flex-start;
      padding: 11px 16px;
      gap: 16px;
      border-bottom: 1px solid var(--hairline);
    }
    .detail-row:last-child { border-bottom: none; }
    .detail-label {
      font-size: 12px;
      font-weight: 500;
      color: var(--text-subtle);
      letter-spacing: .03em;
      text-transform: uppercase;
      white-space: nowrap;
      min-width: 90px;
      padding-top: 1px;
    }
    .detail-value {
      font-size: 13px;
      color: var(--text-default);
      word-break: break-all;
      flex: 1;
    }
    .detail-value.mono {
      font-family: var(--font-mono);
      font-size: 12px;
      color: var(--text-subtle);
    }
    .detail-value .rule-name-text {
      font-weight: 600;
      color: var(--text-strong);
      font-size: 14px;
    }
    .category-pill {
      display: inline-block;
      background: var(--warning-tint);
      border: 1px solid rgba(245,158,11,.25);
      color: var(--warning);
      font-size: 11px;
      font-weight: 600;
      padding: 1px 8px;
      border-radius: 99px;
      letter-spacing: .03em;
      margin-left: 8px;
      vertical-align: middle;
    }

    /* ===== Info banner ===== */
    .info-banner {
      background: var(--tint);
      border: 1px solid var(--hairline);
      border-radius: var(--radius-md);
      padding: 12px 16px;
      font-size: 13px;
      color: var(--text-subtle);
      display: flex;
      gap: 10px;
      align-items: flex-start;
    }
    .info-banner svg { flex-shrink: 0; margin-top: 1px; }

    /* ===== Action button ===== */
    .btn-primary {
      appearance: none;
      border: none;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 7px;
      background: var(--cf-orange);
      color: #fff;
      font-family: inherit;
      font-weight: 600;
      font-size: 14px;
      padding: 10px 20px;
      border-radius: var(--radius-sm);
      transition: background .15s ease, transform .08s ease, box-shadow .15s ease;
      box-shadow: 0 1px 3px rgba(0,0,0,.3), 0 0 0 1px rgba(243,128,32,.4);
      text-decoration: none;
    }
    .btn-primary:hover { background: var(--cf-orange-dim); }
    .btn-primary:active { transform: translateY(1px); }

    .btn-ghost {
      appearance: none;
      border: 1px solid var(--hairline-strong);
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 7px;
      background: var(--elevated);
      color: var(--text-default);
      font-family: inherit;
      font-weight: 500;
      font-size: 14px;
      padding: 10px 20px;
      border-radius: var(--radius-sm);
      transition: background .15s ease, transform .08s ease;
      text-decoration: none;
    }
    .btn-ghost:hover { background: var(--tint); }
    .btn-ghost:active { transform: translateY(1px); }

    .actions { display: flex; justify-content: center; gap: 10px; padding-top: 4px; }

    /* ===== Card footer ===== */
    .card-footer {
      border-top: 1px solid var(--hairline);
      background: var(--recessed);
      padding: 12px 24px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }
    .footer-logo {
      display: flex;
      align-items: center;
      gap: 7px;
      color: var(--text-inactive);
      font-size: 11px;
      font-weight: 500;
      letter-spacing: .02em;
      text-transform: uppercase;
    }
    .footer-logo svg { width: 14px; height: 14px; opacity: .5; }
    .footer-text {
      font-size: 12px;
      color: var(--text-inactive);
      text-align: right;
    }

    /* ===== Modal overlay ===== */
    .modal {
      display: none;
      position: fixed; inset: 0;
      z-index: 100;
      background: rgba(0,0,0,.6);
      backdrop-filter: blur(4px);
      animation: fadeIn .18s ease;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }
    .modal.open { display: flex; }

    .modal-panel {
      background: var(--base);
      border: 1px solid var(--hairline-strong);
      border-radius: var(--radius-lg);
      box-shadow: var(--shadow-modal);
      width: 100%;
      max-width: 580px;
      max-height: 85vh;
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }

    .modal-header {
      padding: 18px 20px 16px;
      border-bottom: 1px solid var(--hairline);
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-shrink: 0;
    }
    .modal-title {
      font-size: 15px;
      font-weight: 600;
      color: var(--text-strong);
    }
    .modal-close {
      background: none;
      border: none;
      cursor: pointer;
      color: var(--text-subtle);
      padding: 4px;
      border-radius: var(--radius-sm);
      display: flex;
      align-items: center;
      transition: color .15s, background .15s;
    }
    .modal-close:hover { color: var(--text-default); background: var(--tint); }

    .modal-body {
      padding: 20px;
      overflow-y: auto;
      flex: 1;
      display: flex;
      flex-direction: column;
      gap: 14px;
    }

    .field-group { display: flex; flex-direction: column; gap: 5px; }
    .field-label {
      font-size: 11px;
      font-weight: 600;
      color: var(--text-subtle);
      text-transform: uppercase;
      letter-spacing: .04em;
    }
    .field-value {
      font-size: 13px;
      color: var(--text-default);
    }

    .email-body-box {
      background: var(--recessed);
      border: 1px solid var(--hairline);
      border-radius: var(--radius-md);
      padding: 14px;
      font-family: var(--font-mono);
      font-size: 12px;
      white-space: pre-line;
      max-height: 240px;
      overflow-y: auto;
      color: var(--text-subtle);
      line-height: 1.7;
    }

    .modal-footer {
      padding: 14px 20px;
      border-top: 1px solid var(--hairline);
      display: flex;
      align-items: center;
      gap: 10px;
      flex-shrink: 0;
      flex-wrap: wrap;
    }
    .copy-success {
      font-size: 12px;
      font-weight: 600;
      color: var(--success);
      opacity: 0;
      transition: opacity .2s;
      margin-left: auto;
    }

    /* ===== Animations ===== */
    @keyframes fadeIn { from { opacity: 0 } to { opacity: 1 } }
    @keyframes pulse {
      0%, 100% { opacity: 1 }
      50% { opacity: .4 }
    }

    /* ===== Responsive ===== */
    @media (max-width: 600px) {
      .topbar { padding: 0 16px; }
      .topbar-section { display: none; }
      .card-header { padding: 22px 20px 18px; }
      .card-body { padding: 18px; gap: 14px; }
      .detail-label { min-width: 72px; font-size: 11px; }
      .card-footer { flex-direction: column; align-items: flex-start; gap: 6px; }
      .footer-text { text-align: left; }
      .actions { flex-direction: column; }
      .btn-primary, .btn-ghost { width: 100%; }
    }
  </style>
</head>
<body>
  <!-- Top navigation bar -->
  <nav class="topbar">
    <!-- Cloudflare wordmark (SVG) -->
    <svg class="topbar-logo" viewBox="0 0 109 41" fill="none" xmlns="http://www.w3.org/2000/svg" aria-label="Cloudflare">
      <path d="M73.3 20.5c0 11.3-9.2 20.5-20.5 20.5S32.3 31.8 32.3 20.5 41.5 0 52.8 0s20.5 9.2 20.5 20.5" fill="#F38020"/>
      <path d="M52.8 0C41.5 0 32.3 9.2 32.3 20.5S41.5 41 52.8 41c8.9 0 16.6-5.7 19.4-13.7H52.8V20.5h20.5C73.3 9.2 64.1 0 52.8 0" fill="#FBAD41"/>
    </svg>
    <span class="topbar-product">Cloudflare Gateway</span>
    <span class="topbar-sep">|</span>
    <span class="topbar-section">Security Policy</span>
    <button class="theme-toggle" id="themeToggle" aria-label="Toggle light/dark mode">
      <!-- Sun icon (shown in dark mode to switch to light) -->
      <svg class="icon-moon" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <!-- Moon icon (shown in light mode to switch to dark) -->
      <svg class="icon-sun" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="12" cy="12" r="5" stroke="currentColor" stroke-width="1.8"/>
        <line x1="12" y1="1" x2="12" y2="3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
        <line x1="12" y1="21" x2="12" y2="23" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
        <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
        <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
        <line x1="1" y1="12" x2="3" y2="12" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
        <line x1="21" y1="12" x2="23" y2="12" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
        <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
        <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
      </svg>
    </button>
    <span class="topbar-badge">Blocked</span>
  </nav>

  <!-- Main card -->
  <div class="card">
    <!-- Header -->
    <div class="card-header">
      <div class="shield-icon">
        <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M12 2L4 6v6c0 5.5 3.4 10.7 8 12 4.6-1.3 8-6.5 8-12V6l-8-4z" stroke="#F38020" stroke-width="1.8" stroke-linejoin="round"/>
          <path d="M9 12l2 2 4-4" stroke="#F38020" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
      </div>
      <h1>Access Blocked</h1>
      <p>This request was intercepted and blocked by your organization's Gateway security policy.</p>
    </div>

    <!-- Body -->
    <div class="card-body">
      <!-- Detail table -->
      <div class="detail-table">
        <div class="detail-row">
          <span class="detail-label">Rule</span>
          <span class="detail-value">
            <span class="rule-name-text">${escapeHtml(ruleName)}</span>${displayCategory ? `<span class="category-pill">${displayCategory}</span>` : ''}
          </span>
        </div>
        ${displayFilter ? `
        <div class="detail-row">
          <span class="detail-label">Policy Type</span>
          <span class="detail-value">${displayFilter}</span>
        </div>` : ''}
        ${blockedUrl ? `
        <div class="detail-row">
          <span class="detail-label">URL</span>
          <span class="detail-value mono">${displayUrl}</span>
        </div>` : ''}
        ${displayDevice ? `
        <div class="detail-row">
          <span class="detail-label">Device</span>
          <span class="detail-value">${displayDevice}</span>
        </div>` : ''}
        ${displayWarpV4 ? `
        <div class="detail-row">
          <span class="detail-label">CF One Client IPv4</span>
          <span class="detail-value mono">${displayWarpV4}</span>
        </div>` : ''}
        ${displayWarpV6 ? `
        <div class="detail-row">
          <span class="detail-label">CF One Client IPv6</span>
          <span class="detail-value mono">${displayWarpV6}</span>
        </div>` : ''}
        ${ruleId ? `
        <div class="detail-row">
          <span class="detail-label">Rule ID</span>
          <span class="detail-value mono">${escapeHtml(ruleId)}</span>
        </div>` : ''}
        ${displayRayId ? `
        <div class="detail-row">
          <span class="detail-label">Ray ID</span>
          <span class="detail-value mono">${displayRayId}</span>
        </div>` : ''}
        <div class="detail-row">
          <span class="detail-label">Time</span>
          <span class="detail-value">${displayTime}</span>
        </div>
      </div>

      <!-- Info banner -->
      <div class="info-banner">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
          <circle cx="12" cy="12" r="9" stroke="#8B8D98" stroke-width="1.6"/>
          <path d="M12 8v.01M12 11v5" stroke="#8B8D98" stroke-width="1.6" stroke-linecap="round"/>
        </svg>
        <span>If you believe this was blocked in error, contact your IT administrator and include the rule ID and blocked URL.</span>
      </div>

      <!-- Actions -->
      <div class="actions">
        <button id="contactBtn" class="btn-primary">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>
            <polyline points="22,6 12,13 2,6" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>
          </svg>
          Contact Administrator
        </button>
      </div>
    </div>

    <!-- Footer -->
    <div class="card-footer">
      <div class="footer-logo">
        <svg viewBox="0 0 109 41" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M73.3 20.5c0 11.3-9.2 20.5-20.5 20.5S32.3 31.8 32.3 20.5 41.5 0 52.8 0s20.5 9.2 20.5 20.5" fill="currentColor"/>
        </svg>
        Cloudflare
      </div>
      <span class="footer-text">Protected by Cloudflare Gateway</span>
    </div>
  </div>

  <!-- Contact Modal -->
  <div id="contactModal" class="modal" role="dialog" aria-modal="true" aria-labelledby="modalTitle">
    <div class="modal-panel">
      <div class="modal-header">
        <span class="modal-title" id="modalTitle">Contact Administrator</span>
        <button id="modalCloseBtn" class="modal-close" aria-label="Close">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
            <line x1="18" y1="6" x2="6" y2="18" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
            <line x1="6" y1="6" x2="18" y2="18" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
          </svg>
        </button>
      </div>

      <div class="modal-body">
        <div class="field-group">
          <span class="field-label">To</span>
          <span class="field-value">${escapeHtml(emailContent.adminEmail)}</span>
        </div>
        <div class="field-group">
          <span class="field-label">Subject</span>
          <span class="field-value">${escapeHtml(emailContent.subject)}</span>
        </div>
        <div class="field-group">
          <span class="field-label">Message body</span>
          <div class="email-body-box" id="emailContent">${escapeHtml(emailContent.body)}</div>
        </div>
      </div>

      <div class="modal-footer">
        <button id="copyBtn" class="btn-primary">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
            <rect x="9" y="9" width="13" height="13" rx="2" stroke="currentColor" stroke-width="1.8"/>
            <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" stroke="currentColor" stroke-width="1.8"/>
          </svg>
          Copy Message
        </button>
        <a href="mailto:${escapeHtml(emailContent.adminEmail)}?subject=${encodeURIComponent(emailContent.subject)}" class="btn-ghost">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
            <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>
            <polyline points="22,6 12,13 2,6" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>
          </svg>
          Open Email Client
        </a>
        <span id="copySuccess" class="copy-success">Copied!</span>
      </div>
    </div>
  </div>

  <script nonce="${nonce}">
    /* ===== Theme toggle ===== */
    document.getElementById('themeToggle').addEventListener('click', function(){
      var html = document.documentElement;
      var next = html.getAttribute('data-mode') === 'dark' ? 'light' : 'dark';
      html.setAttribute('data-mode', next);
      localStorage.setItem('cf-gw-mode', next);
    });

    /* ===== Modal helpers ===== */
    function openContactModal(){
      var m = document.getElementById('contactModal');
      m.classList.add('open');
      document.body.style.overflow = 'hidden';
    }
    function closeContactModal(){
      var m = document.getElementById('contactModal');
      m.classList.remove('open');
      document.body.style.overflow = '';
    }

    /* ===== Button wiring (no inline onclick — required by CSP nonce policy) ===== */
    document.getElementById('contactBtn').addEventListener('click', openContactModal);
    document.getElementById('modalCloseBtn').addEventListener('click', closeContactModal);

    document.getElementById('copyBtn').addEventListener('click', function(){
      var body = \`${emailContent.body.replace(/`/g,'\\`').replace(/\$/g,'\\$')}\`;
      navigator.clipboard.writeText(body).then(function(){
        showCopySuccess();
      }).catch(function(){
        var ta = document.createElement('textarea');
        ta.value = body;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        showCopySuccess();
      });
    });

    function showCopySuccess(){
      var s = document.getElementById('copySuccess');
      s.style.opacity = '1';
      setTimeout(function(){ s.style.opacity = '0'; }, 2500);
    }

    /* ===== Close on backdrop click ===== */
    document.getElementById('contactModal').addEventListener('click', function(e){
      if(e.target === this) closeContactModal();
    });

    /* ===== Close on Escape key ===== */
    document.addEventListener('keydown', function(e){
      if(e.key === 'Escape') closeContactModal();
    });
  </script>
</body>
</html>
  `.trim()
}