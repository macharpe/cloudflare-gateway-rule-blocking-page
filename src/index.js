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

    // Validate Gateway context - require at least one Gateway parameter
    const hasGatewayContext = ruleId || blockedUrl || category || userEmail ||
      url.searchParams.has('cf_rule_id') || url.searchParams.has('cf_site_uri') ||
      url.searchParams.has('cf_request_category_names') || url.searchParams.has('cf_user_email')
    
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
      return handleJsonRequest(ruleId, blockedUrl, category, userEmail, env, request)
    }

    return handleHtmlRequest(ruleId, blockedUrl, category, timestamp, userEmail, env)
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
 * @param {object} env
 * @param {Request} request
 */
async function handleJsonRequest(ruleId, blockedUrl, category, userEmail, env, request) {
  const ruleName = ruleId ? await getRuleName(ruleId, env) : 'Unknown Rule'
  
  const response = {
    blocked: true,
    rule_id: ruleId,
    rule_name: ruleName,
    blocked_url: blockedUrl,
    category: category,
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
 * @param {object} env
 */
async function handleHtmlRequest(ruleId, blockedUrl, category, timestamp, userEmail, env) {
  const ruleName = ruleId ? await getRuleName(ruleId, env) : 'Security Policy'
  const nonce = crypto.randomUUID().replace(/-/g, '')
  const html = generateBlockingPage(ruleName, ruleId, blockedUrl, category, timestamp, env, nonce)
  
  return new Response(html, {
    headers: {
      'Content-Type': 'text/html',
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
 * Get cached rule name from KV storage
 * @param {string} ruleId 
 * @param {object} env
 * @returns {Promise<string|null>}
 */
async function getCachedRuleName(ruleId, env) {
  try {
    if (env.RULE_CACHE) {
      const cached = await env.RULE_CACHE.get(`rule:${ruleId}`)
      return cached
    }
  } catch {
    // Cache read error - continue without cache
  }
  return null
}

/**
 * Cache rule name in KV storage
 * @param {string} ruleId 
 * @param {string} ruleName 
 * @param {object} env
 */
async function cacheRuleName(ruleId, ruleName, env) {
  try {
    if (env.RULE_CACHE) {
      // Cache TTL from environment variable, default to 1 hour
      const cacheTtl = parseInt(env.CACHE_TTL) || 3600
      await env.RULE_CACHE.put(`rule:${ruleId}`, ruleName, { expirationTtl: cacheTtl })
    }
  } catch {
    // Cache write error - continue without cache
  }
}

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
 * @returns {{subject: string, body: string, adminEmail: string}} - Returns subject and body for the email
 */
function generateEmailContent(adminEmail, ruleName, ruleId, blockedUrl, category, timestamp) {
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
Category: ${category}` : ''}

INCIDENT TIME:
${timestamp ? new Date(timestamp).toLocaleString() : new Date().toLocaleString()}

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

/**
 * Generate HTML blocking page
 * @param {string} ruleName 
 * @param {string} ruleId 
 * @param {string} blockedUrl 
 * @param {string} category 
 * @param {string} timestamp 
 * @param {object} env
 * @param {string} nonce
 * @returns {string}
 */
function generateBlockingPage(ruleName, ruleId, blockedUrl, category, timestamp, env, nonce) {
  const displayUrl = blockedUrl ? escapeHtml(decodeURIComponent(blockedUrl)) : 'the requested resource'
  const displayCategory = category ? ` (${escapeHtml(category)})` : ''
  const adminEmail = env.ADMIN_EMAIL || 'admin@example.com'
  /** @type {{subject: string, body: string, adminEmail: string}} */
  const emailContent = generateEmailContent(adminEmail, ruleName, ruleId, displayUrl, category, timestamp)
  
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Access Blocked</title>
  <style nonce="${nonce}">
    /* Reset */
    * { margin:0; padding:0; box-sizing:border-box; }

    /* ===== Base / Layout ===== */
    :root{
      --accent: #F38020;         /* Cloudflare Orange */
      --cta: #2563EB;            /* Blue CTA */
      --cta-hover: #1E40AF;
      --surface: #ffffff;        /* Card & modal surface */
      --muted: #6B7280;          /* Muted text */
      --border: #E5E7EB;         /* Subtle borders */
      --panel: #F8FAFC;          /* Light panels inside card */
      --shadow: 0 12px 30px rgba(2,6,23,.18);
      --radius: 16px;
    }

    body{
      font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,Cantarell,sans-serif;
      background: radial-gradient(1200px 800px at 50% -10%, #111827 0%, #0f172a 60%);
      min-height:100vh;
      display:flex;
      align-items:center;
      justify-content:center;
      color:#0f172a;
      line-height:1.6;
      -webkit-font-smoothing:antialiased;
      -moz-osx-font-smoothing:grayscale;
    }

    .container{
      background:var(--surface);
      border-radius:var(--radius);
      box-shadow:var(--shadow);
      max-width:620px;
      width:100%;
      margin:24px;
      overflow:hidden; /* keep header radius crisp */
    }

    /* ===== Header (accent strip) ===== */
    .header{
      background:var(--accent);
      color:#fff;
      padding:28px 28px 24px;
      text-align:center;
    }
    .header .icon{
      font-size:40px;
      display:block;
      margin-bottom:12px;
      line-height:1;
    }
    .header h1{
      font-size:28px;
      font-weight:700;
      letter-spacing:.2px;
      margin-bottom:6px;
    }
    .header p{
      font-size:14px;
      opacity:.95;
    }

    /* ===== Content ===== */
    .content{ padding:28px; }

    .rule-info{
      background:var(--panel);
      border:1px solid var(--border);
      border-radius:12px;
      padding:16px 18px;
    }
    .rule-name{
      font-weight:700;
      font-size:16px;
      color:#111827;
      margin-bottom:6px;
    }
    .rule-info p{
      font-size:14px;
      color:#374151;
    }

    .blocked-url{
      margin:18px 0 0;
      padding:14px 16px;
      background:#F3F4F6;                /* neutral, no yellow */
      border:1px solid var(--border);
      border-radius:10px;
      font-size:14px;
      color:#111827;
      word-break:break-all;
    }
    .blocked-url strong{
      font-weight:600;
      font-size:14px;
    }

    .details{
      margin-top:18px;
      font-size:13px;
      color:var(--muted);
    }
    .details div{ margin:4px 0; }

    .actions{
      margin-top:22px;
      text-align:center;
    }
    .btn{
      appearance:none;
      border:none;
      cursor:pointer;
      background:var(--cta);
      color:#fff;
      font-weight:600;
      font-size:16px;
      padding:12px 22px;
      border-radius:12px;
      transition:transform .05s ease, background .2s ease, box-shadow .2s ease;
      box-shadow:0 6px 14px rgba(37,99,235,.25);
    }
    .btn:hover{ background:var(--cta-hover); }
    .btn:active{ transform:translateY(1px); }

    .footer{
      border-top:1px solid var(--border);
      background:var(--panel);
      padding:16px 20px;
      text-align:center;
      color:var(--muted);
      font-size:13px;
    }

    /* ===== Modal (kept functions; restyled) ===== */
    .modal{
      display:none;
      position:fixed; inset:0;
      z-index:1000;
      background:rgba(15,23,42,.55);
      backdrop-filter: blur(2px);
      animation:fadeIn .2s ease;
    }
    .modal-content{
      background:var(--surface);
      margin:5% auto;
      padding:0;
      border-radius:var(--radius);
      width:92%;
      max-width:620px;
      max-height:80vh;
      overflow:auto;
      box-shadow:var(--shadow);
      position:relative;
    }
    .modal-header{
      background:var(--cta);
      color:#fff;
      padding:18px 24px;
      border-radius:var(--radius) var(--radius) 0 0;
    }
    .modal-header h3{
      margin:0; font-size:18px; font-weight:700;
    }
    .close{
      position:absolute; right:20px; top:16px;
      color:#fff; font-size:28px; font-weight:700; cursor:pointer; line-height:1;
      opacity:.95;
    }
    .close:hover{ opacity:.8; }

    .modal-body{ padding:22px 24px 26px; }

    .copy-instructions{
      background:#EFF6FF;
      border:1px solid #DBEAFE;
      color:#1f2937;
      padding:12px 14px;
      border-radius:10px;
      font-size:14px;
      margin-bottom:16px;
    }

    .email-content{
      background:var(--panel);
      border:1px solid var(--border);
      border-radius:10px;
      padding:14px;
      font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;
      font-size:13px;
      white-space:pre-line;
      max-height:280px;
      overflow-y:auto;
      margin:10px 0 4px;
      color:#111827;
    }

    .btn-copy{ background:#16A34A; }
    .btn-copy:hover{ background:#15803D; }
    .btn-secondary{
      background:#6B7280;
      margin-left:6px;
    }
    .btn-secondary:hover{ background:#4B5563; }

    .copy-success{
      color:#16A34A; font-weight:700; margin-left:10px; opacity:0; transition:opacity .2s;
    }

    @keyframes fadeIn{ from{opacity:0} to{opacity:1} }

    @media (max-width:600px){
      .container{ margin:12px; }
      .content{ padding:22px; }
      .header{ padding:24px; }
      .header h1{ font-size:24px; }
      .modal-content{ margin:10% auto; width:95%; }
      .modal-header,.modal-body{ padding:18px 20px; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <span class="icon">🛡️</span>
      <h1>Access Blocked</h1>
      <p>This request has been blocked by your organization's security policy</p>
    </div>

    <div class="content">
      <div class="rule-info">
        <div class="rule-name">${escapeHtml(ruleName)}${displayCategory}</div>
        <p>Your request was blocked by the security rule shown above. This helps protect your organization from potentially harmful content.</p>

        ${blockedUrl ? `
        <div class="blocked-url">
          <strong>Blocked URL:</strong><br>
          ${displayUrl}
        </div>
        ` : ''}
      </div>

      <div class="details">
        ${ruleId ? `<div><strong>Rule ID:</strong> ${escapeHtml(ruleId)}</div>` : ''}
        ${category ? `<div><strong>Category:</strong> ${category}</div>` : ''}
        ${timestamp ? `<div><strong>Time:</strong> ${new Date(timestamp).toLocaleString()}</div>` : `<div><strong>Time:</strong> ${new Date().toLocaleString()}</div>`}
      </div>

      <div class="actions">
        <button onclick="openContactModal()" class="btn">Contact Administrator</button>
      </div>
    </div>

    <div class="footer">
      If you believe this was blocked in error, please contact your IT administrator.
    </div>
  </div>

  <!-- Contact Modal -->
  <div id="contactModal" class="modal">
    <div class="modal-content">
      <div class="modal-header">
        <h3>Contact Administrator</h3>
        <span class="close" onclick="closeContactModal()">&times;</span>
      </div>
      <div class="modal-body">
        <div class="copy-instructions">
          <strong>Instructions:</strong> Use "Copy Message Body" to copy only the message text, then compose a new email to the administrator with the provided subject line.
        </div>

        <div><strong>To:</strong> ${escapeHtml(emailContent.adminEmail)}</div>
        <div style="margin:10px 0;"><strong>Subject:</strong> ${escapeHtml(emailContent.subject)}</div>

        <div><strong>Message:</strong></div>
        <div class="email-content" id="emailContent">${escapeHtml(emailContent.body)}</div>

        <div style="text-align:center; margin-top:20px;">
          <button onclick="copyEmailContent()" class="btn btn-copy">Copy Message Body</button>
          <a href="mailto:${escapeHtml(emailContent.adminEmail)}?subject=${encodeURIComponent(emailContent.subject)}" class="btn btn-secondary">Open Email Client</a>
          <span id="copySuccess" class="copy-success">Message copied!</span>
        </div>
      </div>
    </div>
  </div>

  <script nonce="${nonce}">
    function openContactModal(){ document.getElementById('contactModal').style.display='block'; }
    function closeContactModal(){ document.getElementById('contactModal').style.display='none'; }

    function copyEmailContent(){
      const body = \`${emailContent.body.replace(/`/g,'\\`').replace(/\$/g,'\\$')}\`;
      navigator.clipboard.writeText(body).then(function(){
        const s=document.getElementById('copySuccess'); s.style.opacity='1';
        setTimeout(()=>{ s.style.opacity='0'; },3000);
      }).catch(function(){
        const ta=document.createElement('textarea'); ta.value=body; document.body.appendChild(ta);
        ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
        const s=document.getElementById('copySuccess'); s.style.opacity='1';
        setTimeout(()=>{ s.style.opacity='0'; },3000);
      });
    }

    window.onclick=function(e){ const m=document.getElementById('contactModal'); if(e.target===m){ closeContactModal(); } }
  </script>
</body>
</html>
  `.trim()
}