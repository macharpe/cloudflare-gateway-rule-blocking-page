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
  } catch (error) {
    console.error('Error handling request:', error)
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
  if (!ruleId) return 'Unknown Rule'
  
  try {
    // Check cache first
    const cached = await getCachedRuleName(ruleId, env)
    if (cached) return cached
    
    // Fetch from API with retry logic
    const apiToken = env.CLOUDFLARE_API_TOKEN
    const accountId = env.CLOUDFLARE_ACCOUNT_ID
    
    if (!apiToken || !accountId) {
      console.warn('API credentials not configured')
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
  } catch (error) {
    console.error('Error fetching rule name for rule:', ruleId, error)
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
  } catch (error) {
    console.error('Cache read error:', error)
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
  } catch (error) {
    console.error('Cache write error:', error)
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
 * @returns {object} - Returns subject and body for the email
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
  const emailContent = generateEmailContent(adminEmail, ruleName, ruleId, displayUrl, category, timestamp)
  
  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Blocked</title>
    <style nonce="${nonce}">
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #333;
            line-height: 1.6;
        }
        
        .container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            max-width: 600px;
            margin: 20px;
            overflow: hidden;
        }
        
        .header {
            background: #ff6b6b;
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2rem;
            margin-bottom: 10px;
        }
        
        .header .icon {
            font-size: 3rem;
            margin-bottom: 20px;
            display: block;
        }
        
        .content {
            padding: 40px 30px;
        }
        
        .rule-info {
            background: #f8f9fa;
            border-left: 4px solid #007bff;
            padding: 20px;
            margin: 20px 0;
            border-radius: 0 8px 8px 0;
        }
        
        .rule-name {
            font-weight: bold;
            color: #007bff;
            font-size: 1.1rem;
            margin-bottom: 10px;
        }
        
        .details {
            color: #666;
            font-size: 0.9rem;
            margin-top: 20px;
        }
        
        .details div {
            margin: 5px 0;
        }
        
        .blocked-url {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 6px;
            padding: 15px;
            margin: 20px 0;
            word-break: break-all;
            color: #856404;
        }
        
        .actions {
            margin-top: 30px;
            text-align: center;
        }
        
        .btn {
            background: #007bff;
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 6px;
            text-decoration: none;
            display: inline-block;
            margin: 0 10px;
            transition: background-color 0.3s;
            cursor: pointer;
        }
        
        .btn:hover {
            background: #0056b3;
        }
        
        .btn-secondary {
            background: #6c757d;
        }
        
        .btn-secondary:hover {
            background: #545b62;
        }
        
        .footer {
            background: #f8f9fa;
            padding: 20px 30px;
            text-align: center;
            color: #666;
            font-size: 0.9rem;
            border-top: 1px solid #e9ecef;
        }
        
        /* Modal styles */
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
            animation: fadeIn 0.3s;
        }
        
        .modal-content {
            background-color: white;
            margin: 5% auto;
            padding: 0;
            border-radius: 12px;
            width: 90%;
            max-width: 600px;
            max-height: 80vh;
            overflow-y: auto;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
            position: relative;
        }
        
        .modal-header {
            background: #007bff;
            color: white;
            padding: 20px 30px;
            border-radius: 12px 12px 0 0;
            border-bottom: 1px solid #e9ecef;
        }
        
        .modal-header h3 {
            margin: 0;
            font-size: 1.3rem;
        }
        
        .close {
            position: absolute;
            right: 20px;
            top: 20px;
            color: white;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
            line-height: 1;
        }
        
        .close:hover,
        .close:focus {
            opacity: 0.7;
        }
        
        .modal-body {
            padding: 30px;
        }
        
        .email-content {
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 6px;
            padding: 20px;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            white-space: pre-line;
            max-height: 300px;
            overflow-y: auto;
            margin: 15px 0;
        }
        
        .copy-instructions {
            margin: 20px 0;
            padding: 15px;
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            border-radius: 0 6px 6px 0;
        }
        
        .btn-copy {
            background: #28a745;
            margin-right: 10px;
        }
        
        .btn-copy:hover {
            background: #218838;
        }
        
        .copy-success {
            color: #28a745;
            font-weight: bold;
            margin-left: 10px;
            opacity: 0;
            transition: opacity 0.3s;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        @media (max-width: 600px) {
            .container {
                margin: 10px;
            }
            
            .header, .content {
                padding: 20px;
            }
            
            .header h1 {
                font-size: 1.5rem;
            }
            
            .modal-content {
                margin: 10% auto;
                width: 95%;
            }
            
            .modal-header, .modal-body {
                padding: 20px;
            }
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
            </div>
            
            ${blockedUrl ? `
            <div class="blocked-url">
                <strong>Blocked URL:</strong><br>
                ${displayUrl}
            </div>
            ` : ''}
            
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
                
                <div>
                    <strong>To:</strong> ${escapeHtml(emailContent.adminEmail)}
                </div>
                <div style="margin: 10px 0;">
                    <strong>Subject:</strong> ${escapeHtml(emailContent.subject)}
                </div>
                
                <div>
                    <strong>Message:</strong>
                </div>
                <div class="email-content" id="emailContent">${escapeHtml(emailContent.body)}</div>
                
                <div style="text-align: center; margin-top: 20px;">
                    <button onclick="copyEmailContent()" class="btn btn-copy">Copy Message Body</button>
                    <a href="mailto:${escapeHtml(emailContent.adminEmail)}?subject=${encodeURIComponent(emailContent.subject)}" class="btn btn-secondary">Open Email Client</a>
                    <span id="copySuccess" class="copy-success">Message copied!</span>
                </div>
            </div>
        </div>
    </div>

    <script nonce="${nonce}">
        function openContactModal() {
            document.getElementById('contactModal').style.display = 'block';
        }
        
        function closeContactModal() {
            document.getElementById('contactModal').style.display = 'none';
        }
        
        function copyEmailContent() {
            const body = \`${emailContent.body.replace(/`/g, '\\`').replace(/\$/g, '\\$')}\`;
            
            navigator.clipboard.writeText(body).then(function() {
                const successMsg = document.getElementById('copySuccess');
                successMsg.style.opacity = '1';
                setTimeout(function() {
                    successMsg.style.opacity = '0';
                }, 3000);
            }).catch(function(err) {
                // Fallback for older browsers
                const textArea = document.createElement('textarea');
                textArea.value = body;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                
                const successMsg = document.getElementById('copySuccess');
                successMsg.style.opacity = '1';
                setTimeout(function() {
                    successMsg.style.opacity = '0';
                }, 3000);
            });
        }
        
        // Close modal when clicking outside of it
        window.onclick = function(event) {
            const modal = document.getElementById('contactModal');
            if (event.target == modal) {
                closeContactModal();
            }
        }
    </script>
</body>
</html>
  `.trim()
}