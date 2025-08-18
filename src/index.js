/**
 * Cloudflare Worker for Gateway blocking page
 * Dynamically retrieves rule names and displays custom blocking pages
 */

export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, env);
  }
};

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
      return handleJsonRequest(ruleId, blockedUrl, category, userEmail, env)
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
 */
async function handleJsonRequest(ruleId, blockedUrl, category, userEmail, env) {
  const ruleName = ruleId ? await getRuleName(ruleId, env) : 'Unknown Rule'
  
  const response = {
    blocked: true,
    rule_id: ruleId,
    rule_name: ruleName,
    blocked_url: blockedUrl,
    category: category,
    timestamp: new Date().toISOString()
  }
  
  return new Response(JSON.stringify(response, null, 2), {
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
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
  const html = generateBlockingPage(ruleName, ruleId, blockedUrl, category, timestamp)
  
  return new Response(html, {
    headers: {
      'Content-Type': 'text/html',
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer'
    }
  })
}

/**
 * Retrieve rule name from Cloudflare Gateway API
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
    
    // Fetch from API
    const apiToken = env.CLOUDFLARE_API_TOKEN
    const accountId = env.CLOUDFLARE_ACCOUNT_ID
    
    if (!apiToken || !accountId) {
      console.warn('API credentials not configured')
      return 'Rule ' + ruleId
    }
    
    const apiUrl = `https://api.cloudflare.com/client/v4/accounts/${accountId}/gateway/rules/${ruleId}`
    
    const response = await fetch(apiUrl, {
      headers: {
        'Authorization': `Bearer ${apiToken}`,
        'Content-Type': 'application/json'
      }
    })
    
    if (!response.ok) {
      console.error(`API request failed: ${response.status} ${response.statusText}`)
      return 'Rule ' + ruleId
    }
    
    const data = await response.json()
    const ruleName = data.result?.name || ('Rule ' + ruleId)
    
    // Cache the result
    await cacheRuleName(ruleId, ruleName, env)
    
    return ruleName
  } catch (error) {
    console.error('Error fetching rule name for rule:', ruleId, error)
    return 'Rule ' + ruleId
  }
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
      // Cache for 1 hour
      await env.RULE_CACHE.put(`rule:${ruleId}`, ruleName, { expirationTtl: 3600 })
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
 * Generate HTML blocking page
 * @param {string} ruleName 
 * @param {string} ruleId 
 * @param {string} blockedUrl 
 * @param {string} category 
 * @param {string} timestamp 
 * @returns {string}
 */
function generateBlockingPage(ruleName, ruleId, blockedUrl, category, timestamp) {
  const displayUrl = blockedUrl ? escapeHtml(decodeURIComponent(blockedUrl)) : 'the requested resource'
  const displayCategory = category ? ` (${escapeHtml(category)})` : ''
  
  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Blocked</title>
    <style>
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
                <a href="mailto:support@macharpe.com?subject=Access%20Blocked%20-%20Please%20Review&body=Hello,%0A%0AI%20was%20blocked%20from%20accessing%20the%20following%20resource:%0A%0ABLOCKED%20URL:%0A${blockedUrl ? encodeURIComponent(displayUrl) : 'N/A'}%0A%0ASECURITY%20RULE%20DETAILS:%0ARule%20Name:%20${encodeURIComponent(ruleName)}%0ARule%20ID:%20${ruleId || 'N/A'}%0A${category ? `Category:%20${encodeURIComponent(category)}%0A` : ''}%0ATIMESTAMP:%0A${encodeURIComponent(timestamp ? new Date(timestamp).toLocaleString() : new Date().toLocaleString())}%0A%0AREQUEST%20FOR%20REVIEW:%0APlease%20review%20this%20block%20as%20I%20believe%20it%20may%20be%20in%20error.%20If%20this%20is%20a%20legitimate%20business%20resource,%20please%20consider%20updating%20the%20security%20policy.%0A%0AThank%20you%20for%20your%20assistance." class="btn">Contact Administrator</a>
            </div>
        </div>
        
        <div class="footer">
            If you believe this was blocked in error, please contact your IT administrator.
        </div>
    </div>
</body>
</html>
  `.trim()
}