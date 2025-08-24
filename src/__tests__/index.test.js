/**
 * Tests for the Gateway blocking page worker
 */

// Mock the global fetch function
global.fetch = jest.fn()

// Mock crypto.randomUUID
global.crypto = {
  randomUUID: jest.fn(() => 'mock-uuid-1234-5678-9abc-def0')
}

// Import the worker after setting up mocks
const worker = require('../index.js').default

describe('Gateway Blocking Page Worker', () => {
  let env
  let mockKV

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks()

    // Mock KV namespace
    mockKV = {
      get: jest.fn(),
      put: jest.fn()
    }

    // Mock environment
    env = {
      CLOUDFLARE_API_TOKEN: 'test-token',
      CLOUDFLARE_ACCOUNT_ID: 'test-account-id',
      ADMIN_EMAIL: 'admin@test.com',
      CACHE_TTL: '7200',
      ALLOWED_ORIGINS: 'https://test1.com,https://test2.com',
      RULE_CACHE: mockKV
    }

    // Mock successful API response
    global.fetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        result: {
          name: 'Test Security Rule'
        }
      })
    })
  })

  describe('Access Control', () => {
    test('should deny access when no Gateway context is provided', async () => {
      const request = new Request('https://example.com/block')
      const response = await worker.fetch(request, env)
      
      expect(response.status).toBe(403)
      expect(await response.text()).toBe('Access Denied')
    })

    test('should allow access with valid Gateway context', async () => {
      const request = new Request('https://example.com/block?rule_id=test-rule-id')
      const response = await worker.fetch(request, env)
      
      expect(response.status).toBe(200)
      expect(response.headers.get('Content-Type')).toBe('text/html')
    })
  })

  describe('CORS Policy', () => {
    test('should return secure CORS headers for JSON requests', async () => {
      const request = new Request('https://example.com/block?rule_id=test-rule', {
        headers: {
          'Accept': 'application/json',
          'Origin': 'https://test1.com'
        }
      })

      const response = await worker.fetch(request, env)
      
      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('https://test1.com')
      expect(response.headers.get('Vary')).toBe('Origin')
    })

    test('should reject unauthorized origins', async () => {
      const request = new Request('https://example.com/block?rule_id=test-rule', {
        headers: {
          'Accept': 'application/json',
          'Origin': 'https://malicious.com'
        }
      })

      const response = await worker.fetch(request, env)
      
      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('null')
    })
  })

  describe('API Caching', () => {
    test('should use cached rule name when available', async () => {
      // Mock cached value
      mockKV.get.mockResolvedValue('Cached Rule Name')
      
      const request = new Request('https://example.com/block?rule_id=test-rule')
      const response = await worker.fetch(request, env)
      
      expect(mockKV.get).toHaveBeenCalledWith('rule:test-rule')
      expect(global.fetch).not.toHaveBeenCalled()
      
      const html = await response.text()
      expect(html).toContain('Cached Rule Name')
    })

    test('should fetch from API when not cached', async () => {
      // Mock no cached value
      mockKV.get.mockResolvedValue(null)
      
      const request = new Request('https://example.com/block?rule_id=test-rule')
      const response = await worker.fetch(request, env)
      
      expect(mockKV.get).toHaveBeenCalledWith('rule:test-rule')
      expect(global.fetch).toHaveBeenCalledWith(
        'https://api.cloudflare.com/client/v4/accounts/test-account-id/gateway/rules/test-rule',
        expect.objectContaining({
          headers: expect.objectContaining({
            'Authorization': 'Bearer test-token'
          })
        })
      )
      expect(mockKV.put).toHaveBeenCalledWith('rule:test-rule', 'Test Security Rule', { expirationTtl: 7200 })
    })
  })

  describe('Rate Limiting and Retry Logic', () => {
    test('should retry on 429 rate limit response', async () => {
      // Mock rate limit response, then success
      global.fetch
        .mockResolvedValueOnce({
          ok: false,
          status: 429,
          statusText: 'Too Many Requests'
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ result: { name: 'Retried Rule' } })
        })

      mockKV.get.mockResolvedValue(null)

      const request = new Request('https://example.com/block?rule_id=test-rule')
      const response = await worker.fetch(request, env)
      
      expect(global.fetch).toHaveBeenCalledTimes(2)
      
      const html = await response.text()
      expect(html).toContain('Retried Rule')
    })

    test('should handle API failures gracefully', async () => {
      global.fetch.mockRejectedValue(new Error('Network error'))
      mockKV.get.mockResolvedValue(null)

      const request = new Request('https://example.com/block?rule_id=test-rule')
      const response = await worker.fetch(request, env)
      
      expect(response.status).toBe(200)
      const html = await response.text()
      expect(html).toContain('Rule test-rule')
    })
  })

  describe('Security Headers', () => {
    test('should include all security headers for HTML responses', async () => {
      const request = new Request('https://example.com/block?rule_id=test-rule')
      const response = await worker.fetch(request, env)
      
      expect(response.headers.get('X-Frame-Options')).toBe('DENY')
      expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff')
      expect(response.headers.get('Referrer-Policy')).toBe('no-referrer')
      expect(response.headers.get('Content-Security-Policy')).toContain('default-src \'none\'')
      expect(response.headers.get('Content-Security-Policy')).toContain('nonce-')
    })
  })

  describe('HTML Generation', () => {
    test('should escape HTML in user inputs', async () => {
      const maliciousUrl = 'https://example.com/<script>alert(1)</script>'
      const request = new Request(`https://example.com/block?rule_id=test-rule&blocked_url=${encodeURIComponent(maliciousUrl)}`)
      const response = await worker.fetch(request, env)
      
      const html = await response.text()
      expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;')
      expect(html).not.toContain('<script>alert(1)</script>')
    })

    test('should use environment variables in template', async () => {
      const request = new Request('https://example.com/block?rule_id=test-rule')
      const response = await worker.fetch(request, env)
      
      const html = await response.text()
      expect(html).toContain('admin@test.com')
    })
  })

  describe('JSON API Response', () => {
    test('should return proper JSON structure', async () => {
      const request = new Request('https://example.com/block?rule_id=test-rule&blocked_url=https://malicious.com', {
        headers: { 'Accept': 'application/json' }
      })

      const response = await worker.fetch(request, env)
      const data = await response.json()
      
      expect(data).toMatchObject({
        blocked: true,
        rule_id: 'test-rule',
        rule_name: 'Test Security Rule',
        blocked_url: 'https://malicious.com',
        category: null,
        timestamp: expect.any(String)
      })
    })
  })

  describe('Error Handling', () => {
    test('should handle missing API credentials gracefully', async () => {
      const envWithoutCreds = { ...env, CLOUDFLARE_API_TOKEN: undefined }
      
      const request = new Request('https://example.com/block?rule_id=test-rule')
      const response = await worker.fetch(request, envWithoutCreds)
      
      expect(response.status).toBe(200)
      const html = await response.text()
      expect(html).toContain('Rule test-rule')
    })

    test('should return 500 for unexpected errors', async () => {
      // Mock an error in the main handler
      const originalConsoleError = console.error
      console.error = jest.fn()
      
      // Create a request that will cause an error
      const request = new Request('invalid-url')
      
      try {
        const response = await worker.fetch(request, env)
        expect(response.status).toBe(500)
        expect(await response.text()).toBe('Internal Server Error')
      } finally {
        console.error = originalConsoleError
      }
    })
  })
})