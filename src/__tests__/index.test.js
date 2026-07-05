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
      await worker.fetch(request, env)
      
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
    }, 10000)
  })

  describe('Security Headers', () => {
    test('should include all security headers for HTML responses', async () => {
      const request = new Request('https://example.com/block?rule_id=test-rule')
      const response = await worker.fetch(request, env)

      expect(response.headers.get('X-Frame-Options')).toBe('DENY')
      expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff')
      expect(response.headers.get('Referrer-Policy')).toBe('no-referrer')
      expect(response.headers.get('Content-Security-Policy')).toContain('default-src \'none\'')
      expect(response.headers.get('Content-Security-Policy')).toContain('style-src \'nonce-')
      expect(response.headers.get('Content-Security-Policy')).toContain('script-src \'nonce-')
    })

    test('should set no-store cache header for HTML responses (nonce-protected pages must not be cached)', async () => {
      const request = new Request('https://example.com/block?rule_id=test-rule')
      const response = await worker.fetch(request, env)

      expect(response.headers.get('Cache-Control')).toBe('no-store')
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
      expect(html).toContain('Contact Administrator')
      expect(html).toContain('openContactModal')
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

  describe('Filter Type', () => {
    test('should render human-readable label for cf_filter=http', async () => {
      const request = new Request('https://example.com/block?cf_rule_id=test-rule&cf_filter=http')
      const response = await worker.fetch(request, env)

      expect(response.status).toBe(200)
      const html = await response.text()
      expect(html).toContain('HTTP Policy')
      expect(html).toContain('Policy Type')
    })

    test('should render human-readable label for cf_filter=dns', async () => {
      const request = new Request('https://example.com/block?cf_rule_id=test-rule&cf_filter=dns')
      const response = await worker.fetch(request, env)

      const html = await response.text()
      expect(html).toContain('DNS Policy')
    })

    test('should include filter_type in JSON response', async () => {
      const request = new Request('https://example.com/block?cf_rule_id=test-rule&cf_filter=http', {
        headers: { 'Accept': 'application/json' }
      })
      const response = await worker.fetch(request, env)
      const data = await response.json()

      expect(data.filter_type).toBe('http')
    })

    test('should not render Policy Type row when cf_filter is absent', async () => {
      const request = new Request('https://example.com/block?cf_rule_id=test-rule')
      const response = await worker.fetch(request, env)

      const html = await response.text()
      expect(html).not.toContain('Policy Type')
    })
  })

  describe('Ray ID', () => {
    test('should render Ray ID from cf_ray_id query param', async () => {
      const request = new Request('https://example.com/block?cf_rule_id=test-rule&cf_ray_id=abc123def456')
      const response = await worker.fetch(request, env)

      expect(response.status).toBe(200)
      const html = await response.text()
      expect(html).toContain('abc123def456')
      expect(html).toContain('Ray ID')
    })

    test('should fall back to CF-Ray request header when cf_ray_id param is absent', async () => {
      const request = new Request('https://example.com/block?cf_rule_id=test-rule', {
        headers: { 'CF-Ray': 'header-ray-789xyz' }
      })
      const response = await worker.fetch(request, env)

      const html = await response.text()
      expect(html).toContain('header-ray-789xyz')
      expect(html).toContain('Ray ID')
    })

    test('should include ray_id in JSON response', async () => {
      const request = new Request('https://example.com/block?cf_rule_id=test-rule&cf_ray_id=ray-json-test', {
        headers: { 'Accept': 'application/json' }
      })
      const response = await worker.fetch(request, env)
      const data = await response.json()

      expect(data.ray_id).toBe('ray-json-test')
    })

    test('should not render Ray ID row when neither param nor header is present', async () => {
      const request = new Request('https://example.com/block?cf_rule_id=test-rule')
      const response = await worker.fetch(request, env)

      const html = await response.text()
      expect(html).not.toContain('Ray ID')
    })
  })

  describe('Device Name', () => {
    test('should use cached device name when available', async () => {
      mockKV.get.mockImplementation((key) => {
        if (key === 'rule:test-rule') return Promise.resolve('Test Rule')
        if (key === 'device:test-device-id') return Promise.resolve('My Laptop')
        return Promise.resolve(null)
      })

      const request = new Request('https://example.com/block?cf_rule_id=test-rule&cf_device_id=test-device-id')
      const response = await worker.fetch(request, env)

      expect(mockKV.get).toHaveBeenCalledWith('device:test-device-id')
      const html = await response.text()
      expect(html).toContain('My Laptop')
      expect(html).toContain('Device')
    })

    test('should fetch device name from API on cache miss and write to KV', async () => {
      mockKV.get.mockResolvedValue(null)
      global.fetch.mockImplementation((url) => {
        if (url.includes('/gateway/rules/')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: async () => ({ result: { name: 'Test Security Rule' } })
          })
        }
        if (url.includes('/devices/')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: async () => ({ result: { name: 'MacBook Pro' } })
          })
        }
        return Promise.reject(new Error('Unexpected fetch: ' + url))
      })

      const request = new Request('https://example.com/block?cf_rule_id=test-rule&cf_device_id=test-device-id')
      const response = await worker.fetch(request, env)

      expect(global.fetch).toHaveBeenCalledWith(
        'https://api.cloudflare.com/client/v4/accounts/test-account-id/devices/test-device-id',
        expect.objectContaining({
          headers: expect.objectContaining({
            'Authorization': 'Bearer test-token'
          })
        })
      )
      expect(mockKV.put).toHaveBeenCalledWith('device:test-device-id', 'MacBook Pro', { expirationTtl: 7200 })

      const html = await response.text()
      expect(html).toContain('MacBook Pro')
    })

    test('should fall back to "Device {id}" when Devices API fails', async () => {
      mockKV.get.mockResolvedValue(null)
      global.fetch.mockImplementation((url) => {
        if (url.includes('/gateway/rules/')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: async () => ({ result: { name: 'Test Security Rule' } })
          })
        }
        if (url.includes('/devices/')) {
          return Promise.reject(new Error('Network error'))
        }
        return Promise.reject(new Error('Unexpected fetch: ' + url))
      })

      const request = new Request('https://example.com/block?cf_rule_id=test-rule&cf_device_id=test-device-id')
      const response = await worker.fetch(request, env)

      expect(response.status).toBe(200)
      const html = await response.text()
      expect(html).toContain('Device test-device-id')
    }, 10000)

    test('should include device_id and device_name in JSON response', async () => {
      mockKV.get.mockImplementation((key) => {
        if (key === 'device:test-device-id') return Promise.resolve('Office Desktop')
        return Promise.resolve(null)
      })

      const request = new Request('https://example.com/block?cf_rule_id=test-rule&cf_device_id=test-device-id', {
        headers: { 'Accept': 'application/json' }
      })
      const response = await worker.fetch(request, env)
      const data = await response.json()

      expect(data.device_id).toBe('test-device-id')
      expect(data.device_name).toBe('Office Desktop')
    })

    test('should not render Device row when cf_device_id is absent', async () => {
      const request = new Request('https://example.com/block?cf_rule_id=test-rule')
      const response = await worker.fetch(request, env)

      const html = await response.text()
      // "Device" only appears if the row is rendered; "Contact Administrator" button is always present
      // Check the specific detail-label context
      expect(html).not.toMatch(/detail-label[^<]*>Device</)
    })
  })

  describe('Cloudflare One Client IP Addresses', () => {
    beforeEach(() => {
      // Reset Cache API mock before each test
      caches.default.match.mockResolvedValue(undefined)
      caches.default.put.mockResolvedValue(undefined)
    })

    test('should render CF One Client IPv4 and IPv6 rows when device has IPs', async () => {
      mockKV.get.mockResolvedValue(null)
      global.fetch.mockImplementation((url) => {
        if (url.includes('/gateway/rules/')) {
          return Promise.resolve({ ok: true, status: 200, json: async () => ({ result: { name: 'Test Rule' } }) })
        }
        if (url.includes('/devices/test-device-id')) {
          return Promise.resolve({ ok: true, status: 200, json: async () => ({ result: { name: 'My Laptop' } }) })
        }
        if (url.includes('/devices/registrations')) {
          return Promise.resolve({
            ok: true, status: 200,
            json: async () => ({
              result: [{ id: 'reg-1', device: { id: 'test-device-id' }, virtual_ipv4: '100.96.0.1', virtual_ipv6: 'fd01::1', last_seen_at: '2026-07-05T10:00:00Z' }]
            })
          })
        }
        return Promise.reject(new Error('Unexpected fetch: ' + url))
      })

      const request = new Request('https://example.com/block?cf_rule_id=test-rule&cf_device_id=test-device-id')
      const response = await worker.fetch(request, env)

      expect(response.status).toBe(200)
      const html = await response.text()
      expect(html).toContain('100.96.0.1')
      expect(html).toContain('fd01::1')
      expect(html).toContain('CF One Client IPv4')
      expect(html).toContain('CF One Client IPv6')
    })

    test('should use Cache API hit and skip fetch for CF One Client IPs', async () => {
      mockKV.get.mockResolvedValue(null)

      // Simulate a Cache API hit for the CF One Client IPs request
      const cachedResult = { v4: '100.96.0.2', v6: null }
      caches.default.match.mockResolvedValue({
        json: async () => cachedResult
      })

      global.fetch.mockImplementation((url) => {
        if (url.includes('/gateway/rules/')) {
          return Promise.resolve({ ok: true, status: 200, json: async () => ({ result: { name: 'Test Rule' } }) })
        }
        if (url.includes('/devices/test-device-id')) {
          return Promise.resolve({ ok: true, status: 200, json: async () => ({ result: { name: 'My Laptop' } }) })
        }
        // registrations should NOT be called — cache hit
        return Promise.reject(new Error('Unexpected fetch: ' + url))
      })

      const request = new Request('https://example.com/block?cf_rule_id=test-rule&cf_device_id=test-device-id')
      const response = await worker.fetch(request, env)

      const html = await response.text()
      expect(html).toContain('100.96.0.2')
      // Confirm teamnet was never fetched
      const teamnetCalled = global.fetch.mock.calls.some(([url]) => url.includes('/teamnet/'))
      expect(teamnetCalled).toBe(false)
    })

    test('should not render CF One Client IP rows when credentials are missing', async () => {
      const envNoCreds = { ...env, CLOUDFLARE_API_TOKEN: undefined }
      mockKV.get.mockResolvedValue(null)
      global.fetch.mockImplementation((url) => {
        if (url.includes('/gateway/rules/')) {
          return Promise.resolve({ ok: true, status: 200, json: async () => ({ result: { name: 'Test Rule' } }) })
        }
        if (url.includes('/devices/test-device-id')) {
          return Promise.resolve({ ok: true, status: 200, json: async () => ({ result: { name: 'My Laptop' } }) })
        }
        return Promise.reject(new Error('Unexpected fetch: ' + url))
      })

      const request = new Request('https://example.com/block?cf_rule_id=test-rule&cf_device_id=test-device-id')
      const response = await worker.fetch(request, envNoCreds)

      const html = await response.text()
      expect(html).not.toContain('CF One Client IPv4')
      expect(html).not.toContain('CF One Client IPv6')
    })

    test('should not render CF One Client IP rows when no device_id is present', async () => {
      const request = new Request('https://example.com/block?cf_rule_id=test-rule')
      const response = await worker.fetch(request, env)

      const html = await response.text()
      expect(html).not.toContain('CF One Client IPv4')
      expect(html).not.toContain('CF One Client IPv6')
    })

    test('should include cf1client_ipv4 and cf1client_ipv6 in JSON response', async () => {
      mockKV.get.mockImplementation((key) => {
        if (key === 'device:test-device-id') return Promise.resolve('My Laptop')
        return Promise.resolve(null)
      })
      global.fetch.mockImplementation((url) => {
        if (url.includes('/devices/registrations')) {
          return Promise.resolve({
            ok: true, status: 200,
            json: async () => ({
              result: [{ id: 'reg-1', device: { id: 'test-device-id' }, virtual_ipv4: '100.96.0.5', virtual_ipv6: 'fd01::5', last_seen_at: '2026-07-05T10:00:00Z' }]
            })
          })
        }
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ result: { name: 'Test Rule' } }) })
      })

      const request = new Request('https://example.com/block?cf_rule_id=test-rule&cf_device_id=test-device-id', {
        headers: { 'Accept': 'application/json' }
      })
      const response = await worker.fetch(request, env)
      const data = await response.json()

      expect(data.cf1client_ipv4).toBe('100.96.0.5')
      expect(data.cf1client_ipv6).toBe('fd01::5')
    })

    test('should degrade gracefully when registrations API fails', async () => {
      mockKV.get.mockResolvedValue(null)
      global.fetch.mockImplementation((url) => {
        if (url.includes('/gateway/rules/')) {
          return Promise.resolve({ ok: true, status: 200, json: async () => ({ result: { name: 'Test Rule' } }) })
        }
        if (url.includes('/devices/test-device-id')) {
          return Promise.resolve({ ok: true, status: 200, json: async () => ({ result: { name: 'My Laptop' } }) })
        }
        if (url.includes('/devices/registrations')) {
          return Promise.reject(new Error('API unavailable'))
        }
        return Promise.reject(new Error('Unexpected fetch: ' + url))
      })

      const request = new Request('https://example.com/block?cf_rule_id=test-rule&cf_device_id=test-device-id')
      const response = await worker.fetch(request, env)

      // Page still renders, just without CF One Client IP rows
      expect(response.status).toBe(200)
      const html = await response.text()
      expect(html).toContain('My Laptop')
      expect(html).not.toContain('CF One Client IPv4')
      expect(html).not.toContain('CF One Client IPv6')
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
      
      // Create a request that will cause an error by mocking URL constructor to throw
      const originalURL = global.URL
      global.URL = class {
        constructor() {
          throw new Error('Invalid URL')
        }
      }
      
      const request = new Request('https://example.com/block?rule_id=test')
      
      try {
        const response = await worker.fetch(request, env)
        expect(response.status).toBe(500)
        expect(await response.text()).toBe('Internal Server Error')
      } finally {
        console.error = originalConsoleError
        global.URL = originalURL
      }
    })
  })
})