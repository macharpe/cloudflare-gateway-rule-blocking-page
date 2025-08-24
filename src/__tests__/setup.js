/**
 * Jest setup file for Cloudflare Worker tests
 */

// Mock Request and Response objects for Node.js environment
if (typeof Request === 'undefined') {
  global.Request = class Request {
    constructor(input, init = {}) {
      this.url = input
      this.method = init.method || 'GET'
      this.headers = new Map()
      
      // Handle headers
      if (init.headers) {
        if (init.headers instanceof Map) {
          this.headers = new Map(init.headers)
        } else if (typeof init.headers === 'object') {
          for (const [key, value] of Object.entries(init.headers)) {
            this.headers.set(key.toLowerCase(), value)
          }
        }
      }
      
      this.body = init.body
      this.mode = init.mode || 'cors'
      this.credentials = init.credentials || 'same-origin'
    }

    get(name) {
      return this.headers.get(name.toLowerCase())
    }
  }

  // Add headers.get method
  global.Request.prototype.headers = {
    get: function(name) {
      return this.headers.get(name.toLowerCase())
    }
  }
}

if (typeof Response === 'undefined') {
  global.Response = class Response {
    constructor(body, init = {}) {
      this.body = body
      this.status = init.status || 200
      this.statusText = init.statusText || 'OK'
      this.headers = new Map()
      
      if (init.headers) {
        if (typeof init.headers === 'object') {
          for (const [key, value] of Object.entries(init.headers)) {
            this.headers.set(key, value)
          }
        }
      }
      
      this.ok = this.status >= 200 && this.status < 300
    }

    async text() {
      return this.body
    }

    async json() {
      return JSON.parse(this.body)
    }
  }

  // Add headers property to Response prototype
  Object.defineProperty(global.Response.prototype, 'headers', {
    value: {
      get: function(name) {
        return this.headers.get(name)
      }
    },
    writable: false
  })
}

// Mock URL constructor
if (typeof URL === 'undefined') {
  global.URL = class URL {
    constructor(url) {
      const urlObj = new require('url').URL(url)
      this.href = urlObj.href
      this.protocol = urlObj.protocol
      this.host = urlObj.host
      this.hostname = urlObj.hostname
      this.port = urlObj.port
      this.pathname = urlObj.pathname
      this.search = urlObj.search
      this.hash = urlObj.hash
      this.searchParams = urlObj.searchParams
    }
  }
}

// Mock setTimeout for testing delays
if (typeof setTimeout === 'undefined') {
  global.setTimeout = (callback) => {
    setImmediate(callback)
    return 1
  }
}