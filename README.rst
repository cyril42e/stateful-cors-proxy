CORS Proxy
==========

A Python CORS proxy with session-persistent cookies, allowing access to APIs that require
ongoing authentication or stateful browsing.

Configuration
=============

The proxy uses a JSON configuration file (config.json) that contains:
- Key for proxy authentication
- Object of allowed target domains with their specific configurations
- List of allowed origins for CORS (defaults to ["*"] if not specified)
- Port number for the proxy server (defaults to 8080 if not specified)
- bind_localhost_only: if true, binds only to 127.0.0.1 instead of all interfaces (defaults to false)
- headers: a dictionary of headers to be added to all requests (defaults to empty)

Domain Configuration
====================

Each domain in "allowed_domains" can have the following configuration:
- headers_override: domain-specific headers that override the global headers

Example config.json:
{
  "key": "0b304a3743f3d4a679ec0f82b827fbf29539da96",
  "allowed_domains": {
    "api.domain.com": {
      "sequential": false,
      "headers_override": {
        "Accept": "application/json"
      }
    }
  },
  "allowed_origins": [
    "https://yourdomain.com"
  ],
  "port": 8080,
  "bind_localhost_only": false,
  "headers": {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0"
  }
}

Usage
=====

Start the proxy by running:

    python3 session-cors-proxy.py

The proxy can be used with a path-based syntax:
http://localhost:8080/api.domain.com/some/path?key=your-key
forwards to api.domain.com/some/path.

(Replace 8080 with your configured port if different)

Cookie Management
=================

The proxy automatically stores all the cookies for the allowed domains,
and reuses and updates them for subsequent requests. It also saves the cookies in the file system,
so that they can be reused even if the proxy is restarted.

The cookies are saved in the file system in the same directory as the proxy script,
in files named cookies.domain.json.

If necessary, an initial value for the cookies and their domains can be obtained by accessing the API with a normal browser,
and then inspecting the stored cookies or using the network tab of the developer tools to intercept the request.
These initial values can be manually filled in the cookies.domain.json file before the first request by the proxy.

Origin Control
==============

The proxy supports origin-based access control through the "allowed_origins" configuration.
This controls which origins are allowed to make CORS requests to the proxy:

- Set to ["*"] to allow all origins (default behavior if not specified)
- Set to specific origins like ["https://yourdomain.com", "http://localhost:3000"] to restrict access
- Set to empty to allow only same-origin requests (no Origin header)
- Requests without an Origin header (same-origin requests or direct navigation) are always allowed
- CORS preflight requests (OPTIONS) are also subject to origin validation

Nginx configuration
===================

If you are running the proxy on the same server than a website, configuring nginx as a reverse proxy has
multiple benefits:

  * it allows to use the proxy on a standard port (80 or 443) that isn't blocked by external firewalls
  * it allows a more explicit and simple usage with a URL prefix instead of a port number
    (https://yourdomain.com/proxy/api.domain.com/some/path?key=your-key instead of http://yourdomain.com:8080/api.domain.com/some/path?key=your-key)
  * it allows to use the proxy with https, and benefit from an existing https configuration
  * it allows to benefit from the server's logging and monitoring (eg fail2ban)
  * hiding the proxy behind a standard URL prefix makes it more difficult to guess than an open port,
    reducing the risk of abuse from bots and scanners (for this to work, you need to set "bind_localhost_only": true in your config.json)

You simply have use the following nginx configuration (inside the server block) :

location /proxy/ {
        proxy_pass http://127.0.0.1:8080/;
        proxy_set_header Host $host;
    }

(Replace 8080 with your configured port if different)
