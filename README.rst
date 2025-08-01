CORS Proxy
==========

A Python CORS proxy with session-persistent cookies, allowing access to APIs that require
ongoing authentication or stateful browsing.

Configuration
=============

The proxy uses a JSON configuration file (config.json) that contains:
- Key for proxy authentication
- List of allowed target domains
- Port number for the proxy server (defaults to 8080 if not specified)

Example config.json:
{
  "key": "0b304a3743f3d4a679ec0f82b827fbf29539da96",
  "allowed_domains": [
    "api.domain.com"
  ],
  "port": 8080
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

Nginx configuration
===================

If you are running the proxy on the same server than a website,
and want to use the proxy on a standard port or benefit from an existing https configuration,
you can use the following nginx configuration :

location /proxy/ {
        proxy_pass http://127.0.0.1:8080/;
        proxy_set_header Host $host;
    }

(Replace 8080 with your configured port if different)

and use it with https://yourdomain.com/proxy/api.domain.com/some/path?key=your-key