"""
honeypot.py — Deceptive endpoints designed to lure and log attackers.

CONCEPT — Why Realistic Responses?
────────────────────────────────────
A honeypot that just returns 404 to every fake route is quickly identified and
skipped by sophisticated scanners.  Instead we want to:

  1. Return plausible-looking responses that keep the attacker engaged.
  2. Never actually reveal real data (everything is fabricated).
  3. Return HTTP 200 so automated scanners mark the route as "interesting"
     and probe it further — giving us MORE telemetry, not less.

The middleware (interceptor.py) does the actual logging/analysis.  These route
handlers just need to return convincing fake content.

Routes we expose:
  /wp-admin              → WordPress admin login page redirect
  /.env                  → Fake environment file (text/plain)
  /.git/config           → Fake git config (text/plain)
  /api/v1/admin/config   → Fake JSON API config dump
  /admin                 → Fake admin JSON
  /phpinfo.php           → Fake PHP info response
  /config.php            → Fake PHP config (empty response, like a real misconfigured site)
  /backup.zip            → 403 Forbidden (teasing the attacker)
  /server-status         → Fake Apache mod_status page
  /api/v1/users          → Fake user list JSON
  /api/v1/login          → Fake login endpoint (accepts any credentials)
"""

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response, HTMLResponse

router = APIRouter(tags=["🍯 Honeypot"])


# ── /wp-admin ─────────────────────────────────────────────────────────────────
@router.get("/wp-admin", summary="[Honeypot] WordPress admin")
@router.post("/wp-admin", summary="[Honeypot] WordPress admin")
async def wp_admin(request: Request):
    """Mimics the WordPress admin redirect before login."""
    html = """<!DOCTYPE html>
<html><head><title>Log In &lsaquo; WordPress &mdash; WordPress</title></head>
<body>
<div id="login">
  <h1><a href="#">WordPress</a></h1>
  <form method="post" action="/wp-login.php">
    <label for="user_login">Username or Email Address</label>
    <input type="text" name="log" id="user_login" />
    <label for="user_pass">Password</label>
    <input type="password" name="pwd" id="user_pass" />
    <input type="submit" value="Log In" />
    <input type="hidden" name="redirect_to" value="/wp-admin/" />
  </form>
</div>
</body></html>"""
    return HTMLResponse(content=html)


# ── /.env ─────────────────────────────────────────────────────────────────────
@router.get("/.env", summary="[Honeypot] Environment file")
async def env_file(request: Request):
    """Mimics a leaked .env file — a VERY common scanner target."""
    fake_env = """APP_NAME=MyApp
APP_ENV=production
APP_KEY=base64:kXr9Zp2Vq8Nm4Lh7Jw1Fc6Yt3Bs5Oe0Pu=
APP_DEBUG=false
APP_URL=http://localhost

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=myapp_prod
DB_USERNAME=myapp_user
DB_PASSWORD=Sup3rS3cr3tP@ssw0rd!

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1

MAIL_DRIVER=smtp
MAIL_HOST=smtp.mailtrap.io
REDIS_HOST=127.0.0.1
REDIS_PASSWORD=null
REDIS_PORT=6379
"""
    return PlainTextResponse(content=fake_env)


# ── /.git/config ──────────────────────────────────────────────────────────────
@router.get("/.git/config", summary="[Honeypot] Git config")
async def git_config(request: Request):
    """Mimics an exposed .git/config — attackers use this to clone repositories."""
    fake_config = """[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote "origin"]
\turl = https://github.com/mycompany/myapp-private.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
"""
    return PlainTextResponse(content=fake_config)


# ── /api/v1/admin/config ──────────────────────────────────────────────────────
@router.get("/api/v1/admin/config", summary="[Honeypot] Admin config API")
async def admin_config(request: Request):
    """Fake admin configuration endpoint."""
    return JSONResponse({
        "database": {
            "host": "db-prod-01.internal",
            "port": 5432,
            "name": "myapp_production",
            "user": "api_user",
        },
        "cache": {"backend": "redis", "host": "redis-01.internal", "port": 6379},
        "feature_flags": {"new_dashboard": True, "beta_api": False},
        "maintenance_mode": False,
        "version": "3.14.1",
    })


# ── /admin ────────────────────────────────────────────────────────────────────
@router.get("/admin", summary="[Honeypot] Generic admin")
@router.post("/admin", summary="[Honeypot] Generic admin")
async def admin_panel(request: Request):
    return JSONResponse({"status": "ok", "authenticated": False, "redirect": "/admin/login"})


# ── /phpinfo.php ──────────────────────────────────────────────────────────────
@router.get("/phpinfo.php", summary="[Honeypot] PHP info")
async def phpinfo(request: Request):
    """Minimal fake phpinfo page — real phpinfo exposes server internals."""
    html = """<!DOCTYPE html><html><head><title>phpinfo()</title></head>
<body>
<table><tr class="h"><td><a href="https://www.php.net/">PHP Version 8.2.10</a></td></tr>
<tr><td>System</td><td>Linux web-prod-01 5.15.0-1033-aws #37-Ubuntu SMP</td></tr>
<tr><td>Build Date</td><td>Sep 26 2023 09:09:05</td></tr>
<tr><td>Server API</td><td>FPM/FastCGI</td></tr>
<tr><td>document_root</td><td>/var/www/html</td></tr>
</table>
</body></html>"""
    return HTMLResponse(content=html)


# ── /config.php ───────────────────────────────────────────────────────────────
@router.get("/config.php", summary="[Honeypot] PHP config file")
async def config_php(request: Request):
    """A misconfigured server would return empty body when PHP isn't executed."""
    return Response(content=b"", media_type="text/html")


# ── /backup.zip ───────────────────────────────────────────────────────────────
@router.get("/backup.zip", summary="[Honeypot] Backup archive")
async def backup_zip(request: Request):
    """Return 403 — teases the attacker into believing the file exists."""
    return JSONResponse(
        {"error": "Access denied", "code": 403},
        status_code=403,
    )


# ── /server-status ────────────────────────────────────────────────────────────
@router.get("/server-status", summary="[Honeypot] Apache mod_status")
async def server_status(request: Request):
    html = """<!DOCTYPE html><html>
<head><title>Apache Status</title></head><body>
<h1>Apache Server Status for localhost</h1>
<dl><dt>Server Version: Apache/2.4.57 (Ubuntu)</dt>
<dt>Server MPM: event</dt>
<dt>Current Time: Monday, 01-Jun-2026 00:00:00 UTC</dt>
<dt>Restart Time: Sunday, 31-May-2026 12:00:00 UTC</dt>
<dt>Parent Server Config. Generation: 1</dt>
<dt>Server uptime: 12 hours 0 minutes 0 seconds</dt>
<dt>Total accesses: 4821 - Total Traffic: 38 MB</dt>
</dl>
</body></html>"""
    return HTMLResponse(content=html)


# ── /api/v1/users ─────────────────────────────────────────────────────────────
@router.get("/api/v1/users", summary="[Honeypot] User list API")
async def user_list(request: Request):
    """Fake paginated user list — looks like a misconfigured REST API."""
    return JSONResponse({
        "page": 1,
        "total": 3,
        "users": [
            {"id": 1, "username": "admin", "email": "admin@example.com", "role": "superadmin"},
            {"id": 2, "username": "jsmith", "email": "j.smith@example.com", "role": "editor"},
            {"id": 3, "username": "deploy", "email": "deploy@example.com", "role": "service"},
        ],
    })


# ── /api/v1/login ─────────────────────────────────────────────────────────────
@router.post("/api/v1/login", summary="[Honeypot] Login endpoint")
async def fake_login(request: Request):
    """
    Accepts any credentials and returns a fake JWT.
    This keeps credential-stuffing bots engaged and logging more data.
    """
    fake_token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    return JSONResponse({
        "access_token": fake_token,
        "token_type": "bearer",
        "expires_in": 3600,
    })
