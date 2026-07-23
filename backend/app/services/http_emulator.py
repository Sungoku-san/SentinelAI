import asyncio
from fastapi import FastAPI, Request, Response, Form, UploadFile, File
from fastapi.responses import HTMLResponse, PlainTextResponse
import uvicorn
from backend.app.config.settings import settings
from backend.app.services.honeypot_engine import honeypot_engine_instance
from backend.app.services.session_recorder import session_recorder_instance
from backend.app.services.packet_analyzer import packet_analyzer_instance
from backend.app.utils.helpers import get_logger

logger = get_logger("http_emulator")

app_http = FastAPI(title="SentinelAI HTTP Honeypot Emulator", docs_url=None, redoc_url=None)

# Middleware to intercept every request and manage sessions
@app_http.middleware("http")
async def intercept_http_traffic(request: Request, call_next):
    # Retrieve client IP
    ip = request.client.host
    port = request.client.port
    path = request.url.path
    method = request.method
    
    # Register packet in analyzer
    packet_analyzer_instance.log_simulated_packet(ip, settings.PORT_HTTP, "TCP")
    
    # Retrieve or create session for HTTP tracking
    # We group HTTP requests from same IP within a brief duration into a single session
    # Let's see if an active HTTP session already exists in the recorder
    session_id = None
    for active_id, sess in list(session_recorder_instance.active_sessions.items()):
        if sess["ip_address"] == ip and sess["protocol"] == "HTTP":
            session_id = active_id
            break
            
    if not session_id:
        session_id = await session_recorder_instance.create_session(ip, settings.PORT_HTTP, "HTTP")
        
    # Log this path request as a scan/traversal
    await session_recorder_instance.log_scan_request(session_id, f"{method} {path}", method)
    
    # Process queries for SQL Injection or Command Injection checks
    query_params = str(request.query_params)
    if query_params:
        await session_recorder_instance.log_command_execution(session_id, f"Query string check: {query_params}", "")
        
    # Adaptive Delay (Tarpitting)
    delay = await honeypot_engine_instance.get_connection_delay(ip)
    if delay > 0:
        await asyncio.sleep(delay)
        
    # Process request
    response = await call_next(request)
    
    # We keep HTTP sessions alive for active recording. We'll close them via a helper or keep them open 
    # and expire them, or close them immediately if it's a one-off request. 
    # For HTTP, we can close the session after a short timer or close immediately if we want to 
    # commit to DB. Let's close immediately so the dashboard updates in real-time for HTTP scanners!
    await session_recorder_instance.close_session(session_id)
    
    return response

# Vulnerable endpoints and default pages
@app_http.get("/", response_class=HTMLResponse)
async def homepage():
    return """
    <html>
    <head><title>IIS Windows Server</title>
    <style>body { font-family: Arial; margin: 40px; background-color: #f0f0f0; }</style>
    </head>
    <body>
    <div style="background: white; padding: 30px; border: 1px solid #ccc; max-width: 600px; margin: auto;">
        <h2>Internet Information Services (IIS)</h2>
        <p>Welcome to the IIS default server landing page. If you are the administrator, you can configure your website details in the configuration files.</p>
        <hr>
        <p style="font-size: 11px; color: #666;">Server Version: IIS 10.0 on Windows Server 2019</p>
    </div>
    </body>
    </html>
    """

@app_http.get("/wp-login.php", response_class=HTMLResponse)
@app_http.get("/wp-admin", response_class=HTMLResponse)
async def wordpress_login():
    return """
    <html>
    <head><title>Log In &lsaquo; WordPress</title>
    <style>body { background: #f1f1f1; font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; }</style>
    </head>
    <body>
    <form action="/wp-login.php" method="POST" style="background: white; padding: 24px; width: 320px; border: 1px solid #ccd0d4; box-shadow: 0 1px 3px rgba(0,0,0,.04);">
        <h2 style="text-align: center; margin-bottom: 20px; color: #23282d;">WordPress</h2>
        <label>Username or Email Address<br>
        <input type="text" name="log" style="width: 100%; padding: 8px; margin: 5px 0 15px; border: 1px solid #8c8f94;"></label>
        <label>Password<br>
        <input type="password" name="pwd" style="width: 100%; padding: 8px; margin: 5px 0 15px; border: 1px solid #8c8f94;"></label>
        <input type="submit" value="Log In" style="background: #007cba; border-color: #007cba; color: #fff; padding: 8px 12px; cursor: pointer; width: 100%;">
    </form>
    </body>
    </html>
    """

@app_http.post("/wp-login.php")
async def wordpress_login_post(request: Request, log: str = Form(None), pwd: str = Form(None)):
    ip = request.client.host
    honeypot_engine_instance.register_login_failure(ip)
    
    # We find active session and log credential
    # Because middleware opens and closes the session, we check active sessions (this will be registered during this connection handler execution)
    for active_id, sess in list(session_recorder_instance.active_sessions.items()):
        if sess["ip_address"] == ip and sess["protocol"] == "HTTP":
            await session_recorder_instance.log_credential_attempt(active_id, log or "unknown", pwd or "unknown", success=False)
            break
            
    return HTMLResponse("WordPress Log In: Incorrect password.", status_code=200)

@app_http.get("/phpMyAdmin", response_class=HTMLResponse)
@app_http.get("/phpmyadmin", response_class=HTMLResponse)
async def phpmyadmin_login():
    return """
    <html>
    <head><title>phpMyAdmin</title></head>
    <body style="font-family: sans-serif; background: #ececec; margin: 50px;">
    <div style="width: 450px; margin: auto; background: white; border: 1px solid #aaa; padding: 20px;">
        <h3>phpMyAdmin - Login</h3>
        <form action="/phpmyadmin" method="POST">
            Username: <input type="text" name="pma_username" style="width: 100%; margin: 5px 0;"><br>
            Password: <input type="password" name="pma_password" style="width: 100%; margin: 5px 0;"><br>
            <input type="submit" value="Go" style="margin-top: 10px;">
        </form>
    </div>
    </body>
    </html>
    """

@app_http.post("/phpmyadmin")
@app_http.post("/phpMyAdmin")
async def phpmyadmin_login_post(request: Request, pma_username: str = Form(None), pma_password: str = Form(None)):
    ip = request.client.host
    honeypot_engine_instance.register_login_failure(ip)
    for active_id, sess in list(session_recorder_instance.active_sessions.items()):
        if sess["ip_address"] == ip and sess["protocol"] == "HTTP":
            await session_recorder_instance.log_credential_attempt(active_id, pma_username or "", pma_password or "", success=False)
            break
    return HTMLResponse("phpMyAdmin: Access Denied.", status_code=403)

@app_http.get("/admin", response_class=HTMLResponse)
async def admin_panel():
    return """
    <html>
    <head><title>Admin Control Panel</title></head>
    <body style="background:#222; color:#fff; font-family: monospace; display:flex; justify-content:center; align-items:center; height:100vh;">
    <form action="/admin" method="POST" style="background:#333; padding:30px; border:1px solid #555;">
        <h2>SYSTEM LOG IN</h2>
        Username: <input type="text" name="user" style="background:#444; color:#fff; border:1px solid #555; display:block; margin: 10px 0;"><br>
        Password: <input type="password" name="pass" style="background:#444; color:#fff; border:1px solid #555; display:block; margin: 10px 0;"><br>
        <input type="submit" value="ENTER" style="background:#666; color:#fff; border:none; padding:10px; cursor:pointer;">
    </form>
    </body>
    </html>
    """

@app_http.post("/admin")
async def admin_panel_post(request: Request, user: str = Form(None), pass_val: str = Form(alias="pass", default=None)):
    ip = request.client.host
    honeypot_engine_instance.register_login_failure(ip)
    for active_id, sess in list(session_recorder_instance.active_sessions.items()):
        if sess["ip_address"] == ip and sess["protocol"] == "HTTP":
            await session_recorder_instance.log_credential_attempt(active_id, user or "", pass_val or "", success=False)
            break
    return HTMLResponse("Authentication failed.", status_code=401)

# File upload vulnerability simulator (e.g. mock file upload for web shell / malware)
@app_http.post("/upload")
@app_http.post("/wp-content/uploads")
async def upload_file(request: Request, file: UploadFile = File(...)):
    ip = request.client.host
    content = await file.read()
    
    # Quarantine uploaded web shell / malware
    res = await honeypot_engine_instance.isolate_and_quarantine_file(file.filename, content)
    
    # Find session and log upload details
    for active_id, sess in list(session_recorder_instance.active_sessions.items()):
        if sess["ip_address"] == ip and sess["protocol"] == "HTTP":
            await session_recorder_instance.log_file_upload(
                active_id, res["filename"], res["size"], res["hashes"], res["quarantine_path"]
            )
            break
            
    return {"status": "success", "message": "File uploaded successfully.", "file": file.filename}

# Trap / Decoys (Dynamic content generator)
@app_http.get("/.env", response_class=PlainTextResponse)
@app_http.get("/config.php.bak", response_class=PlainTextResponse)
@app_http.get("/backup.sql", response_class=PlainTextResponse)
@app_http.get("/.git/config", response_class=PlainTextResponse)
@app_http.get("/config.json", response_class=PlainTextResponse)
async def decoy_endpoints(request: Request):
    ip = request.client.host
    honeypot_engine_instance.register_directory_scan(ip)
    
    # Return dynamic realistic honeypot output
    decoy_content = honeypot_engine_instance.generate_dynamic_http_decoy(request.url.path)
    return decoy_content

# Catch-all endpoint for general scanner traps
@app_http.get("/{path:path}", response_class=HTMLResponse)
async def catch_all(request: Request, path: str):
    ip = request.client.host
    # Increment scan count if they hits random paths (enumeration)
    if any(ext in path for ext in (".php", ".asp", ".jsp", ".xml", ".txt", ".git", ".zip", ".tar")):
        honeypot_engine_instance.register_directory_scan(ip)
        
    # Standard 404 response or dynamic listing if depth is triggered
    profile = honeypot_engine_instance.get_profile(ip)
    if profile["directories_scanned"] >= 3:
        # Attacker is scanning. We adapt: serve a fake index page containing dynamic trap links to keep them busy!
        decoy_content = honeypot_engine_instance.generate_dynamic_http_decoy(path)
        return HTMLResponse(content=decoy_content, status_code=200)
        
    return HTMLResponse(
        content=f"<html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1><p>The requested URL /{path} was not found on this server.</p></body></html>",
        status_code=404
    )

class HTTPEmulator:
    def __init__(self):
        self.server = None
        self.task = None

    async def start(self):
        """Starts uvicorn on settings.PORT_HTTP."""
        config = uvicorn.Config(app=app_http, host="0.0.0.0", port=settings.PORT_HTTP, log_level="warning")
        self.server = uvicorn.Server(config)
        
        # Run server in asyncio loop task
        self.task = asyncio.create_task(self.server.serve())
        logger.info(f"HTTP Honeypot Emulator listening on port {settings.PORT_HTTP}...")

    async def stop(self):
        """Stops uvicorn server."""
        if self.server:
            self.server.should_exit = True
            await self.server.shutdown()
            logger.info("HTTP Honeypot Emulator stopped.")

http_emulator_instance = HTTPEmulator()
