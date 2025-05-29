import logging
import os
import json
import asyncio
import http.server
import urllib.parse
import webbrowser
import aiohttp
import random
import time
import requests
import threading
import uuid
import socketserver
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse, urlencode
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QListWidget, QStackedWidget, QMessageBox, QComboBox, QCompleter,
    QLineEdit, QFormLayout, QDialog, QCheckBox, QInputDialog, QFileDialog
)
from PyQt6.QtCore import Qt, QSortFilterProxyModel, PYQT_VERSION_STR, QThread, pyqtSignal, QTimer, QEvent
from PyQt6.QtGui import QFont
import twitchio
from twitchio.ext import commands
import sys
import ctypes
from threading import Event
from ctypes import wintypes
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from twitchio import errors

# Import obsws-python for OBS WebSocket 5
try:
    import obsws_python as obs  # type: ignore
except ImportError as e:
    logging.getLogger('squawkbot').error(f"Failed to import obsws_python: {e}, arrgh!")
    raise

# Constants
SAVE_PATH = os.path.expanduser(os.path.join("~", ".squawkbot"))
CONFIG_FILE = os.path.join(SAVE_PATH, "squawkbot_config.json")
CLIENT_ID = ""
CLIENT_SECRET = ""
REDIRECT_URI = "http://localhost:3000"
TYRIAN_PURPLE = "#66023C"
GOLD = "#FFD700"
WEATHERED_PARCHMENT = "#EAD9B5"
DARK_PARCHMENT = "#D2B48C"
OAUTH_TIMEOUT = 60  # Timeout in seconds for OAuth response
DEFAULT_OBS_IP = "localhost"
DEFAULT_OBS_PORT = "4455"

# Initialize logger
logger = logging.getLogger('squawkbot')
logger.setLevel(logging.INFO)
os.makedirs(SAVE_PATH, exist_ok=True)

# File handler for logging to file
file_handler = logging.FileHandler(os.path.join(SAVE_PATH, "squawkbot.log"), encoding='utf-8', mode='w')
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)

# Console handler for logging to terminal
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(console_handler)

logger.debug("SquawkBot.py module loaded, arrgh!")
logger.debug(f"PyQt6 version: {PYQT_VERSION_STR}, arrgh!")

# Windows API setup for font enumeration
gdi32 = ctypes.WinDLL('gdi32.dll')
user32 = ctypes.WinDLL('user32.dll')

def refresh_twitch_token(refresh_token):
    """Refresh the access token using the refresh token."""
    logger.debug(f"Refreshing token with refresh_token: {refresh_token[:5]}..., arrgh!")
    try:
        token_url = "https://id.twitch.tv/oauth2/token"
        params = {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token"
        }
        response = requests.post(token_url, data=params, timeout=10)
        logger.debug(f"Token refresh response status: {response.status_code}, arrgh!")
        logger.debug(f"Token refresh response body: {response.text}, arrgh!")
        if response.status_code == 200:
            data = response.json()
            access_token = data.get("access_token")
            expires_in = data.get("expires_in", 0)
            new_refresh_token = data.get("refresh_token")
            if access_token:
                logger.debug(f"Successfully refreshed token: {access_token[:5]}..., expires_in={expires_in}, new_refresh_token={new_refresh_token[:5]}..., arrgh!")
                return access_token, expires_in, new_refresh_token, None
            logger.error("No access token in refresh response, arrgh!")
            file_handler.flush()
            console_handler.flush()
            return None, 0, None, "No access token received in refresh response."
        logger.error(f"Token refresh failed: {response.status_code} {response.text}, arrgh!")
        file_handler.flush()
        console_handler.flush()
        return None, 0, None, f"Token refresh failed: {response.status_code} {response.text}"
    except requests.RequestException as e:
        logger.error(f"Token refresh request failed: {e}, arrgh!", exc_info=True)
        file_handler.flush()
        console_handler.flush()
        return None, 0, None, f"Token refresh request failed: {str(e)}"
    finally:
        logger.debug("Exiting refresh_twitch_token, arrgh!")

class LOGFONTW(ctypes.Structure):
    _fields_ = [
        ("lfHeight", wintypes.LONG),
        ("lfWidth", wintypes.LONG),
        ("lfEscapement", wintypes.LONG),
        ("lfOrientation", wintypes.LONG),
        ("lfWeight", wintypes.LONG),
        ("lfItalic", wintypes.BYTE),
        ("lfUnderline", wintypes.BYTE),
        ("lfStrikeOut", wintypes.BYTE),
        ("lfCharSet", wintypes.BYTE),
        ("lfOutPrecision", wintypes.BYTE),
        ("lfClipPrecision", wintypes.BYTE),
        ("lfQuality", wintypes.BYTE),
        ("lfPitchAndFamily", wintypes.BYTE),
        ("lfFaceName", wintypes.WCHAR * 32),
    ]

class ENUMLOGFONTEXW(ctypes.Structure):
    _fields_ = [
        ("elfLogFont", LOGFONTW),
        ("elfFullName", wintypes.WCHAR * 64),
        ("elfStyle", wintypes.WCHAR * 32),
        ("elfScript", wintypes.WCHAR * 32),
    ]

FONTENUMPROCW = ctypes.WINFUNCTYPE(
    ctypes.c_int,
    ctypes.POINTER(ENUMLOGFONTEXW),
    ctypes.c_void_p,
    wintypes.DWORD,
    wintypes.LPARAM
)

# LOADS SYSTEM FONTS
def get_system_fonts():
    """Retrieve all system fonts using the Windows API."""
    logger.debug("Entering get_system_fonts, arrgh!")
    fonts = set()

    @FONTENUMPROCW
    def font_enum_callback(logfont, textmetric, font_type, lparam):
        font_name = logfont.contents.elfLogFont.lfFaceName
        if font_name and font_name.strip():
            fonts.add(font_name)
        return 1

    try:
        hdc = user32.GetDC(None)
        if not hdc:
            logger.error("Failed to get device context, arrgh!")
            file_handler.flush()
            console_handler.flush()
            raise Exception("Failed to get device context")

        logfont = LOGFONTW()
        logfont.lfCharSet = 1  # DEFAULT_CHARSET
        logfont.lfFaceName = ""

        gdi32.EnumFontFamiliesExW(
            hdc,
            ctypes.byref(logfont),
            font_enum_callback,
            0,
            0
        )

        user32.ReleaseDC(None, hdc)

        valid_fonts = sorted(list(fonts))
        logger.debug(f"Loaded {len(valid_fonts)} system fonts via Windows API, arrgh!")
        return valid_fonts
    except Exception as e:
        logger.error(f"Failed to enumerate system fonts: {e}, arrgh!", exc_info=True)
        file_handler.flush()
        console_handler.flush()
        return ["Arial", "Times New Roman", "Courier New"]
    finally:
        logger.debug("Exiting get_system_fonts, arrgh!")

# TWITCH DUAL OAUTH FLOW
def validate_twitch_token(token):
    logger.debug(f"Enterin’ validate_twitch_token with token: {token[:10]}..., arrgh!")
    try:
        headers = {"Authorization": f"OAuth {token}"}
        for attempt in range(3):
            try:
                response = requests.get("https://id.twitch.tv/oauth2/validate", headers=headers, timeout=10)
                status = response.status_code
                body = response.json()
                logger.debug(f"Token validation response status: {status}, arrgh!")
                logger.debug(f"Token validation response body: {body}, arrgh!")
                
                if status != 200:
                    logger.error(f"Token validation failed with status {status}: {body}, arrgh!")
                    return False, f"HTTP {status}: {body.get('message', 'Unknown error')}", 0
                
                username = body.get("login", "")
                scopes = body.get("scopes", [])
                expires_in = body.get("expires_in", 0)
                logger.debug(f"Token scopes: {scopes}, expires_in: {expires_in}, arrgh!")
                
                if not username:
                    logger.error("No username found in token validation response, arrgh!")
                    return False, "No username in response", 0
                
                logger.debug(f"Twitch token is valid for user {username}, arrgh!")
                return True, username, expires_in
            except requests.RequestException as e:
                logger.warning(f"Network error in validate_twitch_token (attempt {attempt + 1}): {e}, arrgh!")
                if attempt < 2:
                    time.sleep(2)  # Wait before retry
                    continue
                return False, f"Network error: {str(e)}", 0
    except Exception as e:
        logger.error(f"Unexpected error in validate_twitch_token: {e}, arrgh!", exc_info=True)
        return False, f"Unexpected error: {str(e)}", 0
    finally:
        logger.debug("Exitin’ validate_twitch_token, arrgh!")

def exchange_code_for_token(code):
    """Exchange the authorization code for an access token using the Client Secret."""
    logger.debug(f"Exchanging authorization code {code[:5]}... for access token, arrgh!")
    try:
        token_url = "https://id.twitch.tv/oauth2/token"
        params = {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": REDIRECT_URI
        }
        response = requests.post(token_url, data=params, timeout=10)
        logger.debug(f"Token exchange response status: {response.status_code}, arrgh!")
        logger.debug(f"Token exchange response body: {response.text}, arrgh!")
        if response.status_code == 200:
            data = response.json()
            access_token = data.get("access_token")
            expires_in = data.get("expires_in", 0)
            refresh_token = data.get("refresh_token")  # Extract refresh_token
            logger.debug(f"Raw expires_in from Twitch: {expires_in} seconds, arrgh!")
            if access_token:
                logger.debug(f"Successfully exchanged code for access token: {access_token[:5]}..., expires_in={expires_in}, refresh_token={refresh_token[:5]}..., arrgh!")
                return access_token, None, expires_in, refresh_token  # Return refresh_token
            logger.error("No access token in token response, arrgh!")
            file_handler.flush()
            console_handler.flush()
            return None, "No access token received in token response.", 0, None
        logger.error(f"Token exchange failed: {response.status_code} {response.text}, arrgh!")
        file_handler.flush()
        console_handler.flush()
        return None, f"Token exchange failed: {response.status_code} {response.text}", 0, None
    except requests.RequestException as e:
        logger.error(f"Token exchange request failed: {e}, arrgh!", exc_info=True)
        file_handler.flush()
        console_handler.flush()
        return None, f"Token exchange request failed: {str(e)}", 0, None
    finally:
        logger.debug("Exiting exchange_code_for_token, arrgh!")

class OAuthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            parsed_url = urlparse(self.path)
            query_params = parse_qs(parsed_url.query)
            
            # Log the full URL for debugging
            full_url = f"http://{self.headers['Host']}{self.path}"
            logger.debug(f"Received redirect URL: {full_url}, arrgh!")
            logger.debug(f"Query parameters: {query_params}, arrgh!")
            
            if parsed_url.path == "/":
                if "error" in query_params:
                    error = query_params.get("error", ["Unknown error"])[0]
                    error_description = query_params.get("error_description", ["No description provided"])[0]
                    error_message = f"Login Failed! Error: {error} - {error_description}"
                    logger.error(f"OAuth error: {error_message}, arrgh!")
                    file_handler.flush()
                    console_handler.flush()
                    self.server.error_message = error_message
                    self.send_response(400)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(f"<html><body><h1>{error_message}</h1></body></html>".encode())
                else:
                    code = query_params.get("code", [None])[0]
                    state = query_params.get("state", [None])[0]
                    
                    if state and state != self.server.state:
                        error_message = "Login Failed! State mismatch in OAuth response."
                        logger.error(error_message)
                        file_handler.flush()
                        console_handler.flush()
                        self.server.error_message = error_message
                        self.send_response(400)
                        self.send_header("Content-type", "text/html")
                        self.end_headers()
                        self.wfile.write(f"<html><body><h1>{error_message}</h1></body></html>".encode())
                        return
                    
                    if code:
                        access_token, error_message, expires_in, refresh_token = exchange_code_for_token(code)
                        if access_token:
                            logger.debug(f"Setting server access token: {access_token[:5]}..., expires_in={expires_in}, refresh_token={refresh_token[:5]}..., arrgh!")
                            self.server.access_token = access_token
                            self.server.expires_in = expires_in
                            self.server.refresh_token = refresh_token
                            self.send_response(200)
                            self.send_header("Content-type", "text/html")
                            self.end_headers()
                            self.wfile.write(b"<html><body><h1>Login Successful! You can close this window.</h1></body></html>")
                        else:
                            logger.error(error_message)
                            file_handler.flush()
                            console_handler.flush()
                            self.server.error_message = error_message
                            self.send_response(400)
                            self.send_header("Content-type", "text/html")
                            self.end_headers()
                            self.wfile.write(f"<html><body><h1>{error_message}</h1><p>Check the log at ~/.squawkbot/squawkbot.log for more details.</p></body></html>".encode())
                    else:
                        error_message = "Login Failed! No authorization code received. Please ensure you authorized the application."
                        logger.error(error_message)
                        file_handler.flush()
                        console_handler.flush()
                        self.server.error_message = error_message
                        self.send_response(400)
                        self.send_header("Content-type", "text/html")
                        self.end_headers()
                        self.wfile.write(f"<html><body><h1>{error_message}</h1><p>Check the log at ~/.squawkbot/squawkbot.log for more details.</p></body></html>".encode())
            else:
                error_message = f"Invalid path: {parsed_url.path}. Expected /. Please ensure the redirect URI in Twitch Developer Console is set to http://localhost:3000."
                logger.error(error_message)
                file_handler.flush()
                console_handler.flush()
                self.server.error_message = error_message
                self.send_response(404)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(f"<html><body><h1>{error_message}</h1></body></html>".encode())
        except Exception as e:
            error_message = f"Unexpected error during OAuth handling: {str(e)}"
            logger.error(error_message, exc_info=True)
            file_handler.flush()
            console_handler.flush()
            self.server.error_message = error_message
            self.send_response(500)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(f"<html><body><h1>{error_message}</h1><p>Check the log at ~/.squawkbot/squawkbot.log for more details.</p></body></html>".encode())

class TimeoutHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    timeout = OAUTH_TIMEOUT  # Set the timeout for the server

    def __init__(self, server_address, RequestHandlerClass, state):
        super().__init__(server_address, RequestHandlerClass)
        self.state = state
        self.access_token = None
        self.expires_in = 0
        self.refresh_token = None  # Add refresh_token field
        self.error_message = None
        self.timed_out = False
        self.request_processed = Event()

    def server_bind(self):
        super().server_bind()
        self.socket.settimeout(self.timeout)

    def handle_timeout(self):
        self.timed_out = True
        logger.debug("OAuth server timed out waiting for response, arrgh!")
        self.server_close()

    def finish_request(self, request, client_address):
        """Override to signal when the request is fully processed."""
        super().finish_request(request, client_address)
        self.request_processed.set()

def run_oauth_server(state):
    """Run a local server to capture OAuth redirect with a timeout."""
    try:
        server = TimeoutHTTPServer(("localhost", 3000), OAuthHandler, state)
        logger.debug("Starting OAuth server with timeout, arrgh!")

        server_thread = threading.Thread(target=server.handle_request)
        server_thread.start()
        server.request_processed.wait(timeout=OAUTH_TIMEOUT)

        if not server.request_processed.is_set():
            logger.debug("OAuth server did not process request within timeout, shutting down, arrgh!")
            server.timed_out = True
            server.server_close()
            server_thread.join()
            error_message = "Login Failed! OAuth process timed out. Did you close the browser or fail to authorize?"
            logger.error(error_message)
            file_handler.flush()
            console_handler.flush()
            return None, error_message, 0, None

        logger.debug(f"Server state after request: access_token={server.access_token[:5] if server.access_token else None}..., expires_in={server.expires_in}, refresh_token={server.refresh_token[:5] if server.refresh_token else None}..., error_message={server.error_message}, arrgh!")

        server_thread.join()

        if server.timed_out:
            error_message = "Login Failed! OAuth process timed out. Did you close the browser or fail to authorize?"
            logger.error(error_message)
            file_handler.flush()
            console_handler.flush()
            return None, error_message, 0, None

        return server.access_token, server.error_message, server.expires_in, server.refresh_token
    except Exception as e:
        logger.error(f"Failed to run OAuth server: {str(e)}, arrgh!", exc_info=True)
        file_handler.flush()
        console_handler.flush()
        return None, f"Failed to run OAuth server: {str(e)}", 0, None

def start_oauth_flow(account_type, scope):
    """Initiate OAuth flow for the specified account type using authorization code flow."""
    logger.debug(f"Starting OAuth flow for {account_type}, arrgh!")
    
    try:
        state = str(uuid.uuid4())
        params = {
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "scope": scope,
            "state": state,
            "force_verify": "true"
        }
        auth_url = f"https://id.twitch.tv/oauth2/authorize?{urlencode(params)}"
        
        logger.debug(f"Opening authorization URL: {auth_url}, arrgh!")
        webbrowser.open(auth_url)
        
        token, error_message, expires_in, refresh_token = run_oauth_server(state)
        
        logger.debug(f"run_oauth_server returned: token={token[:5] if token else None}..., expires_in={expires_in}, refresh_token={refresh_token[:5] if refresh_token else None}..., error_message={error_message}, arrgh!")
        
        if error_message:
            logger.error(f"OAuth flow failed: {error_message}, arrgh!")
            file_handler.flush()
            console_handler.flush()
            return None, None, None, None, error_message
        
        if token:
            valid, username_or_error, _ = validate_twitch_token(token)
            logger.debug(f"validate_twitch_token result: valid={valid}, username_or_error={username_or_error}, arrgh!")
            if valid:
                username = username_or_error
                logger.info(f"Successfully authenticated {account_type} as {username}, expires_in={expires_in}, arrgh!")
                return token, username, expires_in, refresh_token, None
            else:
                error_message = f"Invalid token received after authentication: {username_or_error}"
                logger.error(error_message)
                file_handler.flush()
                console_handler.flush()
                return None, None, None, None, error_message
        else:
            error_message = "No token received after authentication. Check logs for details."
            logger.error(error_message)
            file_handler.flush()
            console_handler.flush()
            return None, None, None, None, error_message
    except Exception as e:
        error_message = f"Unexpected error in OAuth flow: {str(e)}"
        logger.error(error_message, exc_info=True)
        file_handler.flush()
        console_handler.flush()
        return None, None, None, None, error_message

# AUTO CONNECT OBS WEBSOCKET AND WEBSOCKET FUNCTIONALITY 
class OBSClient:
    def __init__(self, gui):
        self.gui = gui
        self.req_client = None  # For sending requests
        self.event_client = None  # For receiving events
        self.connected = False
        self.should_reconnect = False
        self.reconnect_task = None
        logger.debug("OBSClient initialized with WebSocket 5 support, arrgh!")

    def on_connection_opened(self, data):
        logger.info("OBS WebSocket 5 connected, arrgh!")
        self.connected = True
        self.should_reconnect = True
        self.gui.update_obs_status_label()
        self.gui.update_obs_buttons()

    def on_connection_closed(self, data):
        logger.info("OBS WebSocket 5 disconnected, arrgh!")
        self.connected = False
        self.event_client = None
        self.req_client = None
        self.gui.update_obs_status_label()
        self.gui.update_obs_buttons()
        if self.should_reconnect and not self.reconnect_task:
            self.reconnect_task = asyncio.get_event_loop().create_task(self.reconnect())

    def on_error(self, data):
        logger.error(f"OBS WebSocket 5 error: {data}, arrgh!")
        file_handler.flush()
        console_handler.flush()
        self.connected = False
        self.event_client = None
        self.req_client = None
        self.gui.update_obs_status_label()
        self.gui.update_obs_buttons()

    def on_event(self, data):
        """Handle all incoming OBS WebSocket events and dispatch to specific handlers."""
        event_type = getattr(data, 'event', None)
        logger.debug(f"Received OBS event: {event_type}, arrgh!")
        if event_type == "ConnectionOpened":
            self.on_connection_opened(data)
        elif event_type == "ConnectionClosed":
            self.on_connection_closed(data)
        elif event_type == "WebSocketCommunicationError":
            self.on_error(data)
        else:
            logger.debug(f"Unhandled OBS event: {event_type}, arrgh!")

    def refresh_browser(self, source_name):
        """Refresh a browser source in OBS to reload its content."""
        if not self.connected or not self.req_client:
            logger.warning("Cannot refresh browser source, OBS not connected, arrgh!")
            raise Exception("OBS not connected")
        try:
            # Use TriggerMediaInputAction to refresh the browser source
            self.req_client.trigger_media_input_action(source_name, "OBS_WEBSOCKET_MEDIA_INPUT_ACTION_RESTART")
            logger.debug(f"Refreshed browser source {source_name}, arrgh!")
        except Exception as e:
            logger.error(f"Failed to refresh browser source {source_name}: {e}, arrgh!", exc_info=True)
            raise


    def restart_media(self, source_name):
        """Restart a media source to force it to reload its content."""
        try:
            self.req_client.trigger_media_input_action(source_name, "OBS_WEBSOCKET_MEDIA_INPUT_ACTION_RESTART")
            logger.debug(f"Sent restart command to media source {source_name}, arrgh!")
        except Exception as e:
            logger.error(f"Failed to restart media source {source_name}: {e}, arrgh!", exc_info=True)
            raise

    def get_input_settings(self, source_name):
        """Get the current settings of an input source."""
        try:
            response = self.req_client.get_input_settings(source_name)
            settings = response.input_settings
            logger.debug(f"Retrieved settings for source {source_name}: {settings}, arrgh!")
            return settings
        except Exception as e:
            logger.error(f"Failed to get input settings for source {source_name}: {e}, arrgh!", exc_info=True)
            raise

    async def reconnect(self):
        max_attempts = 3
        attempt = 1
        while attempt <= max_attempts and self.should_reconnect:
            logger.debug(f"Attempting to reconnect to OBS (attempt {attempt}/{max_attempts}), arrgh!")
            try:
                await asyncio.sleep(5)
                self.connect(
                    self.gui.obs_config["server_ip"],
                    self.gui.obs_config["server_port"],
                    self.gui.obs_config["server_password"]
                )
                if self.connected:
                    logger.info("Successfully reconnected to OBS, arrgh!")
                    break
            except Exception as e:
                error_msg = str(e).replace(self.gui.obs_config["server_password"], "****") if self.gui.obs_config["server_password"] else str(e)
                logger.error(f"Reconnect attempt {attempt} failed: {error_msg}, arrgh!", exc_info=True)
                file_handler.flush()
                console_handler.flush()
            attempt += 1
        if not self.connected:
            logger.error("Failed to reconnect to OBS after max attempts, arrgh!")
            file_handler.flush()
            console_handler.flush()
        self.reconnect_task = None

    def connect(self, host, port, password):
        logger.debug(f"Connecting to OBS WebSocket 5 at {host}:{port}, arrgh!")
        try:
            self.disconnect()
            self.req_client = obs.ReqClient(host=host, port=int(port), password=password if password else None)
            self.event_client = obs.EventClient(host=host, port=int(port), password=password if password else None)
            self.event_client.callback.register(self.on_event)
            self.req_client.get_version()
            self.connected = True
            logger.debug("OBS WebSocket 5 connection initiated with separate clients, arrgh!")
            self.gui.update_obs_status_label()
            self.gui.update_obs_buttons()
        except Exception as e:
            error_msg = str(e).replace(password, "****") if password else str(e)
            logger.error(f"Failed to connect to OBS WebSocket 5: {error_msg}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            self.connected = False
            self.gui.update_obs_status_label()
            self.gui.update_obs_buttons()
            raise Exception(f"Failed to connect to OBS WebSocket 5: {error_msg}")

    def disconnect(self):
        logger.debug("Disconnecting from OBS WebSocket 5, arrgh!")
        try:
            self.should_reconnect = False
            if self.reconnect_task:
                self.reconnect_task.cancel()
                self.reconnect_task = None

            # Disconnect both clients separately without unregistering callbacks
            if self.event_client:
                self.event_client.disconnect()
                self.event_client = None
            if self.req_client:
                self.req_client.disconnect()
                self.req_client = None

            self.connected = False
            logger.info("Disconnected from OBS WebSocket 5, arrgh!")
            self.gui.update_obs_status_label()
            self.gui.update_obs_buttons()
        except Exception as e:
            logger.error(f"Failed to disconnect from OBS WebSocket 5: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            self.connected = False
            self.gui.update_obs_status_label()
            self.gui.update_obs_buttons()

    def get_scenes(self):
        """Fetch a list of scene names from OBS."""
        if not self.connected or not self.req_client:
            raise Exception("OBS not connected")
        try:
            response = self.req_client.get_scene_list()
            scenes = response.scenes
            return [scene["sceneName"] for scene in scenes]
        except Exception as e:
            logger.error(f"Failed to fetch scenes from OBS: {e}, arrgh!", exc_info=True)
            raise

    def get_current_program_scene(self):
        if not self.connected or not self.req_client:
            logger.warning("Cannot get current program scene, OBS not connected, arrgh!")
            return {"sceneName": ""}
        try:
            response = self.req_client.get_current_program_scene()
            return {"sceneName": response.current_program_scene_name}
        except Exception as e:
            logger.error(f"Failed to get current program scene: {e}, arrgh!", exc_info=True)
            return {"sceneName": ""}

    def get_sources(self, scene_name):
        """Fetch a list of source names for a specific scene."""
        if not self.connected or not self.req_client:
            raise Exception("OBS not connected")
        try:
            response = self.req_client.get_scene_item_list(scene_name)
            scene_items = response.scene_items
            return [item["sourceName"] for item in scene_items]
        except Exception as e:
            logger.error(f"Failed to fetch sources for scene {scene_name}: {e}, arrgh!", exc_info=True)
            raise

    def set_input_settings(self, source_name, settings, overlay=True):
        logger.debug(f"Setting input settings for source {source_name}: {settings}, arrgh!")
        try:
            self.req_client.set_input_settings(source_name, settings, overlay=overlay)
            logger.debug(f"Successfully set input settings for {source_name}, arrgh!")
        except Exception as e:
            logger.error(f"Failed to set input settings for {source_name}: {e}, arrgh!", exc_info=True)
            raise

    def set_source_visibility(self, scene_name, source_name, visible):
        if not self.connected or not self.req_client:
            raise Exception("OBS not connected")
        try:
            # Use get_scene_item_list to fetch all items in the scene
            response = self.req_client.get_scene_item_list(scene_name)
            scene_items = response.scene_items  # This should be a list of scene items
            scene_item_id = None
            for item in scene_items:
                if item["sourceName"] == source_name:
                    scene_item_id = item["sceneItemId"]
                    break
            if scene_item_id is None:
                logger.error(f"No scene item ID for source {source_name} in scene {scene_name}, skippin’ visibility change, arrgh!")
                raise Exception(f"No scene item ID for source {source_name} in scene {scene_name}")
            self.req_client.set_scene_item_enabled(scene_name, scene_item_id, visible)
            logger.debug(f"Set visibility for source {source_name} in scene {scene_name} to {visible}, arrgh!")
        except Exception as e:
            logger.error(f"Failed to set source visibility for {source_name} in {scene_name}: {e}, arrgh!", exc_info=True)
            raise

class SquawkBot(commands.Bot):
    def __init__(self, gui, broadcaster_token, bot_token, broadcaster_username, bot_username, channel, loop=None):
        logger.debug(f"Enterin’ SquawkBot.__init__ with broadcaster={broadcaster_username}, bot={bot_username}, channel={channel}, arrgh!")
        try:
            # Set random seed for varied random choices
            random.seed(int(time.time()))
            # Validate tokens before proceedin’
            bot_valid, bot_result, _ = validate_twitch_token(bot_token.replace("oauth:", ""))
            if not bot_valid:
                logger.error(f"Invalid bot token: {bot_result}, arrgh!")
                raise errors.AuthenticationError("Invalid or unauthorized bot Access Token passed.")

            broadcaster_valid, broadcaster_result, broadcaster_expires_in = validate_twitch_token(broadcaster_token.replace("oauth:", ""))
            if not broadcaster_valid:
                logger.warning(f"Invalid broadcaster token: {broadcaster_result}, tryin’ to refresh, arrgh!")
                refresh_token = gui.broadcaster_config.get("refresh_token")
                if refresh_token:
                    access_token, expires_in, new_refresh_token, error_message = refresh_twitch_token(refresh_token)
                    if access_token:
                        logger.debug(f"Successfully refreshed broadcaster token: {access_token[:5]}..., expires_in={expires_in}, arrgh!")
                        issued_at = int(time.time())
                        gui.broadcaster_config["token"] = f"oauth:{access_token}" if not access_token.startswith("oauth:") else access_token
                        gui.broadcaster_config["issued_at"] = issued_at
                        gui.broadcaster_config["expires_at"] = issued_at + expires_in
                        gui.broadcaster_config["refresh_token"] = new_refresh_token
                        gui._save_config()
                        broadcaster_token = gui.broadcaster_config["token"]
                        broadcaster_valid, broadcaster_result, broadcaster_expires_in = validate_twitch_token(broadcaster_token.replace("oauth:", ""))
                        if not broadcaster_valid:
                            logger.error(f"Refreshed broadcaster token still invalid: {broadcaster_result}, arrgh!")
                            raise errors.AuthenticationError("Refreshed broadcaster Access Token is invalid.")
                    else:
                        logger.error(f"Failed to refresh broadcaster token: {error_message}, arrgh!")
                        raise errors.AuthenticationError(f"Failed to refresh broadcaster token: {error_message}")
                else:
                    logger.error(f"No refresh token available for broadcaster, arrgh!")
                    raise errors.AuthenticationError("Invalid or unauthorized broadcaster Access Token passed.")

            # Reset all WebSocket and connection state
            self._connection = None
            self._ws = None
            self._broadcaster_ws = None
            self._bot_ws = None
            logger.debug("Reset all WebSocket and connection states, arrgh!")

            # Initialize the bot with the provided event loop
            super().__init__(
                token=bot_token,
                prefix="!",
                initial_channels=[channel] if channel else [],
                loop=loop
            )
            self.gui = gui
            self.broadcaster_username = broadcaster_username.lower()
            self.bot_username = bot_username.lower()
            self.channel = channel.lower()
            self.client_id = CLIENT_ID

            # Initialize broadcaster client
            try:
                self.broadcaster_client = twitchio.Client(token=broadcaster_token, loop=loop)
                self.broadcaster_client.event_ready = self.broadcaster_event_ready
                logger.debug(f"Broadcaster client initialized for {broadcaster_username}, arrgh!")
            except Exception as e:
                logger.error(f"Failed to initialize broadcaster client: {e}, arrgh!", exc_info=True)
                raise

            self.brb_clips = []
            self.brb_scene_check_task = None
            self.raid_command_obj = None
            self.bot_token = bot_token
            self.broadcaster_token = broadcaster_token
            self.session_raid_targets = set(self.gui.config.get("raid_settings", {}).get("session_raid_targets", []))
            self.raid_attempts = self.gui.config.get("raid_settings", {}).get("raid_attempts", [])
            self.current_brb_clip = None
            self.current_brb_clip_position = 0
            self.brb_clip_start_time = 0
            self.is_brb_clip_paused = False

            # Register shoutout command
            try:
                command_name = self.gui.shoutout_command_input.text().strip()
                if not command_name.startswith("!"):
                    command_name = f"!{command_name}"
                command_name = command_name.lstrip("!")
                shoutout_command = commands.Command(name=command_name, func=self.shoutout)
                self.add_command(shoutout_command)
                logger.debug(f"Registered shoutout command as '!{command_name}', arrgh!")
            except Exception as e:
                logger.error(f"Failed to register shoutout command: {e}, arrgh!", exc_info=True)
                raise

            # Register raid command
            try:
                self._register_raid_command()
                logger.debug(f"SquawkBot initialized with broadcaster {broadcaster_username} and bot {bot_username}, arrgh!")
            except Exception as e:
                logger.error(f"Failed to register raid command: {e}, arrgh!", exc_info=True)
                raise
        except Exception as e:
            logger.error(f"Failed to initialize SquawkBot: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            raise
        finally:
            logger.debug("Exitin’ SquawkBot.__init__, arrgh!")

    def _register_raid_command(self):
        """Register the dynamic raid command."""
        command_name = self.gui.raid_command_input.text().strip()
        if not command_name.startswith("!"):
            command_name = f"!{command_name}"
        command_name = command_name.lstrip("!")
        if self.raid_command_obj:
            self.remove_command(self.raid_command_obj.name)
        raid_command = commands.Command(name=command_name, func=self.raid)
        self.add_command(raid_command)
        self.raid_command_obj = raid_command
        logger.debug(f"Registered raid command as '!{command_name}', arrgh!")

    def update_settings(self):
        """Update bot settings on the fly when GUI changes, arrgh!"""
        logger.debug("Updating bot settings dynamically, arrgh!")
        # Re-register raid command if it changed
        self._register_raid_command()
        logger.debug("Bot settings updated on the fly, arrgh!")

    async def cleanup(self):
        logger.debug("Cleaning up SquawkBot resources, arrgh!")
        try:
            # Stop the BRB scene check task if it exists
            if self.brb_scene_check_task and not self.brb_scene_check_task.done():
                self.brb_scene_check_task.cancel()
                try:
                    await self.brb_scene_check_task
                except asyncio.CancelledError:
                    logger.debug("BRB scene check task cancelled successfully, arrgh!")
                except Exception as e:
                    logger.warning(f"Failed to cancel BRB scene check task: {e}, arrgh!")
                self.brb_scene_check_task = None

            # Clear WebSocket state
            if hasattr(self, '_ws'):
                self._ws = None
                logger.debug("Cleared WebSocket state (_ws), arrgh!")
            if hasattr(self, '_connection'):
                self._connection = None
                logger.debug("Cleared WebSocket connection state (_connection), arrgh!")
            if hasattr(self, '_broadcaster_ws'):
                self._broadcaster_ws = None
                logger.debug("Cleared broadcaster WebSocket state (_broadcaster_ws), arrgh!")
            if hasattr(self, '_bot_ws'):
                self._bot_ws = None
                logger.debug("Cleared bot WebSocket state (_bot_ws), arrgh!")
            
            # Clear broadcaster client state if it exists
            if hasattr(self, 'broadcaster_client') and self.broadcaster_client:
                self.broadcaster_client._connection = None
                self.broadcaster_client._ws = None
                self.broadcaster_client.loop = None
                logger.debug("Cleared broadcaster client WebSocket and loop state, arrgh!")
                self.broadcaster_client = None
            
            # Reset any cached channels or state
            if hasattr(self, 'connected_channels'):
                self.connected_channels = []
                logger.debug("Cleared connected channels, arrgh!")
            
            # Clear WebSocket thread state if possible
            if hasattr(self, '_ws_thread'):
                self._ws_thread = None
                logger.debug("Cleared WebSocket thread state (_ws_thread), arrgh!")
            if hasattr(self, '_broadcaster_ws_thread'):
                self._broadcaster_ws_thread = None
                logger.debug("Cleared broadcaster WebSocket thread state (_broadcaster_ws_thread), arrgh!")

        except Exception as e:
            logger.error(f"Error during SquawkBot cleanup: {e}, arrgh!", exc_info=True)
        finally:
            logger.debug("SquawkBot cleanup completed, arrgh!")

    async def raid(self, ctx: commands.Context):
        """Handle the raid command like a true pirate, arrgh!"""
        if not self.gui.config["toggles"].get("raids_enabled", True):
            logger.debug("Raids toggle disabled, skippin’ raid, arrgh!")
            return
        logger.debug(f"Enterin’ raid command for user {ctx.author.name}, arrgh!")
        try:
            user = ctx.author
            is_allowed = user.is_mod or user.name.lower() == self.broadcaster_username.lower()
            if not is_allowed:
                await ctx.send(f"Squawk! Only mods or the cap’n can raid, {user.name}, arrgh!")
                return
            current_time = time.time()
            self.raid_attempts = [t for t in self.raid_attempts if current_time - t < 600]
            if len(self.raid_attempts) >= 10:
                await ctx.send(f"Squawk! Too many raids, {user.name}! Wait a few minutes, arrgh!")
                return
            parts = ctx.message.content.split()
            command_name = self.gui.raid_command_input.text().strip()
            if not command_name.startswith("!"):
                command_name = f"!{command_name}"
            raid_targets = [parts[1].strip().lower()] if len(parts) > 1 else self.gui.raid_targets.copy()
            logger.debug(f"Raid targets to check: {raid_targets}, arrgh!")
            if not raid_targets:
                await ctx.send(f"Squawk! No raid targets set, {user.name}, arrgh!")
                return
            raid_targets = [t for t in raid_targets if t not in self.session_raid_targets]
            logger.debug(f"Raid targets after filterin’ session raided: {raid_targets}, arrgh!")
            if not raid_targets:
                await ctx.send(f"Squawk! Already raided all targets this session, {user.name}, arrgh!")
                return
            if self.gui.raid_active:
                logger.debug("Stoppin’ ongoing raid clips, arrgh!")
                try:
                    await self.gui._stop_raid_clips()
                except Exception as e:
                    logger.warning(f"Failed to stop raid clips: {e}, arrgh!", exc_info=True)
            live_targets = []
            for _ in range(3):
                try:
                    live_targets = await self._get_live_targets(raid_targets)
                    if live_targets:
                        break
                    logger.debug(f"No live targets found, retryin’ in 2 seconds, arrgh!")
                    await asyncio.sleep(2)
                except Exception as e:
                    logger.warning(f"Failed to get live targets: {e}, arrgh!", exc_info=True)
                    continue
            logger.debug(f"Live targets found: {live_targets}, arrgh!")
            if not live_targets:
                await ctx.send(f"Squawk! No one on the list is live, arrgh!")
                return
            logger.debug(f"Before shufflin’, live targets: {live_targets}, arrgh!")
            random.shuffle(live_targets)
            logger.debug(f"After shufflin’, live targets: {live_targets}, arrgh!")
            token = self.gui.broadcaster_config["token"].replace("oauth:", "")
            valid, result, _ = validate_twitch_token(token)
            if not valid:
                logger.warning(f"Broadcaster token invalid: {result}, tryin’ to refresh, arrgh!")
                try:
                    success = self.gui.refresh_broadcaster_token()
                    if not success:
                        await ctx.send(f"Squawk! Broadcaster token’s bad, check yer OAuth, arrgh!")
                        return
                except Exception as e:
                    logger.error(f"Failed to refresh broadcaster token: {e}, arrgh!", exc_info=True)
                    await ctx.send(f"Squawk! Failed to refresh token.")
                    return
            target = None
            failed_reasons = []
            while live_targets:
                target = live_targets.pop(0)
                logger.debug(f"Attemptin’ to raid {target}, arrgh!")
                success, reason = await self._initiate_raid(target)
                self.session_raid_targets.add(target)
                self.raid_attempts.append(current_time)
                logger.info(f"Attempted raid on {target} and marked in session, arrgh!")
                if success:
                    break
                else:
                    failed_reasons.append(f"{target}: {reason}")
                    logger.debug(f"Raid failed for {target} with reason: {reason}, tryin’ next target, arrgh!")
                    if not live_targets:
                        logger.warning(f"All raid attempts failed, reasons: {'; '.join(failed_reasons)}, arrgh!")
                        return
                    continue
            self.gui.raid_active = True
            try:
                duration = float(self.gui.raid_clip_duration_input.text() or 60)
            except ValueError:
                duration = 60
            logger.debug(f"Fetchin’ and playin’ clips for {target}, duration {duration}, arrgh!")
            try:
                await self.play_raid_clips(target, duration)
            except Exception as e:
                logger.error(f"Failed to play raid clips: {e}, arrgh!", exc_info=True)
                self.gui.raid_active = False
        except Exception as e:
            logger.error(f"Unexpected error in raid command: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            await ctx.send(f"Squawk! Somethin’ went wrong with the raid, arrgh!")
        finally:
            logger.debug("Exitin’ raid command, arrgh!")

    async def _get_live_targets(self, targets):
            """Check which raid targets are live, with batch lookups, arrgh!"""
            live_targets = []
            headers = {
                "Client-ID": CLIENT_ID,
                "Authorization": f"Bearer {self.bot_token.replace('oauth:', '')}"
            }
            async with aiohttp.ClientSession() as session:
                try:
                    # Batch user ID lookups
                    url = f"https://api.twitch.tv/helix/users?login={'&login='.join(targets)}"
                    async with session.get(url, headers=headers) as user_response:
                        if user_response.status == 200:
                            user_data = await user_response.json()
                            user_ids = {user["login"].lower(): user["id"] for user in user_data.get("data", [])}
                            logger.debug(f"Fetched user IDs: {user_ids}, arrgh!")
                        else:
                            logger.error(f"Failed to fetch user IDs: {user_response.status}, arrgh!")
                            return []
                except Exception as e:
                    logger.error(f"Error fetchin’ user IDs: {e}, arrgh!")
                    return []

                # Check streams and viewer count
                for target in targets:
                    if target.lower() not in user_ids:
                        logger.debug(f"Target {target} not found in user IDs, skippin’, arrgh!")
                        continue
                    url = f"https://api.twitch.tv/helix/streams?user_id={user_ids[target.lower()]}"
                    try:
                        async with session.get(url, headers=headers) as response:
                            if response.status == 200:
                                data = await response.json()
                                if data["data"]:
                                    stream = data["data"][0]
                                    viewer_count = stream.get("viewer_count", 0)
                                    logger.debug(f"Target {target} is live with {viewer_count} viewers, arrgh!")
                                    # Skip targets with fewer than 5 viewers
                                    if viewer_count < 5:
                                        logger.debug(f"Target {target} has too few viewers ({viewer_count}), skippin’, arrgh!")
                                        continue
                                    live_targets.append(target)
                                else:
                                    logger.debug(f"Target {target} is not live, arrgh!")
                            else:
                                logger.error(f"Failed to check live status for {target}: {response.status}, arrgh!")
                    except Exception as e:
                        logger.error(f"Error checkin’ live status for {target}: {e}, arrgh!")
                logger.debug(f"Live targets found: {live_targets}, arrgh!")
            return live_targets

    async def _initiate_raid(self, target):
            """Initiate a Twitch raid, arrgh!"""
            logger.debug(f"Enterin’ _initiate_raid for target {target}, arrgh!")
            try:
                user_id = await self._get_user_id(target)
                logger.debug(f"Got user_id {user_id} for target {target}, arrgh!")
                if not user_id:
                    logger.error(f"No user ID found for {target}, arrgh!")
                    return False, "user_not_found"

                broadcaster_id = await self._get_user_id(self.broadcaster_username)
                logger.debug(f"Got broadcaster_id {broadcaster_id} for {self.broadcaster_username}, arrgh!")
                if not broadcaster_id:
                    logger.error(f"No broadcaster ID found for {self.broadcaster_username}, arrgh!")
                    return False, "broadcaster_not_found"

                headers = {
                    "Client-ID": CLIENT_ID,
                    "Authorization": f"Bearer {self.broadcaster_token.replace('oauth:', '')}",
                    "Content-Type": "application/json"
                }
                data = {
                    "from_broadcaster_id": broadcaster_id,
                    "to_broadcaster_id": user_id
                }
                async with aiohttp.ClientSession() as session:
                    logger.debug(f"Sending raid request for {target}, arrgh!")
                    async with session.post(
                        "https://api.twitch.tv/helix/raids",
                        headers=headers,
                        json=data,
                        timeout=aiohttp.ClientTimeout(total=10)  # 10-second timeout
                    ) as response:
                        logger.debug(f"Raid response status for {target}: {response.status}, arrgh!")
                        if response.status == 200:
                            logger.info(f"Successfully raided {target}, arrgh!")
                            return True, "success"
                        error_text = await response.text()
                        logger.error(f"Raid failed for {target}: {response.status} {error_text}, arrgh!")
                        # Check for specific failure reasons
                        if response.status == 400:
                            # Twitch often returns 400 for reasons like low viewers
                            return False, "low_viewers"
                        elif response.status == 429:
                            return False, "rate_limited"
                        else:
                            return False, f"error_{response.status}"
            except asyncio.TimeoutError:
                logger.error(f"Raid request to {target} timed out after 10 seconds, arrgh!")
                return False, "timeout"
            except Exception as e:
                logger.error(f"Raid initiation error for {target}: {e}, arrgh!", exc_info=True)
                return False, "generic_error"
            finally:
                logger.debug(f"Exitin’ _initiate_raid for target {target}, arrgh!")

    async def _get_user_id(self, username):
        """Get Twitch user ID for a username."""
        headers = {
            "Client-ID": CLIENT_ID,
            "Authorization": f"Bearer {self.bot_token.replace('oauth:', '')}"
        }
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://api.twitch.tv/helix/users?login={username}", headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    user_id = data["data"][0]["id"] if data["data"] else None
                    logger.debug(f"Got user ID {user_id} for {username}, arrgh!")
                    return user_id
                logger.error(f"Failed to get ID for {username}: {response.status}, arrgh!")
                return None

    async def event_raid(self, raid):
        """Handle incoming raids and stop clip playback, arrgh!"""
        logger.info(f"Raid from {raid.user.name} with {raid.viewers} viewers, arrgh!")
        await self.gui._stop_raid_clips()

    async def broadcaster_event_ready(self):
        logger.debug(f"Broadcaster client ready for {self.broadcaster_username}, arrgh!")
        try:
            logger.info(f"Broadcaster client connected as {self.broadcaster_username}, arrgh!")
            broadcaster_status = f"Broadcaster: Logged In as {self.broadcaster_username} (Running)"
            bot_status = f"Bot: Logged In as {self.gui.bot_config['username']}" if self.gui.bot_config["username"] else "Bot: Not Logged In"
            if self.gui.bot and self.gui.bot_thread and self.gui.bot_thread.isRunning():
                bot_status += " (Running)"
            # Check if bot_thread is still available before emitting signal
            if self.gui.bot_thread:
                self.gui.bot_thread.login_status_updated.emit(broadcaster_status, bot_status)
            else:
                logger.warning("BotThread be None, cannot emit login_status_updated signal, arrgh!")
        except Exception as e:
            logger.error(f"Error in broadcaster_event_ready: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            # Check if bot_thread is still available before emitting error signal
            if self.gui.bot_thread:
                self.gui.bot_thread.error_occurred.emit(f"Broadcaster connection issue: {e}, arrgh!")
            else:
                logger.warning("BotThread be None, cannot emit error_occurred signal, arrgh!")

    async def event_ready(self):
        logger.debug(f"Enterin’ event_ready for bot {self.bot_username}, arrgh!")
        try:
            # Check shutdown flag immediately
            if self.gui.is_shutting_down:
                logger.warning("Bot is shuttin’ down, skippin’ event_ready, arrgh!")
                return

            # Check if the event loop is still running
            if not self.loop.is_running():
                logger.error("Event loop is not runnin’ in event_ready, cannot proceed, arrgh!")
                self.status_updated.emit("Bot Status: Crashed due to closed event loop")
                self.error_occurred.emit("Event loop is not runnin’ in event_ready, arrgh!")
                return

            logger.info(f"Bot connected as {self.bot_username}, arrgh!")
            broadcaster_status = f"Broadcaster: Logged In as {self.gui.broadcaster_config['username']}" if self.gui.broadcaster_config["username"] else "Broadcaster: Not Logged In"
            if self.gui.bot and self.gui.bot_thread and self.gui.bot_thread.isRunning():
                broadcaster_status += " (Running)"
            bot_status = f"Bot: Logged In as {self.bot_username} (Running)"
            try:
                self.login_status_updated.emit(broadcaster_status, bot_status)
            except Exception as e:
                logger.warning(f"Failed to emit login status update: {e}, arrgh!", exc_info=True)

            channel_name = self.channel.lstrip("#")
            logger.debug(f"Bot ensurin’ connection to channel {channel_name}, arrgh!")
            
            # Ensure the bot has joined the channel
            if channel_name not in [chan.name for chan in self.connected_channels]:
                logger.debug(f"Channel {channel_name} not in connected channels, joinin’ now, arrgh!")
                try:
                    await self.join_channels([channel_name])
                    await asyncio.sleep(1)
                    logger.debug(f"After join attempt, connected channels: {[chan.name for chan in self.connected_channels]}, arrgh!")
                except Exception as e:
                    logger.error(f"Failed to join channel {channel_name}: {e}, arrgh!", exc_info=True)
                    self.status_updated.emit("Bot Status: Failed to join channel")
                    self.error_occurred.emit(f"Failed to join channel {channel_name}: {e}, arrgh!")
                    return

            # Check shutdown and loop state again after async operation
            if self.gui.is_shutting_down:
                logger.warning("Bot is shuttin’ down after channel join, skippin’ further operations, arrgh!")
                return
            if not self.loop.is_running() or self.loop.is_closed():
                logger.warning("Event loop is not runnin’ or closed after channel join, skippin’ further operations, arrgh!")
                return

            # Retrieve the channel object
            channel = self.get_channel(channel_name)
            logger.debug(f"Channel object retrieved: {channel}, arrgh!")
            if not channel:
                logger.error(f"Failed to get channel {channel_name} even after joinin’, arrgh!")
                file_handler.flush()
                console_handler.flush()
                self.status_updated.emit("Bot Status: Failed to access channel")
                self.error_occurred.emit(f"Failed to access channel {channel_name}, arrgh! Check channel name and bot permissions.")
                return

            # Note: Ready message ("Squawk! Cap’n and I are at full speed!") is sent by SquawkBot’s event_ready to avoid duplication
            # Keep-alive task omitted as it was not needed in prior working state

            # Update GUI status
            try:
                self.status_updated.emit("Bot Status: Full Sailin’!")
                self.gui.start_button.setEnabled(False)
                self.gui.stop_button.setEnabled(True)
            except Exception as e:
                logger.warning(f"Failed to update GUI status: {e}, arrgh!", exc_info=True)

            # Register commands after the bot is ready
            try:
                self.update_commands()
                self.update_counter_commands()
                logger.debug("Shoutout and counter commands registered after bot is ready, arrgh!")
            except Exception as e:
                logger.error(f"Failed to register commands: {e}, arrgh!", exc_info=True)

            # Fetch BRB clips on startup and ensure it completes
            if self.gui.config["toggles"].get("intermission_enabled", True):
                try:
                    await self.fetch_brb_clips()
                    if self.brb_clips:
                        random.shuffle(self.brb_clips)
                        logger.debug(f"Fetched and randomized {len(self.brb_clips)} BRB clips on startup, arrgh!")
                    else:
                        logger.warning("No BRB clips fetched on startup, arrgh!")
                except Exception as e:
                    logger.error(f"Failed to fetch BRB clips: {e}, arrgh!", exc_info=True)

            # Start the BRB scene check task
            if self.gui.config["toggles"].get("intermission_enabled", True):
                try:
                    await self.start_brb_scene_check()
                    logger.debug("BRB scene check task started, arrgh!")
                except Exception as e:
                    logger.error(f"Failed to start BRB scene check: {e}, arrgh!", exc_info=True)

        except Exception as e:
            logger.error(f"Unexpected error in event_ready: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            self.status_updated.emit("Bot Status: Crashed after connection")
            self.error_occurred.emit(f"Bot crashed after connectin’: {e}, arrgh! Check logs for details.")
        finally:
            logger.debug("Exitin’ event_ready, arrgh!")

        async def event_raw_data(self, data):
            logger.debug(f"Raw IRC data received: {data}, arrgh!")
            file_handler.flush()
            console_handler.flush()

        async def event_error(self, error):
            logger.error(f"Twitch IRC error: {error}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            
            # Check for 401 Unauthorized error
            if "401" in str(error) or "Unauthorized" in str(error):
                logger.debug("Detected 401 Unauthorized error, attempting to refresh bot token, arrgh!")
                success = self.gui.refresh_bot_token()
                if not success:
                    logger.error("Token refresh failed, bot requires re-authentication, arrgh!")
                    self.gui.bot_thread.error_occurred.emit("Bot token expired and refresh failed. Please re-authenticate the bot, arrgh!")
                    await self.shutdown_all_resources()  # Updated line 1510
                    self.gui.bot_thread.status_updated.emit("Bot Status: Token Expired - Re-authentication Required")
                else:
                    # Restart the bot with the new token
                    logger.debug("Token refreshed successfully, restarting bot connection, arrgh!")
                    await self.shutdown_all_resources()  # Updated line 1516
                    await self.start_all()
            else:
                self.gui.bot_thread.error_occurred.emit(f"Twitch IRC error: {error}, arrgh!")

    async def event_connect(self):
        logger.debug(f"Bot attempting to connect to Twitch IRC as {self.bot_username}, arrgh!")
        file_handler.flush()
        console_handler.flush()

    async def event_disconnect(self):
        logger.debug(f"Bot disconnected from Twitch IRC, arrgh!")
        file_handler.flush()
        console_handler.flush()
        self.gui.bot_thread.status_updated.emit("Bot Status: Disconnected")


    async def fetch_clip(self, username):
        """Fetch a random clip from the user's channel and its duration."""
        try:
            # Validate the broadcaster token before making the API call
            token = self.gui.broadcaster_config["token"].replace("oauth:", "")
            valid, result, _ = validate_twitch_token(token)
            if not valid:
                logger.warning(f"Broadcaster token invalid: {result}, attempting to refresh, arrgh!")
                success = self.gui.refresh_broadcaster_token()
                if not success:
                    logger.error("Broadcaster token refresh failed, skipping clip fetch, arrgh!")
                    return None, None
                token = self.gui.broadcaster_config["token"].replace("oauth:", "")

            headers = {
                "Client-ID": CLIENT_ID,
                "Authorization": f"Bearer {token}"
            }
            # Get the user ID
            user_url = f"https://api.twitch.tv/helix/users?login={username}"
            user_response = requests.get(user_url, headers=headers)
            if user_response.status_code != 200:
                logger.error(f"Failed to fetch user ID for {username}: {user_response.text}, arrgh!")
                return None, None
            user_data = user_response.json()
            if not user_data["data"]:
                logger.error(f"No user found for {username}, arrgh!")
                return None, None
            user_id = user_data["data"][0]["id"]

            # Check channel metadata for rich preview
            channel_url = f"https://api.twitch.tv/helix/channels?broadcaster_id={user_id}"
            channel_response = requests.get(channel_url, headers=headers)
            if channel_response.status_code != 200:
                logger.warning(f"Failed to fetch channel metadata for {username}: {channel_response.text}, arrgh!")
            else:
                channel_data = channel_response.json()
                if not channel_data["data"]:
                    logger.warning(f"No channel metadata found for {username}, rich preview may not display, arrgh!")
                else:
                    channel_info = channel_data["data"][0]
                    logger.debug(f"Channel metadata for {username}: title={channel_info.get('title')}, game={channel_info.get('game_name')}, arrgh!")
                    if not channel_info.get("title"):
                        logger.warning(f"Channel {username} has no title set, rich preview may not display properly, arrgh!")

            # Fetch clips with pagination to get more options
            clips = []
            cursor = None
            for _ in range(3):  # Fetch up to 3 pages of clips (max 100 clips per page)
                clips_url = f"https://api.twitch.tv/helix/clips?broadcaster_id={user_id}&first=100"
                if cursor:
                    clips_url += f"&after={cursor}"
                clips_response = requests.get(clips_url, headers=headers)
                if clips_response.status_code != 200:
                    logger.error(f"Failed to fetch clips for {username}: {clips_response.text}, arrgh!")
                    return None, None
                clips_data = clips_response.json()
                new_clips = clips_data.get("data", [])
                clips.extend(new_clips)
                logger.debug(f"Fetched {len(new_clips)} clips for {username}, total clips: {len(clips)}, arrgh!")
                cursor = clips_data.get("pagination", {}).get("cursor")
                if not cursor or not new_clips:
                    break

            if not clips:
                logger.debug(f"No clips found for {username}, arrgh!")
                return None, None

            # Ensure a random clip is selected
            clip = random.choice(clips)
            clip_id = clip.get("id", "unknown")
            clip_url = clip["url"]
            clip_duration = clip["duration"]  # Duration in seconds
            logger.debug(f"Selected clip for {username}: ID={clip_id}, URL={clip_url}, arrgh!")

            # Construct the Twitch embed URL to match the old code
            embed_url = f"https://clips.twitch.tv/embed?clip={clip_id}&parent=localhost&autoplay=true&muted=false"
            logger.debug(f"Fetched clip for {username}: {embed_url}, duration: {clip_duration}s, arrgh!")
            return embed_url, clip_duration
        except Exception as e:
            logger.error(f"Error fetching clip for {username}: {e}, arrgh!", exc_info=True)
            return None, None

    async def play_clip_in_obs(self, video_url, clip_duration, context="brb", scene_name=None, source_name=None):
        """Play the clip in OBS usin’ the specified or selected scene and source, arrgh!"""
        logger.info(f"Enterin’ play_clip_in_obs: video_url={video_url}, duration={clip_duration}, scene={scene_name}, source={source_name}, context={context}, arrgh!")
        async with asyncio.Lock():  # Prevent concurrent OBS requests
            try:
                # Check if bot be shuttin’ down
                if self.gui.is_shutting_down:
                    logger.warning("Bot be shuttin’ down, skippin’ clip playback, arrgh!")
                    return False

                # Validate OBS client and video URL
                if not self.gui.obs_client or not self.gui.obs_client.connected:
                    logger.error("OBS client not connected, arrgh!")
                    return False
                if not video_url:
                    logger.error("No video URL provided, arrgh!")
                    return False

                # Select scene/source based on context if not provided
                if scene_name is None:
                    if context == "shoutout":
                        scene_name = self.gui.scene_dropdown.currentText().strip()
                    elif context == "raid":
                        scene_name = self.gui.raid_scene_dropdown.currentText().strip()
                    else:  # brb
                        scene_name = self.gui.brb_scene_dropdown.currentText().strip()
                if source_name is None:
                    if context == "shoutout":
                        source_name = self.gui.source_dropdown.currentText().strip()
                    elif context == "raid":
                        source_name = self.gui.raid_source_dropdown.currentText().strip()
                    else:  # brb
                        source_name = self.gui.brb_source_dropdown.currentText().strip()

                # Log actual scene/source used
                logger.info(f"Usin’ scene: {scene_name}, source: {source_name} for context {context}, arrgh!")

                # Validate scene/source existence with fallback
                try:
                    loop = asyncio.get_event_loop()
                    scenes_response = await loop.run_in_executor(None, lambda: self.gui.obs_client.req_client.get_scene_list())
                    scene_names = [scene["sceneName"] for scene in scenes_response.scenes]
                    if scene_name not in scene_names:
                        logger.error(f"Scene {scene_name} not found in OBS, available scenes: {scene_names}, arrgh!")
                        return False
                    sources_response = await loop.run_in_executor(None, lambda: self.gui.obs_client.req_client.get_scene_item_list(scene_name))
                    logger.debug(f"Sources response for scene {scene_name}: {sources_response}, arrgh!")
                    source_names = [source["sourceName"] for source in sources_response.scene_items]
                    if source_name not in source_names:
                        source_names_lower = [s.lower() for s in source_names]
                        if source_name.lower() not in source_names_lower:
                            logger.warning(f"Source {source_name} not found in scene {scene_name}, available sources: {source_names}, proceedin’ with caution, arrgh!")
                        else:
                            source_name = source_names[source_names_lower.index(source_name.lower())]
                            logger.info(f"Matched source {source_name} case-insensitively, arrgh!")
                except Exception as e:
                    logger.warning(f"Failed to validate scene {scene_name} or source {source_name}: {e}, proceedin’ with caution, arrgh!")
                    # Continue to avoid breaking playback if validation fails

                # Check current scene
                try:
                    loop = asyncio.get_event_loop()
                    current_scene_response = await loop.run_in_executor(None, lambda: self.gui.obs_client.req_client.get_current_program_scene())
                    if not hasattr(current_scene_response, 'current_program_scene_name'):
                        logger.warning(f"Invalid response type {type(current_scene_response)} for get_current_program_scene, assumin’ scene is {scene_name}, arrgh!")
                        current_scene = scene_name  # Assume correct scene to avoid skippin’ playback
                    else:
                        current_scene = current_scene_response.current_program_scene_name
                    if current_scene != scene_name:
                        logger.debug(f"Current scene {current_scene} does not match target {scene_name}, skippin’ playback, arrgh!")
                        return False
                except Exception as e:
                    logger.error(f"Failed to check current scene: {e}, arrgh!")
                    return False

                # Check if we need to update source settings
                current_settings = None
                current_url = ""
                try:
                    loop = asyncio.get_event_loop()
                    current_settings = await loop.run_in_executor(None, lambda: self.gui.obs_client.req_client.get_input_settings(source_name))
                    current_url = current_settings.input_settings.get("url", "")
                except Exception as e:
                    logger.error(f"Failed to get input settings for {source_name}: {e}, arrgh!")
                    return False

                if current_url != video_url:
                    # Hide source to stop any ongoing playback
                    try:
                        loop = asyncio.get_event_loop()
                        scene_item_id = self._get_scene_item_id(scene_name, source_name)
                        if scene_item_id is None:
                            logger.error(f"No scene item ID for source {source_name} in scene {scene_name}, skippin’ hide, arrgh!")
                            return False
                        await loop.run_in_executor(None, lambda: self.gui.obs_client.req_client.set_scene_item_enabled(scene_name, scene_item_id, False))
                        logger.info(f"Set visibility fer source {source_name} in scene {scene_name} to False to stop playback, arrgh!")
                        await asyncio.sleep(0.5)
                    except Exception as e:
                        logger.error(f"Failed to hide source {source_name}: {e}, arrgh!")
                        return False

                    # Set new URL for the browser source
                    settings = {
                        "url": video_url,
                        "is_local_file": False,
                        "width": 1920,
                        "height": 1080,
                        "restart_on_activate": False
                    }
                    try:
                        loop = asyncio.get_event_loop()
                        await loop.run_in_executor(None, lambda: self.gui.obs_client.req_client.set_input_settings(source_name, settings, overlay=True))
                        logger.info(f"Set video URL {video_url} to source {source_name} in scene {scene_name}, arrgh!")
                        await asyncio.sleep(0.5)
                    except Exception as e:
                        logger.error(f"Failed to set input settings for {source_name}: {e}, arrgh!")
                        return False

                    # Verify settings
                    try:
                        loop = asyncio.get_event_loop()
                        current_settings = await loop.run_in_executor(None, lambda: self.gui.obs_client.req_client.get_input_settings(source_name))
                        current_url = current_settings.input_settings.get("url", "")
                        if current_url != video_url:
                            logger.error(f"Failed to set video URL fer source {source_name}, current URL be {current_url}, arrgh!")
                            return False
                    except Exception as e:
                        logger.error(f"Failed to verify input settings for {source_name}: {e}, arrgh!")
                        return False
                else:
                    logger.debug(f"Resumin’ clip {video_url} with {clip_duration}s remainin’, skippin’ source settings update, arrgh!")

                # Make source visible
                try:
                    loop = asyncio.get_event_loop()
                    scene_item_id = self._get_scene_item_id(scene_name, source_name)
                    if scene_item_id is None:
                        logger.error(f"No scene item ID for source {source_name} in scene {scene_name}, skippin’ show, arrgh!")
                        return False
                    current_enabled = await loop.run_in_executor(None, lambda: self.gui.obs_client.req_client.get_scene_item_enabled(scene_name, scene_item_id))
                    if not current_enabled.scene_item_enabled:
                        await loop.run_in_executor(None, lambda: self.gui.obs_client.req_client.set_scene_item_enabled(scene_name, scene_item_id, True))
                        logger.info(f"Set visibility fer source {source_name} in scene {scene_name} to True to play clip, arrgh!")
                except Exception as e:
                    logger.error(f"Failed to show source {source_name}: {e}, arrgh!")
                    return False

                # Wait for clip duration
                remaining_duration = clip_duration
                start_time = time.time()
                logger.info(f"Waitin’ fer clip duration: {clip_duration} seconds, arrgh!")
                while remaining_duration > 0:
                    if self.gui.is_shutting_down:
                        logger.warning("Bot shuttin’ down, stoppin’ clip playback, arrgh!")
                        return False
                    try:
                        loop = asyncio.get_event_loop()
                        current_scene_response = await loop.run_in_executor(None, lambda: self.gui.obs_client.req_client.get_current_program_scene())
                        if not hasattr(current_scene_response, 'current_program_scene_name'):
                            logger.warning(f"Invalid response type {type(current_scene_response)} during clip playback, assumin’ scene is {scene_name}, arrgh!")
                            current_scene = scene_name  # Assume correct scene to avoid pausin’ playback
                        else:
                            current_scene = current_scene_response.current_program_scene_name
                        if current_scene != scene_name:
                            logger.debug(f"Left scene {scene_name} durin’ playback, pausin’ clip, arrgh!")
                            return False
                    except Exception as e:
                        logger.error(f"Failed to check current scene during playback: {e}, arrgh!")
                        return False
                    elapsed = time.time() - start_time
                    remaining_duration = clip_duration - elapsed
                    if remaining_duration <= 0:
                        break
                    await asyncio.sleep(min(0.5, remaining_duration))
                    logger.debug(f"Waitin’ for clip, elapsed: {elapsed}s, remainin’: {remaining_duration}s, arrgh!")
                logger.info("Clip playback duration completed, arrgh!")

                return True

            except Exception as e:
                logger.error(f"Failed to play clip in OBS: {e}, arrgh!", exc_info=True)
                return False
            finally:
                logger.info("Exitin’ play_clip_in_obs, arrgh!")

    def _get_scene_item_id(self, scene_name, source_name):
        """Helper to get scene item ID for a source in a scene, arrgh!"""
        try:
            sources_response = self.gui.obs_client.req_client.get_scene_item_list(scene_name)
            for item in sources_response.scene_items:
                if item["sourceName"] == source_name:
                    return item["sceneItemId"]
            logger.warning(f"Source {source_name} not found in scene {scene_name}, arrgh!")
            return None
        except Exception as e:
            logger.error(f"Failed to get scene item ID for {source_name} in {scene_name}: {e}, arrgh!")
            return None

    async def shoutout(self, ctx: commands.Context):
        """Handle the shoutout command with role-based access control."""
        command_name = self.gui.shoutout_command_input.text().strip()
        if not command_name.startswith("!"):
            command_name = f"!{command_name}"
        
        # Check role-based access
        access_level = self.gui.access_dropdown.currentText().lower()
        user = ctx.author
        is_allowed = False
        is_broadcaster = user.name.lower() == self.broadcaster_username.lower()
        is_mod = user.is_mod
        is_vip = user.is_vip if hasattr(user, 'is_vip') else False
        is_regular = True  # Assume all users are regulars by default

        if is_broadcaster:
            is_allowed = True
        elif access_level == "mods" and is_mod:
            is_allowed = True
        elif access_level == "vips" and (is_mod or is_vip):
            is_allowed = True
        elif access_level == "regulars" and (is_mod or is_vip or is_regular):
            is_allowed = True
        elif access_level == "all":
            is_allowed = True

        if not is_allowed:
            logger.debug(f"User {user.name} not authorized for shoutout command, access level: {access_level}, arrgh!")
            await ctx.send(f"Sorry {user.name}, you don't have permission to use this command, arrgh!")
            return

        # Parse the target user from the command
        if not ctx.message.content.startswith(command_name):
            return
        target_user = ctx.message.content[len(command_name):].strip()
        if not target_user:
            await ctx.send(f"Please provide a username to shoutout, e.g., {command_name} username, arrgh!")
            return
        target_user = target_user.lstrip('@').lower()

        # Add to queue
        self.gui.add_to_shoutout_queue(target_user)

        # Process the queue if this is the only user
        if len(self.gui.shoutout_queue) == 1:
            await self.process_shoutout_queue(ctx.channel)

    def update_shoutout_command(self, old_name, new_name):
        """Update the registered shoutout command name."""
        old_name = old_name.lstrip("!")
        new_name = new_name.lstrip("!")
        # Remove the old command
        if old_name in self.commands:
            self.remove_command(old_name)
        # Add the new command
        shoutout_command = commands.Command(name=new_name, func=self.shoutout)
        self.add_command(shoutout_command)
        logger.debug(f"Updated shoutout command from '!{old_name}' to '!{new_name}', arrgh!")

    async def process_shoutout_queue(self, channel):
        """Process the shoutout queue by playin’ clips in OBS and sendin’ messages to chat, arrgh!"""
        logger.info("Enterin’ process_shoutout_queue, arrgh!")
        while self.gui.shoutout_queue:
            if self.gui.is_shutting_down:
                logger.warning("Bot be shuttin’ down, stoppin’ shoutout queue processin’, arrgh!")
                return

            user = self.gui.shoutout_queue[0]
            logger.info(f"Processin’ shoutout for {user}, arrgh!")
            try:
                # Validate bot token
                token = self.bot_token.replace("oauth:", "")
                valid, result, _ = validate_twitch_token(token)
                if not valid:
                    logger.warning(f"Bot token invalid: {result}, tryin’ to refresh, arrgh!")
                    success = self.gui.refresh_bot_token()
                    if not success:
                        logger.error("Failed to refresh bot token, cannot proceed with shoutout, arrgh!")
                        await channel.send(f"Squawk! Failed to shoutout {user} due to token issues, arrgh!")
                        self.gui.shoutout_queue.pop(0)
                        self.gui.update_shoutout_queue_list()
                        logger.info(f"Removed {user} from shoutout queue due to token failure, arrgh!")
                        continue
                    token = self.bot_token.replace("oauth:", "")

                # Fetch channel metadata
                headers = {
                    "Client-ID": CLIENT_ID,
                    "Authorization": f"Bearer {token}"
                }
                user_url = f"https://api.twitch.tv/helix/users?login={user}"
                async with aiohttp.ClientSession() as session:
                    async with session.get(user_url, headers=headers) as user_response:
                        if user_response.status != 200:
                            logger.error(f"Failed to fetch user ID for {user}: {user_response.status}, arrgh!")
                            await channel.send(f"Squawk! Failed to fetch info for {user}, arrgh!")
                            self.gui.shoutout_queue.pop(0)
                            self.gui.update_shoutout_queue_list()
                            logger.info(f"Removed {user} from shoutout queue due to user fetch failure, arrgh!")
                            continue
                        user_data = await user_response.json()
                        if not user_data["data"]:
                            logger.error(f"No user found for {user}, arrgh!")
                            await channel.send(f"Squawk! No user found for {user}, arrgh!")
                            self.gui.shoutout_queue.pop(0)
                            self.gui.update_shoutout_queue_list()
                            logger.info(f"Removed {user} from shoutout queue due to no user found, arrgh!")
                            continue
                        user_id = user_data["data"][0]["id"]

                channel_url = f"https://api.twitch.tv/helix/channels?broadcaster_id={user_id}"
                metadata = ""
                async with aiohttp.ClientSession() as session:
                    async with session.get(channel_url, headers=headers) as channel_response:
                        if channel_response.status == 200:
                            channel_data = await channel_response.json()
                            if channel_data["data"]:
                                channel_info = channel_data["data"][0]
                                title = channel_info.get("title", "No title set")
                                game = channel_info.get("game_name", "Unknown game")
                                metadata = f"Last stream: {title} (playin’ {game})"
                                logger.info(f"Channel metadata for {user}: {metadata}, arrgh!")
                        else:
                            logger.warning(f"Failed to fetch channel info for {user}: {channel_response.status}, arrgh!")

                # Send Twitch /shoutout command
                shoutout_command = f"/shoutout {user}"
                try:
                    await channel.send(shoutout_command)
                    logger.info(f"Sent Twitch shoutout command for {user}: {shoutout_command}, arrgh!")
                except Exception as e:
                    logger.error(f"Failed to send Twitch shoutout command for {user}: {e}, arrgh!")
                    await channel.send(f"Squawk! Failed to send shoutout command for {user}, arrgh!")
                    self.gui.shoutout_queue.pop(0)
                    self.gui.update_shoutout_queue_list()
                    logger.info(f"Removed {user} from shoutout queue due to shoutout command failure, arrgh!")
                    continue

                # Fetch a clip
                clip_result = await self.fetch_clip(user)
                clip_duration = 0
                if not clip_result:
                    logger.warning(f"No clip found for {user}, sendin’ shoutout message only, arrgh!")
                    # Send shoutout message even if no clip
                    message_template = self.gui.shoutout_message_input.text().strip()
                    link = f"https://twitch.tv/{user}"
                    message = message_template.format(user=user, link=f" {link} ")
                    message = " ".join(message.split())
                    if message:
                        try:
                            await channel.send(message)
                            logger.info(f"Sent shoutout message for {user}: {message}, arrgh!")
                        except Exception as e:
                            logger.error(f"Failed to send shoutout message for {user}: {e}, arrgh!")
                else:
                    video_url, clip_duration = clip_result
                    # Send shoutout message before playing the clip
                    message_template = self.gui.shoutout_message_input.text().strip()
                    link = f"https://twitch.tv/{user}"
                    message = message_template.format(user=user, link=f" {link} ")
                    message = " ".join(message.split())
                    if message:
                        try:
                            await channel.send(message)
                            logger.info(f"Sent shoutout message for {user}: {message}, arrgh!")
                        except Exception as e:
                            logger.error(f"Failed to send shoutout message for {user}: {e}, arrgh!")
                    
                    # Ensure the shoutout source is visible before playing the clip
                    try:
                        if not self.gui.obs_client or not self.gui.obs_client.connected:
                            logger.warning("OBS client not connected, skippin’ shoutout source visibility check, arrgh!")
                        else:
                            scene_name = self.gui.scene_dropdown.currentText().strip()
                            source_name = self.gui.source_dropdown.currentText().strip()
                            if not scene_name or scene_name == "(No scenes available)" or not source_name or source_name == "(No sources available)":
                                logger.warning(f"Invalid scene ({scene_name}) or source ({source_name}) for shoutout visibility check, skippin’, arrgh!")
                            else:
                                # Get the scene item ID and set visibility to True
                                response = self.gui.obs_client.req_client.get_scene_item_id(scene_name, source_name)
                                scene_item_id = response.scene_item_id  # Updated attribute name
                                self.gui.obs_client.req_client.set_scene_item_enabled(scene_name, scene_item_id, True)
                                logger.info(f"Ensured shoutout source {source_name} is visible in scene {scene_name}, arrgh!")
                    except AttributeError as e:
                        logger.warning(f"Failed to validate scene {scene_name} or source {source_name}: {e}, proceedin’ with caution, arrgh!", exc_info=True)
                    except Exception as e:
                        logger.error(f"Failed to ensure shoutout source visibility: {e}, arrgh!", exc_info=True)
                        # Continue with the shoutout even if visibility check fails

                    # Play the clip in OBS with shoutout context
                    success = await self.play_clip_in_obs(
                        video_url,
                        clip_duration,
                        context="shoutout"
                    )
                    if not success:
                        logger.warning(f"Failed to play clip for {user} in OBS, arrgh!")

                # Remove user from queue
                self.gui.shoutout_queue.pop(0)
                self.gui.update_shoutout_queue_list()
                logger.info(f"Removed {user} from shoutout queue after processin’, arrgh!")

            except Exception as e:
                logger.error(f"Error processin’ shoutout for {user}: {e}, arrgh!", exc_info=True)
                self.gui.shoutout_queue.pop(0)
                self.gui.update_shoutout_queue_list()
                logger.info(f"Removed {user} from shoutout queue due to error, arrgh!")

        # When queue is empty, set shoutout source URL to about:blank
        if not self.gui.shoutout_queue:
            try:
                if not self.gui.obs_client or not self.gui.obs_client.connected:
                    logger.warning("OBS client not connected, skippin’ shoutout source URL reset, arrgh!")
                else:
                    scene_name = self.gui.scene_dropdown.currentText().strip()
                    source_name = self.gui.source_dropdown.currentText().strip()
                    if not scene_name or scene_name == "(No scenes available)" or not source_name or source_name == "(No sources available)":
                        logger.warning(f"Invalid scene ({scene_name}) or source ({source_name}) for shoutout URL reset, skippin’, arrgh!")
                    else:
                        # Add a buffer to ensure the clip finishes playing
                        await asyncio.sleep(1)  # 1-second buffer, arrgh!
                        settings = {
                            "url": "about:blank",
                            "is_local_file": False,
                            "width": 1920,
                            "height": 1080,
                            "restart_on_activate": False
                        }
                        loop = asyncio.get_event_loop()
                        await loop.run_in_executor(None, lambda: self.gui.obs_client.req_client.set_input_settings(source_name, settings, overlay=True))
                        logger.info(f"Set shoutout source {source_name} URL to about:blank in scene {scene_name} as queue is empty, arrgh!")
            except Exception as e:
                logger.error(f"Failed to set shoutout source URL to about:blank: {e}, arrgh!", exc_info=True)

        logger.info("Exitin’ process_shoutout_queue, arrgh!")

    async def fetch_brb_clips(self):
        """Fetch BRB clips from Twitch and store them with embedded URLs."""
        logger.info("Startin’ fetch_brb_clips, arrgh!")
        # Validate the broadcaster token before making any API calls
        token = self.gui.broadcaster_config["token"].replace("oauth:", "")
        valid, result, _ = validate_twitch_token(token)
        if not valid:
            logger.warning(f"Broadcaster token invalid: {result}, attemptin’ to refresh, arrgh!")
            success = self.gui.refresh_broadcaster_token()
            if not success:
                logger.error("Broadcaster token refresh failed, skippin’ clip fetch, arrgh!")
                self.brb_clips = []
                return
            token = self.gui.broadcaster_config["token"].replace("oauth:", "")

        headers = {
            "Client-ID": CLIENT_ID,
            "Authorization": f"Bearer {token}"
        }

        # Fetch the broadcaster ID directly using the broadcaster's username
        channel_name = self.channel.lstrip("#")
        user_url = f"https://api.twitch.tv/helix/users?login={channel_name}"
        user_response = requests.get(user_url, headers=headers)
        if user_response.status_code != 200:
            logger.error(f"Failed to fetch broadcaster ID for {channel_name}: {user_response.status_code} {user_response.text}, arrgh!")
            self.brb_clips = []
            return
        user_data = user_response.json()
        if not user_data["data"]:
            logger.error(f"No user found for broadcaster {channel_name}, arrgh!")
            self.brb_clips = []
            return
        broadcaster_id = user_data["data"][0]["id"]
        logger.info("Fetchin’ BRB clips fer broadcaster_id: %s (channel: %s), arrgh!", broadcaster_id, channel_name)
        if not broadcaster_id:
            logger.error("Broadcaster ID not available for channel %s, skippin’ clip fetch, arrgh!", channel_name)
            self.brb_clips = []
            return

        try:
            clips = []
            cursor = None
            max_retries = 3
            retry_delay = 5  # seconds
            while True:
                url = f"https://api.twitch.tv/helix/clips?broadcaster_id={broadcaster_id}&first=50"
                if cursor:
                    url += f"&after={cursor}"
                logger.debug("Fetchin’ clips from: %s, arrgh!", url)

                for attempt in range(max_retries):
                    response = requests.get(url, headers=headers)
                    if response.status_code == 200:
                        break
                    elif response.status_code == 429:  # Rate limit
                        logger.warning("Hit rate limit fetchin’ clips, retryin’ in %s seconds (attempt %s/%s), arrgh!", retry_delay, attempt + 1, max_retries)
                        time.sleep(retry_delay)
                    else:
                        logger.error("BRB clip fetch failed: status %s, %s, arrgh!", response.status_code, response.text)
                        self.brb_clips = []
                        return
                else:
                    logger.error("Max retries reached for clip fetch, givin’ up, arrgh!")
                    self.brb_clips = []
                    return

                data = response.json()
                new_clips = data.get("data", [])
                logger.info("Fetched %s new BRB clips, total %s, arrgh!", len(new_clips), len(clips) + len(new_clips))
                clips.extend(new_clips)
                cursor = data.get("pagination", {}).get("cursor")
                if not cursor:  # Only break if no cursor
                    break

            self.brb_clips = []
            for clip in clips:
                duration = clip.get("duration")
                if duration is None or not isinstance(duration, (int, float)) or duration <= 0:
                    logger.warning("Invalid or missing duration for clip %s, skippin’, arrgh!", clip.get("id", "unknown"))
                    continue
                self.brb_clips.append({
                    "embed_url": f"https://clips.twitch.tv/embed?clip={clip['id']}&parent=localhost&autoplay=true&muted=false",
                    "duration": float(duration)
                })
            random.shuffle(self.brb_clips)
            logger.info("Loaded %s BRB clips into brb_clips, arrgh!", len(self.brb_clips))
            if not self.brb_clips:
                logger.warning("No valid BRB clips loaded, brb_clips empty, arrgh!")
            elif len(self.brb_clips) < 100:
                logger.warning("Loaded only %s BRB clips, expected ~149; check Twitch API or clip availability, arrgh!", len(self.brb_clips))
        except Exception as e:
            logger.error("BRB clip fetch blunder: %s, arrgh!", e, exc_info=True)
            self.brb_clips = []

    async def play_brb_clips(self, scene_name, source_name):
        """Play BRB clips in a loop while the active scene matches the BRB scene."""
        async with self.brb_playback_lock:
            logger.info("Startin’ BRB clip playback for scene %s, source %s, arrgh!", scene_name, source_name)
            try:
                if not self.brb_clips:
                    logger.error("No BRB clips available to play, arrgh!")
                    return

                # Reshuffle clips at the start of each session for a new random order
                random.seed(time.time())  # Reseed for different shuffle each session
                random.shuffle(self.brb_clips)
                self.brb_current_clip_index = 0
                logger.info("Shuffled %s BRB clips for new session, arrgh!", len(self.brb_clips))

                if len(self.brb_clips) < 100:
                    logger.warning("Only %s BRB clips loaded, expected ~149; repetition may occur, arrgh!", len(self.brb_clips))

                while self.brb_playing:
                    if self.brb_current_clip_index >= len(self.brb_clips):
                        self.brb_current_clip_index = 0
                        random.shuffle(self.brb_clips)
                        logger.info("Reshuffled %s BRB clips after cyclin’ through all, arrgh!", len(self.brb_clips))

                    clip = self.brb_clips[self.brb_current_clip_index]
                    video_url = clip["embed_url"]
                    clip_duration = clip["duration"]
                    logger.info("Playin’ BRB clip %s (index %s/%s), duration %ss, arrgh!", video_url, self.brb_current_clip_index, len(self.brb_clips), clip_duration)

                    # Double-check the active scene before playing
                    try:
                        response = self.gui.obs_client.req_client.get_current_program_scene()
                        current_scene = response.current_program_scene_name
                    except Exception as e:
                        logger.error(f"Failed to get current OBS scene during BRB playback: {e}, arrgh!")
                        self.brb_playing = False
                        break

                    if current_scene != scene_name:
                        logger.debug(f"Active scene changed to %s, pausin’ BRB clip playback, arrgh!", current_scene)
                        break  # Exit loop but preserve index for next session

                    # Play the clip
                    success = await self.play_clip_in_obs(video_url, clip_duration, context="brb")
                    if not success:
                        logger.warning(f"Failed to play BRB clip %s, skippin’ to next clip, arrgh!", video_url)
                    else:
                        logger.info(f"Successfully played BRB clip %s for %ss, arrgh!", video_url, clip_duration)

                    self.brb_current_clip_index += 1
            except Exception as e:
                logger.error(f"Error in BRB clip playback loop: %s, arrgh!", e, exc_info=True)
            finally:
                try:
                    self.gui.obs_client.set_source_visibility(scene_name, source_name, False)
                    logger.debug(f"BRB playback stopped, source %s hidden, arrgh!", source_name)
                except Exception as e:
                    logger.error(f"Failed to hide source %s after BRB playback: {e}, arrgh!", source_name)
                logger.info("Exitin’ BRB clip playback, arrgh!")
        
    async def shutdown_all_resources(self):
        """Close all bot connections safely, arrgh!"""
        logger.debug("Enterin’ SquawkBot.shutdown_all_resources, arrgh!")
        try:
            # Close the broadcaster client connection
            if self.broadcaster_client and hasattr(self.broadcaster_client, '_connection') and self.broadcaster_client._connection:
                try:
                    await self.broadcaster_client.close()
                    logger.debug("Broadcaster client closed, arrgh!")
                except Exception as e:
                    logger.error(f"Failed to close broadcaster client: {e}, arrgh!", exc_info=True)
            
            # Close the bot's connection (self is the twitchio Bot instance)
            if hasattr(self, '_connection') and self._connection is not None:
                if hasattr(self._connection, 'is_alive') and callable(self._connection.is_alive):
                    if self._connection.is_alive():
                        try:
                            await self._connection.close()
                            logger.debug("Bot connection closed, arrgh!")
                        except Exception as e:
                            logger.error(f"Failed to close bot connection: {e}, arrgh!", exc_info=True)
                    else:
                        logger.debug("Bot connection already closed, arrgh!")
                else:
                    logger.warning("self._connection.is_alive is not callable, skippin’ bot connection close, arrgh!")
            else:
                logger.debug("No bot connection to close, arrgh!")
        except Exception as e:
            logger.error(f"Error in shutdown_all_resources: {e}, arrgh!", exc_info=True)
        finally:
            logger.debug("Exitin’ SquawkBot.shutdown_all_resources, arrgh!")

    async def check_brb_scene(self):
        """Check if OBS is on the BRB scene and play clips continuously, arrgh!"""
        logger.debug("Enterin’ check_brb_scene to monitor BRB scene, arrgh!")
        try:
            if not self.gui.obs_client or not self.gui.obs_client.connected:
                logger.warning("OBS client not connected, skippin’ BRB scene check, arrgh!")
                return

            # Initialize variables to track pause state and timing
            paused_start_time = 0  # When pause begins
            total_paused_time = 0  # Total time paused for current clip
            current_clip_url = ""  # Track current clip URL
            playback_active = False  # Track if playback be explicitly started

            while True:
                try:
                    if not self.gui.obs_client or not self.gui.obs_client.connected:
                        logger.debug("OBS not connected, skippin’ clip playback, arrgh!")
                        await asyncio.sleep(2)
                        continue

                    # Dynamically get BRB scene and source from GUI dropdowns
                    brb_scene = self.gui.brb_scene_dropdown.currentText().strip()
                    brb_source = self.gui.brb_source_dropdown.currentText().strip()
                    if not brb_scene or not brb_source:
                        logger.debug("BRB scene or source not set in GUI dropdowns, skippin’ playback, arrgh!")
                        await asyncio.sleep(2)
                        continue

                    # Validate scene/source existence
                    try:
                        loop = asyncio.get_event_loop()
                        scenes_response = await loop.run_in_executor(None, lambda: self.gui.obs_client.req_client.get_scene_list())
                        scene_names = [scene["sceneName"] for scene in scenes_response.scenes]
                        if brb_scene not in scene_names:
                            logger.debug(f"BRB scene {brb_scene} not found in OBS, skippin’ playback, arrgh!")
                            await asyncio.sleep(2)
                            continue
                        sources_response = await loop.run_in_executor(None, lambda: self.gui.obs_client.req_client.get_scene_item_list(brb_scene))
                        source_names = [source["sourceName"] for source in sources_response.scene_items]
                        if brb_source not in source_names:
                            logger.debug(f"BRB source {brb_source} not found in scene {brb_scene}, skippin’ playback, arrgh!")
                            await asyncio.sleep(2)
                            continue
                    except Exception as e:
                        logger.debug(f"Failed to validate scene {brb_scene} or source {brb_source}: {e}, arrgh!")
                        await asyncio.sleep(2)
                        continue

                    # Get current scene
                    try:
                        loop = asyncio.get_event_loop()
                        current_scene_response = await loop.run_in_executor(None, lambda: self.gui.obs_client.req_client.get_current_program_scene())
                        current_scene = current_scene_response.current_program_scene_name
                    except Exception as e:
                        logger.debug(f"Failed to get current scene: {e}, arrgh!")
                        await asyncio.sleep(2)
                        continue
                    logger.debug(f"Current OBS scene: {current_scene}, target BRB scene: {brb_scene}, playback_active: {playback_active}, arrgh!")

                    # If not on the BRB scene
                    if current_scene != brb_scene:
                        if self.current_brb_clip and not self.is_brb_clip_paused:
                            # Pause clip: save position, hide source, start pausin’ timer
                            elapsed_time = time.time() - self.brb_clip_start_time - total_paused_time
                            self.current_brb_clip_position = max(0, elapsed_time)
                            self.is_brb_clip_paused = True
                            paused_start_time = time.time()
                            logger.debug(f"Pausing clip {self.current_brb_clip['embed_url']}, saved position: {self.current_brb_clip_position}s, arrgh!")
                            try:
                                loop = asyncio.get_event_loop()
                                scene_item_id = self._get_scene_item_id(brb_scene, brb_source)
                                if scene_item_id is None:
                                    logger.debug(f"No scene item ID for source {brb_source} in scene {brb_scene}, skippin’ hide, arrgh!")
                                else:
                                    await loop.run_in_executor(None, lambda: self.gui.obs_client.req_client.set_scene_item_enabled(brb_scene, scene_item_id, False))
                                    logger.debug(f"Paused BRB clip, hidden source {brb_source}, arrgh!")
                            except Exception as e:
                                logger.debug(f"Failed to hide source {brb_source} during pause: {e}, arrgh!")
                        elif self.is_brb_clip_paused and paused_start_time > 0:
                            # Update paused time
                            total_paused_time += time.time() - paused_start_time
                            paused_start_time = time.time()
                            logger.debug(f"Accumulated paused time: {total_paused_time}s for clip {self.current_brb_clip['embed_url'] if self.current_brb_clip else 'None'}, arrgh!")
                        playback_active = False  # Deactivate playback off-scene
                        await asyncio.sleep(0.5)
                        continue

                    # Ensure clips are loaded
                    if not self.brb_clips:
                        logger.debug("No BRB clips loaded, skippin’ playback, arrgh!")
                        await asyncio.sleep(0.5)
                        continue

                    # On BRB scene: Activate playback and resume or start clip
                    playback_active = True
                    if self.current_brb_clip and self.is_brb_clip_paused:
                        # Resume clip
                        self.is_brb_clip_paused = False
                        self.brb_clip_start_time = time.time() - self.current_brb_clip_position - total_paused_time
                        total_paused_time = 0
                        paused_start_time = 0
                        clip = self.current_brb_clip
                        remaining_duration = max(0, clip.get("duration", 30) - self.current_brb_clip_position)
                        logger.debug(f"Resumin’ BRB clip {clip['embed_url']} at position {self.current_brb_clip_position}s, remainin’ duration: {remaining_duration}s, arrgh!")
                        current_clip_url = clip["embed_url"]
                        try:
                            success = await asyncio.wait_for(
                                self.play_clip_in_obs(
                                    video_url=clip["embed_url"],
                                    clip_duration=remaining_duration,
                                    scene_name=brb_scene,
                                    source_name=brb_source
                                ),
                                timeout=remaining_duration + 2
                            )
                            if success:
                                logger.debug(f"Resumed BRB clip successfully, movin’ to next, arrgh!")
                                self.current_brb_clip = None
                                self.current_brb_clip_position = 0
                                self.is_brb_clip_paused = False
                                total_paused_time = 0
                                paused_start_time = 0
                                current_clip_url = ""
                            else:
                                logger.debug(f"Resume failed on BRB scene, pausin’ clip to retry next loop, arrgh!")
                                self.is_brb_clip_paused = True
                                paused_start_time = time.time()
                        except asyncio.TimeoutError:
                            logger.debug(f"Timeout resumin’ clip {clip['embed_url']}, pausin’ clip, arrgh!")
                            self.is_brb_clip_paused = True
                            paused_start_time = time.time()
                        except Exception as e:
                            logger.debug(f"Error resumin’ clip {clip['embed_url']}: {e}, arrgh!")
                            self.is_brb_clip_paused = True
                            paused_start_time = time.time()
                    elif not self.current_brb_clip and playback_active:
                        # Start new clip
                        clip = random.choice(self.brb_clips)
                        self.current_brb_clip = clip
                        self.current_brb_clip_position = 0
                        self.is_brb_clip_paused = False
                        self.brb_clip_start_time = time.time()
                        total_paused_time = 0
                        paused_start_time = 0
                        clip_duration = clip.get("duration", 30)
                        logger.debug(f"Selected new BRB clip: {clip['embed_url']}, duration: {clip_duration}s, arrgh!")
                        current_clip_url = clip["embed_url"]
                        try:
                            success = await asyncio.wait_for(
                                self.play_clip_in_obs(
                                    video_url=clip["embed_url"],
                                    clip_duration=clip_duration,
                                    scene_name=brb_scene,
                                    source_name=brb_source
                                ),
                                timeout=clip_duration + 2
                            )
                            if success:
                                logger.debug(f"Played new BRB clip successfully, movin’ to next, arrgh!")
                                self.current_brb_clip = None
                                self.current_brb_clip_position = 0
                                self.is_brb_clip_paused = False
                                total_paused_time = 0
                                paused_start_time = 0
                                current_clip_url = ""
                            else:
                                logger.debug(f"New clip playback failed on BRB scene, pausin’ clip to retry next loop, arrgh!")
                                self.current_brb_clip_position = 0
                                self.is_brb_clip_paused = True
                                paused_start_time = time.time()
                                loop = asyncio.get_event_loop()
                                scene_item_id = self._get_scene_item_id(brb_scene, brb_source)
                                if scene_item_id is None:
                                    logger.debug(f"No scene item ID for source {brb_source} in scene {brb_scene}, skippin’ hide, arrgh!")
                                else:
                                    await loop.run_in_executor(None, lambda: self.gui.obs_client.req_client.set_scene_item_enabled(brb_scene, scene_item_id, False))
                        except asyncio.TimeoutError:
                            logger.debug(f"Timeout playin’ new clip {clip['embed_url']}, pausin’ clip, arrgh!")
                            self.current_brb_clip_position = 0
                            self.is_brb_clip_paused = True
                            paused_start_time = time.time()
                            loop = asyncio.get_event_loop()
                            scene_item_id = self._get_scene_item_id(brb_scene, brb_source)
                            if scene_item_id is None:
                                logger.debug(f"No scene item ID for source {brb_source} in scene {brb_scene}, skippin’ hide, arrgh!")
                            else:
                                await loop.run_in_executor(None, lambda: self.gui.obs_client.req_client.set_scene_item_enabled(brb_scene, scene_item_id, False))
                        except Exception as e:
                            logger.debug(f"Error playin’ new clip {clip['embed_url']}: {e}, arrgh!")
                            self.current_brb_clip_position = 0
                            self.is_brb_clip_paused = True
                            paused_start_time = time.time()
                            loop = asyncio.get_event_loop()
                            scene_item_id = self._get_scene_item_id(brb_scene, brb_source)
                            if scene_item_id is None:
                                logger.debug(f"No scene item ID for source {brb_source} in scene {brb_scene}, skippin’ hide, arrgh!")
                            else:
                                await loop.run_in_executor(None, lambda: self.gui.obs_client.req_client.set_scene_item_enabled(brb_scene, scene_item_id, False))

                    # Check if clip is still playin’
                    if self.current_brb_clip and not self.is_brb_clip_paused:
                        clip_duration = self.current_brb_clip.get("duration", 30)
                        elapsed_time = time.time() - self.brb_clip_start_time - total_paused_time
                        if elapsed_time >= clip_duration:
                            logger.debug(f"BRB clip finished (elapsed: {elapsed_time}s, duration: {clip_duration}s), movin’ to next, arrgh!")
                            self.current_brb_clip = None
                            self.current_brb_clip_position = 0
                            self.is_brb_clip_paused = False
                            total_paused_time = 0
                            paused_start_time = 0
                            current_clip_url = ""
                            loop = asyncio.get_event_loop()
                            scene_item_id = self._get_scene_item_id(brb_scene, brb_source)
                            if scene_item_id is None:
                                logger.debug(f"No scene item ID for source {brb_source} in scene {brb_scene}, skippin’ hide, arrgh!")
                            else:
                                await loop.run_in_executor(None, lambda: self.gui.obs_client.req_client.set_scene_item_enabled(brb_scene, scene_item_id, False))
                        else:
                            remaining = clip_duration - elapsed_time
                            logger.debug(f"BRB clip playin’, elapsed: {elapsed_time}s, remainin’: {remaining}s, arrgh!")
                    await asyncio.sleep(0.5)

                except Exception as e:
                    logger.debug(f"Error in BRB scene check loop: {e}, arrgh!")
                    await asyncio.sleep(1)
                    continue

        except asyncio.CancelledError:
            logger.debug("BRB scene check task cancelled, arrgh!")
            if self.current_brb_clip:
                try:
                    brb_scene = self.gui.brb_scene_dropdown.currentText().strip()
                    brb_source = self.gui.brb_source_dropdown.currentText().strip()
                    if brb_scene and brb_source:
                        if not self.is_brb_clip_paused:
                            elapsed_time = time.time() - self.brb_clip_start_time - total_paused_time
                            self.current_brb_clip_position = max(0, elapsed_time)
                            self.is_brb_clip_paused = True
                            logger.debug(f"Paused BRB clip at position {self.current_brb_clip_position}s on cancellation, arrgh!")
                        loop = asyncio.get_event_loop()
                        scene_item_id = self._get_scene_item_id(brb_scene, brb_source)
                        if scene_item_id is None:
                            logger.debug(f"No scene item ID for source {brb_source} in scene {brb_scene}, skippin’ hide, arrgh!")
                        else:
                            await loop.run_in_executor(None, lambda: self.gui.obs_client.req_client.set_scene_item_enabled(brb_scene, scene_item_id, False))
                            logger.debug(f"Hid BRB source {brb_source} on cancellation, arrgh!")
                except Exception as e:
                    logger.debug(f"Failed to hide BRB source on cancellation: {e}, arrgh!")
            raise
        except Exception as e:
            logger.debug(f"Fatal error in BRB scene check: {e}, arrgh!")
            raise
        finally:
            logger.debug("Exitin’ check_brb_scene, arrgh!")

    def _get_scene_item_id(self, scene_name, source_name):
        """Helper to get scene item ID for a source in a scene, arrgh!"""
        try:
            sources_response = self.gui.obs_client.req_client.get_scene_item_list(scene_name)
            for item in sources_response.scene_items:
                if item["sourceName"] == source_name:
                    return item["sceneItemId"]
            logger.warning(f"Source {source_name} not found in scene {scene_name}, arrgh!")
            return None
        except Exception as e:
            logger.error(f"Failed to get scene item ID for {source_name} in {scene_name}: {e}, arrgh!")
            return None

    async def play_brb_clips(self, scene_name, source_name):
        """Play BRB clips in a loop while the active scene matches the BRB scene."""
        async with self.brb_playback_lock:
            try:
                while self.brb_playing:
                    if self.brb_current_clip_index >= len(self.brb_clips):
                        self.brb_current_clip_index = 0  # Loop back to the start
                        random.shuffle(self.brb_clips)  # Randomize clips at the end of the list
                        logger.debug("Reached end of BRB clips, reshuffling and looping, arrgh!")

                    clip = self.brb_clips[self.brb_current_clip_index]
                    video_url = clip["url"]
                    clip_duration = clip["duration"]

                    # Double-check the active scene before playing
                    try:
                        response = self.gui.obs_client.req_client.get_current_program_scene()
                        current_scene = response.current_program_scene
                    except Exception as e:
                        logger.error(f"Failed to get current OBS scene during BRB playback: {e}, arrgh!")
                        self.brb_playing = False
                        break

                    if current_scene != scene_name:
                        logger.debug(f"Active scene changed to {current_scene}, stopping BRB clip playback, arrgh!")
                        self.brb_playing = False
                        break

                    # Play the clip
                    success = await self.play_clip_in_obs(video_url, clip_duration)
                    if not success:
                        logger.warning(f"Failed to play BRB clip {video_url}, skipping to next clip, arrgh!")
                    else:
                        logger.debug(f"Played BRB clip {video_url} for {clip_duration}s, arrgh!")

                    self.brb_current_clip_index += 1
            except Exception as e:
                logger.error(f"Error in BRB clip playback loop: {e}, arrgh!", exc_info=True)
            finally:
                if not self.brb_playing:
                    # Ensure the source is hidden when playback stops
                    try:
                        self.gui.obs_client.set_source_visibility(scene_name, source_name, False)
                        logger.debug(f"BRB playback stopped, source {source_name} hidden, arrgh!")
                    except Exception as e:
                        logger.error(f"Failed to hide BRB source {source_name} on stop: {e}, arrgh!")

    async def play_raid_clips(self, username, total_duration):
        """Play multiple clips from the target in OBS, arrgh!"""
        logger.info(f"Enterin’ play_raid_clips for {username}, total_duration: {total_duration}s, arrgh!")
        try:
            if self.gui.is_shutting_down:
                logger.warning("Bot be shuttin’ down, skippin’ raid clip playback, arrgh!")
                return
            token = self.gui.broadcaster_config["token"].replace("oauth:", "")
            valid, result, _ = validate_twitch_token(token)
            if not valid:
                logger.warning(f"Broadcaster token invalid: {result}, tryin’ to refresh, arrgh!")
                success = self.gui.refresh_broadcaster_token()
                if not success:
                    logger.error("Failed to refresh broadcaster token, cannot fetch clips, arrgh!")
                    await self.send_message(f"Squawk! Failed to fetch clips for {username} due to token issues, arrgh!")
                    return
                token = self.gui.broadcaster_config["token"].replace("oauth:", "")
            headers = {
                "Client-ID": CLIENT_ID,
                "Authorization": f"Bearer {token}"
            }
            user_id = await self._get_user_id(username)
            if not user_id:
                logger.error(f"No user ID for {username}, no clips to play, arrgh!")
                await self.send_message(f"Squawk! No clips found for {username}, arrgh!")
                return
            clips = []
            cursor = None
            for _ in range(3):
                clips_url = f"https://api.twitch.tv/helix/clips?broadcaster_id={user_id}&first=100"
                if cursor:
                    clips_url += f"&after={cursor}"
                async with aiohttp.ClientSession() as session:
                    async with session.get(clips_url, headers=headers) as response:
                        if response.status != 200:
                            logger.error(f"Failed to fetch clips for {username}: {response.status}, arrgh!")
                            break
                        clips_data = await response.json()
                        clips.extend(clips_data.get("data", []))
                        cursor = clips_data.get("pagination", {}).get("cursor")
                        if not cursor or not clips_data.get("data"):
                            break
            if not clips:
                logger.info(f"No clips found for {username}, arrgh!")
                await self.send_message(f"Squawk! No clips found for {username}, arrgh!")
                return
            random.shuffle(clips)
            logger.info(f"Fetched {len(clips)} clips for {username}, arrgh!")
            elapsed = 0
            scene_name = self.gui.raid_scene_dropdown.currentText()
            source_name = self.gui.raid_source_dropdown.currentText()
            for clip in clips:
                if not self.gui.raid_active or elapsed >= total_duration:
                    logger.info(f"Stoppin’ raid clips: raid_active={self.gui.raid_active}, elapsed={elapsed}/{total_duration}, arrgh!")
                    break
                clip_id = clip.get("id", "unknown")
                clip_url = f"https://clips.twitch.tv/embed?clip={clip_id}&parent=localhost&autoplay=true&muted=false"
                clip_duration = min(clip["duration"], total_duration - elapsed)
                logger.info(f"Playin’ clip {clip_id} for {clip_duration}s, arrgh!")
                success = await self.play_clip_in_obs(
                    clip_url,
                    clip_duration,
                    context="raid",
                    scene_name=scene_name,
                    source_name=source_name
                )
                if success:
                    elapsed += clip_duration
                else:
                    logger.error(f"Failed to play clip {clip_id}, movin’ to next, arrgh!")
            self.gui.raid_active = False
            if self.gui.obs_client and self.gui.obs_client.connected and scene_name and source_name:
                self.gui.obs_client.set_source_visibility(scene_name, source_name, False)
                logger.info(f"Finished raid clips, hid source {source_name}, arrgh!")
        except Exception as e:
            logger.error(f"Error playin’ raid clips for {username}: {e}, arrgh!", exc_info=True)
            self.gui.raid_active = False
            if self.gui.obs_client and self.gui.obs_client.connected and scene_name and source_name:
                self.gui.obs_client.set_source_visibility(scene_name, source_name, False)
                logger.info(f"Finished raid clips with error, hid source {source_name}, arrgh!")
        finally:
            logger.info("Exitin’ play_raid_clips, arrgh!")

    async def start_brb_scene_check(self):
        """Start the periodic task to check the active OBS scene for BRB playback, arrgh!"""
        if not self.gui.config["toggles"].get("intermission_enabled", True):
            logger.debug("Intermission toggle disabled, skippin’ BRB scene check, arrgh!")
            return
        max_retries = 3
        retry_delay = 5
        attempt = 1
        while attempt <= max_retries:
            try:
                if self.brb_scene_check_task and not self.brb_scene_check_task.done():
                    logger.debug("BRB scene check task already runnin’, arrgh!")
                    return
                self.brb_scene_check_task = asyncio.create_task(self.check_brb_scene())
                logger.debug("Started BRB scene check task, arrgh!")
                return
            except Exception as e:
                logger.error(f"Failed to start BRB scene check (attempt {attempt}/{max_retries}): {e}, arrgh!", exc_info=True)
                if attempt == max_retries:
                    logger.error("Max retries reached, givin’ up on BRB scene check, arrgh!")
                    file_handler.flush()
                    console_handler.flush()
                    self.error_occurred.emit(f"Failed to start BRB scene check after {max_retries} attempts: {e}, arrgh!")
                    return
                attempt += 1
                await asyncio.sleep(retry_delay)
        logger.debug("Exitin’ start_brb_scene_check, arrgh!")

    async def stop_brb_scene_check(self):
        """Stop the periodic task for checking the active OBS scene."""
        if self.brb_scene_check_task and not self.brb_scene_check_task.done():
            self.brb_scene_check_task.cancel()
            try:
                await self.brb_scene_check_task
            except asyncio.CancelledError:
                pass
            logger.debug("Stopped BRB scene check task, arrgh!")
        self.brb_playing = False
        self.brb_current_clip_index = 0
        # Hide the source if it’s currently visible
        brb_scene = self.gui.brb_settings.get("scene", "")
        brb_source = self.gui.brb_settings.get("source", "")
        if brb_scene and brb_source:
            try:
                self.gui.obs_client.set_source_visibility(brb_scene, brb_source, False)
                logger.debug(f"Stopped BRB, source {brb_source} hidden, arrgh!")
            except Exception as e:
                logger.error(f"Failed to hide BRB source {brb_source} on stop: {e}, arrgh!")

    def update_commands(self):
        """Update dynamic commands based on GUI inputs."""
        if not self.gui.config["toggles"].get("commands_enabled", True):
            logger.debug("Commands toggle disabled, skippin’ command registration, arrgh!")
            return
        try:
            # Remove existing shoutout command
            shoutout_command_name = self.gui.shoutout_command_input.text().strip()
            if not shoutout_command_name.startswith("!"):
                shoutout_command_name = shoutout_command_name.lstrip("!")
            if shoutout_command_name in self.commands:
                try:
                    self.remove_command(shoutout_command_name)
                    logger.debug(f"Removed existin’ shoutout command '{shoutout_command_name}', arrgh!")
                except Exception as e:
                    logger.warning(f"Failed to remove shoutout command '{shoutout_command_name}': {e}, arrgh!", exc_info=True)

            # Add the new shoutout command if shoutouts are enabled
            if self.gui.config["toggles"].get("shoutouts_enabled", True):
                try:
                    self.command(name=shoutout_command_name)(self.shoutout)
                    logger.debug(f"Added shoutout command '{shoutout_command_name}', arrgh!")
                except Exception as e:
                    logger.error(f"Failed to add shoutout command '{shoutout_command_name}': {e}, arrgh!", exc_info=True)
                    self.error_occurred.emit(f"Failed to add shoutout command: {e}, arrgh!")
        except Exception as e:
            logger.error(f"Unexpected error in update_commands: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            self.error_occurred.emit(f"Unexpected error in update_commands: {e}, arrgh!")

    def update_counter_commands(self):
            """Register commands for all counters, including increment functionality."""
            for counter in self.gui.counters:
                command_name = counter["command"].lstrip("!")
                if command_name in self.commands:
                    self.remove_command(command_name)
                
                @self.command(name=command_name)
                async def counter_command(ctx: commands.Context):
                    # Find the counter
                    for c in self.gui.counters:
                        if c["command"].lstrip("!") == ctx.command.name:
                            counter = c
                            break
                    else:
                        logger.error(f"Counter for command {ctx.command.name} not found, arrgh!")
                        return

                    # Increment the counter value
                    counter["value"] += counter["increment"]
                    self.gui._save_config()  # Save the updated counter value
                    self.gui.update_counters_list()  # Update the GUI list

                    # Send the updated value to chat
                    await ctx.send(f"{counter['name']}: {counter['value']}, arrgh!")
                    logger.debug(f"Counter command {ctx.command.name} executed: {counter['name']} = {counter['value']}, arrgh!")

    async def event_message(self, message):
        if message.echo:
            return

        logger.debug(f"Incoming message from {message.author.name if message.author else 'Unknown'}: {message.content}, arrgh!")

        if message.content.startswith("!"):
            command = message.content[1:].lower().split()[0]
            for counter in self.gui.counters:
                if command == counter["command"]:
                    counter["value"] += counter["increment"]
                    self.gui._save_config()
                    self.gui.update_counters_list()
                    channel_name = self.channel.lstrip("#")
                    channel = self.get_channel(channel_name)
                    if channel:
                        await channel.send(f"{counter['name']}: {counter['value']}")
                        logger.debug(f"Counter '{counter['name']}' incremented to {counter['value']}, arrgh!")
                    else:
                        logger.error(f"Failed to send counter message for '{counter['name']}': Channel not found, arrgh!")
                    break

        await self.handle_commands(message)

    async def start_all(self):
        logger.debug("Starting both broadcaster client and bot, arrgh!")
        try:
            await asyncio.gather(
                self.broadcaster_client.start(),
                self.start()
            )
        except Exception as e:
            logger.error(f"Failed to start clients: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            raise

    async def close(self):
        logger.debug("Closing SquawkBot, arrgh!")
        try:
            # Stop the BRB scene check task
            await self.stop_brb_scene_check()

            # Cancel all timer tasks
            for task in self.gui.timer_tasks.values():
                task.cancel()
            self.gui.timer_tasks.clear()
            logger.debug("Cancelled all timer tasks, arrgh!")

            # Close the broadcaster client
            if self.broadcaster_client:
                await self.broadcaster_client.close()
                logger.debug("Broadcaster client closed, arrgh!")

            # Call the parent close method only if self._connection is valid
            logger.debug(f"self._connection state: {self._connection}, arrgh!")
            if (hasattr(self, '_connection') and 
                self._connection is not None and 
                hasattr(self._connection, '_close') and 
                callable(getattr(self._connection, '_close', None))):
                logger.debug("self._connection be valid, callin’ super().close(), arrgh!")
                await super().close()
                logger.debug("SquawkBot closed, arrgh!")
            else:
                logger.warning("No valid WebSocket connection to close, skippin’ super().close(), arrgh!")
        except Exception as e:
            logger.error(f"Error closing SquawkBot: {e}, arrgh!", exc_info=True)

class SquawkBotGUI(QMainWindow):
    toggle_labels = {
        "fonts_enabled": "Fonts",
        "obs_enabled": "OBS",
        "timers_enabled": "Timers",
        "shoutouts_enabled": "Shoutouts",
        "intermission_enabled": "Intermission (BRB)",
        "raids_enabled": "Raids",
        "commands_enabled": "Commands",
        "file_renamer_enabled": "File Renamer"
    }

    def __init__(self, app):
        super().__init__(None)
        self.app = app
        try:
            logger.debug("Starting SquawkBotGUI initialization, arrgh!")
            
            # Initialize config with default values
            default_config = {
                "broadcaster": {"username": "", "token": "", "channel": "", "issued_at": 0, "expires_at": 0, "refresh_token": ""},
                "bot": {"username": "", "token": "", "issued_at": 0, "expires_at": 0, "refresh_token": ""},
                "obs": {"server_ip": DEFAULT_OBS_IP, "server_port": DEFAULT_OBS_PORT, "server_password": ""},
                "selected_font": "Arial",
                "timers": [],
                "counters": [],
                "shoutout_settings": {
                    "command": "!so",
                    "message": "Give a shoutout to {user} at {link}, arrgh!",
                    "access_level": "mods",
                    "scene": "",
                    "source": ""
                },
                "brb_settings": {
                    "scene": "",
                    "source": "",
                    "last_clip_url": ""
                },
                "file_renamer": {"directory": "", "include_subdirs": True},
                "raid_settings": {
                    "targets": [],
                    "command": "!raid",
                    "message": "Squawk! Raidin’ {target}, arrgh!",
                    "scene": "",
                    "source": "",
                    "clip_duration": "60"
                },
                "commands": [],
                "intro_sounds": [],
                "toggles": {
                    "fonts_enabled": True,
                    "obs_enabled": True,
                    "timers_enabled": True,
                    "shoutouts_enabled": True,
                    "intermission_enabled": True,
                    "raids_enabled": True,
                    "commands_enabled": True,
                    "file_renamer_enabled": True
                }
            }
            try:
                self.config = self._load_config()
                logger.debug(f"Loaded config: {self.config}, arrgh!")
            except Exception as e:
                logger.error(f"Failed to load config: {e}, arrgh!", exc_info=True)
                self.config = default_config
                QMessageBox.warning(self, "Blunder", f"Failed to load config: {e}. Usin’ default config, arrgh!")
            
            # Merge default config
            try:
                for key, value in default_config.items():
                    if key not in self.config:
                        self.config[key] = value
                    elif isinstance(value, dict):
                        for subkey, subvalue in value.items():
                            if subkey not in self.config[key]:
                                self.config[key][subkey] = subvalue
                logger.debug(f"Config after mergin’ defaults: {self.config}, arrgh!")
            except Exception as e:
                logger.error(f"Failed to merge config: {e}, arrgh!", exc_info=True)
                QMessageBox.warning(self, "Blunder", f"Failed to merge config: {e}. Some settings may be missin’, arrgh!")

            # Initialize state
            self.timers = self.config.get("timers", [])
            self.counters = self.config.get("counters", [])
            self.raid_targets = self.config.get("raid_settings", {}).get("targets", [])
            self.raid_command = self.config.get("raid_settings", {}).get("command", "!raid")
            self.raid_message = self.config.get("raid_settings", {}).get("message", "Squawk! Raidin’ {target}, arrgh!")
            self.raid_settings = self.config["raid_settings"]
            self.raid_clip_duration = self.config.get("raid_settings", {}).get("clip_duration", "60")
            self.stop_clips_flag = False
            self.raid_active = False
            logger.debug(f"Initialized timers: {self.timers}, counters: {self.counters}, raid_targets: {self.raid_targets}, raid_settings: {self.raid_settings}, arrgh!")

            self.broadcaster_config = self.config["broadcaster"]
            self.bot_config = self.config["bot"]
            self.obs_config = self.config["obs"]
            self.selected_font = self.config["selected_font"]
            self.shoutout_settings = self.config["shoutout_settings"]
            self.brb_settings = self.config["brb_settings"]
            self.bot = None
            self.bot_thread = None
            self.obs_client = OBSClient(self)
            self.shoutout_queue = []
            self.timer_tasks = {}
            self.is_shutting_down = False

            self.known_files = set()
            self.directory = self.config["file_renamer"]["directory"]
            self.include_subdirs = self.config["file_renamer"]["include_subdirs"]
            self.observer = None
            self.active_files = {}

            # Main widget and layout
            self.central_widget = QWidget()
            self.setCentralWidget(self.central_widget)
            self.main_layout = QVBoxLayout(self.central_widget)
            logger.debug("Central widget and layout created, arrgh!")
            
            # Top layout
            top_layout = QHBoxLayout()
            self.status_label = QLabel("Bot Status: Anchored")
            self.status_label.setStyleSheet(f"QLabel {{ color: {GOLD}; background-color: transparent; font-family: '{self.selected_font}'; font-size: 12pt; }}")
            top_layout.addWidget(self.status_label)
            top_layout.addStretch()
            self.start_button = QPushButton("Hoist the Sails!")
            self.start_button.setStyleSheet(
                f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
            )
            self.start_button.clicked.connect(self.start_bot)
            top_layout.addWidget(self.start_button)
            self.stop_button = QPushButton("Drop Anchor")
            self.stop_button.setStyleSheet(
                f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
            )
            self.stop_button.clicked.connect(self.stop_bot)
            self.stop_button.setEnabled(False)
            top_layout.addWidget(self.stop_button)
            self.main_layout.addLayout(top_layout)
            logger.debug("Top layout with status and buttons added, arrgh!")
            
            # Split layout
            self.split_layout = QHBoxLayout()
            self.main_layout.addLayout(self.split_layout)
            
            # Vertical tab list
            self.tab_list = QListWidget()
            self.tab_list.setStyleSheet(
                f"QListWidget {{ background-color: {TYRIAN_PURPLE}; color: {GOLD}; border: 0px; font-family: '{self.selected_font}'; font-size: 14pt; }}"
                f"QListWidget::item {{ padding: 15px; }}"
                f"QListWidget::item:selected {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; }}"
            )
            self.tab_list.setFixedWidth(300)
            self.tab_names = ["⚙️ General", "🔐 Login", "🖌️ Fonts", "🎥 OBS", "⏰ Timers", "📣 Shoutouts", "🎬 Intermission", "🏴‍☠️ Raids", "📋 Commands"]
            for tab_name in self.tab_names:
                self.tab_list.addItem(tab_name)
            self.tab_list.currentRowChanged.connect(self.on_tab_changed)
            self.split_layout.addWidget(self.tab_list)
            logger.debug("Vertical tab list set up, arrgh!")
            
            # Tab content stack
            self.tab_stack = QStackedWidget()
            self.tab_stack.setStyleSheet(f"QStackedWidget {{ background-color: {TYRIAN_PURPLE}; border: 0px; }}")
            self.tab_widgets = {}
            self.status_labels = {}
            for tab_name in self.tab_names:
                tab_widget = QWidget()
                tab_layout = QVBoxLayout(tab_widget)
                if tab_name == "⚙️ General":
                    general_label = QLabel("General Settings")
                    general_label.setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 20pt; font-weight: bold; }}")
                    tab_layout.addWidget(general_label)
                    
                    toggles_form = QFormLayout()
                    toggles_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
                    
                    self.feature_buttons = {}
                    for toggle_key, label in self.toggle_labels.items():
                        toggle_button = QPushButton("Disable" if self.config["toggles"].get(toggle_key, True) else "Enable")
                        toggle_button.setStyleSheet(
                            f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 5px; font-family: '{self.selected_font}'; font-size: 16pt; }}"
                            f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                        )
                        toggle_button.clicked.connect(lambda _, k=toggle_key, b=toggle_button: self.toggle_feature(k, b))
                        self.feature_buttons[toggle_key] = toggle_button
                        toggles_form.addRow(f"{label}:", toggle_button)
                    
                    tab_layout.addLayout(toggles_form)
                    tab_layout.addStretch()
                elif tab_name == "🔐 Login":
                    form_layout = QFormLayout()
                    form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
                    
                    broadcaster_label = QLabel("Broadcaster Account:")
                    broadcaster_label.setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 12pt; font-weight: bold; }}")
                    form_layout.addRow(broadcaster_label)
                    
                    self.broadcaster_status_label = QLabel("Broadcaster: Not Logged In")
                    self.broadcaster_status_label.setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 12pt; }}")
                    form_layout.addRow(self.broadcaster_status_label)
                    
                    self.broadcaster_username_input = QLineEdit()
                    self.broadcaster_username_input.setReadOnly(True)
                    self.broadcaster_username_input.setStyleSheet(
                        f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; padding: 5px; }}"
                    )
                    self.broadcaster_username_input.blockSignals(True)
                    self.broadcaster_username_input.setText(self.broadcaster_config["username"])
                    self.broadcaster_username_input.blockSignals(False)
                    form_layout.addRow(QLabel("Broadcaster Username:"), self.broadcaster_username_input)
                    
                    self.broadcaster_channel_input = QLineEdit()
                    self.broadcaster_channel_input.setStyleSheet(
                        f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; padding: 5px; }}"
                    )
                    self.broadcaster_channel_input.blockSignals(True)
                    self.broadcaster_channel_input.setText(self.broadcaster_config["channel"])
                    self.broadcaster_channel_input.blockSignals(False)
                    form_layout.addRow(QLabel("Broadcaster Channel:"), self.broadcaster_channel_input)
                    
                    broadcaster_button_layout = QHBoxLayout()
                    broadcaster_login_button = QPushButton("Login as Broadcaster")
                    broadcaster_login_button.setStyleSheet(
                        f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                        f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                    )
                    broadcaster_login_button.clicked.connect(lambda: self.handle_login("broadcaster"))
                    broadcaster_button_layout.addWidget(broadcaster_login_button)
                    
                    self.broadcaster_logout_button = QPushButton("Logout")
                    self.broadcaster_logout_button.setStyleSheet(
                        f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                        f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                    )
                    self.broadcaster_logout_button.clicked.connect(lambda: self.handle_logout("broadcaster"))  # Fixed to handle_logout
                    self.broadcaster_logout_button.setEnabled(bool(self.broadcaster_config["username"]))
                    broadcaster_button_layout.addWidget(self.broadcaster_logout_button)
                    
                    form_layout.addRow(broadcaster_button_layout)
                    
                    bot_label = QLabel("Bot Account:")
                    bot_label.setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 12pt; font-weight: bold; }}")
                    form_layout.addRow(bot_label)
                    
                    self.bot_status_label = QLabel("Bot: Not Logged In")
                    self.bot_status_label.setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 12pt; }}")
                    form_layout.addRow(self.bot_status_label)
                    
                    self.bot_username_input = QLineEdit()
                    self.bot_username_input.setReadOnly(True)
                    self.bot_username_input.setStyleSheet(
                        f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; padding: 5px; }}"
                    )
                    self.bot_username_input.blockSignals(True)
                    self.bot_username_input.setText(self.bot_config["username"])
                    self.bot_username_input.blockSignals(False)
                    form_layout.addRow(QLabel("Bot Username:"), self.bot_username_input)
                    
                    bot_button_layout = QHBoxLayout()
                    bot_login_button = QPushButton("Login as Bot")
                    bot_login_button.setStyleSheet(
                        f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                        f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                    )
                    bot_login_button.clicked.connect(lambda: self.handle_login("bot"))
                    bot_button_layout.addWidget(bot_login_button)
                    
                    self.bot_logout_button = QPushButton("Logout")
                    self.bot_logout_button.setStyleSheet(
                        f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                        f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                    )
                    self.bot_logout_button.clicked.connect(lambda: self.handle_logout("bot"))
                    self.bot_logout_button.setEnabled(bool(self.bot_config["username"]))
                    bot_button_layout.addWidget(self.bot_logout_button)
                    
                    form_layout.addRow(bot_button_layout)
                    
                    tab_layout.addLayout(form_layout)
                    tab_layout.addStretch()
                elif tab_name == "🖌️ Fonts":
                    self.status_labels["fonts_enabled"] = QLabel("Fonts: Enabled" if self.config["toggles"].get("fonts_enabled", True) else "Fonts: Disabled")
                    self.status_labels["fonts_enabled"].setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 12pt; }}")
                    tab_layout.addWidget(self.status_labels["fonts_enabled"])
                    
                    font_label = QLabel("Select Font:")
                    font_label.setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 12pt; }}")
                    tab_layout.addWidget(font_label)
                    self.font_combo = QComboBox()
                    self.font_combo.setStyleSheet(
                        f"QComboBox {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; padding: 5px; }}"
                        f"QComboBox::drop-down {{ border: 0px; }}"
                    )
                    self.font_combo.setEditable(True)
                    self.font_combo.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
                    self.font_combo.setMinimumWidth(200)
                    tab_layout.addWidget(self.font_combo)
                    tab_layout.addStretch()
                    self._populate_fonts()
                    proxy_model = QSortFilterProxyModel()
                    proxy_model.setSourceModel(self.font_combo.model())
                    completer = QCompleter(proxy_model, self.font_combo)
                    completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
                    self.font_combo.setCompleter(completer)
                    self.font_combo.blockSignals(True)
                    self.font_combo.currentTextChanged.connect(self.update_fonts)
                elif tab_name == "🎥 OBS":
                    form_layout = QFormLayout()
                    form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
                    
                    self.status_labels["obs_enabled"] = QLabel("OBS: Enabled" if self.config["toggles"].get("obs_enabled", True) else "OBS: Disabled")
                    self.status_labels["obs_enabled"].setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 12pt; }}")
                    form_layout.addRow(self.status_labels["obs_enabled"])
                    
                    obs_label = QLabel("OBS WebSocket Settings:")
                    obs_label.setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 12pt; font-weight: bold; }}")
                    form_layout.addRow(obs_label)
                    
                    self.obs_status_label = QLabel("OBS: Disconnected")
                    self.obs_status_label.setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 12pt; }}")
                    form_layout.addRow(self.obs_status_label)
                    
                    self.obs_ip_input = QLineEdit()
                    self.obs_ip_input.setStyleSheet(
                        f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; padding: 5px; }}"
                    )
                    self.obs_ip_input.blockSignals(True)
                    self.obs_ip_input.setText(self.obs_config["server_ip"])
                    self.obs_ip_input.blockSignals(False)
                    form_layout.addRow(QLabel("Server IP:"), self.obs_ip_input)
                    
                    self.obs_port_input = QLineEdit()
                    self.obs_port_input.setStyleSheet(
                        f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; padding: 5px; }}"
                    )
                    self.obs_port_input.blockSignals(True)
                    self.obs_port_input.setText(str(self.obs_config["server_port"]))
                    self.obs_port_input.blockSignals(False)
                    form_layout.addRow(QLabel("Server Port:"), self.obs_port_input)
                    
                    self.obs_password_input = QLineEdit()
                    self.obs_password_input.setEchoMode(QLineEdit.EchoMode.Password)
                    self.obs_password_input.setStyleSheet(
                        f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; padding: 5px; }}"
                    )
                    self.obs_password_input.blockSignals(True)
                    self.obs_password_input.setText(self.obs_config["server_password"])
                    self.obs_password_input.blockSignals(False)
                    form_layout.addRow(QLabel("Server Password:"), self.obs_password_input)
                    
                    file_renamer_label = QLabel("File Renamer Settings:")
                    file_renamer_label.setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 12pt; font-weight: bold; }}")
                    form_layout.addRow(file_renamer_label)
                    
                    self.status_labels["file_renamer_enabled"] = QLabel("File Renamer: Enabled" if self.config["toggles"].get("file_renamer_enabled", True) else "File Renamer: Disabled")
                    self.status_labels["file_renamer_enabled"].setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 12pt; }}")
                    form_layout.addRow(self.status_labels["file_renamer_enabled"])
                    
                    self.file_renamer_dir_input = QLineEdit()
                    self.file_renamer_dir_input.setPlaceholderText("Enter OBS recording directory")
                    self.file_renamer_dir_input.setStyleSheet(
                        f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; padding: 5px; }}"
                    )
                    self.file_renamer_dir_input.blockSignals(True)
                    self.file_renamer_dir_input.setText(self.config["file_renamer"]["directory"])
                    self.file_renamer_dir_input.blockSignals(False)
                    self.file_renamer_dir_input.textChanged.connect(self.update_file_renamer_dir)
                    dir_layout = QHBoxLayout()
                    dir_layout.addWidget(self.file_renamer_dir_input)
                    self.browse_button = QPushButton("Browse")
                    self.browse_button.setStyleSheet(
                        f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                        f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                    )
                    self.browse_button.clicked.connect(self.browse_directory)
                    dir_layout.addWidget(self.browse_button)
                    form_layout.addRow(QLabel("Recording Directory:"), dir_layout)
                    
                    self.file_renamer_subdirs_check = QCheckBox("Include Subdirectories")
                    self.file_renamer_subdirs_check.setStyleSheet(
                        f"QCheckBox {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                    )
                    self.file_renamer_subdirs_check.blockSignals(True)
                    self.file_renamer_subdirs_check.setChecked(self.config["file_renamer"]["include_subdirs"])
                    self.file_renamer_subdirs_check.blockSignals(False)
                    self.file_renamer_subdirs_check.stateChanged.connect(self.update_file_renamer_subdirs)
                    form_layout.addRow(self.file_renamer_subdirs_check)
                    
                    button_layout = QHBoxLayout()
                    self.obs_connect_button = QPushButton("Connect")
                    self.obs_connect_button.setStyleSheet(
                        f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                        f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                    )
                    self.obs_connect_button.clicked.connect(self.handle_obs_connect)
                    button_layout.addWidget(self.obs_connect_button)
                    
                    self.obs_disconnect_button = QPushButton("Disconnect")
                    self.obs_disconnect_button.setStyleSheet(
                        f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                        f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                    )
                    self.obs_disconnect_button.clicked.connect(self.handle_obs_disconnect)
                    self.obs_disconnect_button.setEnabled(False)
                    button_layout.addWidget(self.obs_disconnect_button)
                    
                    form_layout.addRow(button_layout)
                    tab_layout.addLayout(form_layout)
                    tab_layout.addStretch()
                elif tab_name == "⏰ Timers":
                    self.status_labels["timers_enabled"] = QLabel("Timers: Enabled" if self.config["toggles"].get("timers_enabled", True) else "Timers: Disabled")
                    self.status_labels["timers_enabled"].setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 12pt; }}")
                    tab_layout.addWidget(self.status_labels["timers_enabled"])
                    
                    timers_label = QLabel("Timers")
                    timers_label.setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 16pt; font-weight: bold; }}")
                    tab_layout.addWidget(timers_label)
                    
                    timer_form_layout = QFormLayout()
                    timer_form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
                    
                    self.timer_name_input = QLineEdit()
                    self.timer_name_input.setStyleSheet(
                        f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; padding: 5px; }}"
                    )
                    timer_form_layout.addRow(QLabel("Timer Name:"), self.timer_name_input)
                    
                    self.timer_message_input = QLineEdit()
                    self.timer_message_input.setStyleSheet(
                        f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; padding: 5px; }}"
                    )
                    timer_form_layout.addRow(QLabel("Message:"), self.timer_message_input)
                    
                    self.timer_minutes_input = QLineEdit("0")
                    self.timer_minutes_input.setStyleSheet(
                        f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; padding: 5px; }}"
                    )
                    timer_form_layout.addRow(QLabel("Minutes:"), self.timer_minutes_input)
                    
                    self.timer_seconds_input = QLineEdit("0")
                    self.timer_seconds_input.setStyleSheet(
                        f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; padding: 5px; }}"
                    )
                    timer_form_layout.addRow(QLabel("Seconds:"), self.timer_seconds_input)
                    
                    tab_layout.addLayout(timer_form_layout)
                    
                    self.timers_list = QListWidget()
                    self.timers_list.setStyleSheet(
                        f"QListWidget {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                    )
                    self.timers_list.itemDoubleClicked.connect(self.update_timer)
                    self.timers_list.itemSelectionChanged.connect(self.on_timer_selected)
                    self.update_timers_list()
                    tab_layout.addWidget(self.timers_list)
                    
                    button_layout = QHBoxLayout()
                    add_timer_button = QPushButton("Add Timer")
                    add_timer_button.setStyleSheet(
                        f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                        f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                    )
                    add_timer_button.clicked.connect(self.add_timer)
                    button_layout.addWidget(add_timer_button)
                    
                    update_timer_button = QPushButton("Update Timer")
                    update_timer_button.setStyleSheet(
                        f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                        f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                    )
                    update_timer_button.clicked.connect(self.update_timer)
                    button_layout.addWidget(update_timer_button)
                    
                    delete_timer_button = QPushButton("Remove Timer")
                    delete_timer_button.setStyleSheet(
                        f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                        f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                    )
                    delete_timer_button.clicked.connect(self.delete_timer)
                    button_layout.addWidget(delete_timer_button)
                    
                    tab_layout.addLayout(button_layout)
                    
                    counters_label = QLabel("Counters")
                    counters_label.setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 16pt; font-weight: bold; }}")
                    tab_layout.addWidget(counters_label)
                    
                    counter_form_layout = QFormLayout()
                    counter_form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
                    
                    self.counter_name_input = QLineEdit()
                    self.counter_name_input.setStyleSheet(
                        f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; padding: 5px; }}"
                    )
                    counter_form_layout.addRow(QLabel("Counter Name:"), self.counter_name_input)
                    
                    self.counter_command_input = QLineEdit()
                    self.counter_command_input.setStyleSheet(
                        f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; padding: 5px; }}"
                    )
                    counter_form_layout.addRow(QLabel("Command:"), self.counter_command_input)
                    
                    self.counter_increment_input = QLineEdit("1")
                    self.counter_increment_input.setStyleSheet(
                        f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; padding: 5px; }}"
                    )
                    counter_form_layout.addRow(QLabel("Increment:"), self.counter_increment_input)
                    
                    tab_layout.addLayout(counter_form_layout)
                    
                    self.counters_list = QListWidget()
                    self.counters_list.setStyleSheet(
                        f"QListWidget {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                    )
                    self.counters_list.itemDoubleClicked.connect(self.update_counter)
                    self.counters_list.itemSelectionChanged.connect(self.on_counter_selected)
                    self.update_counters_list()
                    tab_layout.addWidget(self.counters_list)
                    
                    counter_button_layout = QHBoxLayout()
                    add_counter_button = QPushButton("Add Counter")
                    add_counter_button.setStyleSheet(
                        f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                        f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                    )
                    add_counter_button.clicked.connect(self.add_counter)
                    counter_button_layout.addWidget(add_counter_button)
                    
                    self.counter_update_button = QPushButton("Update Counter")
                    self.counter_update_button.setStyleSheet(
                        f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                        f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                    )
                    self.counter_update_button.clicked.connect(self.update_counter)
                    self.counter_update_button.setEnabled(False)
                    counter_button_layout.addWidget(self.counter_update_button)
                    
                    self.counter_delete_button = QPushButton("Remove Counter")
                    self.counter_delete_button.setStyleSheet(
                        f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                        f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                    )
                    self.counter_delete_button.clicked.connect(self.delete_counter)
                    self.counter_delete_button.setEnabled(False)
                    counter_button_layout.addWidget(self.counter_delete_button)
                    
                    tab_layout.addLayout(counter_button_layout)
                    tab_layout.addStretch()
                elif tab_name == "📣 Shoutouts":
                    self.status_labels["shoutouts_enabled"] = QLabel("Shoutouts: Enabled" if self.config["toggles"].get("shoutouts_enabled", True) else "Shoutouts: Disabled")
                    self.status_labels["shoutouts_enabled"].setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 12pt; }}")
                    tab_layout.addWidget(self.status_labels["shoutouts_enabled"])
                    
                    shoutout_label = QLabel("Shoutout Settings")
                    shoutout_label.setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 16pt; font-weight: bold; }}")
                    tab_layout.addWidget(shoutout_label)

                    shoutout_form_layout = QFormLayout()
                    shoutout_form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

                    self.shoutout_command_input = QLineEdit()
                    self.shoutout_command_input.setStyleSheet(
                        f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; padding: 5px; }}"
                    )
                    self.shoutout_command_input.blockSignals(True)
                    self.shoutout_command_input.setText(self.shoutout_settings["command"])
                    self.shoutout_command_input.blockSignals(False)
                    self.shoutout_command_input.textChanged.connect(self.save_shoutout_settings)
                    shoutout_form_layout.addRow(QLabel("Shoutout Command:"), self.shoutout_command_input)

                    self.shoutout_message_input = QLineEdit()
                    self.shoutout_message_input.setStyleSheet(
                        f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; padding: 5px; }}"
                    )
                    self.shoutout_message_input.blockSignals(True)
                    self.shoutout_message_input.setText(self.shoutout_settings["message"])
                    self.shoutout_message_input.blockSignals(False)
                    self.shoutout_message_input.textChanged.connect(self.save_shoutout_settings)
                    shoutout_form_layout.addRow(QLabel("Shoutout Message:"), self.shoutout_message_input)

                    access_label = QLabel("Access Level:")
                    access_label.setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 12pt; }}")
                    self.access_dropdown = QComboBox()
                    self.access_dropdown.addItems(["Broadcaster", "Mods", "VIPs", "Regulars", "All"])
                    self.access_dropdown.setStyleSheet(
                        f"QComboBox {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; padding: 5px; }}"
                    )
                    self.access_dropdown.blockSignals(True)
                    self.access_dropdown.setCurrentText(self.shoutout_settings["access_level"].capitalize())
                    self.access_dropdown.blockSignals(False)
                    self.access_dropdown.currentTextChanged.connect(self.save_shoutout_settings)
                    shoutout_form_layout.addRow(access_label, self.access_dropdown)

                    scene_label = QLabel("Select Scene:")
                    scene_label.setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 12pt; }}")
                    self.scene_dropdown = QComboBox()
                    self.scene_dropdown.setStyleSheet(
                        f"QComboBox {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; padding: 5px; }}"
                    )
                    self.scene_dropdown.blockSignals(True)
                    scenes = self._get_obs_scenes()
                    if not scenes:
                        logger.warning("No OBS scenes found; check OBS connection, arrgh!")
                        scenes = ["(No scenes available)"]
                    self.scene_dropdown.addItems(scenes)
                    if self.shoutout_settings.get("scene", "") in scenes:
                        self.scene_dropdown.setCurrentText(self.shoutout_settings["scene"])
                    elif scenes != ["(No scenes available)"]:
                        self.scene_dropdown.setCurrentText(scenes[0])  # Default to first scene
                    self.scene_dropdown.blockSignals(False)
                    self.scene_dropdown.currentTextChanged.connect(self.on_scene_selected)
                    self.scene_dropdown.currentTextChanged.connect(self.save_shoutout_settings)
                    shoutout_form_layout.addRow(scene_label, self.scene_dropdown)

                    source_label = QLabel("Select Source:")
                    source_label.setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 12pt; }}")
                    self.source_dropdown = QComboBox()
                    self.source_dropdown.setStyleSheet(
                        f"QComboBox {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; padding: 5px; }}"
                    )
                    self.source_dropdown.blockSignals(True)
                    selected_scene = self.scene_dropdown.currentText()
                    if selected_scene and selected_scene != "(No scenes available)" and self.obs_client.connected:
                        try:
                            sources = self.obs_client.get_sources(selected_scene)
                            if not sources:
                                logger.warning(f"No sources found for scene {selected_scene}, arrgh!")
                                sources = ["(No sources available)"]
                            self.source_dropdown.addItems(sources)
                            if self.shoutout_settings.get("source", "") in sources:
                                self.source_dropdown.setCurrentText(self.shoutout_settings["source"])
                            elif sources != ["(No sources available)"]:
                                self.source_dropdown.setCurrentText(sources[0])  # Default to first source
                        except Exception as e:
                            logger.error(f"Failed to populate sources for shoutout scene {selected_scene}: {e}, arrgh!")
                            self.source_dropdown.addItems(["(No sources available)"])
                    else:
                        self.source_dropdown.addItems(["(No sources available)"])
                    self.source_dropdown.blockSignals(False)
                    self.source_dropdown.currentTextChanged.connect(self.save_shoutout_settings)
                    self.source_dropdown.currentTextChanged.connect(self.on_shoutout_source_changed)
                    shoutout_form_layout.addRow(source_label, self.source_dropdown)

                    refresh_obs_button = QPushButton("Refresh OBS Scenes/Sources")
                    refresh_obs_button.setStyleSheet(
                        f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                        f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                    )
                    refresh_obs_button.clicked.connect(self.refresh_obs_scenes_sources)
                    shoutout_form_layout.addRow(refresh_obs_button)

                    queue_label = QLabel("Shoutout Queue:")
                    queue_label.setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 12pt; font-weight: bold; }}")
                    tab_layout.addWidget(queue_label)
                    self.shoutout_queue_list = QListWidget()
                    self.shoutout_queue_list.setStyleSheet(
                        f"QListWidget {{ background-color: {DARK_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; padding: 5px; }}"
                    )
                    tab_layout.addWidget(self.shoutout_queue_list)

                    button_layout = QHBoxLayout()
                    clear_queue_button = QPushButton("Clear Queue")
                    clear_queue_button.setStyleSheet(
                        f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                        f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                    )
                    clear_queue_button.clicked.connect(self.clear_shoutout_queue)
                    button_layout.addWidget(clear_queue_button)

                    remove_shoutout_button = QPushButton("Remove Shoutout")
                    remove_shoutout_button.setStyleSheet(
                        f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                        f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                    )
                    remove_shoutout_button.clicked.connect(self.remove_shoutout)
                    button_layout.addWidget(remove_shoutout_button)

                    tab_layout.addLayout(button_layout)
                    tab_layout.addLayout(shoutout_form_layout)
                    tab_layout.addStretch()
                elif tab_name == "🎬 Intermission":
                    self.status_labels["intermission_enabled"] = QLabel("Intermission: Enabled" if self.config["toggles"].get("intermission_enabled", True) else "Intermission: Disabled")
                    self.status_labels["intermission_enabled"].setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 12pt; }}")
                    tab_layout.addWidget(self.status_labels["intermission_enabled"])
                    
                    intermission_label = QLabel("Intermission Settings (BRB)")
                    intermission_label.setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 16pt; font-weight: bold; }}")
                    tab_layout.addWidget(intermission_label)

                    scene_source_layout = QFormLayout()
                    scene_source_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

                    scene_label = QLabel("Select Scene:")
                    scene_label.setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 12pt; }}")
                    self.brb_scene_dropdown = QComboBox()
                    self.brb_scene_dropdown.setStyleSheet(
                        f"QComboBox {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; padding: 5px; }}"
                    )
                    self.brb_scene_dropdown.blockSignals(True)
                    scenes = self._get_obs_scenes()
                    if not scenes:
                        logger.warning("No OBS scenes found; check OBS connection, arrgh!")
                        scenes = ["(No scenes available)"]
                    self.brb_scene_dropdown.addItems(scenes)
                    if self.brb_settings.get("scene", "") in scenes:
                        self.brb_scene_dropdown.setCurrentText(self.brb_settings["scene"])
                    elif scenes != ["(No scenes available)"]:
                        self.brb_scene_dropdown.setCurrentText(scenes[0])
                    self.brb_scene_dropdown.blockSignals(False)
                    self.brb_scene_dropdown.currentTextChanged.connect(self.on_brb_scene_selected)
                    self.brb_scene_dropdown.currentTextChanged.connect(self.save_brb_settings)
                    scene_source_layout.addRow(scene_label, self.brb_scene_dropdown)

                    source_label = QLabel("Select Source:")
                    source_label.setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 12pt; }}")
                    self.brb_source_dropdown = QComboBox()
                    self.brb_source_dropdown.setStyleSheet(
                        f"QComboBox {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; padding: 5px; }}"
                    )
                    self.brb_source_dropdown.blockSignals(True)
                    selected_scene = self.brb_scene_dropdown.currentText()
                    if selected_scene and selected_scene != "(No scenes available)" and self.obs_client.connected:
                        try:
                            sources = self.obs_client.get_sources(selected_scene)
                            if not sources:
                                logger.warning(f"No sources found for BRB scene {selected_scene}, arrgh!")
                                sources = ["(No sources available)"]
                            self.brb_source_dropdown.addItems(sources)
                            if self.brb_settings.get("source", "") in sources:
                                self.brb_source_dropdown.setCurrentText(self.brb_settings["source"])
                            elif sources != ["(No sources available)"]:
                                self.brb_source_dropdown.setCurrentText(sources[0])
                        except Exception as e:
                            logger.error(f"Failed to populate sources for BRB scene {selected_scene}: {e}, arrgh!")
                            self.brb_source_dropdown.addItems(["(No sources available)"])
                    else:
                        self.brb_source_dropdown.addItems(["(No sources available)"])
                    self.brb_source_dropdown.blockSignals(False)
                    self.brb_source_dropdown.currentTextChanged.connect(self.save_brb_settings)
                    self.brb_source_dropdown.currentTextChanged.connect(self.on_brb_source_changed)
                    scene_source_layout.addRow(source_label, self.brb_source_dropdown)

                    tab_layout.addLayout(scene_source_layout)

                    self.randomize_clips_button = QPushButton("Randomize Clips")
                    self.randomize_clips_button.setStyleSheet(
                        f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                        f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                    )
                    self.randomize_clips_button.clicked.connect(self.randomize_brb_clips)
                    tab_layout.addWidget(self.randomize_clips_button)

                    self.refresh_sources_button = QPushButton("Refresh Sources")
                    self.refresh_sources_button.setStyleSheet(
                        f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                        f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                    )
                    self.refresh_sources_button.clicked.connect(self.refresh_obs_scenes_sources)
                    tab_layout.addWidget(self.refresh_sources_button)

                    tab_layout.addStretch()
                elif tab_name == "🏴‍☠️ Raids":
                    self.status_labels["raids_enabled"] = QLabel("Raids: Enabled" if self.config["toggles"].get("raids_enabled", True) else "Raids: Disabled")
                    self.status_labels["raids_enabled"].setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 12pt; }}")
                    tab_layout.addWidget(self.status_labels["raids_enabled"])
                    
                    raid_label = QLabel("Raid Settings")
                    raid_label.setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 16pt; font-weight: bold; }}")
                    tab_layout.addWidget(raid_label)

                    raid_form_layout = QFormLayout()
                    raid_form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

                    self.raid_command_input = QLineEdit()
                    self.raid_command_input.setStyleSheet(
                        f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; padding: 5px; }}"
                    )
                    self.raid_command_input.blockSignals(True)
                    self.raid_command_input.setText(self.raid_command)
                    self.raid_command_input.blockSignals(False)
                    self.raid_command_input.textChanged.connect(self._update_raid_command)
                    raid_form_layout.addRow(QLabel("Raid Command:"), self.raid_command_input)

                    self.raid_message_input = QLineEdit()
                    self.raid_message_input.setStyleSheet(
                        f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; padding: 5px; }}"
                    )
                    self.raid_message_input.blockSignals(True)
                    self.raid_message_input.setText(self.raid_message)
                    self.raid_message_input.blockSignals(False)
                    self.raid_message_input.textChanged.connect(self._save_config)
                    raid_form_layout.addRow(QLabel("Raid Message (use {target}):"), self.raid_message_input)

                    self.raid_targets_list = QListWidget()
                    self.raid_targets_list.setStyleSheet(
                        f"QListWidget {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; padding: 5px; }}"
                    )
                    for target in self.raid_targets:
                        self.raid_targets_list.addItem(target)
                    raid_form_layout.addRow(QLabel("Raid Targets:"), self.raid_targets_list)

                    button_layout = QHBoxLayout()
                    add_target_button = QPushButton("Add Target")
                    add_target_button.setStyleSheet(
                        f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                        f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                    )
                    add_target_button.clicked.connect(self._add_raid_target)
                    button_layout.addWidget(add_target_button)

                    update_target_button = QPushButton("Update Target")
                    update_target_button.setStyleSheet(
                        f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                        f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                    )
                    update_target_button.clicked.connect(self._update_raid_target)
                    button_layout.addWidget(update_target_button)

                    remove_target_button = QPushButton("Remove Target")
                    remove_target_button.setStyleSheet(
                        f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                        f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                    )
                    remove_target_button.clicked.connect(self._remove_raid_target)
                    button_layout.addWidget(remove_target_button)
                    raid_form_layout.addRow(button_layout)

                    scene_label = QLabel("Select Scene:")
                    scene_label.setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 12pt; }}")
                    self.raid_scene_dropdown = QComboBox()
                    self.raid_scene_dropdown.setStyleSheet(
                        f"QComboBox {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; padding: 5px; }}"
                    )
                    self.raid_scene_dropdown.blockSignals(True)
                    scenes = self._get_obs_scenes()
                    if not scenes:
                        logger.warning("No OBS scenes found; check OBS connection, arrgh!")
                        scenes = ["(No scenes available)"]
                    self.raid_scene_dropdown.addItems(scenes)
                    if self.raid_settings.get("scene", "") in scenes:
                        self.raid_scene_dropdown.setCurrentText(self.raid_settings["scene"])
                    elif scenes != ["(No scenes available)"]:
                        self.raid_scene_dropdown.setCurrentText(scenes[0])
                    self.raid_scene_dropdown.blockSignals(False)
                    self.raid_scene_dropdown.currentTextChanged.connect(self.on_raid_scene_selected)
                    self.raid_scene_dropdown.currentTextChanged.connect(self.save_raid_settings)
                    raid_form_layout.addRow(scene_label, self.raid_scene_dropdown)

                    source_label = QLabel("Select Source:")
                    source_label.setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 12pt; }}")
                    self.raid_source_dropdown = QComboBox()
                    self.raid_source_dropdown.setStyleSheet(
                        f"QComboBox {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; padding: 5px; }}"
                    )
                    self.raid_source_dropdown.blockSignals(True)
                    selected_scene = self.raid_scene_dropdown.currentText()
                    if selected_scene and selected_scene != "(No scenes available)" and self.obs_client.connected:
                        try:
                            sources = self.obs_client.get_sources(selected_scene)
                            if not sources:
                                logger.warning(f"No sources found for raid scene {selected_scene}, arrgh!")
                                sources = ["(No sources available)"]
                            self.raid_source_dropdown.addItems(sources)
                            if self.raid_settings.get("source", "") in sources:
                                self.raid_source_dropdown.setCurrentText(self.raid_settings["source"])
                            elif sources != ["(No sources available)"]:
                                self.raid_source_dropdown.setCurrentText(sources[0])
                        except Exception as e:
                            logger.error(f"Failed to populate sources for raid scene {selected_scene}: {e}, arrgh!")
                            self.raid_source_dropdown.addItems(["(No sources available)"])
                    else:
                        self.raid_source_dropdown.addItems(["(No sources available)"])
                    self.raid_source_dropdown.blockSignals(False)
                    self.raid_source_dropdown.currentTextChanged.connect(self.save_raid_settings)
                    self.raid_source_dropdown.currentTextChanged.connect(self.on_raid_source_changed)
                    raid_form_layout.addRow(source_label, self.raid_source_dropdown)

                    self.raid_clip_duration_input = QLineEdit()
                    self.raid_clip_duration_input.setStyleSheet(
                        f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; padding: 5px; }}"
                    )
                    self.raid_clip_duration_input.blockSignals(True)
                    self.raid_clip_duration_input.setText(self.raid_clip_duration)
                    self.raid_clip_duration_input.blockSignals(False)
                    self.raid_clip_duration_input.textChanged.connect(self._save_config)
                    raid_form_layout.addRow(QLabel("Clip Duration (seconds):"), self.raid_clip_duration_input)

                    self.stop_clips_button = QPushButton("Stop Clips")
                    self.stop_clips_button.setStyleSheet(
                        f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                        f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                    )
                    self.stop_clips_button.clicked.connect(self.stop_raid_clips_sync)
                    raid_form_layout.addRow(self.stop_clips_button)

                    refresh_obs_button = QPushButton("Refresh OBS Scenes/Sources")
                    refresh_obs_button.setStyleSheet(
                        f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                        f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                    )
                    refresh_obs_button.clicked.connect(self.refresh_obs_scenes_sources)
                    raid_form_layout.addRow(refresh_obs_button)

                    tab_layout.addLayout(raid_form_layout)
                    tab_layout.addStretch()
                elif tab_name == "📋 Commands":
                    self.status_labels["commands_enabled"] = QLabel("Commands: Enabled" if self.config["toggles"].get("commands_enabled", True) else "Commands: Disabled")
                    self.status_labels["commands_enabled"].setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 12pt; }}")
                    tab_layout.addWidget(self.status_labels["commands_enabled"])
                    
                    commands_label = QLabel("Commands")
                    commands_label.setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 16pt; font-weight: bold; }}")
                    tab_layout.addWidget(commands_label)

                    commands_form_layout = QFormLayout()
                    commands_form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

                    self.commands_list = QListWidget()
                    self.commands_list.setStyleSheet(
                        f"QListWidget {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; padding: 5px; }}"
                    )
                    for cmd in self.config["commands"]:
                        self.commands_list.addItem(f"{cmd['name']} - {cmd['message']}")
                    commands_form_layout.addRow(QLabel("Commands:"), self.commands_list)

                    commands_button_layout = QHBoxLayout()
                    add_command_button = QPushButton("Add Command")
                    add_command_button.setStyleSheet(
                        f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                        f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                    )
                    add_command_button.clicked.connect(self.add_command)
                    commands_button_layout.addWidget(add_command_button)

                    update_command_button = QPushButton("Update Command")
                    update_command_button.setStyleSheet(
                        f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                        f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                    )
                    update_command_button.clicked.connect(self.update_command)
                    commands_button_layout.addWidget(update_command_button)

                    delete_command_button = QPushButton("Delete Command")
                    delete_command_button.setStyleSheet(
                        f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                        f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                    )
                    delete_command_button.clicked.connect(self.delete_command)
                    commands_button_layout.addWidget(delete_command_button)
                    commands_form_layout.addRow(commands_button_layout)

                    intro_sounds_label = QLabel("Intro Sounds")
                    intro_sounds_label.setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{self.selected_font}'; font-size: 16pt; font-weight: bold; }}")
                    tab_layout.addWidget(intro_sounds_label)

                    intro_sounds_form_layout = QFormLayout()
                    intro_sounds_form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

                    self.intro_sounds_list = QListWidget()
                    self.intro_sounds_list.setStyleSheet(
                        f"QListWidget {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{self.selected_font}'; font-size: 12pt; padding: 5px; }}"
                    )
                    for intro in self.config["intro_sounds"]:
                        self.intro_sounds_list.addItem(f"{intro['username']} - {intro['sound']}")
                    intro_sounds_form_layout.addRow(QLabel("Intro Sounds:"), self.intro_sounds_list)

                    intro_sounds_button_layout = QHBoxLayout()
                    add_intro_sound_button = QPushButton("Add Intro Sound")
                    add_intro_sound_button.setStyleSheet(
                        f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                        f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                    )
                    add_intro_sound_button.clicked.connect(self.add_intro_sound)
                    intro_sounds_button_layout.addWidget(add_intro_sound_button)

                    update_intro_sound_button = QPushButton("Update Intro Sound")
                    update_intro_sound_button.setStyleSheet(
                        f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                        f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                    )
                    update_intro_sound_button.clicked.connect(self.update_intro_sound)
                    intro_sounds_button_layout.addWidget(update_intro_sound_button)

                    delete_intro_sound_button = QPushButton("Delete Intro Sound")
                    delete_intro_sound_button.setStyleSheet(
                        f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }}"
                        f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                    )
                    delete_intro_sound_button.clicked.connect(self.delete_intro_sound)
                    intro_sounds_button_layout.addWidget(delete_intro_sound_button)
                    intro_sounds_form_layout.addRow(intro_sounds_button_layout)

                    tab_layout.addLayout(commands_form_layout)
                    tab_layout.addLayout(intro_sounds_form_layout)
                    tab_layout.addStretch()

                self.tab_widgets[tab_name] = tab_widget
                self.tab_stack.addWidget(tab_widget)
            
            self.split_layout.addWidget(self.tab_stack)
            logger.debug("Tab stack set up, arrgh!")
            
            self.tab_list.setCurrentRow(0)
            logger.debug("Initial tab selected, arrgh!")
            
            self.font_combo.blockSignals(False)
            try:
                self.update_fonts(self.selected_font, save=False)
            except Exception as e:
                logger.error(f"Failed to apply initial font: {e}, arrgh!", exc_info=True)
                QMessageBox.warning(self, "Blunder", f"Failed to apply font: {e}, arrgh!")

            if all([self.obs_config.get("server_ip", ""), self.obs_config.get("server_port", ""), self.obs_config.get("server_password", "")]):
                try:
                    self.handle_obs_connect()
                    logger.debug("OBS auto-connect attempted during initialization, arrgh!")
                    if self.obs_client.connected and self.brb_settings["source"] and self.brb_settings["last_clip_url"]:
                        self.obs_client.set_input_settings(
                            self.brb_settings["source"],
                            {"url": self.brb_settings["last_clip_url"]},
                            overlay=True
                        )
                        logger.debug(f"Restored last clip URL {self.brb_settings['last_clip_url']} to source {self.brb_settings['source']}, arrgh!")
                except Exception as e:
                    logger.error(f"Auto-connect to OBS failed: {e}, arrgh!", exc_info=True)
                    file_handler.flush()
                    console_handler.flush()
                    QMessageBox.warning(self, "Blunder", f"Failed to auto-connect to OBS: {e}, arrgh!")

            try:
                self._setup_file_renamer()
                self.installEventFilter(self)
            except Exception as e:
                logger.error(f"Failed to initialize file renamer: {e}, arrgh!", exc_info=True)
                QMessageBox.warning(self, "Blunder", f"Failed to set up file renamer: {e}, arrgh!")

            try:
                self._save_config()
            except Exception as e:
                logger.error(f"Failed to save config: {e}, arrgh!", exc_info=True)
                QMessageBox.warning(self, "Blunder", f"Failed to save config: {e}, arrgh!")

            logger.info("SquawkBotGUI initialized, arrgh!")
        except Exception as e:
            logger.error(f"GUI initialization crashed: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            QMessageBox.critical(self, "Blunder", f"GUI crashed during startup: {e}, arrgh!")
            raise

    def _populate_fonts(self):
        logger.debug("Entering _populate_fonts, arrgh!")
        try:
            valid_fonts = get_system_fonts()
            try:
                default_font = self.app.font()
                app_font = default_font.family()
                if app_font and isinstance(app_font, str) and app_font.strip():
                    if app_font not in valid_fonts:
                        valid_fonts.insert(0, app_font)
                    logger.debug(f"Added QApplication.font(): {app_font}, arrgh!")
            except Exception as e:
                logger.warning(f"QApplication.font() failed: {e}, arrgh!")
            self.font_combo.clear()
            self.font_combo.addItems(valid_fonts)
            self.font_combo.setCurrentText(self.selected_font if self.selected_font in valid_fonts else "Arial")
            logger.debug(f"Final font list: {valid_fonts[:5]} (showing first 5), arrgh!")
        except Exception as e:
            logger.error(f"Failed to populate fonts: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            QMessageBox.warning(self, "Blunder", f"Failed to populate fonts: {e}, arrgh! Using minimal font list.")
            self.font_combo.clear()
            self.font_combo.addItems(["Arial", "Times New Roman", "Courier New"])
            self.font_combo.setCurrentText("Arial")
            logger.debug("Final fallback: Populated dropdown with minimal font list, arrgh!")
        finally:
            logger.debug("Exiting _populate_fonts, arrgh!")

    def on_brb_source_changed(self, source):
        """Notify bot of BRB source change."""
        logger.debug(f"BRB source switched to {source}, arrgh!")
        if self.bot and self.bot.loop:
            try:
                future = asyncio.run_coroutine_threadsafe(
                    self.bot.notify_source_change("brb", source),
                    self.bot.loop
                )
                future.result(timeout=5)
            except Exception as e:
                logger.error(f"Failed to notify bot of BRB source change: {e}, arrgh!")

    def on_raid_source_changed(self, source):
        """Notify bot of Raid source change."""
        logger.debug(f"Raid source switched to {source}, arrgh!")
        if self.bot and self.bot.loop:
            try:
                future = asyncio.run_coroutine_threadsafe(
                    self.bot.notify_source_change("raid", source),
                    self.bot.loop
                )
                future.result(timeout=5)
            except Exception as e:
                logger.error(f"Failed to notify bot of Raid source change: {e}, arrgh!")

    def on_shoutout_source_changed(self, source):
        """Notify bot of Shoutout source change."""
        logger.debug(f"Shoutout source switched to {source}, arrgh!")
        if self.bot and self.bot.loop:
            try:
                future = asyncio.run_coroutine_threadsafe(
                    self.bot.notify_source_change("shoutout", source),
                    self.bot.loop
                )
                future.result(timeout=5)
            except Exception as e:
                logger.error(f"Failed to notify bot of Shoutout source change: {e}, arrgh!")

    def update_fonts(self, font_name, save=True):
        if not self.config["toggles"].get("fonts_enabled", True):
            logger.debug("Fonts toggle disabled, skippin’ font update, arrgh!")
            return
        logger.debug(f"Enterin’ update_fonts with font: {font_name}, arrgh!")
        try:
            if not font_name:
                logger.debug("No font selected, skippin’ update, arrgh!")
                return
            font = QFont(font_name, 12)
            if not font.exactMatch():
                logger.warning(f"Font '{font_name}' not found, fallin’ back to Arial, arrgh!")
                font = QFont("Arial", 12)
                font_name = "Arial"
            QApplication.setFont(font)
            self.selected_font = font_name
            if save:
                self.config["selected_font"] = font_name
                self._save_config()
            self.setStyleSheet(
                f"QMainWindow {{ background-color: {TYRIAN_PURPLE}; font-family: '{font_name}'; }}"
            )
            self.tab_list.setStyleSheet(
                f"QListWidget {{ background-color: {TYRIAN_PURPLE}; color: {GOLD}; border: 0px; font-family: '{font_name}'; font-size: 14pt; }}"
                f"QListWidget::item {{ padding: 15px; }}"
                f"QListWidget::item:selected {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; }}"
            )
            self.status_label.setStyleSheet(f"QLabel {{ color: {GOLD}; background-color: transparent; font-family: '{font_name}'; font-size: 12pt; }}")
            self.start_button.setStyleSheet(
                f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{font_name}'; font-size: 12pt; }}"
                f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
            )
            self.stop_button.setStyleSheet(
                f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{font_name}'; font-size: 12pt; }}"
                f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
            )
            self.font_combo.setStyleSheet(
                f"QComboBox {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{font_name}'; font-size: 12pt; padding: 5px; }}"
                f"QComboBox::drop-down {{ border: 0px; }}"
            )
            for tab_name in self.tab_names:
                if tab_name == "🖌️ Fonts":
                    for widget in self.tab_widgets[tab_name].findChildren(QLabel):
                        widget.setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{font_name}'; font-size: 12pt; }}")
                elif tab_name == "🔐 Login":
                    for widget in self.tab_widgets[tab_name].findChildren(QLabel):
                        widget.setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{font_name}'; font-size: 12pt; }}")
                    for widget in self.tab_widgets[tab_name].findChildren(QLineEdit):
                        widget.setStyleSheet(
                            f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{font_name}'; font-size: 12pt; padding: 5px; }}"
                        )
                    for widget in self.tab_widgets[tab_name].findChildren(QPushButton):
                        widget.setStyleSheet(
                            f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{font_name}'; font-size: 12pt; }}"
                            f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                        )
                elif tab_name == "🎥 OBS":
                    for widget in self.tab_widgets[tab_name].findChildren(QLabel):
                        widget.setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{font_name}'; font-size: 12pt; }}")
                    for widget in self.tab_widgets[tab_name].findChildren(QLineEdit):
                        widget.setStyleSheet(
                            f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: '{font_name}'; font-size: 12pt; padding: 5px; }}"
                        )
                    for widget in self.tab_widgets[tab_name].findChildren(QPushButton):
                        widget.setStyleSheet(
                            f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{font_name}'; font-size: 12pt; }}"
                            f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                        )
            logger.debug(f"Font updated to {font_name}, arrgh!")
        except Exception as e:
            logger.error(f"Failed to update font: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            QMessageBox.critical(self, "Blunder", f"Failed to update font: {e}, arrgh! Fallin’ back to Arial.")
            try:
                font = QFont("Arial", 12)
                QApplication.setFont(font)
                font_name = "Arial"
                self.setStyleSheet(
                    f"QMainWindow {{ background-color: {TYRIAN_PURPLE}; font-family: 'Arial'; }}"
                )
                self.tab_list.setStyleSheet(
                    f"QListWidget {{ background-color: {TYRIAN_PURPLE}; color: {GOLD}; border: 0px; font-family: 'Arial'; font-size: 14pt; }}"
                    f"QListWidget::item {{ padding: 15px; }}"
                    f"QListWidget::item:selected {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; }}"
                )
                self.status_label.setStyleSheet(f"QLabel {{ color: {GOLD}; background-color: transparent; font-family: 'Arial'; font-size: 12pt; }}")
                self.start_button.setStyleSheet(
                    f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: 'Arial'; font-size: 12pt; }}"
                    f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                )
                self.stop_button.setStyleSheet(
                    f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: 'Arial'; font-size: 12pt; }}"
                    f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                )
                self.font_combo.setStyleSheet(
                    f"QComboBox {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: 'Arial'; font-size: 12pt; padding: 5px; }}"
                    f"QComboBox::drop-down {{ border: 0px; }}"
                )
                for tab_name in self.tab_names:
                    if tab_name == "🖌️ Fonts":
                        for widget in self.tab_widgets[tab_name].findChildren(QLabel):
                            widget.setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: 'Arial'; font-size: 12pt; }}")
                    elif tab_name == "🔐 Login":
                        for widget in self.tab_widgets[tab_name].findChildren(QLabel):
                            widget.setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: 'Arial'; font-size: 12pt; }}")
                        for widget in self.tab_widgets[tab_name].findChildren(QLineEdit):
                            widget.setStyleSheet(
                                f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: 'Arial'; font-size: 12pt; padding: 5px; }}"
                            )
                        for widget in self.tab_widgets[tab_name].findChildren(QPushButton):
                            widget.setStyleSheet(
                                f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: 'Arial'; font-size: 12pt; }}"
                                f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                            )
                    elif tab_name == "🎥 OBS":
                        for widget in self.tab_widgets[tab_name].findChildren(QLabel):
                            widget.setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: 'Arial'; font-size: 12pt; }}")
                        for widget in self.tab_widgets[tab_name].findChildren(QLineEdit):
                            widget.setStyleSheet(
                                f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; font-family: 'Arial'; font-size: 12pt; padding: 5px; }}"
                            )
                        for widget in self.tab_widgets[tab_name].findChildren(QPushButton):
                            widget.setStyleSheet(
                                f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: 'Arial'; font-size: 12pt; }}"
                                f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
                            )
            finally:
                logger.debug("Exitin’ update_fonts, arrgh!")

    def _load_config(self):
        """Load configuration from file, merging with defaults."""
        logger.debug("Entering _load_config, arrgh!")
        config_path = os.path.join(os.path.expanduser("~"), ".squawkbot", "squawkbot_config.json")
        default_config = {
            "broadcaster": {"username": "", "token": "", "channel": "", "issued_at": 0, "expires_at": 0, "refresh_token": ""},
            "bot": {"username": "", "token": "", "issued_at": 0, "expires_at": 0, "refresh_token": ""},
            "obs": {"server_ip": DEFAULT_OBS_IP, "server_port": DEFAULT_OBS_PORT, "server_password": ""},
            "selected_font": "Arial",
            "timers": [],
            "counters": [],
            "file_renamer": {"directory": "", "include_subdirs": True}
        }
        
        try:
            if os.path.exists(config_path):
                with open(config_path, "r") as f:
                    config = json.load(f)
                    # Ensure all expected keys exist
                    for key, value in default_config.items():
                        config.setdefault(key, value)
                    
                    # Ensure sub-dictionaries have all keys
                    for subkey in ["broadcaster", "bot", "file_renamer"]:
                        for field in default_config[subkey]:
                            config[subkey].setdefault(field, default_config[subkey][field])
                    
                    # Migrate timers from "interval" to "minutes" and "seconds"
                    for timer in config["timers"]:
                        if "interval" in timer:
                            total_seconds = timer.pop("interval")
                            timer["minutes"] = total_seconds // 60
                            timer["seconds"] = total_seconds % 60
                    
                    logger.debug("Config loaded successfully, arrgh!")
                    return config
            else:
                logger.debug("Config file not found, creating default config, arrgh!")
                os.makedirs(os.path.dirname(config_path), exist_ok=True)
                with open(config_path, "w") as f:
                    json.dump(default_config, f, indent=4)
                return default_config
        except Exception as e:
            logger.error(f"Failed to load config: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            return default_config

    def _save_config(self):
        """Save the current configuration to the config file, arrgh!"""
        logger.debug("Savin’ config, arrgh!")
        try:
            config_dir = os.path.expanduser("~/.squawkbot")
            os.makedirs(config_dir, exist_ok=True)
                            
            self.config["broadcaster"] = {
                "username": self.broadcaster_username_input.text().strip() if hasattr(self, 'broadcaster_username_input') else self.config["broadcaster"].get("username", ""),
                "token": self.config["broadcaster"].get("token", ""),
                "channel": self.broadcaster_channel_input.text().strip() if hasattr(self, 'broadcaster_channel_input') else self.config["broadcaster"].get("channel", ""),
                "issued_at": self.config["broadcaster"].get("issued_at", 0),
                "expires_at": self.config["broadcaster"].get("expires_at", 0),
                "refresh_token": self.config["broadcaster"].get("refresh_token", "")
            }
            self.config["bot"] = {
                "username": self.bot_username_input.text().strip() if hasattr(self, 'bot_username_input') else self.config["bot"].get("username", ""),
                "token": self.config["bot"].get("token", ""),
                "issued_at": self.config["bot"].get("issued_at", 0),
                "expires_at": self.config["bot"].get("expires_at", 0),
                "refresh_token": self.config["bot"].get("refresh_token", "")
            }
            self.config["obs"] = {
                "server_ip": self.obs_ip_input.text().strip() if hasattr(self, 'obs_ip_input') else self.config["obs"].get("server_ip", ""),
                "server_port": self.obs_port_input.text().strip() if hasattr(self, 'obs_port_input') else self.config["obs"].get("server_port", ""),
                "server_password": self.obs_password_input.text().strip() if hasattr(self, 'obs_password_input') else self.config["obs"].get("server_password", "")
            }
            self.config["selected_font"] = getattr(self, 'selected_font', self.config.get("selected_font", "Arial"))
            self.config["timers"] = self.timers
            self.config["counters"] = self.counters
            self.config["shoutout_settings"] = {
                "command": self.shoutout_command_input.text().strip() if hasattr(self, 'shoutout_command_input') else self.config["shoutout_settings"].get("command", "!so"),
                "message": self.shoutout_message_input.text().strip() if hasattr(self, 'shoutout_message_input') else self.config["shoutout_settings"].get("message", "SQUAWK! a shoutout to {user} at {link}, arrgh!"),
                "access_level": self.access_dropdown.currentText().lower() if hasattr(self, 'access_dropdown') else self.config["shoutout_settings"].get("access_level", "mods"),
                "scene": self.scene_dropdown.currentText() if hasattr(self, 'scene_dropdown') else self.config["shoutout_settings"].get("scene", ""),
                "source": self.source_dropdown.currentText() if hasattr(self, 'source_dropdown') else self.config["shoutout_settings"].get("source", "")
            }
            self.config["brb_settings"] = {
                "scene": self.brb_scene_dropdown.currentText() if hasattr(self, 'brb_scene_dropdown') else self.config["brb_settings"].get("scene", ""),
                "source": self.brb_source_dropdown.currentText() if hasattr(self, 'brb_source_dropdown') else self.config["brb_settings"].get("source", ""),
                "last_clip_url": self.config["brb_settings"].get("last_clip_url", "")
            }
            self.config["file_renamer"] = {
                "directory": self.file_renamer_dir_input.text().strip() if hasattr(self, 'file_renamer_dir_input') else self.config["file_renamer"].get("directory", ""),
                "include_subdirs": self.file_renamer_subdirs_check.isChecked() if hasattr(self, 'file_renamer_subdirs_check') else self.config["file_renamer"].get("include_subdirs", True)
            }
            self.config["raid_settings"] = {
                "targets": self.raid_targets,
                "command": self.raid_command_input.text().strip() if hasattr(self, 'raid_command_input') else self.raid_settings.get("command", "!raid"),
                "message": self.raid_message_input.text().strip() if hasattr(self, 'raid_message_input') else self.raid_settings.get("message", "Squawk! Raidin’ {target}, arrgh!"),
                "scene": self.raid_scene_dropdown.currentText() if hasattr(self, 'raid_scene_dropdown') else self.raid_settings.get("scene", ""),
                "source": self.raid_source_dropdown.currentText() if hasattr(self, 'raid_source_dropdown') else self.raid_settings.get("source", ""),
                "clip_duration": self.raid_clip_duration_input.text().strip() if hasattr(self, 'raid_clip_duration_input') else self.raid_settings.get("clip_duration", "60"),
                "session_raid_targets": list(self.bot.session_raid_targets) if hasattr(self, 'bot') and self.bot else [],
                "raid_attempts": self.bot.raid_attempts if hasattr(self, 'bot') and self.bot else []
            }

            config_path = os.path.join(config_dir, "squawkbot_config.json")
            try:
                with open(config_path, "w", encoding='utf-8') as f:
                    json.dump(self.config, f, indent=4)
                logger.debug(f"Config saved to {config_path}, arrgh!")
            except (OSError, json.JSONDecodeError) as e:
                logger.error(f"Failed to write config file: {e}, arrgh!", exc_info=True)
                file_handler.flush()
                console_handler.flush()
                QMessageBox.warning(self, "Blunder", f"Failed to save config: {e}. Changes may not persist, arrgh!")
        except Exception as e:
            logger.error(f"Unexpected error savin’ config: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            QMessageBox.warning(self, "Blunder", f"Unexpected error savin’ config: {e}, arrgh!")

    def add_command(self):
        """Add a new command."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Add Command")
        dialog.setGeometry(300, 300, 400, 300)
        layout = QFormLayout()

        name_input = QLineEdit()
        name_input.setStyleSheet(f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; border: 0px; padding: 5px; font-family: '{self.selected_font}'; font-size: 12pt; }}")
        layout.addRow("Command Name (e.g., squawk):", name_input)

        message_input = QLineEdit()
        message_input.setStyleSheet(f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; border: 0px; padding: 5px; font-family: '{self.selected_font}'; font-size: 12pt; }}")
        layout.addRow("Message:", message_input)

        sound_input = QLineEdit()
        sound_input.setStyleSheet(f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; border: 0px; padding: 5px; font-family: '{self.selected_font}'; font-size: 12pt; }}")
        layout.addRow("Sound File (optional):", sound_input)
        sound_browse_button = QPushButton("Browse")
        sound_browse_button.setStyleSheet(f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }} QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}")
        sound_browse_button.clicked.connect(lambda: sound_input.setText(QFileDialog.getOpenFileName(self, "Select Sound File", "", "Audio Files (*.mp3 *.wav)")[0]))
        layout.addRow(sound_browse_button)

        permission_dropdown = QComboBox()
        permission_dropdown.addItems(["All", "Mods", "Broadcaster", "VIPs"])
        permission_dropdown.setStyleSheet(f"QComboBox {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; border: 0px; padding: 5px; font-family: '{self.selected_font}'; font-size: 12pt; }}")
        layout.addRow("Permission:", permission_dropdown)

        buttons = QHBoxLayout()
        ok_button = QPushButton("OK")
        ok_button.setStyleSheet(f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }} QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}")
        ok_button.clicked.connect(dialog.accept)
        buttons.addWidget(ok_button)
        cancel_button = QPushButton("Cancel")
        cancel_button.setStyleSheet(f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }} QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}")
        cancel_button.clicked.connect(dialog.reject)
        buttons.addWidget(cancel_button)
        layout.addRow(buttons)

        dialog.setLayout(layout)
        if dialog.exec():
            name = name_input.text().strip()
            message = message_input.text().strip()
            sound = sound_input.text().strip()
            permission = permission_dropdown.currentText().lower()
            if name and message:
                # Remove "!" if present in the name
                name = name.lstrip("!")
                # Check if command already exists
                for cmd in self.config["commands"]:
                    if cmd["name"].lower() == name.lower():
                        QMessageBox.warning(self, "Blunder", f"Command !{name} already exists, arrgh!")
                        return
                self.config["commands"].append({
                    "name": name,
                    "message": message,
                    "sound": sound,
                    "permission": permission
                })
                self.commands_list.addItem(f"{name} - {message}")
                self._save_config()
                # Update bot commands if running
                if self.bot and self.bot_thread and self.bot_thread.isRunning():
                    self.bot.update_commands()

    def update_command(self):
        """Update the selected command."""
        selected_item = self.commands_list.currentItem()
        if not selected_item:
            QMessageBox.warning(self, "Blunder", "Please select a command to update, arrgh!")
            return
        selected_text = selected_item.text()
        command_name = selected_text.split(" - ")[0]
        command_idx = None
        for idx, cmd in enumerate(self.config["commands"]):
            if cmd["name"] == command_name:
                command_idx = idx
                break
        if command_idx is None:
            QMessageBox.warning(self, "Blunder", "Command not found, arrgh!")
            return

        command = self.config["commands"][command_idx]
        dialog = QDialog(self)
        dialog.setWindowTitle("Update Command")
        dialog.setGeometry(300, 300, 400, 300)
        layout = QFormLayout()

        name_input = QLineEdit(command["name"])
        name_input.setStyleSheet(f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; border: 0px; padding: 5px; font-family: '{self.selected_font}'; font-size: 12pt; }}")
        name_input.setEnabled(False)  # Prevent changing the command name
        layout.addRow("Command Name:", name_input)

        message_input = QLineEdit(command["message"])
        message_input.setStyleSheet(f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; border: 0px; padding: 5px; font-family: '{self.selected_font}'; font-size: 12pt; }}")
        layout.addRow("Message:", message_input)

        sound_input = QLineEdit(command["sound"])
        sound_input.setStyleSheet(f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; border: 0px; padding: 5px; font-family: '{self.selected_font}'; font-size: 12pt; }}")
        layout.addRow("Sound File (optional):", sound_input)
        sound_browse_button = QPushButton("Browse")
        sound_browse_button.setStyleSheet(f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }} QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}")
        sound_browse_button.clicked.connect(lambda: sound_input.setText(QFileDialog.getOpenFileName(self, "Select Sound File", "", "Audio Files (*.mp3 *.wav)")[0]))
        layout.addRow(sound_browse_button)

        permission_dropdown = QComboBox()
        permission_dropdown.addItems(["All", "Mods", "Broadcaster", "VIPs"])
        permission_dropdown.setStyleSheet(f"QComboBox {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; border: 0px; padding: 5px; font-family: '{self.selected_font}'; font-size: 12pt; }}")
        permission_dropdown.setCurrentText(command["permission"].capitalize())
        layout.addRow("Permission:", permission_dropdown)

        buttons = QHBoxLayout()
        ok_button = QPushButton("OK")
        ok_button.setStyleSheet(f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }} QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}")
        ok_button.clicked.connect(dialog.accept)
        buttons.addWidget(ok_button)
        cancel_button = QPushButton("Cancel")
        cancel_button.setStyleSheet(f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }} QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}")
        cancel_button.clicked.connect(dialog.reject)
        buttons.addWidget(cancel_button)
        layout.addRow(buttons)

        dialog.setLayout(layout)
        if dialog.exec():
            message = message_input.text().strip()
            sound = sound_input.text().strip()
            permission = permission_dropdown.currentText().lower()
            if message:
                self.config["commands"][command_idx]["message"] = message
                self.config["commands"][command_idx]["sound"] = sound
                self.config["commands"][command_idx]["permission"] = permission
                self.commands_list.item(self.commands_list.currentRow()).setText(f"{command_name} - {message}")
                self._save_config()
                # Update bot commands if running
                if self.bot and self.bot_thread and self.bot_thread.isRunning():
                    self.bot.update_commands()

    def toggle_feature(self, toggle_key, button):
        """Handle feature toggle changes, update button text and status labels, arrgh!"""
        try:
            enabled = not self.config["toggles"].get(toggle_key, True)  # Toggle the current state
            self.config["toggles"][toggle_key] = enabled
            self._save_config()
            logger.debug(f"Toggle '{toggle_key}' {'enabled' if enabled else 'disabled'}, arrgh!")
            # Update button text
            button.setText("Disable" if enabled else "Enable")
            # Update all status labels
            for key, label in self.status_labels.items():
                feature_name = self.toggle_labels.get(key, key.replace("_enabled", "").capitalize())
                label.setText(f"{feature_name}: {'Enabled' if self.config['toggles'].get(key, True) else 'Disabled'}")
            # Update bot commands if running and commands toggle changed
            if toggle_key == "commands_enabled" and self.bot and self.bot_thread and self.bot_thread.isRunning():
                self.bot.update_commands()
        except Exception as e:
            logger.error(f"Failed to toggle '{toggle_key}': {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            QMessageBox.critical(self, "Blunder", f"Failed to toggle '{toggle_key}': {e}, arrgh!")

    def delete_command(self):
        """Delete the selected command."""
        selected_item = self.commands_list.currentItem()
        if not selected_item:
            QMessageBox.warning(self, "Blunder", "Please select a command to delete, arrgh!")
            return
        selected_text = selected_item.text()
        command_name = selected_text.split(" - ")[0]
        self.config["commands"] = [cmd for cmd in self.config["commands"] if cmd["name"] != command_name]
        self.commands_list.takeItem(self.commands_list.currentRow())
        self._save_config()
        # Update bot commands if running
        if self.bot and self.bot_thread and self.bot_thread.isRunning():
            self.bot.update_commands()

    def add_intro_sound(self):
        """Add a new intro sound for a user."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Add Intro Sound")
        dialog.setGeometry(300, 300, 400, 200)
        layout = QFormLayout()

        username_input = QLineEdit()
        username_input.setStyleSheet(f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; border: 0px; padding: 5px; font-family: '{self.selected_font}'; font-size: 12pt; }}")
        layout.addRow("Username:", username_input)

        sound_input = QLineEdit()
        sound_input.setStyleSheet(f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; border: 0px; padding: 5px; font-family: '{self.selected_font}'; font-size: 12pt; }}")
        layout.addRow("Sound File:", sound_input)
        sound_browse_button = QPushButton("Browse")
        sound_browse_button.setStyleSheet(f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }} QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}")
        sound_browse_button.clicked.connect(lambda: sound_input.setText(QFileDialog.getOpenFileName(self, "Select Sound File", "", "Audio Files (*.mp3 *.wav)")[0]))
        layout.addRow(sound_browse_button)

        buttons = QHBoxLayout()
        ok_button = QPushButton("OK")
        ok_button.setStyleSheet(f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }} QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}")
        ok_button.clicked.connect(dialog.accept)
        buttons.addWidget(ok_button)
        cancel_button = QPushButton("Cancel")
        cancel_button.setStyleSheet(f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }} QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}")
        cancel_button.clicked.connect(dialog.reject)
        buttons.addWidget(cancel_button)
        layout.addRow(buttons)

        dialog.setLayout(layout)
        if dialog.exec():
            username = username_input.text().strip().lower()
            sound = sound_input.text().strip()
            if username and sound:
                # Check if user already has an intro sound
                for intro in self.config["intro_sounds"]:
                    if intro["username"].lower() == username:
                        QMessageBox.warning(self, "Blunder", f"User {username} already has an intro sound, arrgh!")
                        return
                self.config["intro_sounds"].append({
                    "username": username,
                    "sound": sound
                })
                self.intro_sounds_list.addItem(f"{username} - {sound}")
                self._save_config()

    def update_intro_sound(self):
        """Update the selected intro sound."""
        selected_item = self.intro_sounds_list.currentItem()
        if not selected_item:
            QMessageBox.warning(self, "Blunder", "Please select an intro sound to update, arrgh!")
            return
        selected_text = selected_item.text()
        username = selected_text.split(" - ")[0]
        intro_idx = None
        for idx, intro in enumerate(self.config["intro_sounds"]):
            if intro["username"] == username:
                intro_idx = idx
                break
        if intro_idx is None:
            QMessageBox.warning(self, "Blunder", "Intro sound not found, arrgh!")
            return

        intro = self.config["intro_sounds"][intro_idx]
        dialog = QDialog(self)
        dialog.setWindowTitle("Update Intro Sound")
        dialog.setGeometry(300, 300, 400, 200)
        layout = QFormLayout()

        username_input = QLineEdit(intro["username"])
        username_input.setStyleSheet(f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; border: 0px; padding: 5px; font-family: '{self.selected_font}'; font-size: 12pt; }}")
        username_input.setEnabled(False)  # Prevent changing the username
        layout.addRow("Username:", username_input)

        sound_input = QLineEdit(intro["sound"])
        sound_input.setStyleSheet(f"QLineEdit {{ background-color: {WEATHERED_PARCHMENT}; color: {TYRIAN_PURPLE}; border: 0px; padding: 5px; font-family: '{self.selected_font}'; font-size: 12pt; }}")
        layout.addRow("Sound File:", sound_input)
        sound_browse_button = QPushButton("Browse")
        sound_browse_button.setStyleSheet(f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }} QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}")
        sound_browse_button.clicked.connect(lambda: sound_input.setText(QFileDialog.getOpenFileName(self, "Select Sound File", "", "Audio Files (*.mp3 *.wav)")[0]))
        layout.addRow(sound_browse_button)

        buttons = QHBoxLayout()
        ok_button = QPushButton("OK")
        ok_button.setStyleSheet(f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }} QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}")
        ok_button.clicked.connect(dialog.accept)
        buttons.addWidget(ok_button)
        cancel_button = QPushButton("Cancel")
        cancel_button.setStyleSheet(f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{self.selected_font}'; font-size: 12pt; }} QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}")
        cancel_button.clicked.connect(dialog.reject)
        buttons.addWidget(cancel_button)
        layout.addRow(buttons)

        dialog.setLayout(layout)
        if dialog.exec():
            sound = sound_input.text().strip()
            if sound:
                self.config["intro_sounds"][intro_idx]["sound"] = sound
                self.intro_sounds_list.item(self.intro_sounds_list.currentRow()).setText(f"{username} - {sound}")
                self._save_config()

    def delete_intro_sound(self):
        """Delete the selected intro sound."""
        selected_item = self.intro_sounds_list.currentItem()
        if not selected_item:
            QMessageBox.warning(self, "Blunder", "Please select an intro sound to delete, arrgh!")
            return
        selected_text = selected_item.text()
        username = selected_text.split(" - ")[0]
        self.config["intro_sounds"] = [intro for intro in self.config["intro_sounds"] if intro["username"] != username]
        self.intro_sounds_list.takeItem(self.intro_sounds_list.currentRow())
        self._save_config()

    def update_commands(self):
        """Register all commands from the config dynamically."""
        logger.debug("Updating bot commands from config, arrgh!")
        # Remove existing dynamic commands (except shoutout and raid)
        for command in list(self.commands.values()):
            if command.name not in [self.gui.shoutout_command_input.text().lstrip("!"), self.gui.raid_command_input.text().lstrip("!")]:
                self.remove_command(command.name)
        
        # Register commands from config
        for cmd in self.gui.config["commands"]:
            command_name = cmd["name"].lstrip("!")
            command_func = self.create_command_handler(cmd)
            new_command = commands.Command(name=command_name, func=command_func)
            self.add_command(new_command)
            logger.debug(f"Registered command '!{command_name}' with message: {cmd['message']}, arrgh!")

    def create_command_handler(self, cmd):
        """Create a command handler for a given command config."""
        async def command_handler(ctx: commands.Context):
            user = ctx.author
            permission = cmd["permission"]
            # Check permission
            if permission == "broadcaster" and user.name.lower() != self.broadcaster_username.lower():
                await ctx.send(f"Squawk! Only the broadcaster can use !{cmd['name']}, arrgh!")
                return
            elif permission == "mods" and not user.is_mod:
                await ctx.send(f"Squawk! Only mods can use !{cmd['name']}, arrgh!")
                return
            elif permission == "vips" and not user.is_vip:
                await ctx.send(f"Squawk! Only VIPs can use !{cmd['name']}, arrgh!")
                return
            # Send the message
            await ctx.send(cmd["message"])
            # Play the sound if attached
            if cmd["sound"]:
                try:
                    self.gui.play_sound(cmd["sound"])
                    logger.debug(f"Played sound clip {cmd['sound']} for command !{cmd['name']}, arrgh!")
                except Exception as e:
                    logger.error(f"Failed to play sound clip {cmd['sound']} for command !{cmd['name']}: {e}, arrgh!")
        return command_handler

    def update_timers_list(self):
        logger.debug("Entering update_timers_list, arrgh!")
        try:
            self.timers_list.clear()
            for timer in self.timers:
                total_seconds = timer["minutes"] * 60 + timer["seconds"]
                item_text = f"{timer['name']}: {timer['message']} (every {timer['minutes']}m {timer['seconds']}s, {total_seconds}s total)"
                self.timers_list.addItem(item_text)
            logger.debug("Timers list updated, arrgh!")
        except Exception as e:
            logger.error(f"Failed to update timers list: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()

    def update_counters_list(self):
        self.counters_list.clear()
        for counter in self.counters:
            self.counters_list.addItem(f"{counter['name']} - !{counter['command']} - Increment: {counter['increment']} - Value: {counter['value']}")
        if self.bot_thread and self.bot_thread.isRunning():
            self.bot_thread.bot.update_counter_commands()

    def _get_obs_scenes(self):
        """Fetch OBS scenes if connected."""
        if self.obs_client.connected:
            try:
                scenes = self.obs_client.get_scenes()
                logger.debug(f"Fetched OBS scenes: {scenes}, arrgh!")
                return scenes
            except Exception as e:
                logger.error(f"Failed to fetch OBS scenes: {e}, arrgh!")
        return []

    def _add_raid_target(self):
        """Add a new raid target to the list, arrgh!"""
        logger.debug("Enterin’ _add_raid_target, arrgh!")
        try:
            # Debug: Log GUI attributes
            logger.debug(f"SquawkBotGUI attributes: {[attr for attr in dir(self) if not attr.startswith('_')]}, arrgh!")
            
            target, ok = QInputDialog.getText(self, "Add Raid Target", "Enter Twitch username to raid, arrgh:", QLineEdit.EchoMode.Normal, "")
            if ok and target:
                target = target.strip().lower()
                if target.startswith("#"):
                    target = target[1:]
                if target in self.raid_targets:
                    QMessageBox.warning(self, "Blunder", f"Target {target} already in the raid list, arrgh!")
                    return
                # Validate username format (letters, numbers, underscores, hyphens, 1-25 chars)
                import re
                if not re.match(r'^[a-zA-Z0-9_-]{1,25}$', target):
                    QMessageBox.warning(self, "Blunder", "Target must be a valid Twitch username (letters, numbers, underscores, hyphens, 1-25 characters), arrgh!")
                    return
                # Verify username exists via Twitch API
                headers = {
                    "Client-ID": CLIENT_ID,
                    "Authorization": f"Bearer {self.bot_config['token'].replace('oauth:', '') if hasattr(self, 'bot_config') and 'token' in self.bot_config else ''}"
                }
                response = requests.get(f"https://api.twitch.tv/helix/users?login={target}", headers=headers)
                if response.status_code == 200 and response.json().get("data"):
                    self.raid_targets.append(target)
                    self.raid_targets_list.addItem(target)
                    self.save_raid_settings()
                    QMessageBox.information(self, "Success", f"Added {target} to raid targets, arrgh!")
                else:
                    QMessageBox.warning(self, "Blunder", f"Target {target} not found on Twitch, arrgh!")
        except Exception as e:
            logger.error(f"Failed to add raid target: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
        finally:
            logger.debug("Exitin’ _add_raid_target, arrgh!")

    def _update_raid_target(self):
        """Update a selected raid target."""
        current_item = self.raid_targets_list.currentItem()
        if not current_item:
            QMessageBox.information(self, "No Selection", "Select a target to update, arrgh!")
            return
        old_target = current_item.text()
        new_target, ok = QInputDialog.getText(self, "Update Raid Target", f"Enter new username for {old_target}:")
        if ok and new_target:
            index = self.raid_targets.index(old_target)
            self.raid_targets[index] = new_target.lower()
            self.raid_targets_list.item(index).setText(new_target.lower())
            self._save_config()
            logger.info(f"Updated raid target from {old_target} to {new_target}, arrgh!")

    def _remove_raid_target(self):
        """Remove the selected raid target from the list, arrgh!"""
        logger.debug("Enterin’ _remove_raid_target, arrgh!")
        try:
            selected_items = self.raid_targets_list.selectedItems()
            if not selected_items:
                QMessageBox.warning(self, "Blunder", "No target selected to remove, arrgh!")
                return
            for item in selected_items:
                target = item.text()
                self.raid_targets.remove(target)
                self.raid_targets_list.takeItem(self.raid_targets_list.row(item))
            self.save_raid_settings()
            QMessageBox.information(self, "Success", "Removed selected raid targets, arrgh!")
        except Exception as e:
            logger.error(f"Failed to remove raid target: {e}, arrgh!", exc_info=True)
        finally:
            logger.debug("Exitin’ _remove_raid_target, arrgh!")

    def stop_raid_clips_sync(self):
        """Synchronous wrapper to run the async _stop_raid_clips method, arrgh!"""
        logger.debug("Enterin’ stop_raid_clips_sync, arrgh!")
        try:
            # Check if bot thread exists and has an event loop
            if self.bot_thread and hasattr(self.bot_thread, 'loop') and self.bot_thread.loop and not self.bot_thread.loop.is_closed():
                loop = self.bot_thread.loop
                # Run the async coroutine in the bot's event loop
                future = asyncio.run_coroutine_threadsafe(self._stop_raid_clips(), loop)
                future.result(timeout=5)  # Wait for the coroutine to complete, with a timeout
                logger.debug("Successfully ran _stop_raid_clips via bot thread loop, arrgh!")
            else:
                # If no bot thread loop, create a new event loop for this operation
                loop = asyncio.new_event_loop()
                try:
                    asyncio.set_event_loop(loop)
                    loop.run_until_complete(self._stop_raid_clips())
                    logger.debug("Successfully ran _stop_raid_clips via new event loop, arrgh!")
                finally:
                    loop.close()
                    logger.debug("Closed temporary event loop in stop_raid_clips_sync, arrgh!")
        except Exception as e:
            logger.error(f"Failed to stop raid clips in stop_raid_clips_sync: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            QMessageBox.warning(self, "Blunder", f"Failed to stop raid clips: {e}, arrgh!")
        finally:
            logger.debug("Exitin’ stop_raid_clips_sync, arrgh!")

    async def _stop_raid_clips(self):
        """Stop raid clip playback and hide OBS source, arrgh!"""
        try:
            self.raid_active = False
            scene_name = self.raid_scene_dropdown.currentText()
            source_name = self.raid_source_dropdown.currentText()
            if self.obs_client and self.obs_client.connected and scene_name and source_name:
                self.obs_client.set_source_visibility(scene_name, source_name, False)
                logger.debug(f"Stopped raid clips, hid source {source_name}, arrgh!")
            self.stop_clips_button.setEnabled(False)
        except Exception as e:
            logger.error(f"Failed to stop raid clips: {e}, arrgh!", exc_info=True)

    def _update_raid_command(self):
        """Update the raid command in the bot."""
        if self.bot:
            self.bot._register_raid_command()
        self._save_config()

    def on_timer_selected(self):
        logger.debug("Entering on_timer_selected, arrgh!")
        try:
            selected_items = self.timers_list.selectedItems()
            if not selected_items:
                # Clear input fields if no timer is selected
                self.timer_name_input.clear()
                self.timer_message_input.clear()
                self.timer_minutes_input.setText("0")
                self.timer_seconds_input.setText("0")
                return
            
            selected_item = selected_items[0]
            timer_index = self.timers_list.row(selected_item)
            timer = self.timers[timer_index]
            
            # Populate input fields with selected timer's details
            self.timer_name_input.setText(timer["name"])
            self.timer_message_input.setText(timer["message"])
            self.timer_minutes_input.setText(str(timer["minutes"]))
            self.timer_seconds_input.setText(str(timer["seconds"]))
            
            logger.debug(f"Selected timer '{timer['name']}', arrgh!")
        except Exception as e:
            logger.error(f"Failed to handle timer selection: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()

    def setup_shoutouts_tab(self):
        shoutouts_tab = QWidget()
        layout = QVBoxLayout()

        # Queue display
        layout.addWidget(QLabel("Shoutout Queue:"))
        self.shoutout_queue_list = QListWidget()
        layout.addWidget(self.shoutout_queue_list)

        # Queue management buttons
        queue_buttons_layout = QHBoxLayout()
        self.clear_queue_button = QPushButton("Clear Queue")
        self.clear_queue_button.clicked.connect(self.clear_shoutout_queue)
        self.remove_user_button = QPushButton("Remove Selected User")
        self.remove_user_button.clicked.connect(self.remove_user_from_queue)
        queue_buttons_layout.addWidget(self.clear_queue_button)
        queue_buttons_layout.addWidget(self.remove_user_button)
        layout.addLayout(queue_buttons_layout)

        # OBS Scene and Source dropdowns
        layout.addWidget(QLabel("Select OBS Scene:"))
        self.scene_dropdown = QComboBox()
        self.scene_dropdown.currentTextChanged.connect(self.update_source_dropdown)
        layout.addWidget(self.scene_dropdown)

        layout.addWidget(QLabel("Select OBS Source:"))
        self.source_dropdown = QComboBox()
        layout.addWidget(self.source_dropdown)

        # Refresh OBS scenes and sources button
        self.refresh_obs_button = QPushButton("Refresh OBS Scenes/Sources")
        self.refresh_obs_button.clicked.connect(self.refresh_obs_scenes_sources)
        layout.addWidget(self.refresh_obs_button)

        # Shoutout settings
        layout.addWidget(QLabel("Shoutout Command (e.g., !so, !shout):"))
        self.shoutout_command_input = QLineEdit("!so")
        layout.addWidget(self.shoutout_command_input)

        layout.addWidget(QLabel("Shoutout Message (use {user} for username, {link} for channel link):"))
        self.shoutout_message_input = QLineEdit("Check out {user} at {link}! Amazing content awaits!")
        layout.addWidget(self.shoutout_message_input)

        layout.addWidget(QLabel("Who can use the command:"))
        self.access_dropdown = QComboBox()
        self.access_dropdown.addItems(["All", "Regulars", "VIPs", "Mods"])
        layout.addWidget(self.access_dropdown)

        shoutouts_tab.setLayout(layout)
        self.tab_widget.addTab(shoutouts_tab, "📣 Shoutouts")

        # Initialize OBS scenes and sources
        self.obs_client = None
        self.shoutout_queue = []
        self.refresh_obs_scenes_sources()

    def clear_shoutout_queue(self):
        self.shoutout_queue.clear()
        self.shoutout_queue_list.clear()
        logger.debug("Shoutout queue cleared, arrgh!")

    def remove_user_from_queue(self):
        selected_items = self.shoutout_queue_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Blunder", "Please select a user to remove from the queue, arrgh!")
            return
        user = selected_items[0].text()
        if user in self.shoutout_queue:
            self.shoutout_queue.remove(user)
            self.shoutout_queue_list.takeItem(self.shoutout_queue_list.row(selected_items[0]))
            logger.debug(f"Removed {user} from shoutout queue, arrgh!")

    def add_to_shoutout_queue(self, user):
        """Add a user to the shoutout queue and update the GUI list."""
        self.shoutout_queue.append(user)
        self.update_shoutout_queue_list()
        logger.debug(f"Added {user} to shoutout queue, queue now: {self.shoutout_queue}, arrgh!")

    def get_next_shoutout_user(self):
        """Get the next user from the shoutout queue and remove them from the list."""
        if self.shoutout_queue:
            user = self.shoutout_queue.pop(0)
            self.shoutout_queue_list.takeItem(0)
            logger.debug(f"Removed {user} from shoutout queue, arrgh!")
            return user
        return None
    
    def on_raid_scene_selected(self, scene):
        """Update raid source dropdown when a raid scene is selected."""
        logger.debug(f"Raid scene selected: {scene}, arrgh!")
        try:
            if not self.obs_client.connected:
                logger.warning("OBS not connected, cannot update raid sources, arrgh!")
                self.raid_source_dropdown.clear()
                return
            if scene:
                sources = self.obs_client.get_sources(scene)
                self.raid_source_dropdown.clear()
                self.raid_source_dropdown.addItems(sources)
                current_source = self.raid_settings.get("source", "")
                if current_source in sources:
                    self.raid_source_dropdown.setCurrentText(current_source)
                    logger.debug(f"Restored raid source: {current_source}, arrgh!")
                else:
                    logger.warning(f"Saved raid source {current_source} not found in OBS for scene {scene}, keeping unset, arrgh!")
            else:
                self.raid_source_dropdown.clear()
                logger.debug("No raid scene selected, cleared source dropdown, arrgh!")
        except Exception as e:
            logger.error(f"Failed to update raid sources: {e}, arrgh!", exc_info=True)
            self.raid_source_dropdown.clear()

    def refresh_obs_scenes_sources(self):
        """Refresh the list of OBS scenes and sources, and restore saved selections."""
        logger.debug("Refreshing OBS scenes and sources, arrgh!")
        try:
            if not self.obs_client.connected:
                logger.warning("OBS not connected, clearing scene and source dropdowns, arrgh!")
                self.scene_dropdown.clear()
                self.source_dropdown.clear()
                self.brb_scene_dropdown.clear()
                self.brb_source_dropdown.clear()
                self.raid_scene_dropdown.clear()
                self.raid_source_dropdown.clear()
                QMessageBox.warning(self, "OBS Disconnected", "Connect to OBS first to refresh scenes and sources, arrgh!")
                return

            # Fetch scenes
            scenes = self.obs_client.get_scenes()
            logger.debug(f"Fetched scenes: {scenes}, arrgh!")

            # Disconnect signals to prevent automatic saving during population
            try:
                self.scene_dropdown.currentTextChanged.disconnect()
                self.source_dropdown.currentTextChanged.disconnect()
                self.brb_scene_dropdown.currentTextChanged.disconnect()
                self.brb_source_dropdown.currentTextChanged.disconnect()
                self.raid_scene_dropdown.currentTextChanged.disconnect()
                self.raid_source_dropdown.currentTextChanged.disconnect()
            except TypeError:
                logger.debug("One or more signals were not connected, proceeding anyway, arrgh!")

            # Update shoutout scene dropdown
            self.scene_dropdown.clear()
            self.scene_dropdown.addItems(scenes)
            current_scene = self.shoutout_settings.get("scene", "")
            if current_scene in scenes:
                self.scene_dropdown.setCurrentText(current_scene)
                logger.debug(f"Restored shoutout scene: {current_scene}, arrgh!")
            else:
                logger.warning(f"Saved shoutout scene {current_scene} not found in OBS, keeping unset, arrgh!")

            # Update shoutout source dropdown based on selected scene
            selected_scene = self.scene_dropdown.currentText()
            if selected_scene:
                sources = self.obs_client.get_sources(selected_scene)
                self.source_dropdown.clear()
                self.source_dropdown.addItems(sources)
                current_source = self.shoutout_settings.get("source", "")
                if current_source in sources:
                    self.source_dropdown.setCurrentText(current_source)
                    logger.debug(f"Restored shoutout source: {current_source}, arrgh!")
                else:
                    logger.warning(f"Saved shoutout source {current_source} not found in OBS for scene {selected_scene}, keeping unset, arrgh!")

            # Update BRB scene dropdown
            self.brb_scene_dropdown.clear()
            self.brb_scene_dropdown.addItems(scenes)
            current_brb_scene = self.brb_settings.get("scene", "")
            if current_brb_scene in scenes:
                self.brb_scene_dropdown.setCurrentText(current_brb_scene)
                logger.debug(f"Restored BRB scene: {current_brb_scene}, arrgh!")
            else:
                logger.warning(f"Saved BRB scene {current_brb_scene} not found in OBS, keeping unset, arrgh!")

            # Update BRB source dropdown based on selected scene
            selected_brb_scene = self.brb_scene_dropdown.currentText()
            if selected_brb_scene:
                sources = self.obs_client.get_sources(selected_brb_scene)
                self.brb_source_dropdown.clear()
                self.brb_source_dropdown.addItems(sources)
                current_brb_source = self.brb_settings.get("source", "")
                if current_brb_source in sources:
                    self.brb_source_dropdown.setCurrentText(current_brb_source)
                    logger.debug(f"Restored BRB source: {current_brb_source}, arrgh!")
                else:
                    logger.warning(f"Saved BRB source {current_brb_source} not found in OBS for scene {selected_brb_scene}, keeping unset, arrgh!")

            # Update raid scene dropdown
            self.raid_scene_dropdown.clear()
            self.raid_scene_dropdown.addItems(scenes)
            current_raid_scene = self.raid_settings.get("scene", "")
            if current_raid_scene in scenes:
                self.raid_scene_dropdown.setCurrentText(current_raid_scene)
                logger.debug(f"Restored raid scene: {current_raid_scene}, arrgh!")
            else:
                logger.warning(f"Saved raid scene {current_raid_scene} not found in OBS, keeping unset, arrgh!")

            # Update raid source dropdown based on selected scene
            selected_raid_scene = self.raid_scene_dropdown.currentText()
            if selected_raid_scene:
                sources = self.obs_client.get_sources(selected_raid_scene)
                self.raid_source_dropdown.clear()
                self.raid_source_dropdown.addItems(sources)
                current_raid_source = self.raid_settings.get("source", "")
                if current_raid_source in sources:
                    self.raid_source_dropdown.setCurrentText(current_raid_source)
                    logger.debug(f"Restored raid source: {current_raid_source}, arrgh!")
                else:
                    logger.warning(f"Saved raid source {current_raid_source} not found in OBS for scene {selected_raid_scene}, keeping unset, arrgh!")

        except Exception as e:
            logger.error(f"Failed to refresh OBS scenes and sources: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            self.scene_dropdown.clear()
            self.source_dropdown.clear()
            self.brb_scene_dropdown.clear()
            self.brb_source_dropdown.clear()
            self.raid_scene_dropdown.clear()
            self.raid_source_dropdown.clear()
            QMessageBox.critical(self, "Blunder", f"Failed to refresh OBS scenes and sources: {e}, arrgh!")
        finally:
            # Reconnect signals after population
            try:
                self.scene_dropdown.currentTextChanged.connect(self.save_shoutout_settings)
                self.source_dropdown.currentTextChanged.connect(self.save_shoutout_settings)
                self.brb_scene_dropdown.currentTextChanged.connect(self.save_brb_settings)
                self.brb_source_dropdown.currentTextChanged.connect(self.save_brb_settings)
                self.raid_scene_dropdown.currentTextChanged.connect(self.on_raid_scene_selected)
                self.raid_scene_dropdown.currentTextChanged.connect(self.save_raid_settings)
                self.raid_source_dropdown.currentTextChanged.connect(self.save_raid_settings)
                logger.debug("Signals reconnected after refreshing scenes and sources, arrgh!")
            except Exception as e:
                logger.error(f"Failed to reconnect signals: {e}, arrgh!", exc_info=True)

    def update_source_dropdown(self):
        """Update the source dropdown based on the selected scene."""
        try:
            current_scene = self.scene_dropdown.currentText()
            self.source_dropdown.clear()
            if not current_scene or not self.obs_client or not self.obs_client.connected:
                logger.warning("No scene selected or OBS not connected, cannot update sources, arrgh!")
                return

            # Fetch sources for the selected scene using the updated OBSClient method
            sources = self.obs_client.get_sources(current_scene)
            if sources:
                self.source_dropdown.addItems(sources)
                logger.debug(f"OBS sources refreshed for scene {current_scene}: {sources}, arrgh!")
            else:
                logger.warning(f"No sources found for scene {current_scene}, arrgh!")
        except Exception as e:
            logger.error(f"Failed to refresh OBS sources: {e}, arrgh!")
            QMessageBox.critical(self, "Blunder", f"Failed to refresh OBS sources: {e}, arrgh!")
            self.source_dropdown.clear()

    def on_counter_selected(self):
        logger.debug("Entering on_counter_selected, arrgh!")
        try:
            selected_items = self.counters_list.selectedItems()
            if selected_items:
                selected_counter = self.counters[self.counters_list.row(selected_items[0])]
                self.counter_name_input.setText(selected_counter["name"])
                self.counter_command_input.setText(selected_counter["command"])
                self.counter_increment_input.setText(str(selected_counter["increment"]))
                self.counter_update_button.setEnabled(True)
                self.counter_delete_button.setEnabled(True)
                logger.debug(f"Selected counter '{selected_counter['name']}', arrgh!")
            else:
                self.counter_name_input.clear()
                self.counter_command_input.clear()
                self.counter_increment_input.setText("1")
                self.counter_update_button.setEnabled(False)
                self.counter_delete_button.setEnabled(False)
                logger.debug("No counter selected, cleared inputs, arrgh!")
        except Exception as e:
            logger.error(f"Failed to handle counter selection: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()

    def add_timer(self):
        logger.debug("Entering add_timer, arrgh!")
        try:
            name = self.timer_name_input.text().strip()
            message = self.timer_message_input.text().strip()
            minutes = self.timer_minutes_input.text().strip()
            seconds = self.timer_seconds_input.text().strip()
            
            if not name or not message or (not minutes and not seconds):
                logger.warning("Timer name, message, or duration missing, arrgh!")
                QMessageBox.warning(self, "Blunder", "Please fill in all timer fields, arrgh!")
                return
            
            # Convert minutes and seconds to integers
            try:
                minutes = int(minutes) if minutes else 0
                seconds = int(seconds) if seconds else 0
                if minutes < 0 or seconds < 0:
                    raise ValueError("Minutes and seconds must be non-negative")
                if seconds >= 60:
                    raise ValueError("Seconds must be less than 60")
                if minutes == 0 and seconds == 0:
                    raise ValueError("Timer duration must be greater than 0")
            except ValueError as e:
                logger.error(f"Invalid timer duration: {e}, arrgh!")
                QMessageBox.critical(self, "Blunder", f"Invalid timer duration: {e}, arrgh!")
                return
            
            # Check for duplicate timer name
            if any(timer["name"] == name for timer in self.timers):
                logger.warning(f"Timer '{name}' already exists, arrgh!")
                QMessageBox.warning(self, "Blunder", f"Timer '{name}' already exists, arrgh!")
                return
            
            # Add the timer
            timer = {"name": name, "message": message, "minutes": minutes, "seconds": seconds}
            self.timers.append(timer)
            self._save_config()
            self.update_timers_list()
            
            # Schedule the timer
            logger.debug(f"Bot thread running: {self.bot_thread.isRunning() if self.bot_thread else False}, arrgh!")
            self.schedule_timer(timer)
            
            # Clear input fields
            self.timer_name_input.clear()
            self.timer_message_input.clear()
            self.timer_minutes_input.setText("0")
            self.timer_seconds_input.setText("0")
            
            logger.info(f"Added timer '{name}', arrgh!")
        except Exception as e:
            logger.error(f"Failed to add timer: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            QMessageBox.critical(self, "Blunder", f"Failed to add timer: {e}, arrgh!")


    def schedule_timer(self, timer):
        try:
            name = timer["name"]
            total_seconds = timer["minutes"] * 60 + timer["seconds"]
            interval = total_seconds * 1000  # Convert to milliseconds for QTimer
            logger.debug(f"Scheduling timer '{name}' with interval {interval/1000} seconds, arrgh!")
            
            timer_obj = QTimer()
            timer_obj.setInterval(interval)
            
            def timer_task():
                try:
                    # Check if the timer still exists in the list
                    timer_exists = any(t["name"] == name for t in self.timers)
                    if not timer_exists:
                        logger.debug(f"Timer '{name}' no longer exists, stopping timer, arrgh!")
                        if name in self.timer_tasks:
                            self.timer_tasks[name].stop()
                            self.timer_tasks[name].timeout.disconnect()
                            del self.timer_tasks[name]
                        return
                    
                    # Check if the bot thread is running
                    if not self.bot_thread or not self.bot_thread.isRunning():
                        logger.warning(f"Cannot send timer message for '{name}', bot thread not running, will retry on next interval, arrgh!")
                        return
                    
                    # Send the timer message
                    channel_name = self.broadcaster_config["channel"].lstrip("#")
                    if self.bot_thread.send_message(timer["message"]):
                        logger.debug(f"Timer '{name}' triggered: {timer['message']}, arrgh!")
                    else:
                        logger.error(f"Failed to send timer message for '{name}', bot thread not running or channel not found, arrgh!")
                except Exception as e:
                    logger.error(f"Timer '{name}' failed to send message: {e}, arrgh!", exc_info=True)
                    file_handler.flush()
                    console_handler.flush()
                    # Stop the timer if it fails to prevent further errors
                    if name in self.timer_tasks:
                        self.timer_tasks[name].stop()
                        self.timer_tasks[name].timeout.disconnect()
                        del self.timer_tasks[name]
            
            timer_obj.timeout.connect(timer_task)
            self.timer_tasks[timer['name']] = timer_obj
            timer_obj.start()
            logger.info(f"Timer '{timer['name']}' started with interval {interval/1000} seconds, arrgh!")
            # Verify the timer is actually running
            logger.debug(f"Timer '{timer['name']}' is active: {timer_obj.isActive()}, arrgh!")
        except Exception as e:
            logger.error(f"Failed to schedule timer '{timer['name']}': {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()

    def update_timer(self):
        logger.debug("Entering update_timer, arrgh!")
        try:
            selected_items = self.timers_list.selectedItems()
            if not selected_items:
                logger.warning("No timer selected for update, arrgh!")
                QMessageBox.warning(self, "Blunder", "Please select a timer to update, arrgh!")
                return
            
            selected_item = selected_items[0]
            timer_index = self.timers_list.row(selected_item)
            timer = self.timers[timer_index]
            
            name = self.timer_name_input.text().strip()
            message = self.timer_message_input.text().strip()
            minutes = self.timer_minutes_input.text().strip()
            seconds = self.timer_seconds_input.text().strip()
            
            if not name or not message or (not minutes and not seconds):
                logger.warning("Timer name, message, or duration missing during update, arrgh!")
                QMessageBox.warning(self, "Blunder", "Please fill in all timer fields, arrgh!")
                return
            
            # Convert minutes and seconds to integers
            try:
                minutes = int(minutes) if minutes else 0
                seconds = int(seconds) if seconds else 0
                if minutes < 0 or seconds < 0:
                    raise ValueError("Minutes and seconds must be non-negative")
                if seconds >= 60:
                    raise ValueError("Seconds must be less than 60")
                if minutes == 0 and seconds == 0:
                    raise ValueError("Timer duration must be greater than 0")
            except ValueError as e:
                logger.error(f"Invalid timer duration during update: {e}, arrgh!")
                QMessageBox.critical(self, "Blunder", f"Invalid timer duration: {e}, arrgh!")
                return
            
            # Check for duplicate name (excluding the current timer)
            if any(t["name"] == name for i, t in enumerate(self.timers) if i != timer_index):
                logger.warning(f"Timer '{name}' already exists during update, arrgh!")
                QMessageBox.warning(self, "Blunder", f"Timer '{name}' already exists, arrgh!")
                return
            
            # Stop and remove the existing timer if scheduled
            if timer["name"] in self.timer_tasks:
                self.timer_tasks[timer["name"]].stop()  # Use stop() instead of cancel()
                del self.timer_tasks[timer["name"]]
            
            # Update the timer
            timer["name"] = name
            timer["message"] = message
            timer["minutes"] = minutes
            timer["seconds"] = seconds
            self._save_config()
            self.update_timers_list()
            
            # Reschedule the timer if the bot is running
            if self.bot_thread and self.bot_thread.isRunning():
                self.schedule_timer(timer)
            
            # Clear input fields
            self.timer_name_input.clear()
            self.timer_message_input.clear()
            self.timer_minutes_input.setText("0")
            self.timer_seconds_input.setText("0")
            
            logger.info(f"Updated timer at index {timer_index} to '{name}', arrgh!")
        except Exception as e:
            logger.error(f"Failed to update timer: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            QMessageBox.critical(self, "Blunder", f"Failed to update timer: {e}, arrgh!")

    def save_shoutout_settings(self):
        """Save shoutout settings to the config when they change."""
        logger.debug("Enterin’ save_shoutout_settings, arrgh!")
        try:
            self.shoutout_settings["command"] = self.shoutout_command_input.text().strip()
            self.shoutout_settings["message"] = self.shoutout_message_input.text().strip()
            self.shoutout_settings["access_level"] = self.access_dropdown.currentText().lower()
            scene = self.scene_dropdown.currentText()
            self.shoutout_settings["scene"] = scene
            self.shoutout_settings["source"] = self.source_dropdown.currentText()
            self.config["shoutout_settings"] = self.shoutout_settings
            self._save_config()
            logger.debug(f"Saved shoutout settings: {self.shoutout_settings}, arrgh!")
            
            # Refresh sources for the selected scene
            logger.debug("Attemptin’ to refresh Shoutout sources, arrgh!")
            if scene and self.obs_client.connected:
                try:
                    # Verify OBS connection
                    self.obs_client.req_client.get_version()
                    logger.debug("OBS connection verified fer Shoutout source refresh, arrgh!")
                    
                    # Fetch sources for the new scene
                    sources = self.obs_client.get_sources(scene)
                    logger.debug(f"Fetched {len(sources)} sources fer Shoutout scene {scene}: {sources}, arrgh!")
                    
                    # Block signals to prevent infinite loop
                    self.source_dropdown.blockSignals(True)
                    try:
                        # Update the source dropdown
                        current_source = self.source_dropdown.currentText()
                        logger.debug(f"Current Shoutout source before refresh: {current_source}, arrgh!")
                        self.source_dropdown.clear()
                        logger.debug("Cleared Shoutout source dropdown, arrgh!")
                        self.source_dropdown.addItems(sources)
                        logger.debug(f"Added {len(sources)} sources to Shoutout source dropdown, arrgh!")
                        
                        # Restore the previous source if it still exists, otherwise reset
                        if current_source in sources:
                            self.source_dropdown.setCurrentText(current_source)
                            logger.debug(f"Restored Shoutout source to {current_source}, arrgh!")
                        else:
                            self.shoutout_settings["source"] = ""
                            self.config["shoutout_settings"] = self.shoutout_settings
                            self._save_config()
                            logger.debug("Shoutout source reset, as previous source be not found in new scene, arrgh!")
                    finally:
                        # Unblock signals after updating the dropdown
                        self.source_dropdown.blockSignals(False)
                except Exception as e:
                    logger.error(f"Failed to fetch sources fer Shoutout scene {scene}: {e}, arrgh!", exc_info=True)
                    file_handler.flush()
                    console_handler.flush()
                    self.source_dropdown.clear()
                    QMessageBox.critical(self, "Blunder", f"Failed to fetch sources fer scene {scene}: {e}, arrgh!")
            else:
                self.source_dropdown.clear()
                logger.debug("No scene selected or OBS be not connected, clearin’ Shoutout sources, arrgh!")
        except Exception as e:
            logger.error(f"Failed to save shoutout settings: {e}, arrgh!", exc_info=True)
        logger.debug("Leavin’ save_shoutout_settings, arrgh!")

    def on_scene_selected(self):
        """Update the source dropdown based on the selected scene."""
        if not self.obs_client.connected:
            logger.warning("OBS not connected, cannot fetch sources, arrgh!")
            return
        try:
            scene_name = self.scene_dropdown.currentText()
            if not scene_name:
                self.source_dropdown.clear()
                return
            sources = self.obs_client.get_sources(scene_name)
            self.source_dropdown.clear()
            self.source_dropdown.addItems(sources)
            if self.shoutout_settings["source"] in sources:
                self.source_dropdown.setCurrentText(self.shoutout_settings["source"])
        except Exception as e:
            logger.error(f"Failed to fetch sources for scene {scene_name}: {e}, arrgh!", exc_info=True)
            self.source_dropdown.clear()

    def clear_shoutout_queue(self):
        """Clear the entire shoutout queue."""
        self.shoutout_queue.clear()
        self.update_shoutout_queue_list()
        logger.info("Shoutout queue cleared, arrgh!")

    def remove_shoutout(self):
        """Remove the selected user from the shoutout queue."""
        selected_items = self.shoutout_queue_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Blunder", "Please select a user to remove from the queue, arrgh!")
            return
        selected_item = selected_items[0]
        user = selected_item.text()
        self.shoutout_queue.remove(user)
        self.update_shoutout_queue_list()
        logger.info(f"Removed {user} from shoutout queue, arrgh!")

    def update_shoutout_queue_list(self):
        """Update the shoutout queue list in the GUI."""
        self.shoutout_queue_list.clear()
        for user in self.shoutout_queue:
            self.shoutout_queue_list.addItem(user)
        logger.debug(f"Updated shoutout queue list with {len(self.shoutout_queue)} users, arrgh!")

    def on_brb_scene_changed(self):
        logger.debug("BRB scene changed, updating sources and saving settings, arrgh!")
        self.save_brb_settings()
        if self.obs_client.connected and self.brb_scene_dropdown.currentText():
            sources = self.obs_client.get_sources(self.brb_scene_dropdown.currentText())
            self.brb_source_dropdown.clear()
            self.brb_source_dropdown.addItems(sources)
            saved_source = self.brb_settings.get("source", "")
            if saved_source in sources:
                self.brb_source_dropdown.setCurrentText(saved_source)

    def on_brb_source_changed(self):
        """Handle source selection changes for BRB, arrgh!"""
        logger.debug("BRB source changed, savin’ settings, arrgh!")
        try:
            source_name = self.brb_source_dropdown.currentText()
            self.brb_settings["source"] = source_name
            self.config["brb_settings"] = self.brb_settings
            self._save_config()
            logger.debug(f"Updated BRB source to {source_name}, arrgh!")
        except Exception as e:
            logger.error(f"Failed to handle BRB source change: {e}, arrgh!", exc_info=True)

    def fetch_brb_scenes(self):
        """Fetch scenes from OBS for the BRB tab."""
        try:
            if not self.obs_client.connected:
                logger.debug("OBS not connected, cannot fetch BRB scenes, arrgh!")
                self.brb_scene_dropdown.clear()
                self.brb_source_dropdown.clear()
                return
            scenes = self.obs_client.get_scenes()
            self.brb_scene_dropdown.clear()
            self.brb_scene_dropdown.addItems(scenes)
            if self.brb_settings["scene"] in scenes:
                self.brb_scene_dropdown.setCurrentText(self.brb_settings["scene"])
            if self.brb_scene_dropdown.currentText():
                self.fetch_brb_sources(self.brb_scene_dropdown.currentText())
        except Exception as e:
            logger.error(f"Failed to fetch BRB scenes: {e}, arrgh!", exc_info=True)
            self.brb_scene_dropdown.clear()
            self.brb_source_dropdown.clear()

    def fetch_brb_sources(self, scene_name):
        """Fetch sources for the selected scene in the BRB tab."""
        try:
            if not self.obs_client.connected or not scene_name:
                logger.debug("OBS not connected or no scene selected, cannot fetch BRB sources, arrgh!")
                self.brb_source_dropdown.clear()
                return
            sources = self.obs_client.get_sources(scene_name)
            self.brb_source_dropdown.clear()
            self.brb_source_dropdown.addItems(sources)
            if self.brb_settings["source"] in sources:
                self.brb_source_dropdown.setCurrentText(self.brb_settings["source"])
        except Exception as e:
            logger.error(f"Failed to fetch BRB sources for scene {scene_name}: {e}, arrgh!", exc_info=True)
            self.brb_source_dropdown.clear()

    def randomize_brb_clips(self):
        """Randomize the order of fetched BRB clips."""
        if not self.bot or not hasattr(self.bot, 'brb_clips'):
            logger.warning("Bot not initialized, cannot randomize clips, arrgh!")
            QMessageBox.warning(self, "Blunder", "Bot is not running. Start the bot to fetch and randomize clips, arrgh!")
            return
        try:
            # If no clips are available, attempt to fetch them
            if not self.bot.brb_clips:
                logger.debug("No BRB clips available, attempting to fetch, arrgh!")
                # Run fetch_brb_clips in the bot's event loop
                loop = asyncio.get_event_loop()
                loop.run_until_complete(self.bot.fetch_brb_clips())
                if not self.bot.brb_clips:
                    logger.warning("Failed to fetch BRB clips, arrgh!")
                    QMessageBox.warning(self, "Blunder", "No clips available to randomize. Ensure the broadcaster has clips and the token is valid, arrgh!")
                    return

            random.shuffle(self.bot.brb_clips)
            logger.debug("Randomized BRB clips, arrgh!")
            QMessageBox.information(self, "Success", "Clips randomized, arrgh!")
        except Exception as e:
            logger.error(f"Failed to randomize BRB clips: {e}, arrgh!", exc_info=True)
            QMessageBox.critical(self, "Blunder", f"Failed to randomize clips: {e}, arrgh!")
        

    def delete_timer(self):
        logger.debug("Entering delete_timer, arrgh!")
        try:
            selected_items = self.timers_list.selectedItems()
            if not selected_items:
                logger.warning("No timer selected for deletion, arrgh!")
                QMessageBox.warning(self, "Blunder", "Please select a timer to delete, arrgh!")
                return
            
            selected_item = selected_items[0]
            timer_index = self.timers_list.row(selected_item)
            timer_name = self.timers[timer_index]["name"]
            
            reply = QMessageBox.question(
                self,
                "Confirm Deletion",
                f"Are ye sure ye want to delete timer '{timer_name}', arrgh?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                # Stop and remove the timer task if it exists
                if timer_name in self.timer_tasks:
                    timer_obj = self.timer_tasks[timer_name]
                    timer_obj.stop()
                    timer_obj.timeout.disconnect()  # Disconnect the timeout signal to prevent pending signals
                    logger.debug(f"Stopped and disconnected timer '{timer_name}' before deletion, arrgh!")
                    del self.timer_tasks[timer_name]
                
                # Remove the timer from the list and save
                self.timers.pop(timer_index)
                self._save_config()
                self.update_timers_list()
                self.on_timer_selected()  # Update input fields
                logger.info(f"Deleted timer '{timer_name}', arrgh!")
            else:
                logger.debug("Timer deletion cancelled, arrgh!")
        except Exception as e:
            logger.error(f"Failed to delete timer: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            QMessageBox.critical(self, "Blunder", f"Failed to delete timer: {e}, arrgh!")

    def add_counter(self):
        logger.debug("Entering add_counter, arrgh!")
        try:
            name = self.counter_name_input.text().strip()
            command = self.counter_command_input.text().strip()
            increment = self.counter_increment_input.text().strip()
            
            if not name or not command or not increment:
                logger.warning("Counter name, command, or increment missing, arrgh!")
                QMessageBox.warning(self, "Blunder", "Please fill in all counter fields, arrgh!")
                return
            
            try:
                increment = int(increment)
                if increment == 0:
                    raise ValueError("Increment must be a non-zero integer")
            except ValueError as e:
                logger.error(f"Invalid counter increment: {e}, arrgh!")
                QMessageBox.critical(self, "Blunder", f"Counter increment must be a non-zero integer, arrgh! Got: {increment}")
                return
            
            # Check for duplicate counter name or command
            if any(counter["name"] == name for counter in self.counters):
                logger.warning(f"Counter '{name}' already exists, arrgh!")
                QMessageBox.warning(self, "Blunder", f"Counter '{name}' already exists, arrgh!")
                return
            
            if any(counter["command"] == command for counter in self.counters):
                logger.warning(f"Command '{command}' already used by another counter, arrgh!")
                QMessageBox.warning(self, "Blunder", f"Command '{command}' is already used, arrgh!")
                return
            
            # Add the counter
            counter = {"name": name, "command": command, "increment": increment, "value": 0}
            self.counters.append(counter)
            self.config["counters"] = self.counters  # Ensure counters are saved in config
            self._save_config()
            self.update_counters_list()
            
            # Clear input fields
            self.counter_name_input.clear()
            self.counter_command_input.clear()
            self.counter_increment_input.setText("1")
            self.counter_update_button.setEnabled(False)
            self.counter_delete_button.setEnabled(False)
            
            # Update commands if the bot is running
            if self.bot_thread and self.bot_thread.isRunning():
                self.bot_thread.bot.update_counter_commands()
            
            logger.info(f"Added counter '{name}', arrgh!")
            QMessageBox.information(self, "Success", f"Added counter '{name}' with command {command}, arrgh!")
        except Exception as e:
            logger.error(f"Failed to add counter: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            QMessageBox.critical(self, "Blunder", f"Failed to add counter: {e}, arrgh!")

    def update_counter(self):
        logger.debug("Entering update_counter, arrgh!")
        try:
            selected_items = self.counters_list.selectedItems()
            if not selected_items:
                logger.warning("No counter selected for update, arrgh!")
                QMessageBox.warning(self, "Blunder", "Please select a counter to update, arrgh!")
                return
            
            selected_item = selected_items[0]
            counter_index = self.counters_list.row(selected_item)
            counter = self.counters[counter_index]
            
            name = self.counter_name_input.text().strip()
            command = self.counter_command_input.text().strip()
            increment = self.counter_increment_input.text().strip()
            
            if not name or not command or not increment:
                logger.warning("Counter name, command, or increment missing during update, arrgh!")
                QMessageBox.warning(self, "Blunder", "Please fill in all counter fields, arrgh!")
                return
            
            try:
                increment = int(increment)
                if increment == 0:
                    raise ValueError("Increment must be a non-zero integer")
            except ValueError as e:
                logger.error(f"Invalid counter increment during update: {e}, arrgh!")
                QMessageBox.critical(self, "Blunder", f"Counter increment must be a non-zero integer, arrgh! Got: {increment}")
                return
            
            # Check for duplicate name or command (excluding the current counter)
            if any(c["name"] == name for i, c in enumerate(self.counters) if i != counter_index):
                logger.warning(f"Counter '{name}' already exists during update, arrgh!")
                QMessageBox.warning(self, "Blunder", f"Counter '{name}' already exists, arrgh!")
                return
            
            if any(c["command"] == command for i, c in enumerate(self.counters) if i != counter_index):
                logger.warning(f"Command '{command}' already used by another counter during update, arrgh!")
                QMessageBox.warning(self, "Blunder", f"Command '{command}' is already used, arrgh!")
                return
            
            # Update the counter
            counter["name"] = name
            counter["command"] = command
            counter["increment"] = increment
            self._save_config()
            self.update_counters_list()
            
            # Clear input fields
            self.counter_name_input.clear()
            self.counter_command_input.clear()
            self.counter_increment_input.setText("1")
            self.counter_update_button.setEnabled(False)
            self.counter_delete_button.setEnabled(False)
            
            logger.info(f"Updated counter at index {counter_index} to '{name}', arrgh!")
        except Exception as e:
            logger.error(f"Failed to update counter: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            QMessageBox.critical(self, "Blunder", f"Failed to update counter: {e}, arrgh!")

    def delete_counter(self):
        logger.debug("Entering delete_counter, arrgh!")
        try:
            selected_items = self.counters_list.selectedItems()
            if not selected_items:
                logger.warning("No counter selected for deletion, arrgh!")
                QMessageBox.warning(self, "Blunder", "Please select a counter to delete, arrgh!")
                return
            
            selected_item = selected_items[0]
            counter_index = self.counters_list.row(selected_item)
            counter_name = self.counters[counter_index]["name"]
            
            reply = QMessageBox.question(
                self,
                "Confirm Deletion",
                f"Are ye sure ye want to delete counter '{counter_name}', arrgh?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self.counters.pop(counter_index)
                self._save_config()
                self.update_counters_list()
                self.on_counter_selected()  # Update input fields and button states
                logger.info(f"Deleted counter '{counter_name}', arrgh!")
            else:
                logger.debug("Counter deletion cancelled, arrgh!")
        except Exception as e:
            logger.error(f"Failed to delete counter: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            QMessageBox.critical(self, "Blunder", f"Failed to delete counter: {e}, arrgh!")

    async def start_timer(self, timer):
        name = timer["name"]
        total_seconds = timer["minutes"] * 60 + timer["seconds"]
        logger.debug(f"Starting timer '{name}' with interval {total_seconds} seconds, arrgh!")
        while self.bot and name in [t["name"] for t in self.timers]:  # Continue while bot is running and timer exists
            try:
                await asyncio.sleep(total_seconds)
                if self.bot and name in [t["name"] for t in self.timers]:  # Double-check after sleep
                    channel_name = self.broadcaster_config["channel"].lstrip("#")
                    channel = self.bot.get_channel(channel_name)
                    if channel:
                        await channel.send(timer["message"])
                        logger.debug(f"Timer '{name}' triggered: {timer['message']}, arrgh!")
                    else:
                        logger.error(f"Failed to send timer message for '{name}': Channel {channel_name} not found, arrgh!")
                        file_handler.flush()
                        console_handler.flush()
                        break  # Exit the loop if channel is unavailable
            except asyncio.CancelledError:
                logger.debug(f"Timer '{name}' cancelled, arrgh!")
                break
            except Exception as e:
                logger.error(f"Timer '{name}' failed: {e}, arrgh!", exc_info=True)
                file_handler.flush()
                console_handler.flush()
                break  # Exit the loop on error to prevent further crashes

    def save_brb_settings(self):
        """Save BRB settings to config, arrgh!"""
        logger.debug("Enterin’ save_brb_settings, arrgh!")
        try:
            self.brb_settings["scene"] = self.brb_scene_dropdown.currentText()
            self.brb_settings["source"] = self.brb_source_dropdown.currentText()
            self.config["brb_settings"] = self.brb_settings
            self._save_config()
            logger.debug(f"Saved BRB settings: {self.brb_settings}, arrgh!")
        except Exception as e:
            logger.error(f"Failed to save BRB settings: {e}, arrgh!", exc_info=True)
        logger.debug("Leavin’ save_brb_settings, arrgh!")

    def save_raid_settings(self):
        """Save raid settings to config, arrgh!"""
        self.config["raid_settings"]["targets"] = self.raid_targets
        self.config["raid_settings"]["command"] = self.raid_command_input.text().strip() if hasattr(self, 'raid_command_input') else self.config["raid_settings"].get("command", "!raid")
        self.config["raid_settings"]["message"] = self.raid_message_input.text().strip() if hasattr(self, 'raid_message_input') else self.config["raid_settings"].get("message", "Squawk! Raidin’ {target}, arrgh!")
        self.config["raid_settings"]["scene"] = self.raid_scene_dropdown.currentText() if hasattr(self, 'raid_scene_dropdown') else self.config["raid_settings"].get("scene", "")
        self.config["raid_settings"]["source"] = self.raid_source_dropdown.currentText() if hasattr(self, 'raid_source_dropdown') else self.config["raid_settings"].get("source", "")
        self.config["raid_settings"]["clip_duration"] = self.raid_clip_duration_input.text().strip() if hasattr(self, 'raid_clip_duration_input') else self.config["raid_settings"].get("clip_duration", "60")
        self.config["raid_settings"]["session_raid_targets"] = list(self.bot.session_raid_targets) if hasattr(self, 'bot') and self.bot else self.config["raid_settings"].get("session_raid_targets", [])
        self.config["raid_settings"]["raid_attempts"] = self.bot.raid_attempts if hasattr(self, 'bot') and self.bot else self.config["raid_settings"].get("raid_attempts", [])
        self._save_config()
        # Notify bot of changes if it's running
        if self.bot and self.bot_thread and self.bot_thread.isRunning():
            self.bot.update_settings()
        logger.debug("Raid settings saved, arrgh!")

    def start_all_timers(self):
        if not self.config["toggles"].get("timers_enabled", True):
            logger.debug("Timers toggle disabled, skippin’ timer start, arrgh!")
            return
        logger.debug("Enterin’ start_all_timers, arrgh!")
        try:
            for timer_name, timer_task in self.timer_tasks.items():
                logger.debug(f"Stoppin’ existin’ timer '{timer_name}', arrgh!")
                try:
                    timer_task.stop()
                except Exception as e:
                    logger.warning(f"Failed to stop timer '{timer_name}': {e}, arrgh!", exc_info=True)
            self.timer_tasks.clear()
            logger.debug("Cleared existin’ timer tasks, arrgh!")
            
            logger.debug(f"Found {len(self.timers)} timers to schedule, arrgh!")
            for timer in self.timers:
                logger.debug(f"Processin’ timer: {timer}, arrgh!")
                try:
                    self.schedule_timer(timer)
                except Exception as e:
                    logger.error(f"Failed to schedule timer {timer}: {e}, arrgh!", exc_info=True)
                    continue
            
            logger.info(f"Scheduled {len(self.timers)} timers, arrgh!")
        except Exception as e:
            logger.error(f"Failed to start timers: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            QMessageBox.warning(self, "Blunder", f"Failed to start timers: {e}, arrgh!")

    def stop_all_timers(self):
        logger.debug("Entering stop_all_timers, arrgh!")
        try:
            for task_name, task in list(self.timer_tasks.items()):
                logger.debug(f"Stopping timer '{task_name}', arrgh!")
                task.stop()
                task.timeout.disconnect()  # Disconnect the timeout signal
            self.timer_tasks.clear()
            logger.debug("All timers stopped and cleared, arrgh!")
        except Exception as e:
            logger.error(f"Failed to stop timers: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()


    def handle_login(self, account_type):
        logger.debug(f"Handling login for {account_type}, arrgh!")
        try:
            config_key = "broadcaster" if account_type == "broadcaster" else "bot"
            username_field = self.broadcaster_username_input if account_type == "broadcaster" else self.bot_username_input
            status_label = self.broadcaster_status_label if account_type == "broadcaster" else self.bot_status_label
            logout_button = self.broadcaster_logout_button if account_type == "broadcaster" else self.bot_logout_button
            
            if account_type == "broadcaster":
                scope = "chat:read chat:edit channel:manage:raids"
            else:  # Bot account
                scope = "chat:read chat:edit moderator:manage:shoutouts channel:manage:raids user:read:broadcast"  # Add user:read:broadcast scope
            token, username, expires_in, refresh_token, error_message = start_oauth_flow(account_type, scope)
            
            if error_message:
                logger.error(f"OAuth flow failed for {account_type}: {error_message}, arrgh!")
                file_handler.flush()
                console_handler.flush()
                QMessageBox.critical(self, "Blunder", f"Failed to log in as {account_type}: {error_message}, arrgh!")
                return
            
            if token and username:
                if not token.startswith("oauth:"):
                    token = f"oauth:{token}"
                    logger.debug(f"Added 'oauth:' prefix to {account_type} token, arrgh!")
                
                issued_at = int(time.time())
                expires_at = issued_at + expires_in
                
                logger.debug(f"issued_at: {issued_at}, expires_at: {expires_at}, arrgh!")
                logger.debug(f"Token expires in {(expires_at - issued_at) / (60 * 60 * 24)} days, arrgh!")
                
                self.config[config_key]["username"] = username
                self.config[config_key]["token"] = token
                self.config[config_key]["issued_at"] = issued_at
                self.config[config_key]["expires_at"] = expires_at
                self.config[config_key]["refresh_token"] = refresh_token
                if account_type == "broadcaster":
                    self.broadcaster_config = self.config[config_key]
                    channel = self.broadcaster_channel_input.text().strip()
                    if not channel:
                        channel = f"#{username}"
                        self.broadcaster_channel_input.setText(channel)
                    self.broadcaster_config["channel"] = channel if channel.startswith("#") else f"#{channel}"
                    self.config[config_key]["channel"] = self.broadcaster_config["channel"]
                else:
                    self.bot_config = self.config[config_key]
                
                self._save_config()
                
                username_field.setText(username)
                status_label.setText(f"{account_type.capitalize()}: Logged In")
                logout_button.setEnabled(True)
                broadcaster_status = f"Broadcaster: Logged In as {self.broadcaster_config['username']}" if self.broadcaster_config["username"] else "Broadcaster: Not Logged In"
                bot_status = f"Bot: Logged In as {self.bot_config['username']}" if self.bot_config["username"] else "Bot: Not Logged In"
                if self.bot_thread and self.bot_thread.isRunning():
                    broadcaster_status += " (Running)"
                    bot_status += " (Running)"
                self.update_login_status_labels(broadcaster_status, bot_status)
                QMessageBox.information(self, "Success", f"Logged in as {account_type} ({username}), arrgh!")
            else:
                logger.error(f"Login failed for {account_type}: No credentials returned, arrgh!")
                file_handler.flush()
                console_handler.flush()
                QMessageBox.critical(self, "Blunder", f"Failed to log in as {account_type}: No credentials returned, arrgh!")
        except Exception as e:
            logger.error(f"Login failed for {account_type}: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            QMessageBox.critical(self, "Blunder", f"Failed to log in as {account_type}: {e}, arrgh!")

    def refresh_broadcaster_token(self):
        """Refresh the broadcaster token using the refresh token."""
        logger.debug("Attempting to refresh broadcaster token, arrgh!")
        try:
            if not self.broadcaster_config.get("refresh_token"):
                logger.error("No refresh token available for broadcaster, cannot refresh, arrgh!")
                return False

            access_token, expires_in, new_refresh_token, error_message = refresh_twitch_token(self.broadcaster_config["refresh_token"])
            if error_message:
                logger.error(f"Failed to refresh broadcaster token: {error_message}, arrgh!")
                file_handler.flush()
                console_handler.flush()
                return False

            issued_at = int(time.time())
            expires_at = issued_at + expires_in

            if not access_token.startswith("oauth:"):
                access_token = f"oauth:{access_token}"
                logger.debug("Added 'oauth:' prefix to refreshed broadcaster token, arrgh!")

            self.broadcaster_config["token"] = access_token
            self.broadcaster_config["issued_at"] = issued_at
            self.broadcaster_config["expires_at"] = expires_at
            self.broadcaster_config["refresh_token"] = new_refresh_token
            self._save_config()

            # Update the bot with the new token if it's running
            if self.bot and self.bot_thread and self.bot_thread.isRunning():
                self.bot.broadcaster_client._http.token = access_token
                self.bot.broadcaster_token = access_token  # Ensure the raid call uses the new token
                logger.debug(f"Updated broadcaster token in running bot: {access_token[:5]}..., arrgh!")

            logger.info("Successfully refreshed broadcaster token, arrgh!")
            return True
        except Exception as e:
            logger.error(f"Failed to refresh broadcaster token: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            return False


    def refresh_bot_token(self):
        """Refresh the bot token using the refresh token."""
        logger.debug("Attempting to refresh bot token, arrgh!")
        try:
            if not self.bot_config.get("refresh_token"):
                logger.error("No refresh token available for bot, cannot refresh, arrgh!")
                return False

            access_token, expires_in, new_refresh_token, error_message = refresh_twitch_token(self.bot_config["refresh_token"])
            if error_message:
                logger.error(f"Failed to refresh bot token: {error_message}, arrgh!")
                file_handler.flush()
                console_handler.flush()
                return False

            issued_at = int(time.time())
            expires_at = issued_at + expires_in

            if not access_token.startswith("oauth:"):
                access_token = f"oauth:{access_token}"
                logger.debug("Added 'oauth:' prefix to refreshed bot token, arrgh!")

            self.bot_config["token"] = access_token
            self.bot_config["issued_at"] = issued_at
            self.bot_config["expires_at"] = expires_at
            self.bot_config["refresh_token"] = new_refresh_token
            self._save_config()

            # Update the bot with the new token if it's running
            if self.bot and self.bot_thread and self.bot_thread.isRunning():
                self.bot._connection._token = access_token
                logger.debug(f"Updated bot token in running bot: {access_token[:5]}..., arrgh!")

            logger.info("Successfully refreshed bot token, arrgh!")
            return True
        except Exception as e:
            logger.error(f"Failed to refresh bot token: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            return False

    def on_brb_scene_selected(self):
        """Handle BRB scene selection to refresh sources, arrgh!"""
        logger.debug("Enterin’ on_brb_scene_selected, arrgh!")
        scene = self.brb_scene_dropdown.currentText()
        logger.debug(f"Selected BRB scene: {scene}, OBS connected: {self.obs_client.connected}, arrgh!")
        
        if scene and self.obs_client.connected:
            try:
                # Fetch sources for the new scene
                sources = self.obs_client.get_sources(scene)
                logger.debug(f"Fetched {len(sources)} sources fer BRB scene {scene}: {sources}, arrgh!")
                
                # Update the source dropdown
                self.brb_source_dropdown.blockSignals(True)
                try:
                    self.brb_source_dropdown.clear()
                    self.brb_source_dropdown.addItems(sources)
                    logger.debug(f"Updated BRB source dropdown with {len(sources)} sources, arrgh!")
                finally:
                    self.brb_source_dropdown.blockSignals(False)
            except Exception as e:
                logger.error(f"Failed to fetch sources fer BRB scene {scene}: {e}, arrgh!", exc_info=True)
                file_handler.flush()
                console_handler.flush()
                self.brb_source_dropdown.clear()
                QMessageBox.critical(self, "Blunder", f"Failed to fetch sources fer scene {scene}: {e}, arrgh!")
        else:
            self.brb_source_dropdown.clear()
            logger.debug("No scene selected or OBS be not connected, clearin’ BRB sources, arrgh!")
        
        self.save_brb_settings()
        logger.debug("Leavin’ on_brb_scene_selected, arrgh!")

    def handle_logout(self, account_type):
        logger.debug(f"Handling logout for {account_type}, arrgh!")
        try:
            if self.bot_thread and self.bot_thread.isRunning():
                QMessageBox.warning(self, "Blunder", "Please stop the bot before logging out, arrgh!")
                return

            if account_type == "broadcaster":
                self.broadcaster_config["username"] = ""
                self.broadcaster_config["token"] = ""
                self.broadcaster_config["channel"] = ""
                self.broadcaster_config["issued_at"] = 0
                self.broadcaster_config["expires_at"] = 0
                self.broadcaster_config["refresh_token"] = ""
                self.config["broadcaster"] = {"username": "", "token": "", "channel": "", "issued_at": 0, "expires_at": 0, "refresh_token": ""}
                self.broadcaster_username_input.setText("")
                self.broadcaster_channel_input.setText("")
                self.broadcaster_logout_button.setEnabled(False)
            else:
                self.bot_config["username"] = ""
                self.bot_config["token"] = ""
                self.bot_config["issued_at"] = 0
                self.bot_config["expires_at"] = 0
                self.bot_config["refresh_token"] = ""
                self.config["bot"] = {"username": "", "token": "", "issued_at": 0, "expires_at": 0, "refresh_token": ""}
                self.bot_username_input.setText("")
                self.bot_logout_button.setEnabled(False)

            self._save_config()
            self.update_login_status_labels()
            QMessageBox.information(self, "Success", f"Logged out {account_type} account, arrgh!")
        except Exception as e:
            logger.error(f"Failed to logout {account_type}: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            QMessageBox.critical(self, "Blunder", f"Failed to logout {account_type}: {str(e)}, arrgh!")

    def handle_obs_connect(self):
        if not self.config["toggles"].get("obs_enabled", True):
            logger.debug("OBS toggle disabled, skippin’ OBS connection, arrgh!")
            return
        logger.debug("Handlin’ OBS connect, arrgh!")
        try:
            # Check if already connected to avoid redundant disconnect-reconnect
            if self.obs_client.connected:
                try:
                    self.obs_client.req_client.get_version()
                    logger.info("OBS is already connected, no need to reconnect, arrgh!")
                    self.update_obs_status_label()
                    self.update_obs_buttons()
                    # Ensure scenes and sources are refreshed and state is restored
                    self.refresh_obs_scenes_sources()
                    if self.tab_list.currentRow() == self.tab_names.index("🎥 OBS"):
                        QMessageBox.information(self, "Success", "Already connected to OBS WebSocket, arrgh!")
                    return
                except Exception as e:
                    logger.debug(f"Existing OBS connection is stale: {e}, proceedin’ with disconnect, arrgh!")
                    self.obs_client.disconnect()
                    self.update_obs_status_label()
                    self.update_obs_buttons()

            server_ip = self.obs_ip_input.text().strip()
            server_port = self.obs_port_input.text().strip()
            server_password = self.obs_password_input.text().strip()

            # Validate all fields are filled
            if not server_ip:
                logger.error("Server IP cannot be empty, arrgh!")
                QMessageBox.critical(self, "Blunder", "Server IP cannot be empty, arrgh!")
                return
            if not server_port:
                logger.error("Server Port cannot be empty, arrgh!")
                QMessageBox.critical(self, "Blunder", "Server Port cannot be empty, arrgh!")
                return
            if not server_password:
                logger.error("Server Password cannot be empty, arrgh!")
                QMessageBox.critical(self, "Blunder", "Server Password cannot be empty, arrgh! OBS requires a password for authentication.")
                return

            # Save OBS settings
            self.obs_config["server_ip"] = server_ip
            self.obs_config["server_port"] = server_port
            self.obs_config["server_password"] = server_password
            self.config["obs"] = self.obs_config
            self._save_config()

            # Connect to OBS
            self.obs_client.connect(server_ip, server_port, server_password)
            time.sleep(0.5)  # Allow connection to establish
            self.update_obs_status_label()
            self.update_obs_buttons()

            # Refresh scenes and sources after connecting, ensuring saved state is applied
            self.refresh_obs_scenes_sources()

            # Show correct prompt based on connection status (only for manual connect, not auto-connect)
            if self.tab_list.currentRow() == self.tab_names.index("🎥 OBS"):
                if self.obs_client.connected:
                    QMessageBox.information(self, "Success", "Connected to OBS WebSocket, arrgh!")
                else:
                    logger.error("Failed to connect to OBS WebSocket, arrgh!")
                    QMessageBox.critical(self, "Blunder", "Failed to connect to OBS WebSocket, arrgh!")
        except Exception as e:
            logger.error(f"Failed to connect to OBS: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            self.obs_client.connected = False
            self.update_obs_status_label()
            self.update_obs_buttons()
            if self.tab_list.currentRow() == self.tab_names.index("🎥 OBS"):
                QMessageBox.critical(self, "Blunder", f"Failed to connect to OBS: {str(e)}, arrgh!")

    def handle_obs_disconnect(self):
        logger.debug("Handling OBS disconnect, arrgh!")
        try:
            if not self.obs_client.req_client and not self.obs_client.event_client:
                logger.info("No active OBS connection to disconnect, arrgh!")
                self.update_obs_status_label()
                self.update_obs_buttons()
                return

            self.obs_client.disconnect()
            time.sleep(0.5)  # Ensure disconnection completes
            self.update_obs_status_label()
            self.update_obs_buttons()
            QMessageBox.information(self, "Success", "Disconnected from OBS WebSocket, arrgh!")
        except Exception as e:
            logger.error(f"Failed to disconnect from OBS: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            self.obs_client.connected = False
            self.update_obs_status_label()
            self.update_obs_buttons()
            QMessageBox.critical(self, "Blunder", f"Failed to disconnect from OBS: {str(e)}, arrgh!")

    def update_obs_status_label(self):
        # Actively check the connection state
        if self.obs_client.req_client:
            try:
                self.obs_client.req_client.get_version()
                self.obs_client.connected = True
                logger.debug("OBS connection confirmed active via get_version, arrgh!")
            except Exception as e:
                logger.debug(f"OBS connection check failed: {e}, arrgh!")
                self.obs_client.connected = False
                self.obs_client.disconnect()  # Clean up if connection is invalid
        else:
            self.obs_client.connected = False
        self.obs_status_label.setText("OBS: Connected" if self.obs_client.connected else "OBS: Disconnected")
        logger.debug(f"OBS status updated to: {self.obs_status_label.text()}, arrgh!")

    def update_obs_buttons(self):
        self.obs_connect_button.setEnabled(not self.obs_client.connected)
        self.obs_disconnect_button.setEnabled(self.obs_client.connected)

    def handle_obs_disconnect(self):
        logger.debug("Handling OBS disconnect, arrgh!")
        try:
            self.obs_client.disconnect()
            QMessageBox.information(self, "Success", "Disconnected from OBS WebSocket, arrgh!")
        except Exception as e:
            logger.error(f"Failed to disconnect from OBS: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            QMessageBox.critical(self, "Blunder", f"Failed to disconnect from OBS: {str(e)}, arrgh!")

    def update_obs_status_label(self):
        # Actively check the connection state
        if self.obs_client.req_client:
            try:
                self.obs_client.req_client.get_version()
                self.obs_client.connected = True
                logger.debug("OBS connection confirmed active via get_version, arrgh!")
            except Exception as e:
                logger.debug(f"OBS connection check failed: {e}, arrgh!")
                self.obs_client.connected = False
                self.obs_client.disconnect()  # Clean up if connection is invalid
        else:
            self.obs_client.connected = False
        self.obs_status_label.setText("OBS: Connected" if self.obs_client.connected else "OBS: Disconnected")
        logger.debug(f"OBS status updated to: {self.obs_status_label.text()}, arrgh!")

    def update_login_status_labels(self, broadcaster_status=None, bot_status=None):
        """Update the login status labels in the Login tab."""
        if broadcaster_status is None or bot_status is None:
            broadcaster_status = f"Broadcaster: Logged In as {self.broadcaster_config['username']}" if self.broadcaster_config["username"] else "Broadcaster: Not Logged In"
            bot_status = f"Bot: Logged In as {self.bot_config['username']}" if self.bot_config["username"] else "Bot: Not Logged In"
            if self.bot_thread and self.bot_thread.isRunning():
                broadcaster_status += " (Running)"
                bot_status += " (Running)"
        
        self.broadcaster_status_label.setText(broadcaster_status)
        self.bot_status_label.setText(bot_status)

    def update_status(self, message=None):
        """Update the main status bar with bot running status only."""
        logger.debug("Entering update_status, arrgh!")
        try:
            if message:
                self.status_label.setText(message)
                return
            bot_status = "Bot Status: Full Sailin!" if self.bot else "Bot Status: Anchored"
            self.status_label.setText(bot_status)
            logger.debug(f"Updated status: {bot_status}, arrgh!")
        except Exception as e:
            logger.error(f"Failed to update status: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
        finally:
            logger.debug("Exiting update_status, arrgh!")

    def on_tab_changed(self, index):
        self.tab_stack.setCurrentIndex(index)
        logger.debug(f"Switched to tab: {self.tab_names[index]}, arrgh!")

    def start_bot(self):
        logger.debug("Entering start_bot, arrgh!")
        try:
            # Fully terminate the existing bot thread if it exists
            if self.bot_thread:
                logger.debug("Terminatin’ existin’ bot thread before startin’ new one, arrgh!")
                if self.bot_thread.isRunning():
                    # Disconnect signals to prevent lingerin’ connections
                    try:
                        self.bot_thread.status_updated.disconnect()
                        self.bot_thread.error_occurred.disconnect()
                        self.bot_thread.login_status_updated.disconnect()
                    except Exception as e:
                        logger.warning(f"Failed to disconnect signals from bot_thread: {e}, arrgh!")
                    self.bot_thread.stop()
                    deadline = time.time() + 10  # Wait up to 10s for thread to terminate
                    self.bot_thread.wait(msecs=10000)
                    if self.bot_thread.isRunning():
                        logger.error("BotThread failed to terminate within 10s, arrgh!")
                        self.update_status("Bot Status: Failed to terminate previous thread")
                        QMessageBox.critical(self, "Blunder", "Failed to terminate previous bot thread, arrgh!")
                        return
                self.bot_thread = None  # Clear the reference

            if not all([self.broadcaster_config["username"], self.broadcaster_config["token"], self.broadcaster_config["channel"]]):
                logger.error("Missing broadcaster credentials, arrgh!")
                file_handler.flush()
                console_handler.flush()
                self.update_status("Bot Status: Missing broadcaster credentials")
                QMessageBox.critical(self, "Blunder", "Please log in as broadcaster and ensure a channel is set, arrgh!")
                return
            
            if not all([self.bot_config["username"], self.bot_config["token"]]):
                logger.error("Missing bot credentials, arrgh!")
                file_handler.flush()
                console_handler.flush()
                self.update_status("Bot Status: Missing bot credentials")
                QMessageBox.critical(self, "Blunder", "Please log in as bot, arrgh!")
                return
            
            bot_token = self.bot_config["token"]
            if not bot_token.startswith("oauth:"):
                bot_token = f"oauth:{bot_token}"
                self.bot_config["token"] = bot_token
                self.config["bot"]["token"] = bot_token
                self._save_config()
                logger.debug("Added 'oauth:' prefix to bot token in start_bot, arrgh!")
            
            current_time = int(time.time())
            bot_expires_at = self.bot_config.get("expires_at", 0)
            
            if bot_expires_at <= current_time or (bot_expires_at - current_time) < 300:
                logger.debug("Bot token is expired or near expiration, attempting to refresh, arrgh!")
                success = self.refresh_bot_token()
                if not success:
                    logger.error("Token refresh failed, re-authentication required, arrgh!")
                    self.update_status("Bot Status: Token Expired - Re-authentication Required")
                    QMessageBox.critical(self, "Blunder", "Bot token expired and refresh failed. Please re-authenticate the bot, arrgh!")
                    return
                bot_token = self.bot_config["token"]
            
            logger.debug(f"Checking token expiry: current_time={current_time}, expires_at={bot_expires_at}, arrgh!")
            
            token_without_prefix = bot_token.replace("oauth:", "")
            valid, result, _ = validate_twitch_token(token_without_prefix)
            if not valid:
                logger.error(f"Bot token is invalid or unauthorized: {result}, arrgh!")
                file_handler.flush()
                console_handler.flush()
                self.update_status("Bot Status: Invalid bot token")
                QMessageBox.critical(
                    self,
                    "Blunder",
                    f"The bot access token is invalid or unauthorized: {result}. Please log in again as the bot, arrgh!"
                )
                return
            
            if self.tab_list.currentRow() == self.tab_names.index("🎥 OBS"):
                try:
                    self.handle_obs_connect()
                except Exception as e:
                    logger.error(f"OBS connection failed before starting bot: {e}, arrgh!", exc_info=True)
                    file_handler.flush()
                    console_handler.flush()
            
            logger.debug(f"Starting bot with token: {bot_token[:10]}... (showing first 10 chars), arrgh!")
            self.bot_thread = BotThread(
                gui=self,
                broadcaster_token=self.broadcaster_config["token"],
                bot_token=bot_token,
                broadcaster_username=self.broadcaster_config["username"],
                bot_username=self.bot_config["username"],
                channel=self.broadcaster_config["channel"]
            )
            self.bot_thread.status_updated.connect(self.update_status)
            self.bot_thread.error_occurred.connect(self.handle_bot_error)
            self.bot_thread.login_status_updated.connect(self.update_login_status_labels)
            self.bot_thread.start()
            
            # Wait for the bot instance to be created in BotThread, with a longer timeout
            deadline = time.time() + 30  # Increased to 30s to handle network delays
            while not hasattr(self.bot_thread, 'bot') or self.bot_thread.bot is None:
                if time.time() > deadline:
                    logger.error("BotThread failed to initialize bot instance within 30s, arrgh!")
                    self.update_status("Bot Status: Failed to initialize")
                    QMessageBox.critical(self, "Blunder", "BotThread failed to initialize bot instance, arrgh!")
                    return
                time.sleep(0.1)
            self.bot = self.bot_thread.bot  # Set self.bot to the BotThread's bot instance
            
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.start_all_timers()
            self.update_status("Bot Status: Full Sailin!")
            broadcaster_status = f"Broadcaster: Logged In as {self.broadcaster_config['username']}" if self.broadcaster_config["username"] else "Broadcaster: Not Logged In"
            bot_status = f"Bot: Logged In as {self.bot_config['username']}" if self.bot_config["username"] else "Bot: Not Logged In"
            if self.bot_thread and self.bot_thread.isRunning():
                broadcaster_status += " (Running)"
                bot_status += " (Running)"
            self.bot_thread.login_status_updated.emit(broadcaster_status, bot_status)
            logger.info("Bot started with broadcaster and bot accounts, arrgh!")
        except Exception as e:
            logger.error(f"Failed to start bot: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            self.update_status("Bot Status: Failed to start")
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            QMessageBox.critical(self, "Blunder", f"Failed to start bot: {e}, arrgh!")
        finally:
            logger.debug("Exiting start_bot, arrgh!")

    def stop_bot(self):
        logger.debug("Enterin’ stop_bot, arrgh!")
        try:
            if not self.bot_thread or not self.bot_thread.isRunning():
                logger.info("No bot runnin’, arrgh!")
                self.update_status("Bot Status: Anchored")
                return
            self.is_shutting_down = True
            logger.debug("Set is_shuttin_down flag, arrgh!")
            self.stop_all_timers()
            logger.debug("Timers stopped, arrgh!")
            time.sleep(0.5)
            if self.bot and hasattr(self.bot, 'loop') and self.bot.loop and not self.bot.loop.is_closed():
                loop = self.bot.loop
                try:
                    tasks = [task for task in asyncio.all_tasks(loop) if task is not asyncio.current_task(loop)]
                    for task in tasks:
                        task.cancel()
                    logger.debug(f"Cancelled {len(tasks)} tasks, arrgh!")
                    if tasks:
                        async def wait_tasks():
                            return await asyncio.wait(tasks, timeout=2, return_when=asyncio.ALL_COMPLETED)
                        future = asyncio.run_coroutine_threadsafe(wait_tasks(), loop)
                        future.result(timeout=2)
                    future = asyncio.run_coroutine_threadsafe(self.bot.close(), loop)
                    future.result(timeout=1)
                    logger.info("Bot closed, arrgh!")
                    if hasattr(self.bot, 'broadcaster_client') and self.bot.broadcaster_client:
                        future = asyncio.run_coroutine_threadsafe(self.bot.broadcaster_client.close(), loop)
                        future.result(timeout=1)
                        logger.info("Broadcaster client closed, arrgh!")
                except Exception as e:
                    logger.warning(f"Error durin’ cleanup: {e}, arrgh!")
            self.bot_thread.stop()
            self.bot_thread.wait(2000)
            self.bot_thread = None
            self.bot = None
            self.is_shutting_down = False
            self.update_status("Bot Status: Anchored")
            broadcaster_status = f"Broadcaster: Logged In as {self.broadcaster_config['username']}" if self.broadcaster_config["username"] else "Broadcaster: Not Logged In"
            bot_status = f"Bot: Logged In as {self.bot_config['username']}" if self.bot_config["username"] else "Bot: Not Logged In"
            self.update_login_status_labels(broadcaster_status, bot_status)
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            logger.info("Bot stopped, arrgh!")
        except Exception as e:
            logger.error(f"Failed to stop bot: {e}, arrgh!")
            self.bot_thread = None
            self.bot = None
            self.is_shutting_down = False
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.update_status("Bot Status: Failed to stop")
        finally:
            logger.debug("Exitin’ stop_bot, arrgh!")

    async def _run_bot(self):
        logger.debug("Entering _run_bot, arrgh!")
        try:
            logger.debug(f"Attempting to start bot with token: {self.bot_config['token'][:10]}... (showing first 10 chars), arrgh!")
            await self.bot.start_all()  # Start both broadcaster client and bot
            logger.debug("Bot started successfully and connected to Twitch, arrgh!")
        except Exception as e:
            logger.error(f"Failed to run bot: {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            self.bot = None
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.update_status("Bot Status: Failed to start")
            QMessageBox.critical(self, "Blunder", f"Failed to run bot: {e}, arrgh!")
            raise
        finally:
            logger.debug("Exiting _run_bot, arrgh!")

    def handle_bot_error(self, error_message):
        """Slot to handle errors emitted by the bot thread."""
        logger.error(f"Bot error received in GUI thread: {error_message}, arrgh!")
        # Emit the login status updated signal before clearing self.bot_thread
        broadcaster_status = f"Broadcaster: Logged In as {self.broadcaster_config['username']}" if self.broadcaster_config["username"] else "Broadcaster: Not Logged In"
        bot_status = f"Bot: Logged In as {self.bot_config['username']}" if self.bot_config["username"] else "Bot: Not Logged In"
        if self.bot_thread:  # Check if bot_thread is still valid
            self.bot_thread.login_status_updated.emit(broadcaster_status, bot_status)
        self.bot = None
        self.bot_thread = None
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.update_status("Bot Status: Crashed")
        QMessageBox.critical(self, "Blunder", error_message)

    def _setup_file_renamer(self):
        """Initialize the file renamer system, detectin’ active recordin’s, arrgh!"""
        self.directory = self.config["file_renamer"]["directory"]
        self.include_subdirs = self.config["file_renamer"]["include_subdirs"]
        if not self.directory or not os.path.isdir(self.directory):
            logger.warning("No valid directory specified for file renamer, please set it in settings, arrgh!")
            return
        self._initialize_known_files()
        
        # Scan for growin’ files on startup
        for root, _, files in os.walk(self.directory):
            for file in files:
                if file.endswith((".mp4", ".mkv", ".flv")):  # Adjust for OBS formats
                    file_path = os.path.join(root, file)
                    if file_path not in self.known_files:
                        self.known_files.add(file_path)
                        logger.debug(f"Detected potential active file on startup: {file_path}, arrgh!")
                        self.check_file_stability(file_path)
        
        self._start_monitoring()
        logger.debug(f"File renamer setup with directory: {self.directory}, include_subdirs: {self.include_subdirs}, arrgh!")

    def browse_directory(self):
        """Open a directory selection dialog and update the file renamer directory."""
        directory = QFileDialog.getExistingDirectory(
            self,
            "Select OBS Recording Directory",
            self.directory or os.path.expanduser("~"),
            QFileDialog.Option.ShowDirsOnly
        )
        if directory:
            self.file_renamer_dir_input.setText(directory)
            # update_file_renamer_dir is triggered by textChanged signal

    def _initialize_known_files(self):
        """Populate known_files with existing files to ignore them."""
        if not self.directory or not os.path.isdir(self.directory):
            logger.error(f"Invalid directory for file renamer: {self.directory}, arrgh!")
            return
        for root, _, files in os.walk(self.directory):
            for file in files:
                full_path = os.path.join(root, file)
                self.known_files.add(full_path)
        logger.debug(f"Initialized {len(self.known_files)} known files, arrgh!")

    def update_file_renamer_dir(self):
        """Update the file renamer directory and restart monitoring."""
        new_dir = self.file_renamer_dir_input.text().strip()
        if not new_dir and self.config["file_renamer"]["directory"]:
            return
        if new_dir and os.path.isdir(new_dir) and new_dir != self.directory:
            self.directory = new_dir
            self.config["file_renamer"]["directory"] = self.directory
            try:
                self._save_config()
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    saved_config = json.load(f)
                if saved_config["file_renamer"]["directory"] != self.directory:
                    logger.error(f"Failed to save file renamer directory to config file, arrgh!")
                else:
                    logger.debug(f"File renamer directory saved to config: {self.directory}, arrgh!")
            except Exception as e:
                logger.error(f"Error savin’ file renamer directory to config: {e}, arrgh!", exc_info=True)
            if self.observer:
                self.observer.stop()
                self.observer.join()
            self._setup_file_renamer()
            logger.debug(f"File renamer directory updated to: {self.directory}, arrgh!")
        else:
            logger.warning(f"Invalid or unchanged directory: {new_dir}, skippin’ update, arrgh!")

    def update_file_renamer_subdirs(self):
        """Update the include subdirectories setting and restart monitoring."""
        self.include_subdirs = self.file_renamer_subdirs_check.isChecked()
        self.config["file_renamer"]["include_subdirs"] = self.include_subdirs
        self._save_config()
        if self.observer:
            self.observer.stop()
            self.observer.join()
        self._setup_file_renamer()
        logger.debug(f"File renamer include_subdirs updated to: {self.include_subdirs}, arrgh!")

    def _start_monitoring(self):
        """Start monitoring the directory for new files."""
        if not self.directory or not os.path.isdir(self.directory):
            logger.error(f"Cannot start monitoring, invalid directory: {self.directory}, arrgh!")
            return
        self.observer = Observer()
        event_handler = NewFileHandler(self)
        self.observer.schedule(event_handler, self.directory, recursive=self.include_subdirs)
        self.observer.start()
        logger.debug(f"Started monitoring directory: {self.directory}, recursive: {self.include_subdirs}, arrgh!")

    def check_file_stability(self, file_path, force_prompt=False):
        """Check if a file is stable (not being written to) and fully readable before prompting for rename."""
        def stability_check():
            prev_size = -1
            stable_count = 0
            STABLE_THRESHOLD = 3   # Number of checks (3 checks * 5s = 15s stability)
            CHECK_INTERVAL = 5     # Seconds between size checks
            MAX_RETRIES = 10       # Max attempts to check if file is unlocked
            RETRY_INTERVAL = 2     # Seconds between retry attempts
            TIMEOUT = 120          # Max seconds to wait overall

            start_time = time.time()
            while time.time() - start_time < TIMEOUT:
                try:
                    current_size = os.path.getsize(file_path)
                    if current_size == prev_size and current_size > 0:
                        stable_count += 1
                        logger.debug(f"File {file_path} size stable for {stable_count}/{STABLE_THRESHOLD} checks, size: {current_size}, arrgh!")
                        if stable_count >= STABLE_THRESHOLD or force_prompt:
                            # Size stable or forced (split detected), check if unlocked
                            for attempt in range(MAX_RETRIES):
                                try:
                                    # Try opening exclusively to mimic rename
                                    with open(file_path, 'rb+') as f:
                                        f.read(1)  # Read a byte to ensure access
                                    logger.debug(f"File {file_path} is readable, prompting rename, arrgh!")
                                    self.app.postEvent(self, QCustomEvent(self.prompt_rename, file_path))
                                    break
                                except (IOError, PermissionError) as e:
                                    logger.debug(f"File {file_path} still locked on attempt {attempt + 1}/{MAX_RETRIES}: {e}, arrgh!")
                                    if attempt == MAX_RETRIES - 1:
                                        logger.error(f"File {file_path} remained locked after {MAX_RETRIES} attempts, giving up, arrgh!")
                                        break
                                    time.sleep(RETRY_INTERVAL)
                            else:
                                continue  # Continue checking if locked
                            break  # Exit if prompt posted or max retries hit
                    else:
                        stable_count = 0  # Reset if size changed
                        logger.debug(f"File {file_path} size changed to {current_size}, resetting stable count, arrgh!")
                    prev_size = current_size
                    time.sleep(CHECK_INTERVAL)
                except FileNotFoundError:
                    logger.debug(f"File {file_path} no longer exists, stopping stability check, arrgh!")
                    break
                except Exception as e:
                    logger.error(f"Error checking stability of {file_path}: {e}, arrgh!", exc_info=True)
                    break
            else:
                logger.error(f"Timeout waiting for {file_path} to stabilize after {TIMEOUT}s, giving up, arrgh!")
            # Only remove from active_files, keep known_files until renamed
            if file_path in self.active_files:
                del self.active_files[file_path]

        # Start or update thread for this file
        if file_path not in self.active_files:
            thread = threading.Thread(target=stability_check, daemon=True)
            self.active_files[file_path] = thread
            thread.start()
            logger.debug(f"Started stability check thread for {file_path}, arrgh!")

    def prompt_rename(self, file_path):
        """Prompt the user to rename the file using a PyQt6 dialog."""
        new_name, ok = QInputDialog.getText(
            self,
            "Rename File",
            f"Enter new name for {os.path.basename(file_path)}:",
            QLineEdit.EchoMode.Normal,
            os.path.basename(file_path)
        )
        if ok and new_name:
            new_path = os.path.join(os.path.dirname(file_path), new_name)
            try:
                os.rename(file_path, new_path)
                logger.info(f"Renamed {file_path} to {new_path}, arrgh!")
                self.known_files.remove(file_path)
                self.known_files.add(new_path)
            except OSError as e:
                logger.error(f"Failed to rename {file_path} to {new_path}: {e}, arrgh!")
                QMessageBox.critical(self, "Error", f"Failed to rename file: {e}, arrgh!")

    def eventFilter(self, obj, event):
        """Handle custom events for rename prompts."""
        if event.type() == QCustomEvent.EVENT_TYPE:
            event.callback(event.data)
            return True
        return super().eventFilter(obj, event)

    def closeEvent(self, event):
        """Handle window close event to stop the observer and save settings."""
        # Save broadcaster channel before closing
        new_channel = self.broadcaster_channel_input.text().strip()
        if new_channel != self.broadcaster_config["channel"]:
            self.broadcaster_config["channel"] = new_channel
            self.config["broadcaster"]["channel"] = new_channel
            self._save_config()
            logger.debug(f"Saved broadcaster channel {new_channel} on close, arrgh!")
        
        # Existing observer shutdown logic
        if self.observer:
            self.observer.stop()
            self.observer.join()
            logger.debug("File renamer observer stopped, arrgh!")
        
        # Ensure bot thread is stopped if running
        self.is_shutting_down = True
        if self.bot_thread and self.bot_thread.isRunning():
            # Run _stop_raid_clips synchronously before stopping the bot
            loop = asyncio.get_event_loop()
            if loop.is_running():
                logger.warning("Event loop is running during closeEvent, cannot run _stop_raid_clips, arrgh!")
            else:
                try:
                    loop.run_until_complete(self._stop_raid_clips())
                    logger.debug("Successfully stopped raid clips during shutdown, arrgh!")
                except Exception as e:
                    logger.error(f"Failed to stop raid clips during shutdown: {e}, arrgh!")
            self.stop_bot()
        
        super().closeEvent(event)

# Custom event class for posting rename prompts to the main thread
class QCustomEvent(QEvent):
    EVENT_TYPE = QEvent.registerEventType()
    def __init__(self, callback, data):
        super().__init__(QEvent.Type(self.EVENT_TYPE))
        self.callback = callback
        self.data = data

# Event handler for file creation
class NewFileHandler(FileSystemEventHandler):
    def __init__(self, gui):
        self.gui = gui

    def on_created(self, event):
        if not event.is_directory:
            file_path = event.src_path
            if file_path not in self.gui.known_files:
                self.gui.known_files.add(file_path)
                logger.debug(f"New file detected: {file_path}, checking stability, arrgh!")
                # Finalize checks for previous files (possible split)
                for prev_path, thread in list(self.gui.active_files.items()):
                    if thread.is_alive() and prev_path != file_path:
                        logger.debug(f"New file {file_path} detected, forcing check on previous {prev_path}, arrgh!")
                        self.gui.check_file_stability(prev_path, force_prompt=True)
                # Start monitoring new file
                self.gui.check_file_stability(file_path)

class OAuthDialog(QDialog):
    def __init__(self, account_type, parent=None):
        super().__init__(parent)
        self.account_type = account_type
        self.username = None
        self.token = None
        self.setWindowTitle(f"Twitch OAuth - {account_type.capitalize()}")
        self.setGeometry(300, 300, 400, 200)
        
        layout = QVBoxLayout()
        self.label = QLabel(f"Please authenticate {account_type} account with Twitch.\nClick the button to open the authentication page.")
        self.label.setStyleSheet(f"QLabel {{ color: {GOLD}; font-family: '{parent.selected_font}'; font-size: 12pt; }}")
        layout.addWidget(self.label)
        
        self.auth_button = QPushButton("Authenticate with Twitch")
        self.auth_button.setStyleSheet(
            f"QPushButton {{ background-color: {GOLD}; color: {TYRIAN_PURPLE}; border: 0px; padding: 10px; font-family: '{parent.selected_font}'; font-size: 12pt; }}"
            f"QPushButton:pressed {{ background-color: {WEATHERED_PARCHMENT}; }}"
        )
        self.auth_button.clicked.connect(self.start_oauth)
        layout.addWidget(self.auth_button)
        
        self.setLayout(layout)
        self.redirect_port = 3000  # Use port 3000 to match REDIRECT_URI
        self.redirect_uri = REDIRECT_URI  # Use the global REDIRECT_URI constant (http://localhost:3000)

    def start_oauth(self):
        # Twitch OAuth URL (scopes for chat access and live status for bot)
        scopes = ["chat:read", "chat:edit", "moderator:manage:shoutouts", "channel:manage:raids"]
        if self.account_type == "bot":
            scopes.append("user:read:broadcast")  # Add user:read:broadcast for bot
        oauth_url = (
            "https://id.twitch.tv/oauth2/authorize"
            f"?client_id={CLIENT_ID}"
            f"&redirect_uri={self.redirect_uri}"
            f"&response_type=code"
            f"&scope={' '.join(scopes)}"
        )
        
        logger.debug(f"Opening browser for OAuth: {oauth_url}, arrgh!")
        webbrowser.open(oauth_url)
        
        # Start a local server to handle the redirect
        class OAuthHandler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(b"Authentication successful! You can close this window.")
                
                # Parse the code from the redirect URL
                query = urllib.parse.urlparse(self.path).query
                params = urllib.parse.parse_qs(query)
                code = params.get("code", [None])[0]
                
                # Signal the dialog to handle the code
                self.server.oauth_code = code
        
        # Start the server
        with socketserver.TCPServer(("", self.redirect_port), OAuthHandler) as httpd:
            httpd.oauth_code = None
            httpd.timeout = 60  # Wait up to 60 seconds for the redirect
            httpd.handle_request()
            
            if httpd.oauth_code:
                # Exchange the code for a token
                token = self.exchange_code_for_token(httpd.oauth_code)
                if token:
                    self.token = token
                    # Get the username associated with the token
                    self.username = self.get_username_from_token(token)
                    if self.username:
                        logger.debug(f"Successfully authenticated {self.account_type} as {self.username}, arrgh!")
                        self.accept()
                    else:
                        logger.error("Failed to get username from token, arrgh!")
                        self.reject()
                else:
                    logger.error("Failed to exchange code for token, arrgh!")
                    self.reject()
            else:
                logger.error("OAuth flow failed: No code received, arrgh!")
                self.reject()

    def exchange_code_for_token(self, code):
        # Exchange the authorization code for an access token
        url = "https://id.twitch.tv/oauth2/token"
        params = {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": self.redirect_uri  # Use the correct redirect_uri
        }
        try:
            response = requests.post(url, data=params)
            response.raise_for_status()
            data = response.json()
            token = data.get("access_token")
            if token:
                return token
            else:
                logger.error("No access token in response, arrgh!")
                return None
        except Exception as e:
            logger.error(f"Failed to exchange code for token: {e}, arrgh!", exc_info=True)
            return None

    def get_username_from_token(self, token):
        # Get the username associated with the token
        url = "https://api.twitch.tv/helix/users"
        headers = {
            "Authorization": f"Bearer {token}",
            "Client-ID": CLIENT_ID
        }
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            users = data.get("data", [])
            if users:
                return users[0]["login"]
            else:
                logger.error("No user data in response, arrgh!")
                return None
        except Exception as e:
            logger.error(f"Failed to get username from token: {e}, arrgh!", exc_info=True)
            return None

    def get_credentials(self):
        return self.username, self.token
    
    
    
class BotThread(QThread):
    status_updated = pyqtSignal(str)
    error_occurred = pyqtSignal(str)
    login_status_updated = pyqtSignal(str, str)

    def __init__(self, gui, broadcaster_token, bot_token, broadcaster_username, bot_username, channel):
        super().__init__()
        self.gui = gui
        self.broadcaster_token = broadcaster_token
        self.bot_token = bot_token
        self.broadcaster_username = broadcaster_username
        self.bot_username = bot_username
        self.channel = channel
        self.bot = None
        self.loop = None
        self.running = True
        self.brb_task = None
        self.keep_alive_task = None
        self._loop_closed = False
        logger.debug("BotThread initialized, arrgh!")

    def run(self):
        """Run the bot with crash resistance, arrgh!"""
        logger.info("BotThread run started, arrgh!")
        retry_count = 0
        max_retries = 5
        while self.running and retry_count < max_retries:
            try:
                # Create a new event loop
                self.loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self.loop)
                logger.info("Event loop created and set for BotThread, arrgh!")

                # Set global exception handler
                def handle_exception(loop, context):
                    logger.error(f"Unhandled exception in event loop: {context.get('exception', context)}, arrgh!", exc_info=True)
                    self.error_occurred.emit(f"Loop error: {context.get('exception', context)}")

                self.loop.set_exception_handler(handle_exception)

                # Clear any existing bot instance
                if hasattr(self, 'bot') and self.bot:
                    logger.info("Clearin’ existin’ SquawkBot instance, arrgh!")
                    try:
                        if not self.loop.is_closed():
                            asyncio.run_coroutine_threadsafe(self.bot.close(), self.loop).result(timeout=1)
                            asyncio.run_coroutine_threadsafe(self.bot.cleanup(), self.loop).result(timeout=1)
                        logger.info("Cleared existin’ SquawkBot instance, arrgh!")
                    except Exception as e:
                        logger.warning(f"Failed to clear existin’ SquawkBot instance: {e}, arrgh!")
                    self.bot = None

                # Initialize new bot instance
                try:
                    self.bot = SquawkBot(
                        gui=self.gui,
                        broadcaster_token=self.broadcaster_token,
                        bot_token=self.bot_token,
                        broadcaster_username=self.broadcaster_username,
                        bot_username=self.bot_username,
                        channel=self.channel,
                        loop=self.loop
                    )
                    self.bot.status_updated = self.status_updated
                    self.bot.error_occurred = self.error_occurred
                    self.bot.login_status_updated = self.login_status_updated
                    logger.info("SquawkBot instance created successfully, arrgh!")
                except Exception as e:
                    logger.error(f"Failed to initialize SquawkBot: {e}, arrgh!", exc_info=True)
                    self.error_occurred.emit(f"Failed to initialize bot: {e}, arrgh!")
                    raise

                # Start broadcaster client and bot tasks
                try:
                    self.loop.create_task(self.bot.broadcaster_client.start())
                    self.loop.create_task(self.bot.start())
                    logger.info("Started broadcaster client and bot tasks, arrgh!")
                except Exception as e:
                    logger.error(f"Failed to start twitchio clients: {e}, arrgh!", exc_info=True)
                    self.error_occurred.emit(f"Failed to start bot clients: {e}, arrgh!")
                    raise

                # Run the event loop
                try:
                    self.loop.run_forever()
                    logger.info("Event loop runnin’ forever, arrgh!")
                except Exception as e:
                    logger.error(f"Event loop crashed: {e}, arrgh!", exc_info=True)
                    self.error_occurred.emit(f"Event loop crashed: {e}, arrgh!")
                    raise
            except Exception as e:
                logger.error(f"BotThread run crashed: {e}, arrgh!", exc_info=True)
                self.error_occurred.emit(f"Bot crashed, attempt {retry_count + 1}/{max_retries}: {e}, arrgh!")
                retry_count += 1
                # Clean up before retry
                try:
                    if self.bot:
                        asyncio.run_coroutine_threadsafe(self.bot.close(), self.loop).result(timeout=1)
                        asyncio.run_coroutine_threadsafe(self.bot.cleanup(), self.loop).result(timeout=1)
                    if self.loop and not self.loop.is_closed():
                        self.loop.run_until_complete(self.loop.shutdown_asyncgens())
                        self.loop.run_until_complete(self.loop.shutdown_default_executor())
                        self.loop.close()
                except Exception as e:
                    logger.warning(f"Failed to clean up before retry: {e}, arrgh!")
                self.bot = None
                self.loop = None
                if self.running and retry_count < max_retries:
                    backoff = min(2 ** retry_count, 30)  # Exponential backoff, max 30s
                    logger.debug(f"Restartin’ BotThread after {backoff} seconds, attempt {retry_count + 1}/{max_retries}, arrgh!")
                    time.sleep(backoff)
                else:
                    logger.error(f"Max retries ({max_retries}) reached or stop requested, arrgh!")
                    break
            finally:
                if not self.running:
                    logger.info("BotThread run finished, arrgh!")
                    self.status_updated.emit("Bot Status: Anchored")

    async def event_ready(self):
        """Handle bot connection with WebSocket recovery, arrgh!"""
        logger.info(f"Enterin’ event_ready for bot {self.bot_username}, arrgh!")
        try:
            if self.gui.is_shutting_down:
                logger.warning("Bot is shuttin’ down, skippin’ event_ready, arrgh!")
                return

            if not self.loop.is_running():
                logger.error("Event loop not runnin’ in event_ready, arrgh!")
                self.status_updated.emit("Bot Status: Crashed due to closed event loop")
                raise RuntimeError("Event loop not runnin’")

            # Validate bot token
            token = self.bot_token.replace("oauth:", "")
            valid, result, _ = validate_twitch_token(token)
            if not valid:
                logger.error(f"Bot token invalid: {result}, arrgh!")
                self.status_updated.emit("Bot Status: Invalid bot token")
                self.error_occurred.emit(f"Bot token invalid: {result}, arrgh!")
                return

            logger.info(f"Bot connected as {self.bot_username}, arrgh!")
            broadcaster_status = f"Broadcaster: Logged In as {self.gui.broadcaster_config['username']}" if self.gui.broadcaster_config.get("username") else "Broadcaster: Not Logged In"
            bot_status = f"Bot: Logged In as {self.bot_username} (Runnin’)"
            self.login_status_updated.emit(broadcaster_status, bot_status)

            # Strip # from channel name
            channel_name = self.channel.lstrip("#")
            logger.debug(f"Channel name: '{channel_name}', arrgh!")

            # Attempt to join channel with retries
            max_attempts = 3
            attempt = 0
            while attempt < max_attempts:
                if channel_name in [chan.name for chan in self.connected_channels]:
                    logger.debug(f"Already joined channel {channel_name}, arrgh!")
                    break
                logger.info(f"Joinin’ channel {channel_name}, attempt {attempt + 1}, arrgh!")
                try:
                    async with asyncio.timeout(5):  # 5-second timeout
                        await self.join_channels([channel_name])
                    logger.debug(f"Joined channel {channel_name}, arrgh!")
                    await asyncio.sleep(2)  # Wait for join to settle
                    break
                except asyncio.TimeoutError:
                    logger.warning(f"Timeout joinin’ channel {channel_name}, attempt {attempt + 1}, arrgh!")
                except Exception as e:
                    logger.error(f"Failed to join channel {channel_name}, attempt {attempt + 1}: {e}, arrgh!")
                attempt += 1
                await asyncio.sleep(2)  # Wait before retry
            else:
                logger.error(f"Failed to join channel {channel_name} after {max_attempts} attempts, arrgh!")
                self.status_updated.emit("Bot Status: Failed to join channel")
                self.error_occurred.emit(f"Failed to join channel {channel_name}, arrgh!")
                return

            channel = self.get_channel(channel_name)
            if not channel:
                logger.error(f"Failed to get channel {channel_name}, arrgh!")
                self.status_updated.emit("Bot Status: Failed to access channel")
                self.error_occurred.emit(f"Failed to access channel {channel_name}, arrgh!")
                raise RuntimeError(f"Channel {channel_name} not found")

            # Start keep-alive task
            if not hasattr(self, 'keep_alive_task') or self.keep_alive_task.done():
                self.keep_alive_task = self.loop.create_task(self.keep_alive(channel_name))
                logger.info("Started keep-alive task for WebSocket, arrgh!")

            # WebSocket health check
            max_attempts = 5
            attempt = 0
            while attempt < max_attempts:
                if hasattr(self, '_ws') and self._ws and not self._ws.closed:
                    logger.debug(f"WebSocket stable on attempt {attempt + 1}, arrgh!")
                    break
                logger.warning(f"WebSocket not ready on attempt {attempt + 1} for {channel_name}, retryin’, arrgh!")
                try:
                    if hasattr(self, '_ws') and self._ws and not self._ws.closed:
                        await self._ws.close()
                        logger.debug(f"Closed old WebSocket for {channel_name}, arrgh!")
                    await self._connect()
                    logger.debug(f"Reconnected WebSocket for {channel_name}, arrgh!")
                    await asyncio.sleep(2)  # Wait for reconnect
                except Exception as e:
                    logger.error(f"Failed to reconnect WebSocket on attempt {attempt + 1}: {e}, arrgh!")
                attempt += 1
            else:
                logger.error(f"WebSocket failed to stabilize after {max_attempts} attempts for {channel_name}, arrgh!")
                self.status_updated.emit("Bot Status: Failed to stabilize WebSocket")
                self.error_occurred.emit(f"WebSocket failed after {max_attempts} attempts, arrgh!")
                return

            # Send ready message
            try:
                await channel.send("Squawk! Cap’n and I are at full speed!")
                logger.info(f"Sent connection message to {channel_name}, arrgh!")
            except Exception as e:
                logger.error(f"Failed to send ready message to {channel_name}: {e}, arrgh!")
                self.status_updated.emit("Bot Status: Failed to send ready message")
                self.error_occurred.emit(f"Failed to send ready message: {e}, arrgh!")
                return

            self.status_updated.emit("Bot Status: Full Sailin’!")
            self.gui.start_button.setEnabled(False)
            self.gui.stop_button.setEnabled(True)

            self.update_commands()
            self.update_counter_commands()
            await self.fetch_brb_clips()
            if self.brb_clips:
                random.shuffle(self.brb_clips)
                logger.info(f"Fetched {len(self.brb_clips)} BRB clips, arrgh!")
            if self.loop and not self.loop.is_closed():
                self.brb_task = self.loop.create_task(self.start_brb_scene_check())
                logger.info("BRB scene check task started, arrgh!")

        except Exception as e:
            logger.error(f"Error in event_ready: {e}, arrgh!", exc_info=True)
            self.status_updated.emit("Bot Status: Crashed after connection")
            self.error_occurred.emit(f"Bot crashed: {e}, arrgh!")
            raise

    async def send_message_async(self, message):
        """Send a message asynchronously, arrgh!"""
        logger.info(f"BotThread sendin’ message: {message}, arrgh!")
        if not self.running or not self.bot:
            logger.warning("Cannot send message, bot not runnin’, arrgh!")
            return False
        try:
            channel_name = self.channel.lstrip("#")
            channel = self.bot.get_channel(channel_name)
            if channel:
                await channel.send(message)
                logger.info(f"Message sent to #{self.channel}: {message}, arrgh!")
                return True
            else:
                logger.warning(f"Channel {self.channel} not found fer sendin’ message, arrgh!")
                return False
        except Exception as e:
            logger.error(f"Failed to send message: {e}, arrgh!", exc_info=True)
            return False

    def send_message(self, message):
        """Send a message synchronously, arrgh!"""
        logger.info(f"Callin’ send_message fer: {message}, arrgh!")
        if self.bot and self.loop and self.running and not self.loop.is_closed():
            try:
                future = asyncio.run_coroutine_threadsafe(self.send_message_async(message), self.loop)
                success = future.result(timeout=2)
                if success:
                    logger.info(f"Successfully sent message: {message}, arrgh!")
                else:
                    logger.info(f"Failed to send message: {message}, arrgh!")
                return success
            except Exception as e:
                logger.error(f"Error in send_message: {e}, arrgh!", exc_info=True)
                return False
        else:
            logger.warning("Cannot send message, bot loop not available, not runnin’, or loop closed, arrgh!")
            return False

    def stop(self):
        """Stop the thread and clean up, arrgh!"""
        logger.info("BotThread stoppin’, arrgh!")
        self.running = False
        try:
            if self.bot and self.loop and not self.loop.is_closed():
                logger.info("Closin’ bot connection and shuttin’ down loop, arrgh!")
                # Cancel tasks
                if self.brb_task and not self.brb_task.done():
                    try:
                        self.brb_task.cancel()
                        asyncio.run_coroutine_threadsafe(self.brb_task, self.loop).result(timeout=1)
                        logger.info("BRB task cancelled, arrgh!")
                    except Exception as e:
                        logger.warning(f"Failed to cancel BRB task: {e}, arrgh!")
                if hasattr(self, 'keep_alive_task') and self.keep_alive_task and not self.keep_alive_task.done():
                    try:
                        self.keep_alive_task.cancel()
                        asyncio.run_coroutine_threadsafe(self.keep_alive_task, self.loop).result(timeout=1)
                        logger.info("Keep-alive task cancelled, arrgh!")
                    except Exception as e:
                        logger.warning(f"Failed to cancel keep-alive task: {e}, arrgh!")
                tasks = [task for task in asyncio.all_tasks(self.loop) if task is not asyncio.current_task(self.loop)]
                logger.debug(f"Cancellin’ {len(tasks)} runnin’ tasks, arrgh!")
                for task in tasks:
                    task.cancel()
                if tasks:
                    try:
                        async def wait_tasks():
                            return await asyncio.wait(tasks, timeout=2, return_when=asyncio.ALL_COMPLETED)
                        asyncio.run_coroutine_threadsafe(wait_tasks(), self.loop).result(timeout=2)
                    except Exception as e:
                        logger.warning(f"Failed to wait for tasks: {e}, arrgh!")
                # Close WebSocket
                if hasattr(self.bot, '_ws') and self.bot._ws and not self.bot._ws.closed:
                    try:
                        asyncio.run_coroutine_threadsafe(self.bot._ws.close(), self.loop).result(timeout=1)
                        logger.info("WebSocket closed, arrgh!")
                    except Exception as e:
                        logger.warning(f"Failed to close WebSocket: {e}, arrgh!")
                # Close bot and broadcaster client
                try:
                    asyncio.run_coroutine_threadsafe(self.bot.close(), self.loop).result(timeout=1)
                    logger.info("TwitchIO client closed, arrgh!")
                except Exception as e:
                    logger.warning(f"Failed to close TwitchIO client: {e}, arrgh!")
                if hasattr(self.bot, 'broadcaster_client') and self.bot.broadcaster_client:
                    try:
                        asyncio.run_coroutine_threadsafe(self.bot.broadcaster_client.close(), self.loop).result(timeout=1)
                        logger.info("Broadcaster client closed, arrgh!")
                    except Exception as e:
                        logger.warning(f"Failed to close broadcaster client: {e}, arrgh!")
                try:
                    asyncio.run_coroutine_threadsafe(self.bot.cleanup(), self.loop).result(timeout=1)
                    logger.info("SquawkBot cleanup completed, arrgh!")
                except Exception as e:
                    logger.warning(f"Failed to cleanup bot: {e}, arrgh!")
                # Shutdown loop
                try:
                    asyncio.run_coroutine_threadsafe(self.loop.shutdown_asyncgens(), self.loop).result(timeout=1)
                    asyncio.run_coroutine_threadsafe(self.loop.shutdown_default_executor(), self.loop).result(timeout=1)
                    logger.info("Loop shutdown completed, arrgh!")
                except Exception as e:
                    logger.warning(f"Failed to shutdown loop: {e}, arrgh!")
                if self.loop.is_running():
                    try:
                        self.loop.call_soon_threadsafe(self.loop.stop)
                        deadline = time.time() + 1
                        while self.loop.is_running() and time.time() < deadline:
                            time.sleep(0.1)
                        logger.debug("Event loop stopped, arrgh!")
                    except Exception as e:
                        logger.warning(f"Failed to stop event loop: {e}, arrgh!")
        except Exception as e:
            logger.error(f"Error in BotThread.stop: {e}, arrgh!", exc_info=True)
        finally:
            self.bot = None
            if self.loop and not self.loop.is_closed():
                logger.info("Closin’ the event loop, arrgh!")
                try:
                    self.loop.close()
                    self._loop_closed = True
                    logger.info("Event loop closed, arrgh!")
                except Exception as e:
                    logger.warning(f"Failed to close event loop: {e}, arrgh!")
            self.loop = None
            logger.info("BotThread stopped, arrgh!")

def main():
    """Main entry point for SquawkBot, arrgh!"""
    logger.debug("Enterin’ main function, arrgh!")
    max_restarts = 5
    restart_delay = 10
    restart_count = 0

    while restart_count < max_restarts:
        try:
            app = QApplication(sys.argv)
            gui = SquawkBotGUI(app)
            gui.show()
            logger.debug("Startin’ Qt application, arrgh!")
            sys.exit(app.exec())
        except Exception as e:
            restart_count += 1
            logger.error(f"Main block crashed (attempt {restart_count}/{max_restarts}): {e}, arrgh!", exc_info=True)
            file_handler.flush()
            console_handler.flush()
            if restart_count >= max_restarts:
                logger.error("Max restarts reached, givin’ up, arrgh!")
                break
            logger.info(f"Restartin’ bot in {restart_delay} seconds, arrgh!")
            time.sleep(restart_delay)
            if 'gui' in locals():
                gui.close()
                del gui
            if 'app' in locals():
                del app
            logger.debug("Cleaned up old GUI and app, preparin’ for restart, arrgh!")
        finally:
            logger.debug("Exitin’ main function attempt, arrgh!")

if __name__ == "__main__":
    main()
