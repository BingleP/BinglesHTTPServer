from http.server import HTTPServer, BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import secrets
import hashlib
from urllib.parse import parse_qs, unquote, quote
import time
import mimetypes
from io import BytesIO
import re
import textwrap
import threading
import users

# Import users module for user management
from users import get_user, add_user, update_user, delete_user, list_users, verify_password

# Configurable root directory for file storage
ROOT_DIR_CONFIG_FILE = "root_dir.json" # Renamed for clarity

def load_root_directories():
    global ROOT_DIRECTORIES # Allow modification during migration
    if os.path.exists(ROOT_DIR_CONFIG_FILE):
        with open(ROOT_DIR_CONFIG_FILE, 'r') as f:
            try:
                data = json.load(f)
                if isinstance(data, dict) and 'root_dirs' in data and isinstance(data['root_dirs'], list):
                    loaded_dirs = data.get('root_dirs')
                    if not loaded_dirs:
                        print(f"Warning: 'root_dirs' in {ROOT_DIR_CONFIG_FILE} is empty. Defaulting to ['uploads'].")
                        return ['uploads']
                    # Filter out empty strings or None from the list
                    valid_dirs = [d for d in loaded_dirs if d and isinstance(d, str)]
                    if not valid_dirs:
                        print(f"Warning: 'root_dirs' in {ROOT_DIR_CONFIG_FILE} contained only invalid entries. Defaulting to ['uploads'].")
                        return ['uploads']
                    return valid_dirs
                elif isinstance(data, dict) and 'root_dir' in data and isinstance(data['root_dir'], str): # Old format
                    old_root = data['root_dir']
                    print(f"Migrating old 'root_dir' ({old_root}) format in {ROOT_DIR_CONFIG_FILE} to ['{old_root}'].")
                    ROOT_DIRECTORIES = [old_root] if old_root else ['uploads']
                    save_root_directories(ROOT_DIRECTORIES)
                    return ROOT_DIRECTORIES
                else:
                    print(f"Warning: {ROOT_DIR_CONFIG_FILE} has unknown format or is empty. Defaulting to ['uploads'].")
                    return ['uploads']
            except json.JSONDecodeError:
                print(f"Error decoding JSON from {ROOT_DIR_CONFIG_FILE}. Defaulting to ['uploads'] and attempting to save default.")
                default_dirs = ['uploads']
                save_root_directories(default_dirs) # Save the default
                return default_dirs
    # File does not exist, so create it with default
    print(f"{ROOT_DIR_CONFIG_FILE} not found. Initializing with default ['uploads'] and creating file.")
    default_dirs = ['uploads']
    save_root_directories(default_dirs) # Create the file with default content
    return default_dirs

def save_root_directories(root_dirs_list):
    # Ensure it's always a list of non-empty strings and not empty itself
    valid_dirs = [d for d in root_dirs_list if d and isinstance(d, str)]
    if not valid_dirs:
        print("Error: Attempted to save an invalid or empty root directories list. Saving ['uploads'] instead.")
        valid_dirs = ['uploads']
    with open(ROOT_DIR_CONFIG_FILE, 'w') as f:
        json.dump({'root_dirs': valid_dirs}, f, indent=4)

ROOT_DIRECTORIES = load_root_directories()

# Helper to get the primary root directory for current operations (temporary for Phase 1)
def get_primary_root_directory():
    if ROOT_DIRECTORIES and ROOT_DIRECTORIES[0]:
        # Ensure the primary root exists, create if not
        primary_root = ROOT_DIRECTORIES[0]
        if not os.path.exists(primary_root):
            try:
                os.makedirs(primary_root)
                print(f"Created primary root directory: {primary_root}")
            except OSError as e:
                print(f"ERROR: Could not create primary root directory {primary_root}: {e}")
                # Fallback if creation fails, though this is problematic.
                # Consider if the server should even start if primary root is not accessible.
                return 'uploads' # Last resort fallback
        return primary_root
    # This case should ideally be prevented by load_root_directories ensuring ['uploads']
    print("Warning: ROOT_DIRECTORIES is empty or invalid. Defaulting to 'uploads' as primary root.")
    if not os.path.exists('uploads'): # Ensure fallback 'uploads' exists
        try:
            os.makedirs('uploads')
        except OSError:
            pass # Avoid error recursion if 'uploads' cannot be made
    return 'uploads'

# Store active tokens and their roles
# token: {"username": ..., "role": ..., "created": ..., "ip": ...}
active_tokens = {}
active_tokens_lock = threading.Lock()

TOKEN_EXPIRATION_SECONDS = 18000  # 5 hours
active_transfers = {}  # token: bool (True if upload/download in progress)
active_transfers_lock = threading.Lock()

# Store public links
PUBLIC_LINKS_FILE = "public_links.json"
public_links = {}
public_links_lock = threading.Lock()

def load_public_links():
    global public_links
    if os.path.exists(PUBLIC_LINKS_FILE):
        try:
            with open(PUBLIC_LINKS_FILE, 'r') as f:
                public_links = json.load(f)
                print(f"Successfully loaded public_links from {PUBLIC_LINKS_FILE}. {len(public_links)} links loaded.")
        except json.JSONDecodeError as e:
            print(f"ERROR: Failed to parse {PUBLIC_LINKS_FILE} due to JSONDecodeError: {e}. Public links may be reset or incomplete.")
            public_links = {} # Reset to avoid issues with corrupted data
        except Exception as e:
            print(f"ERROR: An unexpected error occurred while loading {PUBLIC_LINKS_FILE}: {e}. Public links may be reset or incomplete.")
            public_links = {} # Reset for other errors too
    else:
        print(f"{PUBLIC_LINKS_FILE} not found. Initializing with empty public_links.")
        public_links = {}

def save_public_links():
    with open(PUBLIC_LINKS_FILE, 'w') as f:
        json.dump(public_links, f)

load_public_links()

def get_directory_contents(path_abs, base_for_relpath): # Added base_for_relpath
    """Get contents of a directory with both files and folders."""
    contents = []
    try:
        for item in os.listdir(path_abs):
            full_path_abs = os.path.join(path_abs, item)
            is_dir = os.path.isdir(full_path_abs)
            contents.append({
                'name': item,
                'is_directory': is_dir,
                # 'path' should be relative to the specific root it belongs to.
                'path': os.path.relpath(full_path_abs, base_for_relpath).replace('\\', '/')
            })
        return sorted(contents, key=lambda x: (not x['is_directory'], x['name'].lower()))
    except FileNotFoundError:
        print(f"Directory not found for listing: {path_abs}")
        return [] # Return empty list, the /files handler will send 404
    except PermissionError:
        print(f"Permission error reading directory {path_abs}")
        return [] # Caller should handle this, maybe by sending 403 or error message
    except Exception as e:
        print(f"Error reading directory {path_abs}: {e}")
        return []

class SecureHTTPRequestHandler(BaseHTTPRequestHandler):
    def generate_token(self, username, role):
        token = secrets.token_hex(32)
        with active_tokens_lock:
            active_tokens[token] = {
                "username": username,
                "role": role,
                "created": time.time(),
                "ip": self.client_address[0],  # Mandatory IP binding
            }
        return token

    def is_valid_token(self, token):
        with active_tokens_lock:
            info = active_tokens.get(token)
            print(f"Checking token: {token}, info: {info}, client IP: {self.client_address[0]}")
            if not info:
                print(f"Token {token} not found in active_tokens.")
                return False

            # Expiration check
            expired = time.time() - info["created"] > TOKEN_EXPIRATION_SECONDS
            if expired:
                is_transfer_active_for_token = False
                with active_transfers_lock: # Check active_transfers
                    if active_transfers.get(token):
                        is_transfer_active_for_token = True
                
                if is_transfer_active_for_token:
                    print(f"Token {token} expired but transfer in progress, renewing token.")
                    # info is a reference to the dict in active_tokens, so this updates it
                    active_tokens[token]["created"] = time.time() 
                    return True
                else:
                    print(f"Token {token} expired. Removing from active_tokens.")
                    del active_tokens[token] # Modify active_tokens under its lock
                    # If token expired and no transfer, ensure it's also removed from active_transfers
                    with active_transfers_lock: # Lock active_transfers for modification
                        if token in active_transfers:
                            del active_transfers[token]
                    return False
            
            # Mandatory IP binding (info is from active_tokens, still under active_tokens_lock)
            if info["ip"] != self.client_address[0]:
                if not (info["ip"] in ("127.0.0.1", "localhost") and self.client_address[0] in ("127.0.0.1", "localhost")):
                    print(f"IP mismatch: token IP {info['ip']} vs client IP {self.client_address[0]}. Not removing token, just denying access.")
                    return False
        return True # If not expired and IP matches (lock released here)

    def get_token_role(self, token):
        with active_tokens_lock:
            return active_tokens.get(token, {}).get("role")

    def get_token_username(self, token):
        with active_tokens_lock:
            return active_tokens.get(token, {}).get("username")

    def invalidate_user_tokens(self, username):
        with active_tokens_lock:
            to_delete = [t for t, v in active_tokens.items() if v["username"] == username]
            for t in to_delete:
                print(f"invalidate_user_tokens: Removing token {t} for user {username} from active_tokens.")
                del active_tokens[t]

    def do_GET(self):
        print(f"\n===== GET Request =====")
        print(f"Path: {self.path}")
        print(f"Headers: {self.headers}")

        if self.path == '/' or self.path.startswith('/?'):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            html_content = f'''
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Bingles File Server</title>
                <style>
                    /* ... (existing CSS styles from original file) ... */
                    body {{ margin: 0; padding: 20px; font-family: 'Segoe UI', Arial, sans-serif; background-color: #1a2634; color: #ffffff; }}
                    .container {{ max-width: 800px; margin: 0 auto; background-color: #233446; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }}
                    .admin-menu {{ position: fixed; top: 30px; right: 40px; z-index: 100; display: flex; align-items: center; gap: 15px; }}
                    .admin-menu-btn {{ background: #4a9eff; color: white; border: none; border-radius: 4px; padding: 10px 20px; cursor: pointer; font-size: 16px; }}
                    .admin-menu-btn:hover {{ background: #357abd; }}
                    .admin-menu-dropdown {{ display: none; position: absolute; right: 0; background: #233446; border: 1px solid #4a9eff; border-radius: 6px; min-width: 180px; box-shadow: 0 2px 8px rgba(0,0,0,0.15); margin-top: 8px; }}
                    .admin-menu-dropdown.show {{ display: block; }}
                    .admin-menu-dropdown button {{ width: 100%; background: none; color: #fff; border: none; padding: 12px 20px; text-align: left; font-size: 15px; cursor: pointer; }}
                    .admin-menu-dropdown button:hover {{ background: #2c4058; }}
                    h1, h2 {{ color: #4a9eff; margin-bottom: 20px; text-align: center; }}
                    @keyframes rainbowText {{ 0% {{ background-position: 0% 50%; }} 50% {{ background-position: 100% 50%; }} 100% {{ background-position: 0% 50%; }} }}
                    #serverLogo {{ /* Added for the logo */
                        display: block;
                        margin-left: auto;
                        margin-right: auto;
                        max-width: 50%; /* Changed from 80% to 50% */
                        height: auto; /* Maintain aspect ratio */
                        margin-bottom: 30px; /* Spacing below logo */
                        border-radius: 15px; /* Added to round corners */
                        border: 5px solid #4a9eff; /* Changed border color to match h2 text */
                    }}
                    .custom-file-upload-container {{ /* Added for new file input */
                        display: flex;
                        align-items: center;
                        gap: 10px; /* Space between button and text */
                        margin-bottom: 0; /* Explicitly set to 0 to override .form-group */
                    }}
                    #customBrowseBtn {{ /* Added for new file input */
                        background: linear-gradient(135deg, #1976d2, #42a5f5);
                        color: white;
                        padding: 10px 20px; /* Consistent with other prominent buttons */
                        border: none;
                        border-radius: 6px; /* Consistent with logout/admin menu */
                        font-weight: bold;
                        cursor: pointer;
                        transition: all 0.2s ease-in-out;
                        font-size: 1em; /* Slightly larger than default button */
                    }}
                    #customBrowseBtn:hover {{
                        background: linear-gradient(135deg, #1565c0, #2196f3);
                        transform: translateY(-1px);
                        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
                    }}
                    #fileNameDisplay {{ /* Added for new file input */
                        color: #ccc; /* Dim color for placeholder */
                        font-style: italic;
                        font-size: 0.9em;
                    }}
                    .form-group {{ margin-bottom: 15px; }}
                    input[type="text"], input[type="password"], input[type="file"], select {{ width: 100%; padding: 8px; margin: 5px 0; border-radius: 4px; border: 1px solid #456; background-color: #2c4058; color: white; box-sizing: border-box; }}
                    #loginSection input[type="text"], #loginSection input[type="password"] {{ max-width: 350px; margin-left: auto; margin-right: auto; }}
                    button {{ background: linear-gradient(135deg, #1976d2, #42a5f5); color: white; padding: 4px 8px; border: none; border-radius: 4px; font-weight: bold; cursor: pointer; transition: all 0.2s ease-in-out; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1); font-size: 0.85em; text-align: center; }}
                    button:hover {{ background: linear-gradient(135deg, #1565c0, #2196f3); transform: translateY(-1px); box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2); filter: brightness(110%); }}
                    .folder-link {{ color: #64B5F6; text-decoration: none; font-weight: bold; transition: color 0.2s ease; }}
                    .folder-link:hover {{ color: #90CAF9; text-decoration: underline; }}
                    .message-area {{ margin-top: 10px; font-size: 0.9em; min-height:1.2em; }}
                    .success {{ color: #4aff4a; }}
                    .error {{ color: #ff4a4a; }}
                    .logout-btn-container {{ position: fixed; top: 30px; right: 240px; z-index: 100; }}
                    #logoutBtn {{ background: linear-gradient(135deg, #ff4a4a, #d13b3b); padding: 10px 28px; border-radius: 6px; font-size: 16px; font-weight: bold; }}
                    #viewFilesBtn, #backToMainBtn, #backToMainFromUsersBtn /* General styling for prominent back/action buttons */
                    {{ padding: 12px 28px; border-radius: 8px; font-size: 18px; font-weight: bold; }}
                    #rootSelectionPage {{
                        position: fixed; top: 0; left: 0; right: 0; bottom: 0;
                        background: rgba(26, 38, 52, 0.85); /* Slightly transparent main background */
                        display: flex; align-items: center; justify-content: center;
                        z-index: 2000; display: none; /* Initially hidden */
                        backdrop-filter: blur(5px);
                    }}
                    .root-selection-modal {{
                        background: #233446; /* Darker blue-grey from container */
                        padding: 30px 40px;
                        border-radius: 10px;
                        box-shadow: 0 8px 25px rgba(0,0,0,0.4);
                        text-align: center;
                        min-width: 350px; max-width: 600px;
                        border: 1px solid #4a9eff;
                    }}
                    .root-selection-modal h2 {{ color: #4a9eff; margin-bottom: 25px; font-size: 1.8em; }}
                    .root-selection-modal button.root-select-btn {{
                        display: block; width: 100%; padding: 12px 15px; margin-bottom: 12px;
                        background: #4a9eff; color: white; border: none; border-radius: 5px;
                        cursor: pointer; font-size: 16px; text-align: left;
                        transition: background-color 0.2s ease;
                    }}
                    .root-selection-modal button.root-select-btn:hover {{ background: #357abd; }}
                    .root-selection-modal button#cancelRootSelectionBtn {{
                        background: #7f8c8d; margin-top: 15px;
                        padding: 10px 20px;
                    }}
                    .root-selection-modal button#cancelRootSelectionBtn:hover {{ background: #6c7a7b; }}
                    /* Files Page Styling */
                    #filesPage {{ position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: linear-gradient(135deg, #1976d2 0%, #4a9eff 100%); padding: 60px 20px 20px; overflow-y: auto; z-index: 1000; display: none; }}
                    #fileListPage {{ max-width: 800px; margin:20px auto; background-color:rgba(35,52,70,0.8); padding:20px; border-radius:10px; box-shadow:0 4px 8px rgba(0,0,0,0.2); }}
                    #searchContainer input {{ flex-grow:1; padding:10px; border-radius:5px; border:1px solid #ddd; background-color: #2c4058; color:white; }}
                    #loginSection {{ text-align: center; padding: 20px; }}
                    #loginForm {{
                        /* display: inline-block; */ /* Old display */
                        display: inline-flex; /* New display for flex layout */
                        flex-direction: column; /* Stack items vertically */
                        align-items: center; /* Center items (like .form-group and button) horizontally */
                        width: 100%; 
                        max-width: 380px; /* Max width of the form itself */
                        /* text-align: left; */ /* No longer needed for children centering */
                    }}
                    @keyframes rainbowText {{ 0% {{ background-position: 0% 50%; }} 50% {{ background-position: 100% 50%; }} 100% {{ background-position: 0% 50%; }} }}
                    #uploadForm {{ /* Added/Modified */
                        display: flex;
                        flex-direction: column;
                        align-items: center; /* Centers children horizontally */
                        gap: 15px; /* Space between the file input group and the submit button */
                    }}
                </style>
            </head>
            <body>
                <div id="rootSelectionPage">
                    <div class="root-selection-modal">
                        <h2>Select a File Repository</h2>
                        <div id="rootSelectionButtonsContainer">
                            <!-- Buttons will be populated by JavaScript -->
                        </div>
                         <button id="cancelRootSelectionBtn">Cancel</button>
                    </div>
                </div>

                <div class="container" id="containerDiv">
                    <img id="serverLogo" src="/BingleLogo.png" alt="Bingles File Server Logo" />
                    {self.get_login_section_html()}
                    {self.get_file_section_html()}
                </div>

                {self.get_manage_users_page_html()}
                {self.get_files_page_html()}

                {self.get_main_script_js()}
            </body>
            </html>
            '''
            self.wfile.write(textwrap.dedent(html_content).encode())
            return

        elif self.path.startswith('/get_current_root_dirs'):
            query = parse_qs(self.path.split('?')[1] if '?' in self.path else '')
            token = query.get('token', [None])[0]
            if self.is_valid_token(token): # Allow any valid user to see roots for selection
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(ROOT_DIRECTORIES).encode())
            else:
                self.send_error(401, 'Unauthorized')
            return

        elif self.path.startswith('/admin/get_all_users'):
            query = parse_qs(self.path.split('?')[1] if '?' in self.path else '')
            token = query.get('token', [None])[0]
            if self.is_valid_token(token) and self.get_token_role(token) == 'admin':
                all_users = list_users() # From users.py, already excludes sensitive data
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(all_users).encode())
            else:
                self.send_response_json_error(401, 'Unauthorized to list users.')
            return

        elif self.path.startswith('/files'):
            query_params = parse_qs(self.path.split('?')[1] if '?' in self.path else '')
            token = query_params.get('token', [None])[0]
            selected_root_dir_path = query_params.get('root_dir_path', [None])[0]
            relative_folder_path = query_params.get('path', [''])[0]
            search_query = query_params.get('search',[''])[0] # Added for search

            if not self.is_valid_token(token):
                self.send_response_json_error(401, 'Unauthorized: Invalid token')
                return

            if not selected_root_dir_path or not os.path.isdir(selected_root_dir_path) or selected_root_dir_path not in ROOT_DIRECTORIES:
                self.send_response_json_error(400, 'Bad Request: Missing or invalid root_dir_path')
                return

            if '..' in relative_folder_path or relative_folder_path.startswith(('/', '\\\\')):
                self.send_response_json_error(403, 'Forbidden: Invalid relative path')
                return
            
            target_dir_abs = os.path.normpath(os.path.join(selected_root_dir_path, relative_folder_path))
            
            try:
                real_target_abs = os.path.realpath(target_dir_abs)
                real_root_abs = os.path.realpath(selected_root_dir_path)
                if not real_target_abs.startswith(real_root_abs) or not os.path.isdir(real_target_abs):
                    self.send_response_json_error(404, f"Directory not found or access denied: {relative_folder_path}")
                    return
            except Exception as e:
                print(f"Error processing path {target_dir_abs} for /files: {e}")
                self.send_response_json_error(500, "Server error processing path.")
                return
                
            contents = get_directory_contents(target_dir_abs, base_for_relpath=selected_root_dir_path)
            if search_query:
                contents = [item for item in contents if search_query.lower() in item['name'].lower()]

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(contents).encode())
            return

        elif self.path.startswith('/admin/get_all_public_links'):
            query = parse_qs(self.path.split('?')[1] if '?' in self.path else '')
            token = query.get('token', [None])[0]
            if self.is_valid_token(token) and self.get_token_role(token) == 'admin':
                with public_links_lock:
                    # Make a copy to send, to avoid issues if it's modified while sending
                    links_to_send = dict(public_links)
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(links_to_send).encode())
            else:
                self.send_response_json_error(401, 'Unauthorized to list public links.')
            return

        elif self.path.startswith('/download'):
            query_params = parse_qs(self.path.split('?', 1)[1] if '?' in self.path else '')
            token = query_params.get('token', [None])[0]
            root_path_for_download = unquote(query_params.get('root', [None])[0] or '')
            relative_file_path_for_download = unquote(query_params.get('file', [None])[0] or '')

            if not self.is_valid_token(token):
                self.send_error(401, 'Unauthorized'); return
            if not root_path_for_download or root_path_for_download not in ROOT_DIRECTORIES:
                self.send_error(400, 'Bad Request: Invalid root path for download.'); return
            if not relative_file_path_for_download:
                self.send_error(400, 'Bad Request: Missing file path for download.'); return
            if '..' in relative_file_path_for_download or relative_file_path_for_download.startswith(('/', '\\\\')):
                self.send_error(403, 'Forbidden: Invalid file path.'); return
                
            with active_transfers_lock: active_transfers[token] = True
            full_file_path_abs = os.path.normpath(os.path.join(root_path_for_download, relative_file_path_for_download))
            
            try:
                real_path = os.path.realpath(full_file_path_abs)
                real_root = os.path.realpath(root_path_for_download)
                if not real_path.startswith(real_root) or not os.path.isfile(real_path):
                    self.send_error(404, 'File not found or invalid path.')
                    with active_transfers_lock: 
                        if token in active_transfers: del active_transfers[token]
                    return
            except Exception: 
                self.send_error(500, 'Server error validating file path.')
                with active_transfers_lock: 
                    if token in active_transfers: del active_transfers[token]
                return
            try:
                self.send_response(200)
                mime, _ = mimetypes.guess_type(full_file_path_abs)
                self.send_header('Content-Type', mime or 'application/octet-stream')
                self.send_header('Content-Disposition', f'attachment; filename="{os.path.basename(full_file_path_abs)}"')
                self.send_header('Content-Length', str(os.path.getsize(full_file_path_abs)))
                self.end_headers()
                with open(full_file_path_abs, 'rb') as f:
                    while True:
                        chunk = f.read(8192)
                        if not chunk: break
                        self.wfile.write(chunk)
            except Exception as e: print(f"Error sending file {full_file_path_abs}: {e}")
            finally: 
                with active_transfers_lock: 
                    if token in active_transfers: del active_transfers[token]
            return

        elif self.path.startswith('/public/'):
            path_part = self.path.split('?')[0]
            path_segments = path_part.split('/') 
            query_string = self.path.split('?', 1)[1] if '?' in self.path else ''
            query_params = parse_qs(query_string)
            public_key_from_query = query_params.get('key', [None])[0]

            if len(path_segments) < 4 or not public_key_from_query:
                self.send_error_text(400, "Malformed public link (path or key)."); return
            try:
                encoded_root_dir_path = path_segments[2]
                encoded_relative_file_path = "/".join(path_segments[3:])
                actual_root_dir_path = unquote(encoded_root_dir_path)
                relative_file_path = unquote(encoded_relative_file_path)
            except Exception as e: self.send_error_text(400, f"Malformed public link (decoding error: {e})."); return

            if actual_root_dir_path not in ROOT_DIRECTORIES:
                self.send_error_text(403, "Public link root invalid."); return
            if '..' in relative_file_path or relative_file_path.startswith(('/', '\\\\')):
                self.send_error_text(403, "Public link file path invalid (traversal attempt)."); return

            composite_key_for_lookup = f"{actual_root_dir_path}|{relative_file_path}"
            with public_links_lock: stored_key = public_links.get(composite_key_for_lookup)

            if not stored_key or public_key_from_query != stored_key:
                self.send_error_text(403, "Public link invalid or expired."); return

            actual_file_path_abs = os.path.normpath(os.path.join(actual_root_dir_path, relative_file_path))
            if not os.path.isfile(actual_file_path_abs):
                self.send_error_text(404, "Publicly linked file not found."); return
            
            self.serve_file_range(actual_file_path_abs)
            return

        elif self.path.startswith('/get_public_link'):
            query_params = parse_qs(self.path.split('?')[1] if '?' in self.path else '')
            token = query_params.get('token', [None])[0]
            relative_file = unquote(query_params.get('file', [None])[0] or '')
            root_dir_path_for_link = unquote(query_params.get('root_dir_path', [None])[0] or '')

            if not self.is_valid_token(token): self.send_response_json_error(401, 'Unauthorized'); return
            if not relative_file or not root_dir_path_for_link: self.send_response_json_error(400, 'Missing file or root_dir_path for public link.'); return
            if root_dir_path_for_link not in ROOT_DIRECTORIES: self.send_response_json_error(400, 'Invalid root_dir_path for public link.'); return
            if '..' in relative_file or relative_file.startswith(('/', '\\\\')): self.send_response_json_error(403, 'Invalid file path for public link.'); return

            composite_key = f"{root_dir_path_for_link}|{relative_file}"
            with public_links_lock:
                if composite_key not in public_links: public_links[composite_key] = secrets.token_urlsafe(32)
                save_public_links()
                link_key = public_links[composite_key]
            
            encoded_root = quote(root_dir_path_for_link)
            encoded_relative_file = quote(relative_file)
            public_url_path = f"/public/{encoded_root}/{encoded_relative_file}?key={link_key}"
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'public_url': public_url_path}).encode())
            return
        
        elif self.path.startswith('/all_files'): 
            query = parse_qs(self.path.split('?')[1] if '?' in self.path else '')
            token = query.get('token', [None])[0]
            if self.is_valid_token(token) and self.get_token_role(token) == 'admin':
                primary_root = ROOT_DIRECTORIES[0] if ROOT_DIRECTORIES else 'uploads' 
                if not os.path.exists(primary_root): os.makedirs(primary_root, exist_ok=True)
                files = os.listdir(primary_root)
                self.send_response(200); self.send_header('Content-type', 'application/json'); self.end_headers()
                self.wfile.write(json.dumps(files).encode())
            else: self.send_error(401, 'Unauthorized')
            return
        elif self.path == '/favicon.ico':
            favicon_path = os.path.join(os.path.dirname(__file__), 'favicon.ico')
            if os.path.exists(favicon_path):
                try:
                    self.send_response(200)
                    self.send_header('Content-type', 'image/x-icon') # Or image/vnd.microsoft.icon
                    self.send_header('Content-Length', str(os.path.getsize(favicon_path)))
                    self.end_headers()
                    with open(favicon_path, 'rb') as f:
                        self.wfile.write(f.read())
                except Exception as e:
                    print(f"Error serving favicon.ico: {e}")
                    self.send_response(500)
                    self.end_headers()
            else:
                self.send_response(204) # No Content if favicon.ico doesn't exist
            self.end_headers() # Ensure headers are always ended if not within try/except
            return
        elif self.path == '/BingleLogo.png': # Added this block
            logo_path = os.path.join(os.path.dirname(__file__), 'BingleLogo.png')
            if os.path.exists(logo_path):
                try:
                    self.send_response(200)
                    self.send_header('Content-type', 'image/png')
                    self.send_header('Content-Length', str(os.path.getsize(logo_path)))
                    self.end_headers()
                    with open(logo_path, 'rb') as f:
                        self.wfile.write(f.read())
                except Exception as e:
                    print(f"Error serving BingleLogo.png: {e}")
                    self.send_response(500)
                    self.end_headers()
            else:
                self.send_response(404) # Not found
                self.end_headers()
            return
        else: self.send_error(404, 'Resource not found')

    def serve_file_range(self, file_path_abs):
        try:
            file_size = os.path.getsize(file_path_abs)
        except FileNotFoundError:
            self.send_error_text(404, "File not found during serve_file_range.")
            return
        except Exception as e: 
            print(f"Error getting file size for {file_path_abs}: {e}")
            self.send_error_text(500, "Server error accessing file.")
            return

        range_header = self.headers.get('Range')
        start_byte, end_byte = 0, file_size - 1 # Default to serving the entire file
        status_code = 200

        if file_size == 0:
            if range_header and range_header.strip().lower().startswith('bytes='):
                self.send_header('Content-Range', f'bytes */0')
                self.send_error(416, 'Range Not Satisfiable (file is empty)')
                return
            else: # Serve empty file with 200 OK
                status_code = 200
                # Headers will be set below before sending body
        elif range_header: # File is not empty, and range header is present
            range_header_value = range_header.strip()
            if range_header_value.lower().startswith('bytes='):
                range_specifier = range_header_value.split('=', 1)[1].strip()

                if range_specifier == "0-": # Specific case for TU compatibility
                    status_code = 200
                    # start_byte and end_byte default to 0 and file_size - 1
                    # No Content-Range header for this 200 OK response.
                elif not range_specifier: # e.g. "Range: bytes=" (empty specifier)
                    self.send_header('Content-Range', f'bytes */{file_size}')
                    self.send_error(416, 'Range Not Satisfiable (empty byte range specifier)'); return
                else: # Other range specifiers that are not exactly "0-"
                    match_start_end = re.match(r'^(\d+)-(\d*)?$', range_specifier)
                    match_suffix = re.match(r'^-(\d+)$', range_specifier)

                    if match_start_end:
                        req_start = int(match_start_end.group(1))
                        if req_start < file_size:
                            start_byte = req_start
                            if match_start_end.group(2):
                                end_byte = min(int(match_start_end.group(2)), file_size - 1)
                            # else end_byte remains file_size - 1 (correct for open-ended)
                            if end_byte < start_byte: # e.g. bytes=500-400, after adjustments
                                 self.send_header('Content-Range', f'bytes */{file_size}')
                                 self.send_error(416, 'Range Not Satisfiable (end before start)'); return
                            status_code = 206
                            self.send_header('Content-Range', f'bytes {start_byte}-{end_byte}/{file_size}')
                        else:
                            self.send_header('Content-Range', f'bytes */{file_size}')
                            self.send_error(416, 'Range Not Satisfiable (start >= file size)'); return
                    elif match_suffix:
                        suffix_length = int(match_suffix.group(1))
                        if suffix_length == 0:
                            self.send_header('Content-Range', f'bytes */{file_size}')
                            self.send_error(416, 'Range Not Satisfiable (suffix length 0)'); return
                        
                        start_byte = max(0, file_size - suffix_length)
                        # end_byte remains file_size - 1
                        status_code = 206
                        self.send_header('Content-Range', f'bytes {start_byte}-{end_byte}/{file_size}')
                    else:
                        # Unrecognized bytes= format (but not empty and not "0-"). 
                        # Respond with 206 for the *entire* file, as per previous attempts.
                        start_byte = 0
                        end_byte = file_size - 1
                        status_code = 206
                        self.send_header('Content-Range', f'bytes {start_byte}-{end_byte}/{file_size}')
            # else: Range header present, but not 'bytes='. Ignore it, serve full file (status_code remains 200).
        # else: No range header. Serve full file (status_code remains 200).
        
        self.send_response(status_code)
        content_length_to_send = (end_byte - start_byte) + 1 if file_size > 0 else 0
        
        mime_type, _ = mimetypes.guess_type(file_path_abs)
        self.send_header('Content-Type', mime_type or 'application/octet-stream')
        self.send_header('Accept-Ranges', 'bytes')
        self.send_header('Content-Length', str(content_length_to_send))
        self.send_header('Access-Control-Allow-Origin', '*')

        inline_mime_types = ['image/', 'video/', 'audio/', 'application/pdf', 'text/plain']
        is_inline = any(mime_type.startswith(prefix) for prefix in inline_mime_types if mime_type)
        disposition = 'inline' if is_inline else f'attachment; filename="{os.path.basename(file_path_abs)}"'
        self.send_header('Content-Disposition', disposition)
        self.end_headers()

        if file_size == 0 or content_length_to_send == 0:
            # No body to write for an empty file or zero-length range
            return

        try:
            with open(file_path_abs, 'rb') as f:
                f.seek(start_byte)
                bytes_sent = 0
                while bytes_sent < content_length_to_send:
                    chunk_size = min(8192, content_length_to_send - bytes_sent)
                    chunk = f.read(chunk_size)
                    if not chunk: break
                    self.wfile.write(chunk)
                    bytes_sent += len(chunk)
        except ConnectionResetError:
            # Client closed the connection abruptly. This is common if the client
            # is a media player that stops fetching data, or if there's a network issue.
            print(f"Connection reset by client while serving {file_path_abs}. This may be normal for media players.")
            # Cannot send an error response as the connection is already gone.
        except FileNotFoundError: 
            # This specific catch should ideally be before the general Exception if it needs special handling.
            # Safely check if headers_sent attribute exists AND is False, then try to send a 404.
            if hasattr(self, 'headers_sent') and not self.headers_sent:
                try:
                    self.send_error_text(404, "File not found during streaming.")
                except Exception as e_send_404:
                    print(f"Further error trying to send 404 for FileNotFoundError: {e_send_404}")
            else:
                # Headers were already sent, or headers_sent attribute is missing.
                print(f"File not found (during streaming, headers may have been sent or attribute missing): {file_path_abs}")
        except Exception as e:
            # Catch other exceptions that might occur during file streaming.
            range_header_val = self.headers.get('Range', 'Not specified') # Get range for context
            print(f"General error serving file {file_path_abs} (range request: {range_header_val}): {type(e).__name__}: {e}")
            # Safely check if headers_sent attribute exists AND is False, then try to send a 500.
            if hasattr(self, 'headers_sent') and not self.headers_sent:
                try:
                    self.send_error_text(500, "Server error serving file.")
                except Exception as e_send_500:
                    print(f"Further error trying to send 500 for general error: {e_send_500}")
            # If headers were already sent, or attribute is missing, we can't send another HTTP error.
            # The original error 'e' is printed above.

    def send_response_json_error(self, code, message):
        self.send_response(code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'error': message}).encode())

    def send_error_text(self, code, message):
        self.send_response(code)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(message.encode())

    def do_POST(self):
        global ROOT_DIRECTORIES 
        # ... (Existing login, logout, change_creds, create_user, delete_user, admin_change_password handlers)
        # Ensure they are present and largely unaffected by file storage changes.
        # Critical: Ensure /add_root_dir and /remove_root_dir from Phase 1 are present and correct.

        if self.path == '/upload':
            content_type = self.headers.get('Content-Type', '')
            if not content_type.startswith('multipart/form-data'):
                self.send_response_json_error(400, 'Invalid content type for upload'); return
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0: self.send_response_json_error(400, 'Empty request body for upload'); return

            post_data = self.rfile.read(content_length)
            fields, files_data = parse_multipart(post_data, content_type)
            token = fields.get('token')
            target_root_dir_path = unquote(fields.get('root_dir_path', ''))

            if not self.is_valid_token(token): self.send_response_json_error(401, 'Invalid or expired token for upload'); return
            if not target_root_dir_path or target_root_dir_path not in ROOT_DIRECTORIES:
                self.send_response_json_error(400, 'Missing or invalid target root directory for upload.'); return

            with active_transfers_lock: active_transfers[token] = True
            fileinfo = files_data.get('file')
            if fileinfo is None or not fileinfo['filename']:
                self.send_response_json_error(400, 'No file provided in upload.')
                with active_transfers_lock: 
                    if token in active_transfers: del active_transfers[token]
                return
            
            filename = os.path.basename(fileinfo['filename'])
            if '..' in filename or filename.startswith(('/', '\\\\')):
                self.send_response_json_error(403, 'Invalid filename for upload.')
                with active_transfers_lock: 
                    if token in active_transfers: del active_transfers[token]
                return
                
            file_path_abs = os.path.normpath(os.path.join(target_root_dir_path, filename))
            
            try:
                # Ensure the final path is within the target root (redundant if target_root_dir_path is validated and normpath is used, but good for safety)
                if not os.path.realpath(file_path_abs).startswith(os.path.realpath(target_root_dir_path)):
                     self.send_response_json_error(403, 'Upload path security validation failed.')
                     raise OSError("Upload path breach attempt")

                with open(file_path_abs, 'wb') as f: f.write(fileinfo['content'])
                self.send_response(200); self.send_header('Content-type', 'application/json'); self.end_headers()
                self.wfile.write(json.dumps({'success': True, 'filename': filename}).encode())
            except Exception as e:
                print(f"Error writing uploaded file {file_path_abs}: {e}")
                self.send_response_json_error(500, f"Server error during file upload: {e}")
            finally: 
                with active_transfers_lock: 
                    if token in active_transfers: del active_transfers[token]
            return
        
        # LOGIN (Example of an existing POST handler - ensure all are present)
        elif self.path == '/login':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode()
            params = parse_qs(post_data)
            username = params.get('username', [''])[0]
            password = params.get('password', [''])[0]
            want_redirect = params.get('redirect', [''])[0] == 'true'
            if verify_password(username, password):
                user_info = get_user(username)
                if not user_info: self.send_response_json_error(500, 'Internal server error during login.'); return
                user_role = user_info['role']
                self.invalidate_user_tokens(username)
                token_val = self.generate_token(username, user_role)
                print(f"Login successful: username={username}, role={user_role}, token={token_val}")
                if want_redirect:
                    self.send_response(303); self.send_header('Location', '/')
                    self.send_header('Set-Cookie', f'token={token_val}; Path=/; Max-Age=18000; SameSite=Strict')
                    self.send_header('Set-Cookie', f'role={user_role}; Path=/; Max-Age=18000; SameSite=Strict')
                    self.send_header('Set-Cookie', f'username={username}; Path=/; Max-Age=18000; SameSite=Strict')
                    self.end_headers()
                else:
                    self.send_response(200); self.send_header('Content-type', 'application/json'); self.end_headers()
                    self.wfile.write(json.dumps({'token': token_val, 'role': user_role}).encode())
            else:
                print(f"Login failed: username={username}")
                if want_redirect: self.send_response(303); self.send_header('Location', '/?error=invalid_login'); self.end_headers()
                else: self.send_response_json_error(401, 'Invalid username or password')
            return
        
        # Ensure /add_root_dir and /remove_root_dir from Phase 1 are present and correct.
        elif self.path == '/add_root_dir':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode()
            params = parse_qs(post_data)
            token = params.get('token', [''])[0]
            new_path = params.get('new_root_path', [''])[0].strip()
            if not self.is_valid_token(token) or self.get_token_role(token) != 'admin':
                self.send_response_json_error(401, 'Unauthorized'); return
            if not new_path: self.send_response_json_error(400, 'New root path cannot be empty.'); return
            abs_new_path = os.path.abspath(new_path)
            if abs_new_path in [os.path.abspath(p) for p in ROOT_DIRECTORIES]:
                self.send_response_json_error(400, f"Normalized path '{abs_new_path}' already exists."); return
            try:
                if not os.path.exists(abs_new_path): os.makedirs(abs_new_path)
                elif not os.path.isdir(abs_new_path): self.send_response_json_error(400, f"Path '{abs_new_path}' exists but is not a directory."); return
                ROOT_DIRECTORIES.append(abs_new_path); save_root_directories(ROOT_DIRECTORIES)
                self.send_response(200); self.send_header('Content-type', 'application/json'); self.end_headers()
                self.wfile.write(json.dumps({'success': True, 'message': f"Root directory '{abs_new_path}' added."}).encode())
            except Exception as e: self.send_response_json_error(500, f"Error with path '{new_path}': {e}"); return
            return
        elif self.path == '/remove_root_dir':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode()
            params = parse_qs(post_data)
            token = params.get('token', [''])[0]
            path_to_remove = params.get('root_dir_to_remove', [''])[0].strip()
            if not self.is_valid_token(token) or self.get_token_role(token) != 'admin':
                self.send_response_json_error(401, 'Unauthorized'); return
            if not path_to_remove: self.send_response_json_error(400, 'Path to remove cannot be empty.'); return
            normalized_path_to_remove = os.path.abspath(path_to_remove)
            if normalized_path_to_remove not in [os.path.abspath(p) for p in ROOT_DIRECTORIES]:
                self.send_response_json_error(404, f"Root directory '{path_to_remove}' not found."); return
            if len(ROOT_DIRECTORIES) <= 1: self.send_response_json_error(400, 'Cannot remove the last root directory.'); return
            ROOT_DIRECTORIES = [p for p in ROOT_DIRECTORIES if os.path.abspath(p) != normalized_path_to_remove]
            save_root_directories(ROOT_DIRECTORIES)
            self.send_response(200); self.send_header('Content-type', 'application/json'); self.end_headers()
            self.wfile.write(json.dumps({'success': True, 'message': f"Root directory '{path_to_remove}' removed."}).encode())
            return
        elif self.path == '/set_root_dir': # Deprecated
            self.send_response_json_error(410, 'This endpoint is deprecated.'); return
        
        elif self.path == '/admin/create_user':
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0: self.send_response_json_error(400, 'Empty request body'); return
            post_data = self.rfile.read(content_length).decode()
            params = parse_qs(post_data)
            
            token = params.get('token', [''])[0]
            new_username = params.get('new_username', [''])[0]
            new_password = params.get('new_password', [''])[0]
            role = params.get('role', ['user'])[0]

            if not self.is_valid_token(token) or self.get_token_role(token) != 'admin':
                self.send_response_json_error(401, 'Unauthorized to create user.')
                return

            if not new_username or not new_password:
                self.send_response_json_error(400, 'Username and password are required.')
                return
            
            if role not in ['user', 'admin']:
                self.send_response_json_error(400, 'Invalid role specified.')
                return

            # Updated handling for add_user returning only a boolean:
            user_added_successfully = add_user(new_username, new_password, role)
            
            if user_added_successfully:
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'success': True, 'message': f'User \'{new_username}\' created successfully.'}).encode())
            else:
                # Check if user already exists to provide a more specific error
                # This requires peeking into users, which is not ideal here but users.py add_user doesn't give specific error back
                if get_user(new_username): # We use get_user which is safe
                    self.send_response_json_error(400, f'Failed to create user. Username \'{new_username}\' may already exist or another error occurred.')
                else:
                    self.send_response_json_error(500, 'Failed to create user due to an internal server error or invalid input (e.g. empty password).')
            return
        
        elif self.path == '/admin/delete_user':
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0: self.send_response_json_error(400, 'Empty request body'); return
            post_data = self.rfile.read(content_length).decode()
            params = parse_qs(post_data)
            
            token = params.get('token', [''])[0]
            username_to_delete = params.get('username_to_delete', [''])[0]

            if not self.is_valid_token(token) or self.get_token_role(token) != 'admin':
                self.send_response_json_error(401, 'Unauthorized to delete user.')
                return

            if not username_to_delete:
                self.send_response_json_error(400, 'Username to delete is required.')
                return
            
            # Prevent admin from deleting themselves via this direct endpoint call
            # (though users.delete_user also has a last-admin check)
            session_username = self.get_token_username(token)
            if session_username and username_to_delete.lower() == session_username.lower():
                self.send_response_json_error(403, 'Admins cannot delete themselves through this interface.')
                return

            deleted_successfully = delete_user(username_to_delete) # From users.py
            
            if deleted_successfully:
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'success': True, 'message': f'User "{username_to_delete}" deleted successfully.'}).encode())
            else:
                # users.delete_user returns False if user not found or last admin
                self.send_response_json_error(400, f'Failed to delete user "{username_to_delete}". User may not exist or may be the last admin.')
            return
        
        elif self.path == '/admin/user_change_password':
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0: self.send_response_json_error(400, 'Empty request body'); return
            post_data = self.rfile.read(content_length).decode()
            params = parse_qs(post_data)
            
            token = params.get('token', [''])[0]
            target_username = params.get('target_username', [''])[0]
            new_password = params.get('new_password', [''])[0]

            if not self.is_valid_token(token) or self.get_token_role(token) != 'admin':
                self.send_response_json_error(401, 'Unauthorized to change user password.'); return

            if not target_username or not new_password:
                self.send_response_json_error(400, 'Target username and new password are required.'); return
            
            # Optional: Add check to prevent admin from changing their own password through this specific UI endpoint
            # if self.get_token_username(token).lower() == target_username.lower():
            #    self.send_response_json_error(403, 'Use main admin settings to change your own password.'); return

            updated_successfully = update_user(target_username, password=new_password) # From users.py
            
            if updated_successfully:
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'success': True, 'message': f'Password for user "{target_username}" updated successfully.'}).encode())
            else:
                # users.update_user returns False if user not found or if password hashing failed.
                self.send_response_json_error(400, f'Failed to update password for "{target_username}". User may not exist or an error occurred.')
            return
        
        elif self.path == '/admin/clear_all_public_links':
            content_length = int(self.headers.get('Content-Length', 0))
            # No real body needed, but check for token in params
            post_data = self.rfile.read(content_length).decode()
            params = parse_qs(post_data)
            token = params.get('token', [''])[0]

            if not self.is_valid_token(token) or self.get_token_role(token) != 'admin':
                self.send_response_json_error(401, 'Unauthorized to clear public links.')
                return

            try:
                with public_links_lock:
                    public_links.clear()
                    save_public_links()
                
                print("All public links have been cleared by admin.")
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'success': True, 'message': 'All public links cleared successfully.'}).encode())
            except Exception as e:
                print(f"Error clearing public links: {e}")
                self.send_response_json_error(500, f'Server error while clearing public links: {e}')
            return
        
        elif self.path == '/admin/delete_public_link':
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0: self.send_response_json_error(400, 'Empty request body'); return
            post_data = self.rfile.read(content_length).decode()
            params = parse_qs(post_data)
            token = params.get('token', [''])[0]
            composite_key_to_delete = params.get('composite_key', [''])[0]

            if not self.is_valid_token(token) or self.get_token_role(token) != 'admin':
                self.send_response_json_error(401, 'Unauthorized to delete public link.')
                return
            
            if not composite_key_to_delete:
                self.send_response_json_error(400, 'Missing composite_key for deletion.')
                return

            try:
                with public_links_lock:
                    if composite_key_to_delete in public_links:
                        del public_links[composite_key_to_delete]
                        save_public_links()
                        message = f"Public link for '{composite_key_to_delete.replace('|', '/')}' deleted successfully."
                        print(message)
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps({'success': True, 'message': message}).encode())
                    else:
                        self.send_response_json_error(404, f"Public link for '{composite_key_to_delete.replace('|', '/')}' not found.")
            except Exception as e:
                print(f"Error deleting public link for {composite_key_to_delete}: {e}")
                self.send_response_json_error(500, f'Server error while deleting public link: {e}')
            return
        
        # Fallback for unhandled POST paths
        else:
            self.send_response_json_error(404, f"POST endpoint {self.path} not found.")

    # Helper HTML methods (ensure these are complete as per original structure)
    def get_login_section_html(self): 
        return textwrap.dedent('''
            <div id="loginSection">
                <h2>Login</h2>
                <form id="loginForm" method="POST" action="/login">
                    <div class="form-group"><input type="text" name="username" placeholder="Username" required></div>
                    <div class="form-group"><input type="password" name="password" placeholder="Password" required></div>
                    <input type="hidden" name="redirect" value="true">
                    <button type="submit">Login</button>
                </form>
            </div>
        ''')

    def get_file_section_html(self): 
        return textwrap.dedent(f'''
            <div id="fileSection" style="display: none;">
                <div class="admin-menu">
                    <button id="adminMenuBtn" class="admin-menu-btn" type="button">Admin Menu</button>
                    <div id="adminMenuDropdown" class="admin-menu-dropdown">
                        <button id="adminSettingsBtn" type="button">Settings</button>
                        <button id="manageUsersBtn" type="button">Manage Users</button>
                    </div>
                </div>
                <div class="logout-btn-container"><button id="logoutBtn">Logout</button></div>
                <div style="margin-top: 30px; text-align: center; margin-bottom: 20px;"><button id="viewFilesBtn" type="button">View/Manage Files</button></div>
                
                <form id="uploadForm" enctype="multipart/form-data">
                    <div class="form-group">
                        <label for="uploadTargetRootDirSelect" style="display: block; margin-bottom: 5px; font-weight: bold;">Upload to:</label>
                        <select id="uploadTargetRootDirSelect" name="upload_target_root_dir" style="margin-bottom: 10px; width: 100%;"></select>
                    </div>
                    <div class="form-group custom-file-upload-container">
                        <input type="file" name="file" id="actualUploadInput" required style="display: none;">
                        <button type="button" id="customBrowseBtn">Browse...</button>
                        <span id="fileNameDisplay">No file selected.</span>
                        <input type="hidden" name="token" id="uploadTokenField">
                    </div>
                    <button type="submit">Upload File</button>
                </form>
                <div id="uploadProgress" style="margin-top:10px;"></div>
                <div id="uploadMsg" class="message-area" style="margin-top:10px;"></div>

                <div id="adminSettingsPage" style="display: none;">
                    <button id="backToAdminBtn" type="button" style="position:absolute;top:20px;left:20px;">Back</button>
                    <h2>Manage Root Directories</h2>
                    <div id="rootDirMsg" class="message-area"></div>
                    <div id="currentRootDirsContainer" style="margin-bottom: 20px;"></div>
                    <form id="addRootDirForm">
                        <h3>Add New Root Directory</h3>
                        <div class="form-group">
                            <input type="text" id="newRootPathInput" placeholder="Enter full directory path" required style="width: calc(100% - 120px); margin-right:10px;">
                            <button type="submit" style="width: 100px;">Add</button>
                        </div>
                        <input type="hidden" name="token" id="addRootDirTokenField">
                    </form>
                    <div id="addRootDirMsg" class="message-area"></div>
                    <hr style="margin: 30px 0; border-color: #456;">
                    <h2>Change Admin Credentials</h2>
                    <form id="changeCredsForm" method="POST" action="/change_creds"> <!-- Added method and action -->
                        <div class="form-group"><input type="text" name="new_username" placeholder="New Username" required></div>
                        <div class="form-group"><input type="password" name="new_password" placeholder="New Password" required></div>
                        <input type="hidden" name="token" id="credsTokenField">
                        <button type="submit">Change Credentials</button>
                    </form>
                    <div id="credsMsg" class="message-area"></div>
                    <hr style="margin: 30px 0; border-color: #456;">
                    <h2>Manage Public Links</h2>
                    <div id="currentPublicLinksContainer" style="margin-bottom: 20px;"></div>
                    <button id="clearAllPublicLinksBtn" type="button" style="background-color: #e74c3c; color: white; padding: 10px 15px; border-radius: 5px; font-size: 1em;">Clear All Public Links</button>
                    <div id="publicLinksMsg" class="message-area" style="margin-top:10px;"></div>
                </div>
            </div>
        ''')

    def get_manage_users_page_html(self): 
        return textwrap.dedent('''
            <div id="manageUsersPage" style="display:none; position:fixed; top:0; left:0; right:0; bottom:0; background:linear-gradient(135deg, #2c3e50 0%, #34495e 100%); padding:60px 20px 20px; overflow-y:auto; z-index:1000;">
                <button id="backToMainFromUsersBtn" type="button" style="position:fixed;top:30px;left:30px;z-index:1001; background:linear-gradient(135deg,#4a9eff,#357abd);color:white;padding:12px 28px;border:none;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.18);font-size:18px;font-weight:bold;cursor:pointer;transition:background 0.2s;">Back</button>
                <h2 style="margin-top:60px;color:#fff;text-align:center;text-shadow:0 1px 3px rgba(0,0,0,0.2);">Manage Users</h2>
                <div style="max-width:900px; margin: 20px auto; background-color:rgba(35,52,70,0.9); padding:25px; border-radius:10px; box-shadow:0 4px 12px rgba(0,0,0,0.3);">
                    <h3>Create New User</h3>
                    <form id="adminCreateUserForm" style="margin-bottom:30px;">
                        <div class="form-group">
                            <input type="text" id="adminNewUsername" placeholder="Username" required style="display:inline-block; width: calc(33% - 10px); margin-right:10px;">
                            <input type="password" id="adminNewPassword" placeholder="Password" required style="display:inline-block; width: calc(33% - 10px); margin-right:10px;">
                            <select id="adminNewUserRole" style="display:inline-block; width: calc(33% - 10px); padding: 8px; border-radius: 4px; border: 1px solid #456; background-color: #2c4058; color: white;">
                                <option value="user">User</option><option value="admin">Admin</option>
                            </select>
                        </div>
                        <button type="submit">Create User</button>
                        <div id="adminCreateUserMsg" class="message-area"></div>
                    </form>
                    <h3>Current Users</h3>
                    <div id="userListContainer"></div>
                </div>
            </div>
        ''')

    def get_files_page_html(self): 
        return textwrap.dedent('''
            <div id="filesPage" style="display:none;">
                <button id="backToMainBtn" type="button" style="position:fixed;top:30px;left:30px;z-index:1001; background:linear-gradient(135deg,#1565c0,#42a5f5);color:white;padding:12px 28px;border:none;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.18);font-size:18px;font-weight:bold;cursor:pointer;transition:background 0.2s;">Back to Main Menu</button>
                <div id="searchContainer" style="max-width:800px; margin: 20px auto; display:flex; gap:10px;">
                    <input type="text" id="fileSearchInput" placeholder="Search current folder..." style="flex-grow:1;">
                    <button id="fileSearchBtn">Search</button>
                    <button id="fileSearchClearBtn">Clear</button>
                </div>
                <h2 id="filesPageTitle" style="margin-top:20px;color:#fff;text-align:center;text-shadow:0 2px 8px rgba(25,118,210,0.2);">Files</h2>
                <div id="fileListDebug" class="message-area error" style="text-align:center;max-width:800px;margin:10px auto;"></div>
                <div id="fileListPage"></div>
            </div>
        ''')

    def get_main_script_js(self): 
        # This JS will be extensive. Combining Phase 1 admin root JS with new Phase 2 user-facing root selection & file ops.
        return textwrap.dedent('''
            <script>
                let currentToken = null;
                let currentUserRole = null;
                let currentUsername = null;
                
                let allConfiguredRootDirs = [];
                let currentSelectedRootDirPath = null;
                let currentRelativePath = '';

                function getCookie(name) {
                    const value = `; ${document.cookie}`; const parts = value.split(`; ${name}=`);
                    if (parts.length === 2) return parts.pop().split(';').shift(); return null;
                }
                function showMessage(elementId, message, isSuccess) {
                    const el = document.getElementById(elementId);
                    if (el) { el.textContent = message; el.className = 'message-area ' + (isSuccess ? 'success' : 'error'); }
                }
                
                function displayRootSelectionModal() {
                    const modal = document.getElementById('rootSelectionPage');
                    const buttonsContainer = document.getElementById('rootSelectionButtonsContainer');
                    buttonsContainer.innerHTML = ''; 
                    if (allConfiguredRootDirs.length === 0) {
                        buttonsContainer.innerHTML = '<p class="error">No file repositories configured. Please ask an admin.</p>';
                    } else if (allConfiguredRootDirs.length === 1) {
                        handleRootSelected(allConfiguredRootDirs[0]); return;
                    } else {
                        allConfiguredRootDirs.forEach(rootPath => {
                            const btn = document.createElement('button'); btn.className = 'root-select-btn';
                            let displayName = rootPath.split(/[\\\\/]/).pop() || rootPath;
                            displayName = displayName.length > 35 ? ('...' + displayName.slice(-32)) : displayName;
                            btn.textContent = `${displayName} (${rootPath.length > 30 ? rootPath.substring(0,27)+'...': rootPath})`;
                            btn.onclick = () => handleRootSelected(rootPath);
                            buttonsContainer.appendChild(btn);
                        });
                    }
                    modal.style.display = 'flex';
                }
                function handleRootSelected(rootPath) {
                    currentSelectedRootDirPath = rootPath; currentRelativePath = '';
                    document.getElementById('rootSelectionPage').style.display = 'none';
                    document.getElementById('containerDiv').style.display = 'none'; // Hide main container
                    document.getElementById('filesPage').style.display = 'block';
                    document.getElementById('filesPageTitle').textContent = `Files in: ${currentSelectedRootDirPath.split(/[\\/]/).pop() || currentSelectedRootDirPath}`;
                    refreshListing();

                    // Sync the main upload form's dropdown
                    const uploadDropdown = document.getElementById('uploadTargetRootDirSelect');
                    if (uploadDropdown && allConfiguredRootDirs.includes(rootPath)) {
                        uploadDropdown.value = rootPath;
                    }
                }
                
                function refreshListing(relativePath = currentRelativePath, searchQuery = document.getElementById('fileSearchInput')?.value || '') {
                    if (!currentSelectedRootDirPath) { showMessage('fileListDebug', 'No root directory selected.', false); return; }
                    currentRelativePath = relativePath;
                    const listingDiv = document.getElementById('fileListPage');
                    const table = listingDiv.querySelector('table') || (listingDiv.innerHTML = '<table style="width:100%; border-collapse: separate; border-spacing: 0 8px;"><thead><tr><th style="text-align:left;">Name</th><th style="text-align:left;width:80px;">Type</th><th style="text-align:right;width:260px;">Actions</th></tr></thead><tbody></tbody></table>', listingDiv.querySelector('table'));
                    const tableBody = table.querySelector('tbody');
                    tableBody.innerHTML = '<tr><td colspan="3" style="text-align:center;padding:20px;">Loading files...</td></tr>';
                    document.getElementById('fileListDebug').textContent = '';
                    const url = `/files?token=${currentToken}&root_dir_path=${encodeURIComponent(currentSelectedRootDirPath)}&path=${encodeURIComponent(currentRelativePath)}&search=${encodeURIComponent(searchQuery)}`;
                    fetch(url).then(r => r.ok ? r.json() : r.json().then(e => Promise.reject(e)))
                        .then(data => {
                            if (data.error) throw new Error(data.error);
                            tableBody.innerHTML = '';
                            if (currentRelativePath) {
                                const parentPath = currentRelativePath.substring(0, currentRelativePath.lastIndexOf('/') >= 0 ? currentRelativePath.lastIndexOf('/') : 0);
                                const upRow = tableBody.insertRow(); upRow.innerHTML = `<td><a href="#" class="folder-link" data-path="${parentPath}"><strong>.. (Up)</strong></a></td><td>Folder</td><td></td>`;
                            }
                            data.forEach(item => {
                                const row = tableBody.insertRow();
                                row.insertCell().innerHTML = item.is_directory ? `<a href="#" class="folder-link" data-path="${item.path}"><strong>${item.name}/</strong></a>` : item.name;
                                row.insertCell().textContent = item.is_directory ? 'Folder' : 'File';
                                const actionsCell = row.insertCell(); actionsCell.style.textAlign = "right";
                                if (!item.is_directory) {
                                    actionsCell.innerHTML = 
                                        `<button class="download-btn copyLinkBtn" data-filename="${item.path}">Download</button> ` +
                                        `<button class="public-link-btn copyPublicLinkBtn" data-filename="${item.path}">Get Public Link</button>`;
                                }
                            });
                            if (data.length === 0 && (currentRelativePath === '' || !currentRelativePath.includes('/')) && !searchQuery ) {
                                tableBody.innerHTML = `<tr><td colspan="3" style="text-align:center;padding:20px;">Directory is empty.</td></tr>`;
                            } else if (data.length === 0 && searchQuery) {
                                 tableBody.innerHTML = `<tr><td colspan="3" style="text-align:center;padding:20px;">No files found matching '${searchQuery}'.</td></tr>`;
                            }
                        })
                        .catch(err => { showMessage('fileListDebug', `Error loading files: ${err.error || err.message}`, false); tableBody.innerHTML = '<tr><td colspan="3" style="text-align:center;color:#ff4a4a;padding:20px;">Failed to load files.</td></tr>'; });
                }
                function uploadFile(event) {
                    event.preventDefault();
                    // Get target root directory from the new select dropdown first
                    const uploadTargetSelect = document.getElementById('uploadTargetRootDirSelect');
                    let targetRootDirForUpload = null;

                    if (uploadTargetSelect && uploadTargetSelect.value && !uploadTargetSelect.options[uploadTargetSelect.selectedIndex]?.disabled) {
                        targetRootDirForUpload = uploadTargetSelect.value;
                    } else if (currentSelectedRootDirPath) {
                        // Fallback to currentSelectedRootDirPath if dropdown isn't conclusive (e.g. no options, or placeholder selected)
                        targetRootDirForUpload = currentSelectedRootDirPath;
                    } else if (allConfiguredRootDirs.length === 1) {
                        // If only one root directory is configured, default to it
                        targetRootDirForUpload = allConfiguredRootDirs[0];
                         if(uploadTargetSelect) uploadTargetSelect.value = targetRootDirForUpload; // Also update dropdown if it exists
                    }

                    if (!targetRootDirForUpload) { 
                        showMessage('uploadMsg', 'Please select a target directory for upload.', false); 
                        return; 
                    }

                    const fileInput = document.querySelector('#uploadForm input[name="file"]');
                    const file = fileInput.files[0]; if (!file) { showMessage('uploadMsg', 'No file selected.', false); return; }
                    const formData = new FormData(); formData.append('file', file); formData.append('token', currentToken);
                    formData.append('root_dir_path', targetRootDirForUpload); // Use the determined target root
                    showMessage('uploadMsg', 'Uploading...', true);
                    fetch('/upload', { method: 'POST', body: formData })
                        .then(r => r.json().then(d => ({ok: r.ok, data: d})))
                        .then(({ok, data}) => { if (!ok || !data.success) throw new Error(data.error || 'Upload failed.');
                            showMessage('uploadMsg', `File '${data.filename}' uploaded.`, true); fileInput.value = '';
                            if (document.getElementById('filesPage').style.display === 'block') refreshListing(currentRelativePath);
                        }).catch(err => showMessage('uploadMsg', `Upload error: ${err.message}`, false));
                }
                function downloadFile(relativeFilePath) { /* Uses currentSelectedRootDirPath implicitly */
                    window.location.href = `/download?token=${currentToken}&root=${encodeURIComponent(currentSelectedRootDirPath)}&file=${encodeURIComponent(relativeFilePath)}`;
                }
                function getPublicLink(relativeFilePath, targetButton) { /* Uses currentSelectedRootDirPath implicitly */
                    const oldTxt = targetButton.textContent; targetButton.textContent = 'Wait...'; targetButton.disabled = true;
                    
                    const row = targetButton.closest('tr');
                    const nameCell = row.querySelector('td:first-child');

                    // Remove any existing link or error from the name cell
                    const existingLinkDisplay = nameCell.querySelector('.generated-public-link-display');
                    if (existingLinkDisplay) existingLinkDisplay.remove();

                    fetch(`/get_public_link?token=${currentToken}&root_dir_path=${encodeURIComponent(currentSelectedRootDirPath)}&file=${encodeURIComponent(relativeFilePath)}`)
                        .then(r => r.json().then(d => ({ok: r.ok, data: d})))
                        .then(({ok, data}) => {
                            if (!ok || !data.public_url) {
                                throw new Error(data.error || 'Failed to get public link.');
                            }
                            const linkContainer = document.createElement('div');
                            linkContainer.className = 'generated-public-link-display'; // Class for easy removal
                            linkContainer.style.marginTop = '5px';

                            const link = document.createElement('a');
                            link.href = window.location.origin + data.public_url;
                            link.textContent = data.public_url; // MODIFIED from "Open Public Link"
                            link.target = "_blank";
                            link.style.display = 'inline-block';
                            link.style.padding = '4px 8px';
                            link.style.border = '1px solid #4a9eff'; 
                            link.style.borderRadius = '3px';
                            link.style.backgroundColor = '#2c4058'; 
                            link.style.color = '#f1c40f'; // Yellowish color
                            link.style.textDecoration = 'none';
                            link.style.fontSize = '0.9em';
                            
                            linkContainer.appendChild(link);
                            nameCell.appendChild(linkContainer);
                        })
                        .catch(err => {
                            const errorContainer = document.createElement('div');
                            errorContainer.className = 'generated-public-link-display error'; // Class for easy removal
                            errorContainer.style.marginTop = '5px';
                            errorContainer.style.padding = '4px';
                            errorContainer.style.fontSize = '0.9em';
                            errorContainer.style.color = '#ff4a4a'; // Error color
                            errorContainer.textContent = `Error: ${err.message}`;
                            nameCell.appendChild(errorContainer);
                            console.error(`Public link error: ${err.message}`);
                        })
                        .finally(() => { targetButton.textContent = oldTxt; targetButton.disabled = false; });
                }
                function logout() {
                    fetch('/logout', { method: 'POST', body: new URLSearchParams({token: currentToken}) })
                    .then(() => {
                        document.cookie = 'token=; Path=/; Max-Age=0; SameSite=Strict';
                        document.cookie = 'role=; Path=/; Max-Age=0; SameSite=Strict';
                        document.cookie = 'username=; Path=/; Max-Age=0; SameSite=Strict';
                        currentToken = null; currentUserRole = null; currentUsername = null;
                        window.location.href = '/';
                    }).catch(err => {
                        console.error('Logout failed:', err);
                        // Still attempt to clear cookies and redirect
                        document.cookie = 'token=; Path=/; Max-Age=0; SameSite=Strict';
                        document.cookie = 'role=; Path=/; Max-Age=0; SameSite=Strict';
                        document.cookie = 'username=; Path=/; Max-Age=0; SameSite=Strict';
                        window.location.href = '/';
                    });
                }
                function fetchAndRenderRootDirs() {
                    const container = document.getElementById('currentRootDirsContainer');
                    if (!currentToken) {
                        console.warn('fetchAndRenderRootDirs: currentToken is null or empty, aborting.');
                        if(container) container.innerHTML = '<p class="error">Critical error: No token available to fetch root directories.</p>';
                        return;
                    }
                    console.log('[BINGLEHTTP] fetchAndRenderRootDirs: Fetching with token:', currentToken); // Added for debugging
                    
                    if(container) container.innerHTML = '<p>Loading root directories...</p>';
                    
                    fetch('/get_current_root_dirs?token=' + currentToken)
                        .then(response => {
                            if (!response.ok) {
                                console.error('[BINGLEHTTP] Failed to fetch root dirs. Status:', response.status, 'StatusText:', response.statusText); // Added for debugging
                                throw new Error('Failed to fetch root dirs');
                            }
                            return response.json();
                        })
                        .then(dirs => {
                            allConfiguredRootDirs = dirs || []; // Update global list as well
                            if (dirs && dirs.length > 0) {
                                let tableHtml = '<table style="width: 100%; border-collapse: collapse;">';
                                tableHtml += '<thead><tr><th style="text-align: left; padding: 8px; border-bottom: 1px solid #456;">Directory Path</th><th style="text-align: right; padding: 8px; border-bottom: 1px solid #456; width:100px;">Action</th></tr></thead>';
                                tableHtml += '<tbody>';
                                dirs.forEach(dir => {
                                    tableHtml += '<tr>';
                                    tableHtml += `<td style="padding: 8px; border-bottom: 1px solid #3a4b5f;">${dir}</td>`;
                                    tableHtml += `<td style="text-align: right; padding: 8px; border-bottom: 1px solid #3a4b5f;">
                                                    <button onclick="handleRemoveRootDirWrapper(\'${dir}\')" style="padding: 4px 10px; font-size:0.9em; background-color: #e74c3c; color:white; border:none; border-radius:3px; cursor:pointer;">Remove</button>
                                                 </td>`;
                                    tableHtml += '</tr>';
                                });
                                tableHtml += '</tbody></table>';
                                container.innerHTML = tableHtml;
                            } else {
                                container.innerHTML = '<p>No root directories configured.</p>';
                            }
                            // Update the main root directory selection modal if it exists and is visible
                            // This is just a passive update; the modal has its own fetch logic on display typically
                            const rootSelButtons = document.getElementById('rootSelectionButtonsContainer');
                            if (rootSelButtons && document.getElementById('rootSelectionPage').style.display === 'flex') {
                                // Simplified: just re-trigger its display logic which includes fetch
                                // displayRootSelectionModal(); // Careful with potential loops or redundant calls
                            }
                        })
                        .catch(error => {
                            console.error('Error fetching root directories:', error);
                            container.innerHTML = '<p class="error">Error loading root directories. ' + error.message + '</p>';
                        });
                }
                // Wrapper to prevent issues with os.path.abspath like characters in string for onclick
                function handleRemoveRootDirWrapper(pathStr) {
                  if (confirm(`Are you sure you want to remove root directory: ${pathStr}?`)) {
                    handleRemoveRootDir(pathStr);
                  }
                }
                function handleAddRootDir(event) {
                    event.preventDefault();
                    const newPathInput = document.getElementById('newRootPathInput');
                    const newPath = newPathInput.value.trim();
                    const token = document.getElementById('addRootDirTokenField').value; // Ensure this field is populated

                    if (!newPath) {
                        showMessage('addRootDirMsg', 'New root path cannot be empty.', false);
                        return;
                    }
                    showMessage('addRootDirMsg', 'Adding...', true);

                    const params = new URLSearchParams();
                    params.append('token', token);
                    params.append('new_root_path', newPath);

                    fetch('/add_root_dir', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: params
                    })
                    .then(response => response.json().then(data => ({ok: response.ok, data})))
                    .then(({ok, data}) => {
                        if (!ok || !data.success) {
                            throw new Error(data.error || data.message || 'Failed to add root directory.');
                        }
                        showMessage('addRootDirMsg', data.message || 'Root directory added successfully!', true);
                        newPathInput.value = ''; // Clear input
                        fetchAndRenderRootDirs(); // Refresh the list
                    })
                    .catch(error => {
                        showMessage('addRootDirMsg', `Error: ${error.message}`, false);
                        console.error('Error adding root directory:', error);
                    });
                }
                function handleRemoveRootDir(pathToRemove) {
                    const token = currentToken; // Assuming currentToken is globally available and valid
                    if (!pathToRemove) {
                        showMessage('rootDirMsg', 'Path to remove is invalid.', false);
                        return;
                    }
                    showMessage('rootDirMsg', 'Removing...', true);

                    const params = new URLSearchParams();
                    params.append('token', token);
                    params.append('root_dir_to_remove', pathToRemove);

                    fetch('/remove_root_dir', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: params
                    })
                    .then(response => response.json().then(data => ({ok: response.ok, data})))
                    .then(({ok, data}) => {
                        if (!ok || !data.success) {
                            throw new Error(data.error || data.message || 'Failed to remove root directory.');
                        }
                        showMessage('rootDirMsg', data.message || 'Root directory removed successfully!', true);
                        fetchAndRenderRootDirs(); // Refresh the list
                    })
                    .catch(error => {
                        showMessage('rootDirMsg', `Error: ${error.message}`, false);
                        console.error('Error removing root directory:', error);
                    });
                }
                function showMainFileSectionView() {
                    if (document.getElementById('loginSection')) document.getElementById('loginSection').style.display = 'none'; // Assuming logged in
                    document.getElementById('containerDiv').style.display = 'block';
                    document.getElementById('fileSection').style.display = 'block';
                    
                    // Hide other "page" style views
                    if (document.getElementById('filesPage')) document.getElementById('filesPage').style.display = 'none';
                    if (document.getElementById('manageUsersPage')) document.getElementById('manageUsersPage').style.display = 'none';
                    if (document.getElementById('adminSettingsPage')) document.getElementById('adminSettingsPage').style.display = 'none';
                    if (document.getElementById('rootSelectionPage')) document.getElementById('rootSelectionPage').style.display = 'none';

                    // Show default interactive elements within fileSection
                    const viewFilesBtnContainer = document.getElementById('viewFilesBtn')?.parentElement;
                    const uploadForm = document.getElementById('uploadForm');
                    
                    if(viewFilesBtnContainer) viewFilesBtnContainer.style.display = 'block';
                    if(uploadForm) uploadForm.style.display = 'block';
                    
                    // Clear any messages in fileSection sub-areas if needed
                    showMessage('uploadMsg', '', true);
                }

                function showAdminSettingsPage() {
                    if (document.getElementById('loginSection')) document.getElementById('loginSection').style.display = 'none';
                    document.getElementById('containerDiv').style.display = 'block';
                    document.getElementById('fileSection').style.display = 'block';

                    // Hide other "page" style views
                    if (document.getElementById('filesPage')) document.getElementById('filesPage').style.display = 'none';
                    if (document.getElementById('manageUsersPage')) document.getElementById('manageUsersPage').style.display = 'none';
                    
                    // Within fileSection, hide default view elements
                    const viewFilesBtnContainer = document.getElementById('viewFilesBtn')?.parentElement;
                    const uploadForm = document.getElementById('uploadForm');
                    const uploadProgress = document.getElementById('uploadProgress');
                    const uploadMsg = document.getElementById('uploadMsg');

                    if(viewFilesBtnContainer) viewFilesBtnContainer.style.display = 'none';
                    if(uploadForm) uploadForm.style.display = 'none';
                    if(uploadProgress) uploadProgress.style.display = 'none';
                    if(uploadMsg) uploadMsg.textContent = '';

                    // Show the admin settings page itself
                    if (document.getElementById('adminSettingsPage')) document.getElementById('adminSettingsPage').style.display = 'block';
                    
                    // Ensure token fields are populated if they exist (though they are populated on login generally)
                    if(document.getElementById('addRootDirTokenField')) document.getElementById('addRootDirTokenField').value = currentToken;
                    if(document.getElementById('credsTokenField')) document.getElementById('credsTokenField').value = currentToken;

                    const adminSettingsPageElement = document.getElementById('adminSettingsPage');

                    // Yield to browser to ensure DOM updates are processed
                    setTimeout(() => {
                        if (!adminSettingsPageElement) {
                            console.error('[BINGLEHTTP] showAdminSettingsPage (deferred): adminSettingsPage element was NOT found initially! Attempting fallback.');
                            const fallbackAdminSettings = document.getElementById('adminSettingsPage'); // Try to get it again
                            if (!fallbackAdminSettings) {
                                if(document.getElementById('publicLinksMsg')) showMessage('publicLinksMsg', 'Critical error: Admin settings panel not found. Cannot load public links.', false);
                                console.error('[BINGLEHTTP] showAdminSettingsPage (deferred): Fallback also FAILED to find adminSettingsPage.');
                                // Proceed with other parts of admin settings if possible
                                fetchAndRenderRootDirs(); 
                                showMessage('addRootDirMsg','',true); 
                                showMessage('rootDirMsg','',true); 
                                showMessage('credsMsg','',true);
                                return; 
                            }
                            // If fallback found it, use it
                            console.log('[BINGLEHTTP] showAdminSettingsPage (deferred): Fallback FOUND adminSettingsPage. Proceeding with it for public links.');
                            fetchAndRenderPublicLinks(fallbackAdminSettings);
                        } else {
                             // If originally found, use it
                            console.log('[BINGLEHTTP] showAdminSettingsPage (deferred): Initial adminSettingsPage element found. Proceeding with it for public links.');
                            fetchAndRenderPublicLinks(adminSettingsPageElement);
                        }
                        // These are independent of public links rendering and can proceed if their containers exist
                        fetchAndRenderRootDirs(); 
                        showMessage('addRootDirMsg','',true); 
                        showMessage('rootDirMsg','',true); 
                        showMessage('credsMsg','',true);
                    }, 0); 
                }

                function showManageUsersPage() {
                    // Hide main container (which holds title, login, fileSection) and filesPage
                    if (document.getElementById('containerDiv')) document.getElementById('containerDiv').style.display = 'none';
                    if (document.getElementById('filesPage')) document.getElementById('filesPage').style.display = 'none';
                    if (document.getElementById('rootSelectionPage')) document.getElementById('rootSelectionPage').style.display = 'none';

                    const manageUsersPageEl = document.getElementById('manageUsersPage');
                    if (manageUsersPageEl) manageUsersPageEl.style.display = 'block';
                    
                    showMessage('adminCreateUserMsg', '', true); // Clear any previous messages
                    // fetchUsersAndRender(); // Call this when implemented
                    fetchUsersAndRender(); // Now we call it
                }
                function fetchUsersAndRender() { 
                    if (!currentToken || currentUserRole !== 'admin') {
                        showMessage('userListContainer', 'Unauthorized to fetch users.', false);
                        return;
                    }
                    const userListContainer = document.getElementById('userListContainer');
                    if(userListContainer) userListContainer.innerHTML = '<p>Loading users...</p>';

                    fetch('/admin/get_all_users?token=' + currentToken)
                        .then(response => {
                            if (!response.ok) {
                                return response.json().then(err => { throw new Error(err.error || 'Failed to fetch users'); });
                            }
                            return response.json();
                        })
                        .then(users => {
                            renderUserList(users);
                        })
                        .catch(error => {
                            if(userListContainer) userListContainer.innerHTML = `<p class="error">Error loading users: ${error.message}</p>`;
                            console.error('Error fetching users:', error);
                        });
                }
                function renderUserList(usersArray) { 
                    const container = document.getElementById('userListContainer');
                    if (!container) return;
                    if (!usersArray || usersArray.length === 0) {
                        container.innerHTML = '<p>No users found.</p>';
                        return;
                    }

                    let tableHtml = '<table style="width: 100%; border-collapse: collapse; margin-top:15px;">';
                    tableHtml += '<thead><tr>';
                    tableHtml += '<th style="text-align: left; padding: 10px; border-bottom: 1px solid #456; color: #e0e0e0;">Username</th>';
                    tableHtml += '<th style="text-align: left; padding: 10px; border-bottom: 1px solid #456; color: #e0e0e0;">Role</th>';
                    tableHtml += '<th style="text-align: right; padding: 10px; border-bottom: 1px solid #456; color: #e0e0e0;">Actions</th>';
                    tableHtml += '</tr></thead><tbody>';

                    usersArray.forEach(user => {
                        tableHtml += `<tr data-username="${user.username}">`;
                        tableHtml += `<td style="padding: 10px; border-bottom: 1px solid #3a4b5f; color: #f0f0f0;">${user.username}</td>`;
                        tableHtml += `<td style="padding: 10px; border-bottom: 1px solid #3a4b5f; color: #f0f0f0;">${user.role}</td>`;
                        tableHtml += `<td style="text-align: right; padding: 10px; border-bottom: 1px solid #3a4b5f;">`;
                        // Add buttons with distinct classes for event handling later
                        tableHtml += `<button class="admin-change-password-btn" data-username="${user.username}" style="margin-right: 8px; background-color: #ffc107; color:#333; padding: 5px 10px; font-size:0.9em; border:none; border-radius:3px;">Change Password</button>`;
                        // Prevent admin from deleting themselves easily
                        if (user.username.toLowerCase() !== currentUsername.toLowerCase()) {
                           tableHtml += `<button class="admin-delete-user-btn" data-username="${user.username}" style="background-color: #e74c3c; color:white; padding: 5px 10px; font-size:0.9em; border:none; border-radius:3px;">Delete User</button>`;
                        }
                        tableHtml += '</td></tr>';
                    });
                    tableHtml += '</tbody></table>';
                    container.innerHTML = tableHtml;

                    // Add event listeners for the new buttons (delegated from container for dynamic content)
                    container.querySelectorAll('.admin-change-password-btn').forEach(btn => {
                        btn.addEventListener('click', (e) => {
                            const username = e.target.dataset.username;
                            // Find the cell to pass to showChangePasswordForm if that function needs it
                            const cell = e.target.closest('td'); 
                            showChangePasswordForm(username, cell); // showChangePasswordForm is now implemented
                        });
                    });
                    container.querySelectorAll('.admin-delete-user-btn').forEach(btn => {
                        btn.addEventListener('click', (e) => {
                            const username = e.target.dataset.username;
                            // handleAdminDeleteUser(username); // Old direct call
                            showInlineDeleteConfirmation(username, e.target); // New call
                        });
                    });
                }
                function showInlineDeleteConfirmation(username, originalButtonElement) {
                    if (!username || !originalButtonElement) return;
                    
                    const parentCell = originalButtonElement.parentElement;
                    if (!parentCell) return;

                    // Hide original delete button
                    originalButtonElement.style.display = 'none';

                    const noButton = document.createElement('button');
                    noButton.textContent = 'No';
                    noButton.style.backgroundColor = '#e74c3c'; // Red
                    noButton.style.color = 'white';
                    noButton.style.padding = '5px 10px';
                    noButton.style.fontSize = '0.9em';
                    noButton.style.border = 'none';
                    noButton.style.borderRadius = '3px';
                    noButton.style.marginRight = '5px';
                    noButton.onclick = () => {
                        parentCell.removeChild(noButton);
                        parentCell.removeChild(yesButton);
                        originalButtonElement.style.display = 'inline-block'; // Or original display value
                    };

                    const yesButton = document.createElement('button');
                    yesButton.textContent = 'Yes';
                    yesButton.style.backgroundColor = '#2ecc71'; // Green
                    yesButton.style.color = 'white';
                    yesButton.style.padding = '5px 10px';
                    yesButton.style.fontSize = '0.9em';
                    yesButton.style.border = 'none';
                    yesButton.style.borderRadius = '3px';
                    yesButton.onclick = () => {
                        handleAdminDeleteUser(username); // Proceed with deletion
                        // No need to remove yes/no here, list refresh will do it, or error shown
                        // parentCell.removeChild(noButton);
                        // parentCell.removeChild(yesButton);
                        // originalButtonElement.style.display = 'inline-block'; // Not needed if list refreshes
                    };
                    
                    // Append new buttons - insert before the original button if it were visible
                    // Or simply append if it's easier and layout allows
                    parentCell.appendChild(noButton);
                    parentCell.appendChild(yesButton);
                }

                function showChangePasswordForm(username, cell) { 
                    if (!cell || !username) return;

                    // Remove any existing form in this cell first
                    const existingForm = cell.querySelector('.inline-password-form');
                    if (existingForm) existingForm.remove();

                    const form = document.createElement('form');
                    form.className = 'inline-password-form';
                    form.style.marginTop = '5px';
                    form.style.display = 'flex';
                    form.style.gap = '5px';

                    const passwordInput = document.createElement('input');
                    passwordInput.type = 'password';
                    passwordInput.placeholder = 'New Password';
                    passwordInput.required = true;
                    passwordInput.style.flexGrow = '1';
                    passwordInput.style.padding = '4px';
                    passwordInput.style.fontSize = '0.9em';

                    const submitButton = document.createElement('button');
                    submitButton.type = 'submit';
                    submitButton.textContent = 'Set';
                    submitButton.style.padding = '4px 8px';
                    submitButton.style.fontSize = '0.9em';
                    
                    const cancelButton = document.createElement('button');
                    cancelButton.type = 'button'; // Important: not submit
                    cancelButton.textContent = 'Cancel';
                    cancelButton.style.padding = '4px 8px';
                    cancelButton.style.fontSize = '0.9em';
                    cancelButton.style.backgroundColor = '#7f8c8d';
                    cancelButton.onclick = () => form.remove();

                    form.appendChild(passwordInput);
                    form.appendChild(submitButton);
                    form.appendChild(cancelButton);
                    
                    const messageDiv = document.createElement('div');
                    messageDiv.className = 'inline-password-message message-area'; // Use message-area for styling
                    messageDiv.style.fontSize = '0.85em';
                    messageDiv.style.marginTop = '3px';
                    form.appendChild(messageDiv); // Add message div to the form itself

                    form.onsubmit = (e) => {
                        e.preventDefault();
                        const newPassword = passwordInput.value;
                        if (!newPassword) {
                            messageDiv.textContent = 'Password cannot be empty.';
                            messageDiv.className = 'inline-password-message message-area error';
                            return;
                        }
                        messageDiv.textContent = ''; // Clear previous message
                        handleAdminChangePassword(username, newPassword, form, messageDiv); // Pass form and messageDiv for feedback
                    };
                    
                    // Insert form after existing buttons in the cell
                    cell.appendChild(form);
                    passwordInput.focus();
                }
                function handleAdminChangePassword(username, newPassword, formElement, messageElement) { 
                    if (!username || !newPassword) {
                        if(messageElement) showMessage(messageElement, 'Username or new password missing.', false, true);
                        return;
                    }
                    if(messageElement) showMessage(messageElement, 'Updating password...', true, true);

                    const params = new URLSearchParams();
                    params.append('token', currentToken);
                    params.append('target_username', username);
                    params.append('new_password', newPassword);

                    fetch('/admin/user_change_password', { // New endpoint
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: params
                    })
                    .then(response => response.json().then(data => ({ok: response.ok, data})))
                    .then(({ok, data}) => {
                        if (!ok || !data.success) {
                            throw new Error(data.error || 'Failed to change password.');
                        }
                        if(messageElement) showMessage(messageElement, data.message || 'Password updated successfully!', true, true);
                        if(formElement) setTimeout(() => formElement.remove(), 2000); // Remove form after a delay
                        // No need to call fetchUsersAndRender() as the list content itself hasn't changed structure
                    })
                    .catch(error => {
                        if(messageElement) showMessage(messageElement, `Error: ${error.message}`, false, true);
                        console.error('Error changing password:', error);
                    });
                }
                function handleAdminCreateUser(event) { 
                    event.preventDefault();
                    const newUsername = document.getElementById('adminNewUsername').value.trim();
                    const newPassword = document.getElementById('adminNewPassword').value;
                    const newUserRole = document.getElementById('adminNewUserRole').value;
                    const adminCreateUserMsg = document.getElementById('adminCreateUserMsg');

                    if (!newUsername || !newPassword) {
                        showMessage('adminCreateUserMsg', 'Username and password are required.', false);
                        return;
                    }
                    showMessage('adminCreateUserMsg', 'Creating user...', true);

                    const params = new URLSearchParams();
                    params.append('token', currentToken);
                    params.append('new_username', newUsername);
                    params.append('new_password', newPassword);
                    params.append('role', newUserRole);

                    fetch('/admin/create_user', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: params
                    })
                    .then(response => response.json().then(data => ({ok: response.ok, data})))
                    .then(({ok, data}) => {
                        if (!ok || !data.success) {
                            throw new Error(data.error || 'Failed to create user.');
                        }
                        showMessage('adminCreateUserMsg', data.message || 'User created successfully!', true);
                        document.getElementById('adminNewUsername').value = ''; // Clear fields
                        document.getElementById('adminNewPassword').value = '';
                        fetchUsersAndRender(); // Refresh the user list
                    })
                    .catch(error => {
                        showMessage('adminCreateUserMsg', `Error: ${error.message}`, false);
                        console.error('Error creating user:', error);
                    });
                }
                function handleAdminDeleteUser(username) { 
                    if (!username) return;
                    // The JavaScript confirm() dialog is now replaced by inline Yes/No buttons.
                    // The showInlineDeleteConfirmation function handles the user's choice before calling this.
                    
                    showMessage('adminCreateUserMsg', '', true); // Clear previous messages from create form
                    // const userListContainer = document.getElementById('userListContainer'); // Not directly used for messages here now

                    const params = new URLSearchParams();
                    params.append('token', currentToken);
                    params.append('username_to_delete', username);

                    fetch('/admin/delete_user', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: params
                    })
                    .then(response => response.json().then(data => ({ok: response.ok, data})))
                    .then(({ok, data}) => {
                        if (!ok || !data.success) {
                            throw new Error(data.error || 'Failed to delete user.');
                        }
                        // Show success message temporarily in the main user list area or adminCreateUserMsg
                        showMessage('adminCreateUserMsg', data.message || `User "${username}" deleted successfully!`, true);
                        fetchUsersAndRender(); // Refresh the user list
                    })
                    .catch(error => {
                        showMessage('adminCreateUserMsg', `Error: ${error.message}`, false);
                        console.error('Error deleting user:', error);
                    });
                }
                function handleClearAllPublicLinks() {
                    if (!currentToken || currentUserRole !== 'admin') {
                        showMessage('publicLinksMsg', 'Unauthorized action.', false);
                        return;
                    }
                    // Confirmation is now handled by showClearLinksConfirmation
                    // if (!confirm("Are you sure you want to delete ALL public links? This action cannot be undone.")) {
                    //     return;
                    // }
                    showMessage('publicLinksMsg', 'Clearing all public links...', true);
                    const params = new URLSearchParams();
                    params.append('token', currentToken);

                    fetch('/admin/clear_all_public_links', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: params
                    })
                    .then(response => response.json().then(data => ({ok: response.ok, data})))
                    .then(({ok, data}) => {
                        if (!ok || !data.success) {
                            throw new Error(data.error || 'Failed to clear public links.');
                        }
                        showMessage('publicLinksMsg', data.message || 'All public links cleared successfully!', true);
                    })
                    .catch(error => {
                        showMessage('publicLinksMsg', `Error: ${error.message}`, false);
                        console.error('Error clearing public links:', error);
                    });
                }
                
                function showClearLinksConfirmation(originalButton) {
                    if (!originalButton) return;

                    const parent = originalButton.parentNode;
                    if (!parent) return;

                    // Create a container for the confirmation
                    const confirmationContainer = document.createElement('div');
                    confirmationContainer.className = 'inline-confirm-clear-links'; 
                    confirmationContainer.style.display = 'inline-block'; 
                    confirmationContainer.style.marginLeft = '10px'; 

                    const questionText = document.createElement('span');
                    questionText.textContent = "Are you sure? ";
                    questionText.style.marginRight = '10px';

                    const yesButton = document.createElement('button');
                    yesButton.textContent = 'Yes';
                    yesButton.style.backgroundColor = '#2ecc71'; 
                    yesButton.style.color = 'white';
                    yesButton.style.padding = '5px 10px';
                    yesButton.style.fontSize = '0.9em';
                    yesButton.style.border = 'none';
                    yesButton.style.borderRadius = '3px';
                    yesButton.style.marginRight = '5px';

                    const noButton = document.createElement('button');
                    noButton.textContent = 'No';
                    noButton.style.backgroundColor = '#e74c3c'; 
                    noButton.style.color = 'white';
                    noButton.style.padding = '5px 10px';
                    noButton.style.fontSize = '0.9em';
                    noButton.style.border = 'none';
                    noButton.style.borderRadius = '3px';

                    confirmationContainer.appendChild(questionText);
                    confirmationContainer.appendChild(yesButton);
                    confirmationContainer.appendChild(noButton);

                    originalButton.style.display = 'none';
                    // Insert confirmation container next to the original button's spot
                    parent.insertBefore(confirmationContainer, originalButton.nextSibling);

                    yesButton.onclick = () => {
                        handleClearAllPublicLinks(); // Shows messages in publicLinksMsg
                        if (parent.contains(confirmationContainer)) { // Check if still there
                           parent.removeChild(confirmationContainer);
                        }
                        originalButton.style.display = 'inline-block'; // Restore original button
                    };

                    noButton.onclick = () => {
                        if (parent.contains(confirmationContainer)) { // Check if still there
                           parent.removeChild(confirmationContainer);
                        }
                        originalButton.style.display = 'inline-block'; // Restore original button
                        showMessage('publicLinksMsg', '', true); // Clear any previous messages
                    };
                }

                function showInlineDeleteConfirmation(username, originalButtonElement) {
                    if (!username || !originalButtonElement) return;
                    
                    const parentCell = originalButtonElement.parentElement;
                    if (!parentCell) return;

                    // Hide original delete button
                    originalButtonElement.style.display = 'none';

                    const noButton = document.createElement('button');
                    noButton.textContent = 'No';
                    noButton.style.backgroundColor = '#e74c3c'; // Red
                    noButton.style.color = 'white';
                    noButton.style.padding = '5px 10px';
                    noButton.style.fontSize = '0.9em';
                    noButton.style.border = 'none';
                    noButton.style.borderRadius = '3px';
                    noButton.style.marginRight = '5px';
                    noButton.onclick = () => {
                        parentCell.removeChild(noButton);
                        parentCell.removeChild(yesButton);
                        originalButtonElement.style.display = 'inline-block'; // Or original display value
                    };

                    const yesButton = document.createElement('button');
                    yesButton.textContent = 'Yes';
                    yesButton.style.backgroundColor = '#2ecc71'; // Green
                    yesButton.style.color = 'white';
                    yesButton.style.padding = '5px 10px';
                    yesButton.style.fontSize = '0.9em';
                    yesButton.style.border = 'none';
                    yesButton.style.borderRadius = '3px';
                    yesButton.onclick = () => {
                        handleAdminDeleteUser(username); // Proceed with deletion
                        // No need to remove yes/no here, list refresh will do it, or error shown
                        // parentCell.removeChild(noButton);
                        // parentCell.removeChild(yesButton);
                        // originalButtonElement.style.display = 'inline-block'; // Not needed if list refreshes
                    };
                    
                    // Append new buttons - insert before the original button if it were visible
                    // Or simply append if it's easier and layout allows
                    parentCell.appendChild(noButton);
                    parentCell.appendChild(yesButton);
                }

                document.addEventListener('DOMContentLoaded', function() {
                    currentToken = getCookie('token'); currentUserRole = getCookie('role'); currentUsername = getCookie('username');
                    const containerDiv = document.getElementById('containerDiv'); 
                    const mainFileSection = document.getElementById('fileSection');
                    const loginSection = document.getElementById('loginSection');

                    if (currentToken) {
                        // Initial setup: show main file section view
                        showMainFileSectionView();
                        document.getElementById('uploadTokenField').value = currentToken;
                        if (currentUserRole === 'admin') { 
                            document.getElementById('adminMenuBtn').style.display = 'block'; 
                            document.getElementById('addRootDirTokenField').value = currentToken; 
                            document.getElementById('credsTokenField').value = currentToken; 
                        } else { 
                            document.getElementById('adminMenuBtn').style.display = 'none'; 
                        }
                        fetch('/get_current_root_dirs?token=' + currentToken)
                            .then(r => r.ok ? r.json() : Promise.resolve([])) // Ensure it resolves to an array on error
                            .then(r => { allConfiguredRootDirs = r || []; })
                            .catch(() => allConfiguredRootDirs = []);
                    } else { 
                        if(loginSection) loginSection.style.display = 'block'; 
                        if(mainFileSection) mainFileSection.style.display = 'none'; 
                        if(containerDiv) containerDiv.style.display = 'block'; // Ensure container (for login) is visible
                         // Hide other pages if not logged in
                        if(document.getElementById('filesPage')) document.getElementById('filesPage').style.display = 'none';
                        if(document.getElementById('manageUsersPage')) document.getElementById('manageUsersPage').style.display = 'none';
                        if(document.getElementById('adminSettingsPage')) document.getElementById('adminSettingsPage').style.display = 'none';
                        if(document.getElementById('rootSelectionPage')) document.getElementById('rootSelectionPage').style.display = 'none';
                    }

                    document.getElementById('logoutBtn').addEventListener('click', logout);
                    document.getElementById('viewFilesBtn').addEventListener('click', () => { displayRootSelectionModal(); });
                    document.getElementById('cancelRootSelectionBtn').addEventListener('click', () => { document.getElementById('rootSelectionPage').style.display = 'none'; });
                    
                    document.getElementById('backToMainBtn').addEventListener('click', () => { 
                        // This button is on the #filesPage, so go back to the main file section view
                        showMainFileSectionView();
                        currentSelectedRootDirPath = null; 
                    });
                    document.getElementById('uploadForm').addEventListener('submit', uploadFile);
                    document.getElementById('fileListPage').addEventListener('click', function(e) {
                        const folderLink = e.target.closest('.folder-link');
                        const downloadBtn = e.target.closest('.download-btn');
                        const publicLinkBtn = e.target.closest('.public-link-btn');

                        if (folderLink) { 
                            e.preventDefault(); 
                            refreshListing(folderLink.dataset.path); 
                        } else if (downloadBtn) { 
                            downloadFile(downloadBtn.dataset.filename); 
                        } else if (publicLinkBtn) { 
                            getPublicLink(publicLinkBtn.dataset.filename, publicLinkBtn); 
                        }
                    });
                    document.getElementById('fileSearchBtn').addEventListener('click', () => refreshListing(currentRelativePath));
                    document.getElementById('fileSearchInput').addEventListener('keypress', (e) => { if (e.key === 'Enter') { e.preventDefault(); refreshListing(currentRelativePath); }});
                    document.getElementById('fileSearchClearBtn').addEventListener('click', () => { document.getElementById('fileSearchInput').value = ''; refreshListing(currentRelativePath, ''); });
                    if (currentUserRole === 'admin') { /* Admin Listeners from Phase 1 & original */ 
                        document.getElementById('adminMenuBtn').addEventListener('click', () => document.getElementById('adminMenuDropdown').classList.toggle('show'));
                        
                        document.getElementById('adminSettingsBtn').addEventListener('click', () => { 
                            showAdminSettingsPage();
                            document.getElementById('adminMenuDropdown').classList.remove('show'); 
                        });
                        document.getElementById('backToAdminBtn').addEventListener('click', () => { 
                            showMainFileSectionView();
                        });
                        
                        document.getElementById('addRootDirForm').addEventListener('submit', handleAddRootDir);
                        
                        const changeCredsForm = document.getElementById('changeCredsForm');
                        if (changeCredsForm) {
                            changeCredsForm.addEventListener('submit', function(e) {
                                // Assuming standard POST for now. If AJAX, preventDefault and add logic.
                                showMessage('credsMsg', 'Submitting...', true); // Provide feedback
                                console.log('Change creds form submitted');
                            });
                        }
                        
                        document.getElementById('manageUsersBtn').addEventListener('click', () => { 
                            showManageUsersPage(); 
                            document.getElementById('adminMenuDropdown').classList.remove('show'); 
                        });
                        document.getElementById('backToMainFromUsersBtn').addEventListener('click', () => { 
                            showMainFileSectionView();
                        });
                        document.getElementById('adminCreateUserForm').addEventListener('submit', handleAdminCreateUser);
                        document.getElementById('clearAllPublicLinksBtn').addEventListener('click', function(event) {
                            showClearLinksConfirmation(event.target); // Pass the button element
                        });
                     }

                    // Populate upload target root dir select
                    const uploadTargetRootDirSelect = document.getElementById('uploadTargetRootDirSelect');
                    if (currentToken && uploadTargetRootDirSelect) {
                        // Use allConfiguredRootDirs if already populated and not empty
                        if (allConfiguredRootDirs && allConfiguredRootDirs.length > 0) {
                            populateUploadTargetDropdown(allConfiguredRootDirs);
                        } else {
                            // Otherwise, fetch them specifically for the dropdown
                            fetch('/get_current_root_dirs?token=' + currentToken)
                                .then(r => r.ok ? r.json() : Promise.resolve([]))
                                .then(dirs => {
                                    allConfiguredRootDirs = dirs || []; // Update global too
                                    populateUploadTargetDropdown(allConfiguredRootDirs);
                                })
                                .catch(() => populateUploadTargetDropdown([])); // Handle fetch error
                        }
                    }

                    // Logic for custom file input
                    const actualUploadInput = document.getElementById('actualUploadInput');
                    const customBrowseBtn = document.getElementById('customBrowseBtn');
                    const fileNameDisplay = document.getElementById('fileNameDisplay');

                    if (customBrowseBtn && actualUploadInput && fileNameDisplay) {
                        customBrowseBtn.addEventListener('click', function() {
                            actualUploadInput.click();
                        });

                        actualUploadInput.addEventListener('change', function() {
                            if (actualUploadInput.files.length > 0) {
                                fileNameDisplay.textContent = actualUploadInput.files[0].name;
                                fileNameDisplay.style.fontStyle = 'normal';
                                fileNameDisplay.style.color = '#fff'; // Brighter color for filename
                            } else {
                                fileNameDisplay.textContent = 'No file selected.';
                                fileNameDisplay.style.fontStyle = 'italic';
                                fileNameDisplay.style.color = '#ccc'; // Dim color for placeholder
                            }
                        });
                    }
                });

                function fetchAndRenderPublicLinks(adminSettingsElement) {
                    console.log('[BINGLEHTTP] fetchAndRenderPublicLinks called.');
                    if (!adminSettingsElement) {
                        console.error('[BINGLEHTTP] fetchAndRenderPublicLinks: adminSettingsElement is null or undefined.');
                        const publicLinksMsg = document.getElementById('publicLinksMsg');
                        if (publicLinksMsg) {
                            publicLinksMsg.textContent = 'Error: Admin settings element not found. Cannot display public links.';
                            publicLinksMsg.style.color = 'red';
                        }
                        return;
                    }
                    const container = adminSettingsElement.querySelector('#currentPublicLinksContainer');
                    if (!container) {
                        console.error('[BINGLEHTTP] fetchAndRenderPublicLinks: Container #currentPublicLinksContainer NOT FOUND within adminSettingsElement. Admin Element:', adminSettingsElement);
                        const publicLinksMsg = adminSettingsElement.querySelector('#publicLinksMsg'); // Try to find msg area within admin element
                        if (publicLinksMsg) {
                            publicLinksMsg.innerHTML = 'Error: Public links display area (<code style="font-family: monospace;">#currentPublicLinksContainer</code>) not found.';
                            publicLinksMsg.style.color = 'red';
                        } else {
                            // Fallback if publicLinksMsg is also not found for some reason
                            alert("Error: Public links display area not found. Cannot display public links.");
                        }
                        return;
                    }
                    // Clear previous error messages if any
                    const publicLinksMsg = adminSettingsElement.querySelector('#publicLinksMsg');
                    if (publicLinksMsg) publicLinksMsg.textContent = '';


                    fetch('/admin/get_all_public_links?token=' + currentToken) // Reverted to query parameter
                    .then(response => {
                        if (!response.ok) {
                            throw new Error('Failed to fetch public links. Status: ' + response.status);
                        }
                        return response.json();
                    })
                    .then(data => {
                        console.log('[BINGLEHTTP] Public links data:', data);
                        if (data.error) {
                            throw new Error(data.error);
                        }
                        container.innerHTML = ''; // Clear previous content

                        if (Object.keys(data).length === 0) { // Changed data.public_links to data
                            container.innerHTML = '<p>No public links have been created yet.</p>';
                            return;
                        }

                        const table = document.createElement('table');
                        table.className = 'user-table'; // Reuse user table styling
                        const thead = document.createElement('thead');
                        thead.innerHTML = `
                            <tr>
                                <th>File Path</th>
                                <th>Link Key (click to copy full URL)</th>
                                <th>Actions</th>
                            </tr>
                        `;
                        table.appendChild(thead);
                        const tbody = document.createElement('tbody');

                        for (const compositeKey in data) { // Changed data.public_links to data
                            const linkKey = data[compositeKey]; // Changed linkData = data.public_links[compositeKey] to linkKey = data[compositeKey]
                            const [rootDir, ...filePathParts] = compositeKey.split('|');
                            const relativeFilePath = filePathParts.join('|');

                            const tr = document.createElement('tr');
                            
                            const pathTd = document.createElement('td');
                            pathTd.textContent = relativeFilePath;
                            pathTd.title = `Root: ${rootDir}`;
                            tr.appendChild(pathTd);

                            const linkKeyTd = document.createElement('td');
                            const linkAnchor = document.createElement('a'); // Changed from span to a
                            linkAnchor.textContent = `...${linkKey.substring(0,8)}...`;
                            linkAnchor.href = `${window.location.origin}/public/${encodeURIComponent(rootDir)}/${encodeURIComponent(relativeFilePath)}?key=${linkKey}`; // Set href to full URL
                            linkAnchor.title = 'Right-click and copy link address'; // Updated title
                            linkAnchor.target = '_blank'; // Added to open in new tab
                            linkAnchor.style.cursor = 'pointer'; // Optional: keep pointer cursor, or let browser default for links
                            linkAnchor.style.textDecoration = 'underline';
                            linkAnchor.style.color = '#90caf9'; // A link-like color
                            // linkAnchor.onclick = () => { // REMOVED onclick clipboard logic
                            //     navigator.clipboard.writeText(publicUrl).then(() => {
                            //         const originalText = linkKeySpan.textContent;
                            //         linkKeySpan.textContent = 'Copied!';
                            //         setTimeout(() => { linkKeySpan.textContent = originalText; }, 2000);
                            //     }).catch(err => {
                            //         console.error('Failed to copy public link: ', err);
                            //         alert('Failed to copy link. See console for details.');
                            //     });
                            // };
                            linkKeyTd.appendChild(linkAnchor);
                            tr.appendChild(linkKeyTd);
                            
                            const actionsTd = document.createElement('td');
                            const deleteBtn = document.createElement('button');
                            deleteBtn.textContent = 'Delete';
                            deleteBtn.className = 'delete-user-btn'; // Reuse styling
                            deleteBtn.onclick = () => showDeleteSinglePublicLinkConfirmation(compositeKey, deleteBtn, adminSettingsElement); // Removed linkKey
                            actionsTd.appendChild(deleteBtn);
                            tr.appendChild(actionsTd);

                            tbody.appendChild(tr);
                        }
                        table.appendChild(tbody);
                        container.appendChild(table);
                    })
                    .catch(error => {
                        console.error('[BINGLEHTTP] Error fetching or rendering public links:', error);
                        container.innerHTML = `<p style="color:red;">Error loading public links: ${error.message}</p>`;
                    });
                }

                function showDeleteSinglePublicLinkConfirmation(compositeKey, originalButton, adminSettingsElement) { // Removed linkKey
                    console.log('[BINGLEHTTP] showDeleteSinglePublicLinkConfirmation for key:', compositeKey);
                    originalButton.style.display = 'none';
                    const confirmationDiv = document.createElement('div');
                    confirmationDiv.style.display = 'inline-block';

                    const confirmationText = document.createElement('span');
                    confirmationText.textContent = 'Sure? ';
                    confirmationText.style.color = '#e74c3c'; // Red color for emphasis
                    confirmationDiv.appendChild(confirmationText);

                    const yesButton = document.createElement('button');
                    yesButton.textContent = 'Yes';
                    yesButton.className = 'confirm-action-btn';
                    yesButton.onclick = () => handleDeleteSinglePublicLink(compositeKey, confirmationDiv, adminSettingsElement); // Removed linkKey

                    const noButton = document.createElement('button');
                    noButton.textContent = 'No';
                    noButton.className = 'cancel-action-btn';
                    noButton.onclick = () => {
                        confirmationDiv.remove();
                        originalButton.style.display = 'inline-block';
                    };

                    confirmationDiv.appendChild(yesButton);
                    confirmationDiv.appendChild(noButton);
                    originalButton.parentNode.insertBefore(confirmationDiv, originalButton.nextSibling);
                }

                function handleDeleteSinglePublicLink(compositeKey, confirmationElement, adminSettingsElement) { // Removed linkKey
                    console.log(`[BINGLEHTTP] Attempting to delete public link with compositeKey: ${compositeKey}`);
                    const publicLinksMsg = adminSettingsElement.querySelector('#publicLinksMsg');

                    const params = new URLSearchParams(); // Create URLSearchParams
                    params.append('token', currentToken);    // Add token
                    params.append('composite_key', compositeKey); // Add composite_key

                    fetch('/admin/delete_public_link', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded' // Set correct Content-Type
                        },
                        body: params // Use URLSearchParams as body
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            console.log('[BINGLEHTTP] Successfully deleted public link:', compositeKey);
                            if (publicLinksMsg) {
                                publicLinksMsg.textContent = data.message || 'Public link deleted successfully.';
                                publicLinksMsg.style.color = 'green';
                            }
                            fetchAndRenderPublicLinks(adminSettingsElement); // Refresh the list using passed adminSettingsElement
                        } else {
                            console.error('[BINGLEHTTP] Error deleting public link:', data.error);
                            if (publicLinksMsg) {
                                publicLinksMsg.textContent = 'Error: ' + (data.error || 'Failed to delete public link.');
                                publicLinksMsg.style.color = 'red';
                            }
                        }
                    })
                    .catch(error => {
                        console.error('[BINGLEHTTP] Network or server error deleting public link:', error);
                        if (publicLinksMsg) {
                            publicLinksMsg.textContent = 'Error: Could not connect to server to delete public link.';
                            publicLinksMsg.style.color = 'red';
                        }
                    })
                    .finally(() => {
                        if (confirmationElement) { // Remove the Yes/No confirmation
                            const originalButton = confirmationElement.previousSibling;
                            if (originalButton && originalButton.style.display === 'none') { // Check if it was the button we hid
                                 originalButton.style.display = 'inline-block'; // Show original button again if needed (e.g. on error if list doesn't refresh)
                            }
                            confirmationElement.remove();
                        }
                         // Clear message after a few seconds
                        setTimeout(() => {
                            if (publicLinksMsg) publicLinksMsg.textContent = '';
                        }, 5000);
                    });
                }

                function populateUploadTargetDropdown(dirs) { // New helper function
                    const selectEl = document.getElementById('uploadTargetRootDirSelect');
                    if (!selectEl) return;
                    selectEl.innerHTML = ''; // Clear existing options
                    if (dirs && dirs.length > 0) {
                        dirs.forEach(dirPath => {
                            const option = document.createElement('option');
                            option.value = dirPath;
                            let displayName = dirPath.split(/[\\/]/).pop() || dirPath;
                            displayName = displayName.length > 40 ? ('... ' + displayName.slice(-35)) : displayName;
                            option.textContent = displayName + (dirPath.length > displayName.length ? ` (${dirPath.substring(0,30)}...)` : '');
                            selectEl.appendChild(option);
                        });
                         // Try to set based on currentSelectedRootDirPath if it exists
                        if (currentSelectedRootDirPath && dirs.includes(currentSelectedRootDirPath)) {
                            selectEl.value = currentSelectedRootDirPath;
                        }
                    } else {
                        const option = document.createElement('option');
                        option.textContent = 'No root directories configured';
                        option.disabled = true;
                        selectEl.appendChild(option);
                    }
                }
            </script>
        ''')

def run(server_class=ThreadingHTTPServer, handler_class=SecureHTTPRequestHandler):
    global ROOT_DIRECTORIES
    ROOT_DIRECTORIES = load_root_directories() # Ensure loaded
    
    if not ROOT_DIRECTORIES: # Should be handled by load_root_directories
        print("CRITICAL: No root directories loaded or defined. Defaulting to ['uploads'] for safety.")
        ROOT_DIRECTORIES = ['uploads']
        save_root_directories(ROOT_DIRECTORIES)

    for r_dir in ROOT_DIRECTORIES:
        if not os.path.exists(r_dir):
            try:
                print(f"Attempting to create configured root directory: {r_dir}")
                os.makedirs(r_dir)
                print(f"Successfully created root directory: {r_dir}")
            except OSError as e:
                print(f"ERROR: Could not create configured root directory {r_dir}: {e}")
                # Consider if the server should fail to start if a configured root is not creatable.
                # For now, it will continue, and operations on that root might fail.
        
    server_address = ('0.0.0.0', 6799)
    httpd = server_class(server_address, handler_class)
    print(f'Starting secure server on port 6799 with root directories: {ROOT_DIRECTORIES}...')
    httpd.serve_forever()

def parse_multipart(body, content_type):
    """
    Parses multipart/form-data from the request body.
    Returns a dict of fields and a dict of files (with filename and content).
    """
    # Extract boundary
    match = re.search(r'boundary=([^;]+)', content_type)
    if not match:
        return {}, {}
    boundary = match.group(1)
    if boundary.startswith('"') and boundary.endswith('"'):
        boundary = boundary[1:-1]
    boundary = boundary.encode()
    # Split body by boundary
    parts = body.split(b'--' + boundary)
    fields = {}
    files = {}
    for part in parts:
        part = part.strip()
        if not part or part == b'--':
            continue
        header, _, value = part.partition(b'\r\n\r\n')
        if not value:
            continue
        header_lines = header.decode(errors='ignore').split('\r\n')
        disposition = next((h for h in header_lines if h.lower().startswith('content-disposition')), None)
        if not disposition:
            continue
        disp_match = re.search(r'name="([^"]+)"', disposition)
        if not disp_match:
            continue
        name = disp_match.group(1)
        filename_match = re.search(r'filename="([^"]*)"', disposition)
        if filename_match:
            filename = filename_match.group(1)
            files[name] = {'filename': filename, 'content': value.rstrip(b'\r\n')}
        else:
            fields[name] = value.decode(errors='ignore').rstrip('\r\n')
    return fields, files

if __name__ == '__main__':
    run()
