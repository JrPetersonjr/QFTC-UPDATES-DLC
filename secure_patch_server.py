#!/usr/bin/env python3
"""
TECHNOMANCER - Secure AI Patch Server with LM Studio Integration
Production-ready patch management with security hardening
"""

from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
from pathlib import Path
from dotenv import load_dotenv
import json
import datetime
import os
import hmac
import hashlib
import secrets
import requests
import subprocess
import tempfile
import re
import difflib
import logging

# ============================================================
# CONFIGURATION & SETUP
# ============================================================

load_dotenv()
app = Flask(__name__)
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
CORS(app, resources={r"/api/*": {"origins": "*"}})


# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
ADMIN_PASSWORD = os.getenv('TECHNOMANCER_ADMIN_PASSWORD', 'default-change-me')
if ADMIN_PASSWORD == 'default-change-me':
    logger.warning("⚠️  WARNING: Using default password! Set TECHNOMANCER_ADMIN_PASSWORD env var")

LM_STUDIO_URL = os.getenv('LM_STUDIO_URL', 'http://localhost:1234/v1')
STORAGE_DIR = Path(os.getenv('PATCH_STORAGE_DIR', './patches'))
DLC_DIR = STORAGE_DIR / "dlc"
SYSTEM_PATCHES_DIR = STORAGE_DIR / "system"
PATCH_LOG = STORAGE_DIR / "patch_log.json"
ADMIN_AUDIT_LOG = STORAGE_DIR / "admin_audit.log"
TEMP_DIR = STORAGE_DIR / "temp"

# Whitelist of patchable files
ALLOWED_PATCH_DIRS = {
    "core.js", "battle.js", "ui.js", "terminals.js", 
    "game.js", "fx.js", "updater.js", "intro.js"
}

# Create directories
for d in [STORAGE_DIR, DLC_DIR, SYSTEM_PATCHES_DIR, TEMP_DIR]:
    d.mkdir(exist_ok=True)

# ============================================================
# SECURITY FUNCTIONS
# ============================================================

def hash_password(password):
    """Hash password for comparison"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_admin_password(password):
    """Verify admin password with timing-safe comparison"""
    try:
        password_hash = hash_password(password)
        stored_hash = hash_password(ADMIN_PASSWORD)
        return hmac.compare_digest(password_hash, stored_hash)
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False

def is_safe_file_path(file_path):
    """Validate file path is in allowed list"""
    basename = os.path.basename(file_path)
    return basename in ALLOWED_PATCH_DIRS and '..' not in file_path

def require_admin(f):
    """Decorator to require admin authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        
        if not auth_header.startswith('Bearer '):
            log_admin_action('auth_failed', {'reason': 'missing_auth_header'})
            return jsonify({"error": "Missing authorization"}), 401
        
        password = auth_header[7:]
        
        if not verify_admin_password(password):
            log_admin_action('auth_failed', {'reason': 'invalid_password', 'ip': request.remote_addr})
            return jsonify({"error": "Invalid credentials"}), 403
        
        log_admin_action('auth_success', {'endpoint': request.path})
        return f(*args, **kwargs)
    
    return decorated_function

def log_admin_action(action, details=None):
    """Log admin actions for audit trail"""
    log_entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "action": action,
        "ip": request.remote_addr,
        "user_agent": request.headers.get('User-Agent', 'Unknown'),
        "details": details or {}
    }
    
    try:
        with open(ADMIN_AUDIT_LOG, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    except Exception as e:
        logger.error(f"Failed to log action: {e}")
    
    return log_entry

# ============================================================
# FILE HANDLING
# ============================================================

def load_patch_log():
    """Load patch history"""
    try:
        if PATCH_LOG.exists():
            with open(PATCH_LOG, 'r') as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load patch log: {e}")
    return []

def save_patch_log(log):
    """Save patch history"""
    try:
        with open(PATCH_LOG, 'w') as f:
            json.dump(log, f, indent=2)
    except Exception as e:
        logger.error(f"Failed to save patch log: {e}")

def generate_patch_diff(original_lines, patched_lines):
    """Generate unified diff for review"""
    diff = difflib.unified_diff(
        original_lines,
        patched_lines,
        lineterm='',
        fromfile='original',
        tofile='patched'
    )
    return '\n'.join(diff)

# ============================================================
# JSON RESPONSE HANDLING
# ============================================================

def extract_json_from_response(text):
    """Safely extract JSON from potentially wrapped LM Studio response"""
    # Try direct parsing first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    
    # Try removing markdown code blocks
    json_match = re.search(r'```(?:json)?\s*(.*?)\s*```', text, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(1))
        except json.JSONDecodeError:
            pass
    
    # Try finding first { and last }
    start = text.find('{')
    end = text.rfind('}')
    if start >= 0 and end > start:
        try:
            return json.loads(text[start:end+1])
        except json.JSONDecodeError:
            pass
    
    raise ValueError("Could not extract valid JSON from response")

# ============================================================
# PATCH APPLICATION
# ============================================================

def apply_changes_to_file(lines, changes):
    """Apply changes with full validation"""
    # Validate all changes first
    for i, change in enumerate(changes):
        line_num = change.get('line', 0)
        change_type = change.get('type', '')
        
        if line_num < 1 or line_num > len(lines) + 1:
            raise ValueError(f"Change {i}: Invalid line number {line_num} (file has {len(lines)} lines)")
        
        if change_type not in ['insert', 'replace', 'delete']:
            raise ValueError(f"Change {i}: Invalid type '{change_type}'")
    
    # Sort in reverse to avoid index shifts
    sorted_changes = sorted(changes, key=lambda x: x.get('line', 0), reverse=True)
    
    for change in sorted_changes:
        change_type = change.get('type')
        line_num = change.get('line')
        
        try:
            if change_type == 'insert':
                content = change.get('content', '')
                lines.insert(line_num - 1, content.rstrip() + '\n')
            
            elif change_type == 'replace':
                if 1 <= line_num <= len(lines):
                    new_content = change.get('new_content', '').strip()
                    original_indent = len(lines[line_num - 1]) - len(lines[line_num - 1].lstrip())
                    lines[line_num - 1] = ' ' * original_indent + new_content + '\n'
            
            elif change_type == 'delete':
                count = change.get('count', 1)
                for _ in range(count):
                    if 1 <= line_num <= len(lines):
                        del lines[line_num - 1]
        except Exception as e:
            raise Exception(f"Error applying change at line {line_num}: {e}")
    
    return lines

def validate_patch_syntax(patched_content, file_type):
    """Validate that patched code is syntactically valid"""
    
    if file_type in ['javascript', 'js']:
        try:
            result = subprocess.run(
                ['node', '--check'],
                input=patched_content,
                capture_output=True,
                timeout=5,
                text=True
            )
            if result.returncode != 0:
                raise ValueError(f"JavaScript syntax error: {result.stderr}")
        except FileNotFoundError:
            logger.info("Node.js not available for validation - skipping JS check")
        except Exception as e:
            raise ValueError(f"JavaScript validation failed: {e}")
    
    elif file_type == 'python':
        try:
            compile(patched_content, '<patched>', 'exec')
        except SyntaxError as e:
            raise ValueError(f"Python syntax error: {e.msg} at line {e.lineno}")
        except Exception as e:
            raise ValueError(f"Python validation failed: {e}")
    
    return True

# ============================================================
# LM STUDIO INTEGRATION
# ============================================================

def check_lm_studio_connection():
    """Check if LM Studio is running"""
    try:
        response = requests.get(f"{LM_STUDIO_URL}/models", timeout=5)
        return response.status_code == 200
    except Exception as e:
        logger.warning(f"LM Studio connection check failed: {e}")
        return False

def generate_patch_with_lm_studio(file_content, file_type, instruction):
    """Use local LM Studio to generate a patch"""
    try:
        prompt = f"""You are an expert code patcher. Analyze the following {file_type} code and generate a patch.

INSTRUCTION: {instruction}

CODE TO PATCH:
```{file_type}
{file_content}
```

Respond with ONLY a valid JSON object (no markdown, no code blocks) with this exact structure:
{{
  "analysis": "Brief analysis of what needs to be changed",
  "changes": [
    {{"type": "insert", "line": <number>, "content": "<code to insert>"}},
    {{"type": "replace", "line": <number>, "new_content": "<replacement code>"}},
    {{"type": "delete", "line": <number>, "count": 1}}
  ],
  "explanation": "Why these changes fix the issue"
}}

IMPORTANT:
- Line numbers are 1-indexed
- For insert: content goes BEFORE the specified line
- For replace: replaces the entire line
- For delete: removes lines starting at that line
- Return ONLY the JSON object, nothing else"""

        response = requests.post(
            f"{LM_STUDIO_URL}/chat/completions",
            json={
                "model": "local-model",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.3,
                "max_tokens": 2000,
                "stream": False
            },
            timeout=60
        )
        
        if response.status_code != 200:
            return {
                "success": False,
                "error": f"LM Studio error: {response.status_code}"
            }
        
        response_data = response.json()
        response_text = response_data['choices'][0]['message']['content'].strip()
        
        # Parse JSON with fallback handling
        patch_data = extract_json_from_response(response_text)
        
        return {
            "success": True,
            "analysis": patch_data.get("analysis", ""),
            "changes": patch_data.get("changes", []),
            "explanation": patch_data.get("explanation", "")
        }
    
    except requests.exceptions.Timeout:
        return {"success": False, "error": "LM Studio timeout (request too large?)"}
    except requests.exceptions.ConnectionError:
        return {"success": False, "error": "Cannot connect to LM Studio on " + LM_STUDIO_URL}
    except ValueError as e:
        return {"success": False, "error": f"JSON parsing error: {str(e)}"}
    except Exception as e:
        logger.error(f"LM Studio generation failed: {e}")
        return {"success": False, "error": f"Generation failed: {str(e)}"}

# ============================================================
# API ENDPOINTS - HEALTH & STATUS
# ============================================================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "ok",
        "lm_studio_connected": check_lm_studio_connection(),
        "timestamp": datetime.datetime.now().isoformat()
    }), 200

@app.route('/api/ai/status', methods=['GET'])
def ai_status():
    """Check LM Studio connection status"""
    connected = check_lm_studio_connection()
    return jsonify({
        "connected": connected,
        "server": LM_STUDIO_URL,
        "message": "✅ LM Studio connected" if connected else "❌ Cannot reach LM Studio"
    }), 200

@app.route('/api/ai/models', methods=['GET'])
@limiter.limit("10 per minute")
@require_admin
def list_models():
    """List available LM Studio models"""
    try:
        response = requests.get(f"{LM_STUDIO_URL}/models", timeout=5)
        if response.ok:
            models = response.json().get('data', [])
            return jsonify({"models": models}), 200
    except Exception as e:
        logger.error(f"Failed to fetch models: {e}")
    
    return jsonify({"models": [], "error": "Could not fetch models"}), 200

# ============================================================
# API ENDPOINTS - PATCH GENERATION & PREVIEW
# ============================================================

@app.route('/api/ai/analyze', methods=['POST'])
@limiter.limit("5 per minute")
@require_admin
def analyze_with_ai():
    """Analyze code and generate patch (preview only, no apply)"""
    try:
        data = request.json
        file_content = data.get('content', '')
        file_type = data.get('type', 'javascript')
        instruction = data.get('instruction', '')
        
        if not file_content or not instruction:
            return jsonify({"error": "Missing content or instruction"}), 400
        
        if len(file_content) > 50000:
            return jsonify({"error": "File too large (max 50KB)"}), 400
        
        result = generate_patch_with_lm_studio(file_content, file_type, instruction)
        return jsonify(result), 200 if result.get('success') else 400
    
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/ai/preview-patch', methods=['POST'])
@limiter.limit("5 per minute")
@require_admin
def preview_patch():
    """Preview patch with diff without applying"""
    try:
        data = request.json
        file_path = data.get('file_path', '')
        changes = data.get('changes', [])
        
        if not file_path or not changes:
            return jsonify({"error": "Missing file_path or changes"}), 400
        
        if not is_safe_file_path(file_path):
            log_admin_action('unsafe_patch_attempt', {'file_path': file_path})
            return jsonify({"error": "File not in allowed patch list"}), 403
        
        # Read original file
        if not os.path.exists(file_path):
            return jsonify({"error": f"File not found: {file_path}"}), 404
        
        with open(file_path, 'r', encoding='utf-8') as f:
            original_lines = f.readlines()
        
        # Generate preview
        try:
            patched_lines = apply_changes_to_file(original_lines.copy(), changes)
            diff = generate_patch_diff(original_lines, patched_lines)
            
            return jsonify({
                "success": True,
                "diff": diff,
                "lines_added": len(patched_lines) - len(original_lines),
                "message": "Preview generated - review diff before applying"
            }), 200
        
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 400
    
    except Exception as e:
        logger.error(f"Preview failed: {e}")
        return jsonify({"error": str(e)}), 500

# ============================================================
# API ENDPOINTS - PATCH APPLICATION & ROLLBACK
# ============================================================

@app.route('/api/ai/apply-patch', methods=['POST'])
@limiter.limit("3 per minute")
@require_admin
def apply_ai_patch():
    """Apply AI-generated patch to a file"""
    try:
        data = request.json
        file_path = data.get('file_path', '')
        changes = data.get('changes', [])
        patch_name = data.get('patch_name', 'AI Generated Patch')
        file_type = data.get('file_type', 'javascript')
        
        if not file_path or not changes:
            return jsonify({"error": "Missing file_path or changes"}), 400
        
        # Validate file path
        if not is_safe_file_path(file_path):
            log_admin_action('unsafe_patch_attempt', {'file_path': file_path})
            return jsonify({"error": "File not in allowed patch list"}), 403
        
        if not os.path.exists(file_path):
            return jsonify({"error": f"File not found: {file_path}"}), 404
        
        # Read original file
        with open(file_path, 'r', encoding='utf-8') as f:
            original_lines = f.readlines()
        
        # Create backup
        backup_path = TEMP_DIR / f"{Path(file_path).name}.{secrets.token_hex(4)}.backup"
        with open(backup_path, 'w', encoding='utf-8') as f:
            f.writelines(original_lines)
        
        try:
            # Apply changes
            patched_lines = apply_changes_to_file(original_lines.copy(), changes)
            
            # Validate syntax
            validate_patch_syntax(''.join(patched_lines), file_type)
            
            # Write patched file
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(patched_lines)
            
            # Create patch record
            patch_id = secrets.token_hex(8)
            patch_data = {
                "id": patch_id,
                "name": patch_name,
                "version": datetime.datetime.now().strftime("%Y%m%d-%H%M%S"),
                "description": f"AI-generated patch for {Path(file_path).name}",
                "changes": changes,
                "file_path": file_path,
                "file_type": file_type,
                "backup": str(backup_path),
                "status": "applied",
                "createdAt": datetime.datetime.now().isoformat(),
                "required": False
            }
            
            patch_file = SYSTEM_PATCHES_DIR / f"{patch_id}.json"
            with open(patch_file, 'w') as f:
                json.dump(patch_data, f, indent=2)
            
            # Log
            log_admin_action('patch_applied', {
                'patch_id': patch_id,
                'file': file_path,
                'changes_count': len(changes)
            })
            
            log = load_patch_log()
            log.append({
                "patch_id": patch_id,
                "file": file_path,
                "status": "success",
                "timestamp": datetime.datetime.now().isoformat()
            })
            save_patch_log(log)
            
            return jsonify({
                "success": True,
                "patch_id": patch_id,
                "message": "✅ Patch applied successfully!",
                "backup": str(backup_path)
            }), 201
        
        except Exception as e:
            logger.error(f"Patch application failed: {e}")
            return jsonify({"success": False, "error": str(e)}), 400
    
    except Exception as e:
        logger.error(f"Apply patch endpoint error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/ai/rollback-patch/<patch_id>', methods=['POST'])
@limiter.limit("5 per minute")
@require_admin
def rollback_patch(patch_id):
    """Rollback a previously applied patch"""
    try:
        patch_file = SYSTEM_PATCHES_DIR / f"{patch_id}.json"
        if not patch_file.exists():
            return jsonify({"error": "Patch not found"}), 404
        
        with open(patch_file) as f:
            patch_data = json.load(f)
        
        backup_path = patch_data.get('backup')
        target_path = patch_data.get('file_path')
        
        if not backup_path or not target_path:
            return jsonify({"error": "Missing backup or target info"}), 400
        
        if not os.path.exists(backup_path):
            return jsonify({"error": "Backup file not found"}), 404
        
        try:
            with open(backup_path, 'r') as f:
                backup_content = f.read()
            with open(target_path, 'w') as f:
                f.write(backup_content)
            
            log_admin_action('patch_rolled_back', {'patch_id': patch_id})
            
            return jsonify({
                "success": True,
                "message": "✅ Patch rolled back successfully!",
                "file": target_path
            }), 200
        
        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return jsonify({"error": str(e)}), 500
    
    except Exception as e:
        logger.error(f"Rollback endpoint error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/ai/audit-log', methods=['GET'])
@limiter.limit("10 per minute")
@require_admin
def get_audit_log():
    """View admin audit log"""
    try:
        entries = []
        if ADMIN_AUDIT_LOG.exists():
            with open(ADMIN_AUDIT_LOG, 'r') as f:
                for line in f:
                    try:
                        entries.append(json.loads(line))
                    except:
                        pass
        
        return jsonify({"entries": entries[-100:]}), 200  # Last 100 entries
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ============================================================
# DASHBOARD UI
# ============================================================

@app.route('/ai-patch', methods=['GET'])
def ai_patch_dashboard():
    """AI Patch Generator Dashboard"""
    return render_template_string(AI_DASHBOARD_HTML)

AI_DASHBOARD_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>TECHNOMANCER - Secure AI Patch Generator</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #0d0d2a; color: #00ff88; font-family: 'Courier New', monospace; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; background: rgba(0,0,10,0.7); border: 2px solid #00ff88; padding: 20px; border-radius: 5px; }
        h1 { text-shadow: 0 0 10px #00ff88; margin-bottom: 10px; border-bottom: 2px solid #00ff88; padding-bottom: 10px; }
        .status-bar { background: #1a1a2e; border: 1px solid #00ff88; padding: 12px; margin-bottom: 20px; display: flex; justify-content: space-between; border-radius: 3px; }
        .status-indicator { display: inline-block; width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; }
        .status-connected { background: #00ff88; }
        .status-disconnected { background: #ff6b6b; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #00ff88; border-radius: 3px; background: rgba(0,0,0,0.3); }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        label { display: block; margin: 10px 0 5px 0; color: #6bbf59; font-weight: bold; }
        input, textarea, select { width: 100%; padding: 10px; margin: 5px 0 15px 0; background: #1a1a2e; color: #00ff88; border: 1px solid #00ff88; border-radius: 3px; font-family: 'Courier New', monospace; }
        button { background: #00ff88; color: #000; border: none; padding: 12px 25px; cursor: pointer; font-weight: bold; border-radius: 3px; margin: 5px 5px 5px 0; transition: all 0.3s; }
        button:hover { background: #00dd77; transform: scale(1.05); }
        button:disabled { background: #666; cursor: not-allowed; }
        .output { background: #000; border: 1px solid #00ff88; padding: 15px; margin: 10px 0; min-height: 80px; max-height: 300px; overflow-y: auto; white-space: pre-wrap; word-wrap: break-word; border-radius: 3px; }
        .error { color: #ff6b6b; border-color: #ff6b6b; }
        .success { color: #8be38b; border-color: #8be38b; }
        .warning { color: #ffaa00; border-color: #ffaa00; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🤖 TECHNOMANCER - SECURE AI PATCH GENERATOR</h1>
        
        <div class="status-bar">
            <div>
                <span class="status-indicator" id="statusIndicator"></span>
                <span id="statusText">Checking...</span>
            </div>
            <button onclick="checkStatus()">🔄 Check Status</button>
        </div>
        
        <div class="section">
            <label>🔐 Admin Password:</label>
            <input type="password" id="adminPassword" placeholder="Enter admin password">
            <button onclick="testAuth()">Test Auth</button>
            <div id="authOutput" class="output" style="display:none;"></div>
        </div>
        
        <div class="grid">
            <div>
                <div class="section">
                    <h2>📝 Code to Patch</h2>
                    <label>File Type:</label>
                    <select id="fileType">
                        <option>javascript</option>
                        <option>python</option>
                        <option>html</option>
                    </select>
                    <label>File Path:</label>
                    <input type="text" id="filePath" placeholder="core.js">
                    <label>Code:</label>
                    <textarea id="codeContent" style="min-height:200px;"></textarea>
                </div>
            </div>
            
            <div>
                <div class="section">
                    <h2>🎯 Instructions</h2>
                    <label>What to fix:</label>
                    <textarea id="instruction" style="min-height:200px;"></textarea>
                    <label>Patch Name:</label>
                    <input type="text" id="patchName" placeholder="Fix typo">
                    <button onclick="analyzeCode()">🤖 Analyze</button>
                </div>
            </div>
        </div>
        
        <div class="section">
            <div id="resultOutput" class="output" style="display:none;"></div>
        </div>
    </div>
    
    <script>
        const API_URL = "/api/ai";
        
        async function checkStatus() {
            try {
                const res = await fetch(`${API_URL}/status`);
                const data = await res.json();
                const ind = document.getElementById("statusIndicator");
                const text = document.getElementById("statusText");
                if (data.connected) {
                    ind.className = "status-indicator status-connected";
                    text.innerHTML = '✅ Connected';
                } else {
                    ind.className = "status-indicator status-disconnected";
                    text.innerHTML = '❌ LM Studio offline';
                }
            } catch (e) {
                document.getElementById("statusIndicator").className = "status-indicator status-disconnected";
                document.getElementById("statusText").innerHTML = '❌ Error';
            }
        }
        
        async function testAuth() {
            const pw = document.getElementById("adminPassword").value;
            if (!pw) { alert("Enter password"); return; }
            try {
                const res = await fetch(`${API_URL}/models`, {
                    headers: { "Authorization": `Bearer ${pw}`, "Content-Type": "application/json" }
                });
                const out = document.getElementById("authOutput");
                out.style.display = "block";
                if (res.ok) {
                    out.textContent = "✅ Auth successful!";
                    out.className = "output success";
                } else {
                    out.textContent = "❌ Auth failed!";
                    out.className = "output error";
                }
            } catch (e) {
                document.getElementById("authOutput").textContent = "❌ Error: " + e.message;
                document.getElementById("authOutput").className = "output error";
                document.getElementById("authOutput").style.display = "block";
            }
        }
        
        async function analyzeCode() {
            const pw = document.getElementById("adminPassword").value;
            const code = document.getElementById("codeContent").value;
            const inst = document.getElementById("instruction").value;
            const type = document.getElementById("fileType").value;
            
            if (!pw || !code || !inst) { alert("Fill all fields"); return; }
            
            try {
                const res = await fetch(`${API_URL}/analyze`, {
                    method: "POST",
                    headers: { "Authorization": `Bearer ${pw}`, "Content-Type": "application/json" },
                    body: JSON.stringify({ content: code, type: type, instruction: inst })
                });
                const data = await res.json();
                const out = document.getElementById("resultOutput");
                out.style.display = "block";
                if (data.success) {
                    out.textContent = "Analysis:\n" + data.analysis + "\n\nExplanation:\n" + data.explanation;
                    out.className = "output success";
                } else {
                    out.textContent = "❌ Error: " + data.error;
                    out.className = "output error";
                }
            } catch (e) {
                const out = document.getElementById("resultOutput");
                out.textContent = "❌ Error: " + e.message;
                out.className = "output error";
                out.style.display = "block";
            }
        }
        
        window.addEventListener('load', checkStatus);
    </script>
</body>
</html>
"""

# ============================================================
# MAIN - START SERVER
# ============================================================

if __name__ == '__main__':
    print("🔥 TECHNOMANCER AI Patch Server starting...")
    print("📊 AI Patch Dashboard: http://localhost:5000/ai-patch")
    print(f"🤖 LM Studio Server: {LM_STUDIO_URL}")
    
    if check_lm_studio_connection():
        print("✅ LM Studio connected!")
    else:
        print("⚠️  LM Studio not detected. Make sure it's running on http://localhost:1234")
    
app.run(
    host="0.0.0.0",
    port=int(os.environ.get("PORT", 5000)),
    debug=False
)
