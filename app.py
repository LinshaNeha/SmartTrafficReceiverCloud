from flask import Flask, request, jsonify, render_template
import json
import base64
import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from datetime import datetime

app = Flask(__name__)

# === File paths ===
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
API_DIR = os.path.join(BASE_DIR, "api")
os.makedirs(API_DIR, exist_ok=True)

QKD_KEY_FILE = os.path.join(API_DIR, "qkd_keys.json")
RECEIVED_TRAFFIC_FILE = os.path.join(API_DIR, "received_traffic.json")
DECRYPTED_TRAFFIC_FILE = os.path.join(API_DIR, "decrypted_traffic.json")
ENCRYPTED_TRAFFIC_FILE = os.path.join(API_DIR, "encrypted_traffic.json")
PASSWORD_FILE = os.path.join(API_DIR, "password.json")
PLAIN_TRAFFIC_FILE = os.path.join(API_DIR, "plain_traffic.json")

# === File setup (AUTO-RESET on restart) ===
def reset_file(path, default_content):
    with open(path, 'w') as f:
        json.dump(default_content, f, indent=4)

# Ensure files exist and initialize defaults
reset_file(QKD_KEY_FILE, {})
reset_file(RECEIVED_TRAFFIC_FILE, [])
reset_file(DECRYPTED_TRAFFIC_FILE, [])
reset_file(ENCRYPTED_TRAFFIC_FILE, [])
reset_file(PLAIN_TRAFFIC_FILE, [])            # <-- ensure plain_traffic file is created

if not os.path.exists(PASSWORD_FILE):
    reset_file(PASSWORD_FILE, {"password_hash": ""})

# === Helpers ===
def get_qkd_key():
    try:
        with open(QKD_KEY_FILE, 'r') as f:
            data = json.load(f)
            return data.get("qkd_key", "")
    except Exception:
        return ""

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def check_password(password: str) -> bool:
    try:
        with open(PASSWORD_FILE, 'r') as f:
            data = json.load(f)
            stored_hash = data.get("password_hash", "")
        return stored_hash != "" and stored_hash == hash_password(password)
    except Exception:
        return False

def now_iso():
    """UTC ISO timestamp used as server 'received_at'"""
    return datetime.utcnow().isoformat() + "Z"

def parse_timestamp_to_dt(ts_str):
    """
    Try to parse a timestamp string to a datetime.
    Accepts ISO format and 'YYYY-MM-DD HH:MM:SS' style.
    Returns a datetime (or datetime.min on failure).
    """
    if not ts_str or not isinstance(ts_str, str):
        return datetime.min
    try:
        # try ISO first
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception:
        try:
            return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
        except Exception:
            return datetime.min

# === Password Routes ===
@app.route("/set_password", methods=["POST"])
def set_password():
    try:
        data = request.json
        password = data.get("password", "")
        if not password:
            return jsonify({"error": "Password cannot be empty"}), 400
        with open(PASSWORD_FILE, 'w') as f:
            json.dump({"password_hash": hash_password(password)}, f, indent=4)
        print("🔑 Password has been set/updated")
        return jsonify({"status": "Password set successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/verify_password", methods=["POST"])
def verify_password():
    try:
        data = request.json
        password = data.get("password", "")
        if check_password(password):
            # ✅ Return success and QKD key for frontend
            return jsonify({"success": True, "key": get_qkd_key()}), 200
        else:
            return jsonify({"success": False, "error": "Invalid password"}), 401
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# === QKD Routes ===
@app.route("/receive_qkd_key", methods=["GET", "POST"])
def receive_qkd_key():
    if request.method == "GET":
        password = request.args.get("password", "")
        if not check_password(password):
            return jsonify({"error": "Unauthorized: Invalid password"}), 401
        try:
            with open(QKD_KEY_FILE, 'r') as f:
                data = json.load(f)
        except Exception:
            data = {}
        return jsonify({"qkd_key": data.get("qkd_key", "")})

    # POST: store QKD key from sender
    try:
        data = request.json
        with open(QKD_KEY_FILE, 'w') as f:
            json.dump(data, f, indent=4)
        print("✅ QKD Key Received:", data.get("qkd_key"))
        return jsonify({"status": "QKD key received"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
# === Check if Password Exists ===
@app.route("/password_exists", methods=["GET"])
def password_exists():
    try:
        with open(PASSWORD_FILE, 'r') as f:
            data = json.load(f)
        exists = data.get("password_hash", "") != ""
        return jsonify({"exists": exists}), 200
    except Exception:
        return jsonify({"exists": False}), 200

@app.route("/get_qkd_status", methods=["GET"])
def get_qkd_status():
    try:
        with open(QKD_KEY_FILE, "r") as f:
            data = json.load(f)
        if data.get("qkd_key") and data["qkd_key"].strip() != "":
            return jsonify({"status": "Active"})
        else:
            return jsonify({"status": "Idle"})
    except Exception:
        return jsonify({"status": "Idle"})

# === Data Routes ===
# NOTE: receive_plain_data should read/write PLAIN_TRAFFIC_FILE (not RECEIVED_TRAFFIC_FILE)
@app.route("/receive_plain_data", methods=["GET", "POST"])
def receive_plain_data():
    if request.method == "GET":
        try:
            with open(PLAIN_TRAFFIC_FILE, 'r') as f:
                return jsonify(json.load(f))
        except json.JSONDecodeError:
            return jsonify([])
        except Exception:
            return jsonify([])

    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data received"}), 400

        # attach server received timestamp
        entry = {"type": "plain", "data": data, "received_at": now_iso()}

        with open(PLAIN_TRAFFIC_FILE, 'r+') as f:
            try:
                logs = json.load(f)
            except json.JSONDecodeError:
                logs = []
            logs.append(entry)
            f.seek(0)
            json.dump(logs, f, indent=4)
            f.truncate()
        return jsonify({"status": "Plain data received", "count": len(logs)}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/receive_encrypted_data", methods=["GET", "POST"])
def receive_encrypted_data():
    if request.method == "GET":
        try:
            with open(ENCRYPTED_TRAFFIC_FILE, 'r') as f:
                return jsonify(json.load(f))
        except json.JSONDecodeError:
            return jsonify([])
        except Exception:
            return jsonify([])

    try:
        json_data = request.get_json()
        if not json_data:
            return jsonify({"error": "No data received"}), 400

        # store encrypted with received_at
        enc_entry = {
            "iv": json_data.get('iv'),
            "ciphertext": json_data.get('ciphertext'),
            "received_at": now_iso()
        }
        with open(ENCRYPTED_TRAFFIC_FILE, 'r+') as f:
            try:
                enc_logs = json.load(f)
            except json.JSONDecodeError:
                enc_logs = []
            enc_logs.append(enc_entry)
            f.seek(0)
            json.dump(enc_logs, f, indent=4)
            f.truncate()

        # attempt decryption (using current QKD key)
        try:
            iv = base64.b64decode(json_data['iv'])
            ciphertext = base64.b64decode(json_data['ciphertext'])
            key = get_qkd_key().encode()[:32]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
        except Exception as e:
            # if decryption fails, still store an entry with raw content + received_at
            parsed_data = {"raw": f"decryption_failed: {str(e)}"}
            with open(DECRYPTED_TRAFFIC_FILE, 'r+') as f:
                try:
                    logs = json.load(f)
                except json.JSONDecodeError:
                    logs = []
                logs.append({"type": "decrypted", "data": parsed_data, "received_at": now_iso()})
                f.seek(0)
                json.dump(logs, f, indent=4)
                f.truncate()
            return jsonify({"error": "Decryption failed", "detail": str(e)}), 400

        # parse decrypted text (best-effort)
        try:
            # try JSON
            parsed_data = json.loads(decrypted.replace("'", '"'))
        except Exception:
            parsed_data = {"raw": decrypted}

        # store decrypted with server received timestamp
        with open(DECRYPTED_TRAFFIC_FILE, 'r+') as f:
            try:
                logs = json.load(f)
            except json.JSONDecodeError:
                logs = []
            logs.append({"type": "decrypted", "data": parsed_data, "received_at": now_iso()})
            f.seek(0)
            json.dump(logs, f, indent=4)
            f.truncate()

        return jsonify({"status": "Encrypted data received"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# === Dashboard & Data API ===
@app.route("/get_traffic_data")
def get_traffic_data():
    try:
        try:
            with open(DECRYPTED_TRAFFIC_FILE, 'r') as f:
                decrypted_data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            decrypted_data = []

        try:
            with open(RECEIVED_TRAFFIC_FILE, 'r') as f:
                received_data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            received_data = []

        return jsonify({"decrypted": decrypted_data, "received": received_data})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get_all_traffic')
def get_all_traffic():
    try:
        # load decrypted
        try:
            with open(DECRYPTED_TRAFFIC_FILE, "r") as f:
                decrypted_data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            decrypted_data = []

        # load received
        try:
            with open(RECEIVED_TRAFFIC_FILE, "r") as f:
                received_data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            received_data = []

        # load plain
        try:
            with open(PLAIN_TRAFFIC_FILE, "r") as f:
                plain_data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            plain_data = []

        # Merge everything
        all_logs = (decrypted_data or []) + (received_data or []) + (plain_data or [])

        # Sorting: prefer server 'received_at' (ensures true arrival order),
        # fallback to payload Timestamp / timestamp field if received_at missing.
        def entry_datetime(e):
            # 1) server-side received_at (preferred)
            ts = e.get("received_at")
            if not ts:
                # maybe inside data
                d = e.get("data", {}) if isinstance(e, dict) else {}
                ts = d.get("received_at") or d.get("Timestamp") or d.get("timestamp")
            return parse_timestamp_to_dt(ts)

        all_logs.sort(key=entry_datetime)  # ascending: oldest → newest

        return jsonify({"all": all_logs})
    except Exception as e:
        return jsonify({"error": str(e), "all": []})

# === Reset API ===
@app.route("/reset", methods=["POST"])
def reset_all():
    reset_file(QKD_KEY_FILE, {})
    reset_file(RECEIVED_TRAFFIC_FILE, [])
    reset_file(DECRYPTED_TRAFFIC_FILE, [])
    reset_file(ENCRYPTED_TRAFFIC_FILE, [])
    reset_file(PLAIN_TRAFFIC_FILE, [])            # reset plain file too
    reset_file(PASSWORD_FILE, {"password_hash": ""})
    return jsonify({"status": "All logs reset"}), 200

# === Secure QKD Key View (with password) ===
@app.route("/view_qkd_key", methods=["POST"])
def view_qkd_key():
    try:
        data = request.json
        password = data.get("password", "")
        if check_password(password):
            return jsonify({"success": True, "key": get_qkd_key()}), 200
        else:
            return jsonify({"success": False, "error": "Invalid password"}), 401
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# === Frontend Pages ===
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/status")
def status():
    return "🚦 Receiver is running"

@app.route("/traffic")
def traffic():
    return render_template("traffic.html")

@app.route("/ids")
def ids():
    return render_template("ids.html")

@app.route("/qkd")
def qkd():
    return render_template("qkd.html")

@app.route("/attack")
def attack():
    return render_template("attack.html")

@app.route("/logs")
def logs():
    return render_template("logs.html")

@app.route("/health")
def health():
    return render_template("health.html")

@app.route("/settings")
def settings():
    return render_template("settings.html")

if __name__ == "__main__":
    app.run(port=5002, debug=True,use_reloader=False)

