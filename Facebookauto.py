import sys
import os
import json
import threading
import time
import webbrowser
from urllib.parse import urlencode
from typing import Any, Dict, List

from PySide6 import QtCore, QtWidgets, QtGui
from flask import Flask, request, render_template_string
import requests
from PIL import Image
from PIL.ImageQt import ImageQt

# ---------- Config ----------
OAUTH_HOST = "127.0.0.1"
OAUTH_PORT = 5000
OAUTH_PATH = "/callback"
REDIRECT_URI = f"http://{OAUTH_HOST}:{OAUTH_PORT}{OAUTH_PATH}"
CREDENTIALS_FILE = "credentials.json"
FB_GRAPH_VERSION = "v16.0"   # adjust if needed
MAX_POSTS = 10

# ---------- Flask OAuth receiver ----------
flask_app = Flask(__name__)
oauth_state = {"code": None, "error": None, "message": "", "processed": False}

REDIRECT_HTML = """
<!doctype html><title>OAuth Received</title>
<h3>Facebook OAuth response received</h3>
<p>{{message}}</p>
<p>You can now close this window and return to the application.</p>
"""

@flask_app.route(OAUTH_PATH, methods=["GET"])
def callback():
    code = request.args.get("code")
    error = request.args.get("error")
    error_desc = request.args.get("error_description") or ""
    if code:
        oauth_state.update({"code": code, "error": None, "message": "Code received", "processed": False})
        return render_template_string(REDIRECT_HTML, message="Authorization code received. Return to the application.")
    else:
        oauth_state.update({"code": None, "error": error or "unknown", "message": f"{error}: {error_desc}", "processed": False})
        return render_template_string(REDIRECT_HTML, message=f"Error: {error}. {error_desc}")

def start_flask_server():
    # run Flask in thread; suppress werkzeug logs
    import logging
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    flask_app.run(host=OAUTH_HOST, port=OAUTH_PORT, debug=False, use_reloader=False)

def ensure_flask_running() -> threading.Thread:
    t = threading.Thread(target=start_flask_server, daemon=True)
    t.start()
    return t

# ---------- Utility: credentials load/save ----------
def load_credentials() -> Dict[str, Any]:
    if os.path.exists(CREDENTIALS_FILE):
        try:
            with open(CREDENTIALS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_credentials(obj: Dict[str, Any]):
    with open(CREDENTIALS_FILE, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)

# ---------- Facebook Graph helpers ----------
def exchange_code_for_short_token(app_id: str, app_secret: str, code: str) -> Dict[str, Any]:
    url = f"https://graph.facebook.com/{FB_GRAPH_VERSION}/oauth/access_token"
    params = {
        "client_id": app_id,
        "redirect_uri": REDIRECT_URI,
        "client_secret": app_secret,
        "code": code
    }
    r = requests.get(url, params=params, timeout=15)
    r.raise_for_status()
    return r.json()

def exchange_short_for_long(app_id: str, app_secret: str, short_token: str) -> Dict[str, Any]:
    url = f"https://graph.facebook.com/{FB_GRAPH_VERSION}/oauth/access_token"
    params = {
        "grant_type": "fb_exchange_token",
        "client_id": app_id,
        "client_secret": app_secret,
        "fb_exchange_token": short_token
    }
    r = requests.get(url, params=params, timeout=15)
    r.raise_for_status()
    return r.json()

def fetch_managed_pages(long_user_token: str) -> Dict[str, Any]:
    url = f"https://graph.facebook.com/{FB_GRAPH_VERSION}/me/accounts"
    params = {"access_token": long_user_token}
    r = requests.get(url, params=params, timeout=15)
    r.raise_for_status()
    return r.json()

# ---------- OpenAI JSON processing ----------
try:
    import openai
except Exception:
    openai = None

def validate_llm_json(text: str) -> Dict[str, Any]:
    """
    Extract JSON object from text and validate expected keys.
    Expected schema: {"caption": "...", "hashtags": ["#x",...], "tone": "..."}
    """
    import re, json as _json
    text = text.strip()
    # remove code fences if present
    if text.startswith("```") and text.endswith("```"):
        text = "\n".join(text.splitlines()[1:-1])
    m1 = text.find("{")
    m2 = text.rfind("}")
    if m1 >= 0 and m2 >= 0 and m2 > m1:
        candidate = text[m1:m2+1]
    else:
        candidate = text
    try:
        data = _json.loads(candidate)
    except Exception as e:
        raise ValueError(f"LLM output not valid JSON: {e}")
    if "caption" not in data:
        raise ValueError("JSON missing 'caption' field")
    tags = data.get("hashtags", [])
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split() if t.strip()]
    if not isinstance(tags, list):
        raise ValueError("'hashtags' must be list or string")
    data["hashtags"] = tags
    return data

def call_openai_for_post(prompt: str, creds: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calls OpenAI ChatCompletion, requesting strict JSON. Returns parsed dict.
    Requires openai package and creds['openai_api_key'] in credentials.json to be set.
    """
    if openai is None:
        raise RuntimeError("openai package not installed (pip install openai)")
    key = creds.get("openai_api_key")
    if not key:
        raise RuntimeError("OpenAI API key not set in credentials.json")
    openai.api_key = key
    system = "You must return ONLY valid JSON (no commentary). Schema: {\"caption\": \"...\", \"hashtags\": [\"#a\"], \"tone\": \"optional\"}"
    user_prompt = prompt + "\n\nReturn ONLY valid JSON as described above."
    # Use ChatCompletion API (adapt model name to what you have)
    resp = openai.ChatCompletion.create(
        model="gpt-4o-mini",  # change to a model you have access to
        messages=[{"role": "system", "content": system}, {"role": "user", "content": user_prompt}],
        max_tokens=300,
        temperature=0.6
    )
    text = resp["choices"][0]["message"]["content"]
    return validate_llm_json(text)

# ---------- Facebook posting ----------
def fb_post_photo(dest_id: str, image_path: str, caption: str, page_token: str) -> Dict[str, Any]:
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Image not found: {image_path}")
    url = f"https://graph.facebook.com/{FB_GRAPH_VERSION}/{dest_id}/photos"
    files = {"source": open(image_path, "rb")}
    data = {"caption": caption, "access_token": page_token}
    r = requests.post(url, files=files, data=data, timeout=30)
    try:
        return r.json()
    finally:
        files["source"].close()

def fb_post_feed(dest_id: str, message: str, page_token: str) -> Dict[str, Any]:
    url = f"https://graph.facebook.com/{FB_GRAPH_VERSION}/{dest_id}/feed"
    data = {"message": message, "access_token": page_token}
    r = requests.post(url, data=data, timeout=30)
    return r.json()

# ---------- GUI components ----------
class PostRowWidget(QtWidgets.QWidget):
    def __init__(self, index:int, parent=None):
        super().__init__(parent)
        self.index = index
        self.setup_ui()

    def setup_ui(self):
        layout = QtWidgets.QHBoxLayout(self)
        left = QtWidgets.QVBoxLayout()
        self.header = QtWidgets.QLineEdit()
        self.header.setPlaceholderText("Header")
        self.content = QtWidgets.QPlainTextEdit()
        self.content.setPlaceholderText("Content")
        self.content.setFixedHeight(80)
        img_h = QtWidgets.QHBoxLayout()
        self.imgpath = QtWidgets.QLineEdit()
        self.imgpath.setPlaceholderText("Image path (optional)")
        self.browse = QtWidgets.QPushButton("Browse")
        self.browse.clicked.connect(self.on_browse)
        img_h.addWidget(self.imgpath)
        img_h.addWidget(self.browse)
        left.addWidget(self.header)
        left.addWidget(self.content)
        left.addLayout(img_h)

        right = QtWidgets.QVBoxLayout()
        self.preview = QtWidgets.QLabel()
        self.preview.setFixedSize(160,90)
        self.preview.setStyleSheet("border:1px solid #ccc;")
        self.preview.setAlignment(QtCore.Qt.AlignCenter)
        self.status = QtWidgets.QLabel("Idle")
        self.status.setWordWrap(True)
        right.addWidget(self.preview)
        right.addWidget(self.status)
        right.addStretch()
        layout.addLayout(left, 4)
        layout.addLayout(right, 1)

    def on_browse(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Choose image", "", "Images (*.png *.jpg *.jpeg *.bmp *.gif)")
        if path:
            self.imgpath.setText(path)
            try:
                img = Image.open(path)
                img.thumbnail((160,90))
                qimg = ImageQt(img.convert("RGBA"))
                pix = QtGui.QPixmap.fromImage(qimg)
                self.preview.setPixmap(pix)
            except Exception:
                self.preview.setText(os.path.basename(path))

    def get_data(self) -> Dict[str,str]:
        return {"header": self.header.text().strip(), "content": self.content.toPlainText().strip(), "image": self.imgpath.text().strip()}

    def set_status(self, text:str, color:str="#000"):
        self.status.setText(text)
        self.status.setStyleSheet(f"color:{color}")

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("FB Poster — PySide6 + OAuth")
        self.resize(1100, 800)
        self.creds = load_credentials()
        self.init_ui()
        self.flask_thread = None

    def init_ui(self):
        central = QtWidgets.QWidget()
        v = QtWidgets.QVBoxLayout(central)


        # Scroll area with post rows
        scroll = QtWidgets.QScrollArea()
        scroll.setWidgetResizable(True)
        content_widget = QtWidgets.QWidget()
        content_layout = QtWidgets.QVBoxLayout(content_widget)

        self.post_rows = []
        for i in range(MAX_POSTS):
            row = PostRowWidget(i)
            content_layout.addWidget(row)
            self.post_rows.append(row)

        content_layout.addStretch()
        scroll.setWidget(content_widget)
        v.addWidget(scroll, stretch=7)


        # App config & OAuth
        cfg = QtWidgets.QGroupBox("Facebook App & OAuth")
        cfg_l = QtWidgets.QGridLayout(cfg)
        cfg_l.addWidget(QtWidgets.QLabel("App ID:"), 0, 0)
        self.app_id_edit = QtWidgets.QLineEdit()
        cfg_l.addWidget(self.app_id_edit, 0, 1)
        cfg_l.addWidget(QtWidgets.QLabel("App Secret:"), 1, 0)
        self.app_secret_edit = QtWidgets.QLineEdit()
        self.app_secret_edit.setEchoMode(QtWidgets.QLineEdit.Password)
        cfg_l.addWidget(self.app_secret_edit, 1, 1)
        self.oauth_btn = QtWidgets.QPushButton("Connect Facebook (OAuth)")
        self.oauth_btn.clicked.connect(self.on_connect_oauth)
        cfg_l.addWidget(self.oauth_btn, 0, 2, 2, 1)
        cfg_l.addWidget(QtWidgets.QLabel(f"Register redirect URI: {REDIRECT_URI}"), 2, 0, 1, 3)
        v.addWidget(cfg)

        # Destinations list
        dest_box = QtWidgets.QGroupBox("Saved Destinations")
        dest_l = QtWidgets.QVBoxLayout(dest_box)
        self.dest_list = QtWidgets.QListWidget()
        dest_l.addWidget(self.dest_list)
        v.addWidget(dest_box)

        # Posts area
        posts_box = QtWidgets.QGroupBox("Posts (up to 10)")
        posts_l = QtWidgets.QVBoxLayout(posts_box)
        self.post_rows = []
        for i in range(MAX_POSTS):
            row = PostRowWidget(i)
            posts_l.addWidget(row)
            self.post_rows.append(row)
        posts_l.addStretch()
        v.addWidget(posts_box, 6)

        # Controls & log
        ctrl = QtWidgets.QHBoxLayout()
        self.load_creds_btn = QtWidgets.QPushButton("Reload credentials.json")
        self.load_creds_btn.clicked.connect(self.reload_creds)
        ctrl.addWidget(self.load_creds_btn)
        ctrl.addStretch()
        self.process_btn = QtWidgets.QPushButton("Process & Post")
        self.process_btn.clicked.connect(self.on_process_post)
        ctrl.addWidget(self.process_btn)
        v.addLayout(ctrl)

        self.log = QtWidgets.QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumHeight(200)
        v.addWidget(self.log)

        self.setCentralWidget(central)
        self.reload_creds()

    def log_msg(self, text:str):
        ts = time.strftime("%H:%M:%S")
        self.log.appendPlainText(f"[{ts}] {text}")

    def reload_creds(self):
        self.creds = load_credentials()
        self.dest_list.clear()
        fb = self.creds.get("facebook", {}) or {}
        dests = fb.get("destinations", [])
        for d in dests:
            name = d.get("name") or ""
            id_ = d.get("id") or ""
            self.dest_list.addItem(f"{name} (id: {id_})")
        # show existing app id if present
        if fb.get("app_id"):
            self.app_id_edit.setText(str(fb.get("app_id")))

    def on_connect_oauth(self):
        app_id = self.app_id_edit.text().strip()
        app_secret = self.app_secret_edit.text().strip()
        if not app_id or not app_secret:
            QtWidgets.QMessageBox.warning(self, "Missing fields", "Please enter App ID and App Secret.")
            return

        # save app id into credentials file (don't save secret)
        creds = load_credentials()
        fbcfg = creds.get("facebook", {})
        fbcfg["app_id"] = app_id
        creds["facebook"] = fbcfg
        save_credentials(creds)
        self.creds = creds
        self.reload_creds()

        # start Flask server if not already
        if not self.flask_thread:
            self.flask_thread = ensure_flask_running()

        # prepare OAuth URL and open browser
        auth_params = {
            "client_id": app_id,
            "redirect_uri": REDIRECT_URI,
            "scope": ",".join([
                "public_profile",
                "pages_manage_posts",
                "pages_read_engagement",
                "pages_show_list",
                "publish_to_groups",          # group publishing (may need review)
                "groups_access_member_info"
            ]),
            "response_type": "code",
            "state": "state123"
        }
        oauth_url = f"https://www.facebook.com/{FB_GRAPH_VERSION}/dialog/oauth?{urlencode(auth_params)}"
        self.log_msg("Opening browser for Facebook OAuth...")
        webbrowser.open(oauth_url)

        # start a worker thread to monitor 'oauth_state' and exchange tokens
        t = threading.Thread(target=self.oauth_exchange_worker, args=(app_id, app_secret), daemon=True)
        t.start()

    def oauth_exchange_worker(self, app_id:str, app_secret:str):
        self.log_msg("Waiting for OAuth callback...")
        waited = 0
        # wait up to 300 seconds
        while waited < 300:
            if oauth_state.get("code") or oauth_state.get("error"):
                break
            time.sleep(0.5)
            waited += 0.5

        if oauth_state.get("error"):
            self.log_msg(f"OAuth error: {oauth_state.get('message')}")
            return

        code = oauth_state.get("code")
        if not code:
            self.log_msg("OAuth timed out.")
            return

        self.log_msg("Authorization code received. Exchanging for token...")
        try:
            short = exchange_code_for_short_token(app_id, app_secret, code)
            short_token = short.get("access_token")
            expires = short.get("expires_in")
            self.log_msg(f"Short token acquired (expires in {expires}s).")
        except Exception as e:
            self.log_msg(f"Failed to get short token: {e}")
            return

        try:
            long_t = exchange_short_for_long(app_id, app_secret, short_token)
            long_token = long_t.get("access_token")
            long_expires = long_t.get("expires_in")
            self.log_msg(f"Long-lived user token acquired (expires in {long_expires}s). Fetching managed pages...")
        except Exception as e:
            self.log_msg(f"Failed to obtain long token: {e}")
            return

        try:
            pages_resp = fetch_managed_pages(long_token)
            pages = pages_resp.get("data", [])
            self.log_msg(f"Found {len(pages)} managed pages.")
        except Exception as e:
            self.log_msg(f"Failed to fetch pages: {e}")
            pages = []

        # Prompt user to select pages in the GUI thread
        QtCore.QMetaObject.invokeMethod(self, "show_pages_dialog", QtCore.Qt.QueuedConnection,
                                        QtCore.Q_ARG(list, pages), QtCore.Q_ARG(str, long_token))

    @QtCore.Slot(list, str)
    def show_pages_dialog(self, pages: List[Dict[str,Any]], long_token: str):
        if not pages:
            QtWidgets.QMessageBox.information(self, "No Pages", "No managed pages were found for this account.")
            # still save long token optionally
            creds = load_credentials()
            fbcfg = creds.get("facebook", {})
            fbcfg["user_long_token"] = long_token
            creds["facebook"] = fbcfg
            save_credentials(creds)
            self.log_msg("Saved long user token to credentials.json (no pages).")
            self.reload_creds()
            return

        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle("Select Pages to Save")
        dlg.resize(1100, 800)
        layout = QtWidgets.QVBoxLayout(dlg)
        label = QtWidgets.QLabel("Select pages to save as posting destinations:")
        layout.addWidget(label)
        scroll = QtWidgets.QScrollArea()
        content = QtWidgets.QWidget()
        v = QtWidgets.QVBoxLayout(content)
        checks = []
        for p in pages:
            cb = QtWidgets.QCheckBox(f"{p.get('name')} (id: {p.get('id')})")
            cb.page = p
            v.addWidget(cb)
            checks.append(cb)
        content.setLayout(v)
        scroll.setWidgetResizable(True)
        scroll.setWidget(content)
        layout.addWidget(scroll)
        btn_h = QtWidgets.QHBoxLayout()
        btn_save = QtWidgets.QPushButton("Save Selected")
        btn_cancel = QtWidgets.QPushButton("Cancel")
        btn_h.addStretch()
        btn_h.addWidget(btn_save)
        btn_h.addWidget(btn_cancel)
        layout.addLayout(btn_h)

        def on_save():
            selected = []
            for cb in checks:
                if cb.isChecked():
                    selected.append(cb.page)
            # store to credentials.json
            creds = load_credentials()
            fbcfg = creds.get("facebook", {})
            fbcfg["app_id"] = self.app_id_edit.text().strip()
            fbcfg["user_long_token"] = long_token
            saved = []
            for p in selected:
                saved.append({
                    "id": p.get("id"),
                    "name": p.get("name"),
                    "access_token": p.get("access_token")
                })
            fbcfg["destinations"] = saved
            creds["facebook"] = fbcfg
            save_credentials(creds)
            self.log_msg(f"Saved {len(saved)} page(s) to {CREDENTIALS_FILE}")
            dlg.accept()
            self.reload_creds()

        def on_cancel():
            dlg.reject()

        btn_save.clicked.connect(on_save)
        btn_cancel.clicked.connect(on_cancel)
        dlg.exec()

    # ---------- Processing & posting ----------
    def on_process_post(self):
        # run in background to keep UI responsive
        t = threading.Thread(target=self.process_and_post_worker, daemon=True)
        t.start()

    def process_and_post_worker(self):
        creds = load_credentials()
        fb = creds.get("facebook", {})
        destinations = fb.get("destinations", [])
        if not destinations:
            self.log_msg("No saved destinations. Use OAuth to connect and save pages first.")
            QtWidgets.QMessageBox.warning(self, "No Destinations", "No saved destinations found in credentials.json")
            return

        # for each post row
        for idx, row in enumerate(self.post_rows):
            data = row.get_data()
            if not (data["header"] or data["content"] or data["image"]):
                row.set_status("Skipped (empty)", "#666")
                continue
            row.set_status("Processing (LLM)...", "#0078D7")
            self.log_msg(f"Processing post #{idx+1}")

            prompt = f"Header: {data['header']}\n\nContent: {data['content']}\n\nMake an engaging Facebook caption and return ONLY valid JSON: {{\"caption\":\"...\",\"hashtags\":[\"#x\"],\"tone\":\"...\"}}"

            llm_result = None
            # try OpenAI if configured
            try:
                llm_result = call_openai_for_post(prompt, creds)
                self.log_msg(f"OpenAI result OK for post #{idx+1}")
            except Exception as e:
                self.log_msg(f"OpenAI processing failed for post #{idx+1}: {e}")
                llm_result = {"caption": (data["header"] + "\n\n" + data["content"]).strip(), "hashtags": []}

            caption = llm_result.get("caption", "").strip()
            hashtags = llm_result.get("hashtags", [])
            final_caption = caption + ("\n\n" + " ".join(hashtags) if hashtags else "")

            # post to each destination
            for dest in destinations:
                dest_id = dest.get("id")
                dest_name = dest.get("name")
                page_token = dest.get("access_token")
                try:
                    row.set_status(f"Posting to {dest_name}...", "#0078D7")
                    if data["image"]:
                        res = fb_post_photo(dest_id, data["image"], final_caption, page_token)
                    else:
                        res = fb_post_feed(dest_id, final_caption, page_token)
                    row.set_status(f"Posted to {dest_name}", "#0a7a0a")
                    self.log_msg(f"Post #{idx+1} -> {dest_name} OK: {res}")
                except Exception as e:
                    row.set_status(f"Failed to post to {dest_name}", "#a85a00")
                    self.log_msg(f"Post #{idx+1} -> {dest_name} ERROR: {e}")

            time.sleep(0.5)  # small delay

        QtWidgets.QMessageBox.information(self, "Done", "Processing complete. Check log for details.")
        self.log_msg("All posting operations complete.")

# ---------- Main ----------
def main():
    app = QtWidgets.QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()