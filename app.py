import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet
from datetime import datetime
from uuid import uuid4

st.set_page_config(page_title="Securely", page_icon="🔐", layout="wide")

DATA_FILE = "vault_data.json"

st.markdown("""
<style>
    .alert {
        padding: 15px;
        border-radius: 5px;
        margin-bottom: 15px;
        border-left: 5px solid;
    }
    .alert-success { background-color: #d4edda; color: #155724; border-color: #28a745; }
    .alert-warning { background-color: #fff3cd; color: #856404; border-color: #ffc107; }
    .alert-error { background-color: #f8d7da; color: #721c24; border-color: #dc3545; }
    .alert-info { background-color: #d1ecf1; color: #0c5460; border-color: #17a2b8; }
</style>
""", unsafe_allow_html=True)

try:
    with open("secret.key", "rb") as key_file:
        KEY = key_file.read()
        cipher = Fernet(KEY)
except FileNotFoundError:
    st.error("🔐 Encryption key not found. Run generate_key.py first.")
    st.stop()

if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as f:
        stored_data = json.load(f)
else:
    stored_data = {}

# ----- Session State -----
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "reauth_required" not in st.session_state:
    st.session_state.reauth_required = False
if "activity_log" not in st.session_state:
    st.session_state.activity_log = []
if "current_page" not in st.session_state:
    st.session_state.current_page = "Home"

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(data_id, passkey):
    entry = stored_data.get(data_id)
    if not entry:
        log_activity("❌ Invalid Data ID")
        return None
    if entry["passkey"] == hash_passkey(passkey):
        try:
            decrypted = cipher.decrypt(entry["encrypted_text"].encode()).decode()
            st.session_state.failed_attempts = 0
            log_activity("✅ Decryption successful")
            return decrypted
        except:
            log_activity("❌ Corrupted data")
            return None
    else:
        st.session_state.failed_attempts += 1
        log_activity("❌ Wrong passkey")
        return None

def log_activity(action):
    time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.session_state.activity_log.append(f"{time} — {action}")

def show_alert(message, type):
    st.markdown(f"<div class='alert alert-{type}'>{message}</div>", unsafe_allow_html=True)

def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump(stored_data, f)

with st.sidebar:
    st.title("🔐 Securely")
    st.markdown("## Navigation")
    menu = ["🏠 Home", "🔒 Store Data", "🔑 Retrieve Data", "👤 Authorization"]
    for item in menu:
        if st.button(item):
            st.session_state.current_page = item
            st.rerun()
    st.markdown("---")
    st.markdown(f"Status: {'🔴 Locked' if st.session_state.reauth_required else '🟢 Active'}")
    st.markdown(f"Attempts: {st.session_state.failed_attempts}/3")

choice = st.session_state.current_page
st.title("🛡️Securely")

if choice == "🏠 Home":
    st.header("Welcome!")
    st.markdown("- Encrypt & store sensitive data securely.")
    st.markdown("- Only you can decrypt it with your passkey.")
    st.markdown("- After 3 wrong attempts, system locks you out.")
    st.subheader("Recent Activity")
    if st.session_state.activity_log:
        for log in reversed(st.session_state.activity_log[-5:]):
            st.markdown(f"- {log}")
    else:
        st.markdown("*No activity yet.*")

elif choice == "🔒 Store Data":
    st.header("Store Encrypted Data")
    data = st.text_area("Enter data to encrypt:")
    passkey = st.text_input("Create a passkey:", type="password")
    confirm = st.text_input("Confirm passkey:", type="password")

    if st.button("Encrypt & Save"):
        if not data:
            show_alert("Please enter some data.", "warning")
        elif not passkey:
            show_alert("Please enter a passkey.", "warning")
        elif passkey != confirm:
            show_alert("Passkeys do not match.", "error")
        else:
            encrypted = encrypt_data(data)
            data_id = str(uuid4())
            stored_data[data_id] = {
                "encrypted_text": encrypted,
                "passkey": hash_passkey(passkey),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            save_data()
            log_activity("📝 Data encrypted and stored")
            show_alert("✅ Data stored successfully!", "success")
            st.code(f"Data ID: {data_id}", language="text")

elif choice == "🔑 Retrieve Data":
    if st.session_state.failed_attempts >= 3 or st.session_state.reauth_required:
        st.session_state.reauth_required = True
        show_alert("🚫 Too many failed attempts. Please authorize.", "error")
    else:
        st.header("Retrieve Encrypted Data")
        data_id = st.text_input("Enter your Data ID:")
        passkey = st.text_input("Enter your passkey:", type="password")

        if st.button("Decrypt"):
            if not data_id or not passkey:
                show_alert("Please fill in both fields.", "warning")
            else:
                decrypted = decrypt_data(data_id, passkey)
                if decrypted:
                    show_alert("✅ Success! Here’s your data:", "success")
                    st.text_area("Decrypted Data", decrypted, height=150)
                else:
                    remaining = 3 - st.session_state.failed_attempts
                    show_alert(f"❌ Decryption failed. Attempts left: {remaining}", "error")
                    if remaining == 0:
                        st.session_state.reauth_required = True
                        st.rerun()

elif choice == "👤 Authorization":
    st.header("Reauthorize Access")
    password = st.text_input("Enter master password:", type="password")

    if st.button("Authorize"):
        if password == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.reauth_required = False
            log_activity("🔓 System reauthorized")
            show_alert("✅ Access restored!", "success")
            st.rerun()
        else:
            show_alert("❌ Wrong master password.", "error")
