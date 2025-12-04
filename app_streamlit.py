import streamlit as st
from crypto_backend import encrypt_data, decrypt_data
import pandas as pd
import tempfile, os, time, hashlib
from io import StringIO
from datetime import datetime

def add_history(action, filename, output_bytes):
    h = hashlib.sha256(output_bytes).hexdigest()[:16]
    st.session_state.history.append({
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "action": action,
        "file": filename,
        "size": len(output_bytes),
        "sha": h
    })

st.set_page_config(page_title="AES-256 Encryptor", layout="centered")
st.title("AES-256 File Encryptor | Decryptor")

# Init History in session
if "history" not in st.session_state:
    st.session_state.history = []

# Mode Select
mode = st.radio("Mode:", ["Encrypt", "Decrypt"])

# Password Input + Confirm Pass.
password = st.text_input("Password", type="password")
confirm = ""

if mode == "Encrypt":
    confirm = st.text_input("Confirm Password", type="password")

# Added new pass strength check
def check_strength(pw):
    if len(pw) < 6:
        return "Weak", "red"
    if len(pw) < 10:
        return "Medium", "orange"
    return "Strong", "green"

# Password Strength Indicator
if password:
    strength, color = check_strength(password)
    st.markdown(f"Password Strength: <span style='color:{color}'><b>{strength}</b></span>", unsafe_allow_html=True)

# Confirm validation
if mode == "Encrypt" and password and confirm:
    if password != confirm:
        st.error("Password and Confirm Password do not match.")
    else:
        st.success("Password matched.")

# File Upload
uploaded = st.file_uploader("Upload File")

# Action Log
log_box = st.empty()

def log(msg):
    log_box.info(msg)

if uploaded and password:
    # ==========================
    # ENCRYPT
    # ==========================
    if mode == "Encrypt":

        # Confirm Required
        if confirm == "" or confirm != password:
            st.warning("Please confirm your passwor.")
            st.stop()

        ext = uploaded.name.lower()
        if not(ext.endswith(".csv") or ext.endswith(".xlsx")):
            st.error("Only CSV or XLSX allowed.")
            st.stop()

        log("Reading file...")

        # Save Temporarily
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(uploaded.read())
            tmp_path = tmp.name

        # Normalize to CSV bytes
        df = pd.read_csv(tmp_path) if ext.endswith(".csv") else pd.read_excel(tmp_path)
        
        raw_bytes = df.to_csv(index=False).encode("utf-8")
        log("Converted to CSV bytes.")

        encrypted_bytes = encrypt_data(raw_bytes, password)
        add_history("Encrypt", uploaded.name, encrypted_bytes)
        log("Data encrypted successfully.")

        # Metadata
        st.subheader("Encryption Metadata")
        st.code(f"""
AES Mode       : AES-256 CBC
KDF            : PBKDF2-HMAC-SHA256
Iterations     : 200,000
Salt           : 16 bytes
IV             : 16 bytes
HMAC           : SHA-256 (32 bytes)
Output Size    : {len(encrypted_bytes)} bytes
        """)

         # Ciphertext preview
        st.subheader("Ciphertext (Hex Preview)")
        st.text(encrypted_bytes.hex()[:120] + "...")

        st.download_button(
            "Download Encrypted File (.enc)",
            data=encrypted_bytes,
            file_name=uploaded.name + ".enc",
            mime="application/octet-stream",
        )

    # ==========================
    # DECRYPT
    # ==========================
    else:
        if not uploaded.name.endswith(".enc"):
            st.error("File must be .enc")
            st.stop()
        else:
            encrypted_bytes = uploaded.read()
            log("Loaded encrypted file.")

            try:
                decrypted_bytes = decrypt_data(encrypted_bytes, password)
                add_history("Decrypt", uploaded.name, decrypted_bytes)
                log("HMAC Verification Success. Password Correct.")

                decoded = decrypted_bytes.decode("utf-8")
                df = pd.read_csv(StringIO(decoded))

                st.subheader("Decryption Preview")
                st.dataframe(df.head())

                st.download_button(
                    "Download Decrypted CSV",
                    data=decoded,
                    file_name="decrypted.csv",
                    mime="text/csv"
                )

            except Exception as e:
                st.error(str(e))
