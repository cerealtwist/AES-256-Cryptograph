import streamlit as st
from crypto_backend import encrypt_data, decrypt_data
import pandas as pd
import tempfile
import os

st.set_page_config(page_title="AES-256 Encryptor", layout="centered")
st.title("AES-256 File Encryptor | Decryptor")

mode = st.radio("Mode:", ["Encrypt", "Decrypt"])

password = st.text_input("Password", type="password")

uploaded = st.file_uploader("Upload File")

if uploaded and password:
    # ==========================
    # ENCRYPT
    # ==========================
    if mode == "Encrypt":
        ext = uploaded.name.lower()

        if not(ext.endswith(".csv") or ext.endswith(".xlsx")):
            st.error("Only CSV or XLSX allowed.")
        else:
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp.write(uploaded.read())
                tmp_path = tmp.name

            # Normalize to CSV bytes
            if ext.endswith(".csv"):
                df = pd.read_csv(tmp_path)
            else:
                df = pd.read_excel(tmp_path)

            raw_bytes = df.to_csv(index=False).encode("utf-8")

            encrypted_bytes = encrypt_data(raw_bytes, password)

            st.download_button(
                "Download Encrypted File",
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
        else:
            encrypted_bytes = uploaded.read()

            try:
                decrypted_bytes = decrypt_data(encrypted_bytes, password)
                decoded = decrypted_bytes.decode("utf-8")

                # convert to preview
                df = pd.read_csv(pd.io.common.StringIO(decoded))
                st.write("### Preview:")
                st.dataframe(df.head())

                st.download_button(
                    "Download Decrypted CSV",
                    data=decoded,
                    file_name="decrypted.csv",
                    mime="text/csv"
                )

            except Exception as e:
                st.error(str(e))
