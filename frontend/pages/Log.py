import streamlit as st
import pandas as pd
import json

st.set_page_config(page_title="History")

st.title("Encryption / Decryption History")

# Prepare history data
history = st.session_state.get("history", [])

# Empty case
if len(history) == 0:
    st.info("No operations recorded yet.")
    st.stop()

# Convert to DataFrame
df = pd.DataFrame(history)

st.dataframe(df, use_container_width=True)

# Export buttons
csv_data = df.to_csv(index=False).encode("utf-8")
json_data = json.dumps(history, indent=4).encode("utf-8")

st.download_button(
    "Download History (CSV)",
    data=csv_data,
    file_name="history_log.csv",
    mime="text/csv"
)

st.download_button(
    "Download History (JSON)",
    data=json_data,
    file_name="history_log.json",
    mime="application/json"
)

# Reset
if st.button("Reset History"):
    st.session_state.history = []
    st.success("History cleared.")
