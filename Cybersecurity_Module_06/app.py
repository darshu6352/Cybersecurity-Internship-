
import streamlit as st
import pandas as pd
from datetime import datetime

st.set_page_config(
    page_title="Windows Security Log Analyzer",
    page_icon="🔐",
    layout="wide"
)

st.title("🔐 Windows Security Log Analyzer")
st.write("A Python-based defensive security monitoring dashboard.")

st.info(
    "Upload a Windows Security Events CSV file. "
    "Required columns: Id and Message."
)

uploaded_file = st.file_uploader(
    "Upload Windows Security CSV",
    type=["csv"]
)

if uploaded_file is not None:
    try:
        df = pd.read_csv(uploaded_file)

        if not {"Id", "Message"}.issubset(df.columns):
            st.error("CSV must contain Id and Message columns.")
        else:
            df["Id"] = pd.to_numeric(df["Id"], errors="coerce")

            success = int((df["Id"] == 4624).sum())
            failed = int((df["Id"] == 4625).sum())
            logout = int((df["Id"] == 4634).sum())
            new_accounts = int((df["Id"] == 4720).sum())

            st.subheader("Security Analysis Results")

            col1, col2, col3, col4, col5 = st.columns(5)

            col1.metric("Total Events", len(df))
            col2.metric("Successful Logins", success)
            col3.metric("Failed Logins", failed)
            col4.metric("New Accounts", new_accounts)
            col5.metric("Logouts", logout)

            st.subheader("Event Summary")

            summary = pd.DataFrame({
                "Event": [
                    "Successful Login (4624)",
                    "Failed Login (4625)",
                    "Logout (4634)",
                    "New Account (4720)"
                ],
                "Count": [
                    success, failed, logout, new_accounts
                ]
            })

            st.bar_chart(summary.set_index("Event"))

            st.subheader("Security Alerts")

            if failed >= 3:
                st.warning(
                    f"Review required: {failed} failed login events detected."
                )
            else:
                st.success(
                    f"{failed} failed login events detected. "
                    "No alert threshold reached."
                )

            report = f"""
WINDOWS SECURITY LOG ANALYZER
Generated: {datetime.now()}

Total Events: {len(df)}
Successful Logins (4624): {success}
Failed Logins (4625): {failed}
New Accounts (4720): {new_accounts}
Logout Events (4634): {logout}

Note: Three or more failed login events are an
indicator for investigation, not proof of an attack.
"""

            st.subheader("Download Security Report")

            st.download_button(
                "Download Report",
                data=report,
                file_name="security_report.txt",
                mime="text/plain"
            )

    except Exception as error:
        st.error(f"Unable to analyze CSV: {error}")

else:
    st.caption("Upload a CSV file to begin security analysis.")

st.divider()
st.caption("Cybersecurity Capstone Project | Darshan Chauhan")

