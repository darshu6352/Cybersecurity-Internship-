import pandas as pd
from collections import Counter
from datetime import datetime
from pathlib import Path
import re

print("=" * 50)
print("       WINDOWS SECURITY LOG ANALYZER")
print("=" * 50)

# Read actual Windows Security Events
file_path = "logs/windows_security_events.csv"

df = pd.read_csv(file_path)
df["Id"] = pd.to_numeric(df["Id"], errors="coerce")

failed_users = []
successful_users = []
new_accounts = []
logout_users = []

def get_account(message, event_id):
    message = str(message)

    # Normalize Windows line breaks
    message = message.replace("\\r\\n", "\n")
    message = message.replace("\r\n", "\n")

    # Find the correct section for each event
    if event_id == 4624 and "New Logon:" in message:
        message = message.split("New Logon:", 1)[1]

    elif event_id == 4625 and "Account For Which Logon Failed:" in message:
        message = message.split(
            "Account For Which Logon Failed:", 1
        )[1]

    elif event_id == 4720 and "New Account:" in message:
        message = message.split("New Account:", 1)[1]

    match = re.search(r"Account Name:\s*([^\n]+)", message)

    if match:
        account = match.group(1).strip()

        if account and account != "-":
            return account

    return "Unknown"

# Analyze Windows events
for _, row in df.iterrows():

    event_id = int(row["Id"]) if pd.notna(row["Id"]) else 0
    message = row["Message"]

    if event_id == 4625:
        failed_users.append(get_account(message, event_id))

    elif event_id == 4624:
        successful_users.append(get_account(message, event_id))

    elif event_id == 4720:
        new_accounts.append(get_account(message, event_id))

    elif event_id == 4634:
        logout_users.append(get_account(message, event_id))

# Count events
failed_count = Counter(failed_users)
success_count = Counter(successful_users)

report = []

report.append("WINDOWS SECURITY LOG ANALYZER")
report.append("=" * 45)
report.append(
    "Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
)
report.append("")

report.append("TOTAL EVENTS ANALYZED: " + str(len(df)))
report.append("SUCCESSFUL LOGINS (4624): " + str(len(successful_users)))
report.append("FAILED LOGINS (4625): " + str(len(failed_users)))
report.append("NEW ACCOUNTS (4720): " + str(len(new_accounts)))
report.append("LOGOUT EVENTS (4634): " + str(len(logout_users)))

report.append("\nSUCCESSFUL LOGIN DETAILS")
for user, count in success_count.items():
    report.append(f"{user}: {count}")

report.append("\nFAILED LOGIN DETAILS")
for user, count in failed_count.items():
    report.append(f"{user}: {count}")

    if count >= 3:
        report.append(
            f"ALERT: {user} has {count} failed login events!"
        )

report.append("\nNEW ACCOUNT DETAILS")
for user in new_accounts:
    report.append("New account event: " + user)

report.append("\nLOGOUT DETAILS")
for user in logout_users:
    report.append(user)

report.append("\nAnalysis Completed.")
report.append(
    "\nNote: 3 or more failed logins are flagged for review. "
    "This does not by itself prove an attack."
)

# Display report
for line in report:
    print(line)

# Save report
Path("reports").mkdir(exist_ok=True)

with open("reports/security_report.txt", "w", encoding="utf-8") as file:
    file.write("\n".join(report))

print("\nReport saved: reports/security_report.txt")
