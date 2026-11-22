# Windows Security Log Analyzer

## Project Overview
Windows Security Log Analyzer is a Python-based defensive cybersecurity project that analyzes Windows Security Event Logs and generates a security report.

## Project Objectives
- Analyze Windows Security Event Logs.
- Identify successful login events.
- Detect failed login attempts.
- Monitor new user account creation.
- Track logout activities.
- Generate a security analysis report.

## Technologies Used
- Python
- Pandas
- Windows 10
- PowerShell
- Git and GitHub

## Windows Event IDs

| Event ID | Description |
|---|---|
| 4624 | Successful Login |
| 4625 | Failed Login |
| 4634 | Logout |
| 4720 | New User Account Created |

## Project Architecture

Windows Security Logs → Python Log Analyzer → Security Monitoring → Security Report

![Windows Security Architecture](Windows_Security_Architecture.png)

## Project Structure

```text
Cybersecurity_Module_06/
├── src/
│   └── log_analyzer.py
├── Windows_Security_Architecture.png
└── README.md
```

## Installation

Install Python and Pandas:

```bash
python -m pip install pandas
```

## How to Run

1. Export Windows Security Events to CSV.
2. Place the CSV file inside the local `logs` folder.
3. Run the analyzer:

```bash
python src/log_analyzer.py
```

4. View the generated report in the local `reports` folder.

## Testing Environment
- Operating System: Windows 10
- Data Source: Local Windows Security Logs
- Events Analyzed: Latest 100 matching events exported during testing.

## Security Notice
This project is designed for defensive monitoring on systems owned by the user or systems for which explicit authorization has been provided.

Three or more failed login attempts are flagged for review. This does not by itself prove an attack.

## Project Demo Video

[Watch Windows Security Log Analyzer Demo](https://drive.google.com/file/d/1q1LisUszp30jy7jGyK2hhinYjS4G9OPO/view?usp=drive_link)

## Author
Darshan Chauhan

## Project Type
Cybersecurity Capstone Project
