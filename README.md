# File Integrity Monitoring System with AI Anomaly Detection

A cybersecurity project that monitors important files for unauthorized changes using SHA-256 hashing and detects suspicious file activity using rule-based security analysis and Machine Learning.

## Project Overview

The File Integrity Monitoring System (FIM) checks monitored files and compares their current SHA-256 hash values with a trusted baseline.

It can detect:

- New files
- Modified files
- Deleted files

The project also includes an AI-based anomaly detection component using the Isolation Forest machine learning algorithm to identify unusual file activity patterns.

A Flask web dashboard provides a visual overview of the system status and detected security events.

## Key Features

### 1. SHA-256 File Integrity Monitoring

Each monitored file is hashed using SHA-256.

If the file content changes, its hash value changes and the system identifies the file as modified.

### 2. Baseline Creation

The system creates a trusted baseline containing the SHA-256 hashes of monitored files.

The baseline is used as the reference point for future integrity checks.

### 3. File Change Detection

The system detects:

- New files
- Modified files
- Deleted files

### 4. AI Anomaly Detection

The project uses the Isolation Forest machine learning algorithm to analyze file activity patterns.

The system also applies security rules for high-risk events such as:

- File deletion
- Multiple file modifications
- Multiple new file creations

The dashboard can display:

- NORMAL
- ANOMALY
- LEARNING

### 5. Security Logging

Detected file integrity events are recorded in:

```text
logs/security.log
6. Web Dashboard

A Flask-based dashboard displays:

New file count
Modified file count
Deleted file count
AI anomaly detection result
Anomaly score
Recent security activity
Technology Stack
Python
Flask
SHA-256
Scikit-learn
Isolation Forest
HTML
CSS
JavaScript
JSON
Git / GitHub
Project Structure
file-integrity-monitor/
│
├── ai/
│   ├── anomaly_detector.py
│   ├── activity_history.json
│   └── ai_state.json
│
├── logs/
│   └── security.log
│
├── monitored_files/
│
├── static/
│
├── templates/
│   └── index.html
│
├── venv/
│
├── app.py
├── web_app.py
├── baseline.json
└── README.md
How It Works
                Monitored Files
                       │
                       ▼
                SHA-256 Hashing
                       │
                       ▼
                 Baseline Hash
                       │
                       ▼
              Integrity Comparison
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
        NEW        MODIFIED      DELETED
          │            │            │
          └────────────┼────────────┘
                       ▼
               Security Analysis
                       │
                       ▼
              AI Anomaly Detection
                       │
                       ▼
                Flask Dashboard
Detection Logic
New File

A file is classified as new when it exists in the monitored directory but is not present in the baseline.

Modified File

A file is classified as modified when its current SHA-256 hash differs from the baseline hash.

Deleted File

A file is classified as deleted when it exists in the baseline but is no longer present in the monitored directory.

AI Anomaly Detection

The system represents file activity using three values:

[New Files, Modified Files, Deleted Files]

Example:

[0, 0, 0]

This represents normal activity with no detected changes.

A suspicious activity pattern such as:

[0, 1, 1]

indicates that a file was modified and another file was deleted.

The Isolation Forest algorithm analyzes historical activity patterns and helps identify unusual behavior.

Security Example

Suppose an attacker modifies an important configuration file and deletes another monitored file.

The FIM detects:

Modified Files: 1
Deleted Files: 1

The security analysis then identifies the deletion as suspicious and reports:

AI Detection: ANOMALY

This helps a security analyst investigate possible unauthorized activity.

Installation

Clone the repository:

git clone <YOUR-GITHUB-REPOSITORY-URL>

Move into the project directory:

cd file-integrity-monitor

Create a virtual environment:

python -m venv venv

Activate the virtual environment on Windows:

venv\Scripts\activate

Install the required packages:

pip install flask watchdog scikit-learn
Running the FIM

Run:

python app.py

Use the menu to:

Create Baseline
Check Integrity
Exit
Running the Dashboard

Run:

python web_app.py

Then open the Flask dashboard in a browser.

The dashboard displays the current file integrity status and AI anomaly detection result.

Testing

The project was tested using different file integrity events.

Test 1 — File Modification

A monitored file was modified.

Expected result:

Modified Files: 1
Test 2 — File Deletion

A monitored file was deleted.

Expected result:

Deleted Files: 1
AI Detection: ANOMALY
Test 3 — New File

A new file was added to the monitored directory.

Expected result:

New Files: 1
Security Benefits

This project can help security teams detect:

Unauthorized file modifications
Suspicious file creation
File deletion
Potential file tampering
Abnormal file activity

It can be used as a basic security monitoring component in environments where file integrity is important.

Future Improvements

Possible future enhancements include:

Real-time monitoring using Watchdog
Email security alerts
Telegram/SMS notifications
User authentication
Database-based event storage
SIEM integration
Advanced anomaly detection
Attack/event severity classification
Docker deployment
Cloud deployment
Disclaimer

This project is developed for educational, cybersecurity learning, and authorized security monitoring purposes.

Author

Athila Nowrin

BCA Graduate | Cybersecurity Enthusiast

Skills: Python, Linux, Networking, Ethical Hacking, SIEM, VAPT, Web Security