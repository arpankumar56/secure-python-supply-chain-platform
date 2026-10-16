# Secure Python Supply Chain Verification Platform

A beginner-friendly Flask prototype for a college project. This project is a prototype, not a production-grade security scanner.

## Features in this version

- Dashboard UI with a package scan form.
- Looks up package/version metadata from PyPI.
- Queries OSV for known vulnerability records.
- Accepts a `requirements.txt` file and scans up to 30 parsed package entries.
- Accepts a `.py` source file and runs simple AST-based heuristics for selected risky API patterns.
- Mid-II analytics page: descriptive statistics, mean/median/mode, correlation matrix, and illustrative ANOVA.
- Responsive frontend and JSON API endpoints.

## Important limitations

- A clean OSV result does **not** prove a package is safe.
- The displayed risk score is a transparent demo heuristic based on vulnerability count; it is not a trained or validated Random Forest model.
- Source inspection is heuristic only. It does not execute uploaded source code and does not prove malware presence or absence.
- This version does not download/install packages, recursively resolve the full dependency graph, verify downloaded artifacts with SHA-256, verify package provenance/signatures, or perform dynamic analysis.
- Analytics use a small, manually authored illustrative dataset in `analytics.py`. Do not present these figures as real experiment results. Replace them with verified scan records before academic reporting.
- Network lookups require internet access. PyPI/OSV may be unavailable or rate-limited.
- Debug mode is disabled by default. Do not enable it on a public deployment.

## Run in VS Code on Windows

1. Install Python 3.10 or newer and VS Code.
2. In VS Code, choose **File → Open Folder** and open the folder containing `app.py` and `requirements.txt`.
3. Choose **Terminal → New Terminal**.
4. Create a virtual environment (run this command by itself):

   ```cmd
   py -m venv .venv
   ```

5. Activate it. In **Command Prompt** terminal, run:

   ```cmd
   .venv\Scripts\activate.bat
   ```

   In **PowerShell**, run:

   ```powershell
   .venv\Scripts\Activate.ps1
   ```

   If PowerShell says scripts are disabled, switch the terminal profile to **Command Prompt** and use the `.bat` command above. You do not need to change the computer's execution policy.

6. Install dependencies (run each command separately):

   ```cmd
   python -m pip install --upgrade pip
   python -m pip install -r requirements.txt
   ```

7. Start the local website:

   ```cmd
   python app.py
   ```

8. Open `http://127.0.0.1:5000` in your browser. Keep the terminal open while using the local website.
9. To stop the server, return to the terminal and press `Ctrl+C`.

If the browser shows `ERR_CONNECTION_REFUSED`, the Flask server is probably not running. Open the correct project folder in the terminal and run `python app.py` again.

## Deploy online with Render

1. Upload the **contents** of this project folder to a GitHub repository. `app.py` and `requirements.txt` must be at the repository root. Include `templates/` and `static/`. Do **not** upload `.venv/`.
2. Make sure `gunicorn` is present in `requirements.txt` (it is included in this version).
3. In Render, create a **Web Service** and connect the GitHub repository.
4. Use these settings:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app`
   - **Root Directory:** leave blank when `app.py` is at the repository root.
5. Deploy and use the public `.onrender.com` URL shown by Render.

The free hosting option, if available, may sleep after inactivity. The first visit after sleep can take longer. A public URL does not mean the free service is guaranteed to be awake at every moment.

## Test the scanner

- Enter `requests` with no version to inspect PyPI metadata and OSV records.
- Try `urllib3` or another known package, optionally specifying a version.
- Upload a `requirements.txt` file with pinned entries, for example:

  ```text
  requests==2.31.0
  urllib3==1.26.18
  ```

- Source check accepts a `.py` file and reports selected calls such as `eval`, `exec`, `os.system`, and `subprocess.Popen`. Use harmless test files only.

## Project structure

```text
secure_python_supply_chain_platform/
├── app.py
├── scanner.py
├── analytics.py
├── requirements.txt
├── README.md
├── templates/
│   └── index.html
└── static/
    ├── style.css
    └── app.js
```
