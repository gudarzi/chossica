# Rubika File Uploader (Single‑file)

An interactive script that uploads any file from your local machine directly to your Rubika **Saved Messages**.  
It handles authentication once and then lets you drop files continuously with a live progress bar.

---

## 🔧 Setup (Virtual Environment)

From the project directory, run:

```bash
# Create virtual environment
python3 -m venv venv

# Activate it
# Linux / macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# Upgrade pip
pip install --upgrade pip

# Install the dependency
pip install -r requirements.txt