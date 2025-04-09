<img src="https://github.com/user-attachments/assets/6c161540-df80-4a5f-a250-7ccf9f24c66d" alt="Draven" width="100%" height="400px">

# ⚔️ Draven Tool V3.0

**Draven** is an advanced ethical hacking tool designed for **authorized security testing**. Built for **pentesters and security researchers**, it provides a suite of tools to perform **OSINT**, **network scanning**, and more — all in a **single, easy-to-use interface**.

---

## 🚀 Getting Started

Follow these steps to download, set up, and run **Draven** on **Kali Linux**, **Windows**, **macOS**, or other Linux distributions.

---

## 📥 1. Download the Project

### Option A: Clone with Git

git clone https://github.com/Pharmyx/Draven-Tool.git cd Draven-Tool

### Option B: Download ZIP

1. Go to the [GitHub repository](https://github.com/Pharmyx/Draven-Tool).
2. Click the green `Code` button → `Download ZIP`.
3. Extract the ZIP file to a folder on your computer.

---

## 🐍 2. Install Python 3

### ✅ Kali Linux (Pre-installed)

python3 --version

### 🪟 Windows / 🍎 macOS / 🐧 Other Linux

Download Python 3 from [https://www.python.org](https://www.python.org)

> 💡 On **Windows**, check the box to **Add Python to PATH** during installation.

---

## 🔧 3. Install System Dependencies

### 📦 Kali Linux / Ubuntu / Other Linux

sudo apt update sudo apt install python3 python3-pip python3-venv nmap libpcap-dev chromium chromium-driver -y

### 🪟 Windows

1. Install [Nmap](https://nmap.org) and ensure it’s added to your **PATH**.
2. Install [Google Chrome](https://www.google.com/chrome/).
3. Download [ChromeDriver](https://chromedriver.chromium.org) (matching your Chrome version).
4. Extract and place ChromeDriver in a folder in your **PATH** (e.g., `C:\Program Files\ChromeDriver`).

### 🍎 macOS

Install Homebrew if not already installed:

/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

Then install the dependencies:

brew install python nmap libpcap chromedriver

Ensure `chromedriver` is in your **PATH**.

---

## 🧪 4. Set Up a Virtual Environment (Recommended)

Navigate to the project folder:

cd path/to/Draven-Tool

Example for Kali Linux:

cd ~/Downloads/Draven-Tool-main

Create a virtual environment:

python3 -m venv venv

### Activate the virtual environment:

**Linux/macOS:**

source venv/bin/activate

**Windows:**

venv\Scripts\activate

> 🧠 Your terminal prompt should now show `(venv)`.

---

## ⚠️ Kali Linux Users Note

Kali marks Python as "externally managed" (PEP 668). Using a virtual environment avoids `pip install` errors.  
**⚠️ Do NOT use `--break-system-packages`.**

---

## 📦 5. Install Python Dependencies

With the virtual environment activated:

pip install -r requirements.txt

### If `requirements.txt` is missing, create it manually:

echo -e "colorama\npython-nmap\nscapy\nbeautifulsoup4\nparamiko\npyfiglet\ndnspython\npython-whois\nshodan\nselenium\nnetifaces\nrequests" > requirements.txt

### Install packages individually if needed:

Example:

pip install shodan

---

## ▶️ 6. Run the Tool

Run the tool:

python3 draven.py

If root access is required (e.g., for Nmap or scapy):

sudo venv/bin/python3 draven.py
> ⚠️ Only use `sudo` when required.

---

## 📝 Notes

- Ensure all system and Python dependencies are installed properly.
- Some features (e.g., Nmap, packet sniffing) require **root privileges**.
- If `selenium` fails, verify ChromeDriver is installed and version matches Chrome.
- Use a virtual environment to avoid PEP 668 errors on Kali Linux.

---

## ⚖️ Legal Warning

**This tool is for authorized security testing only.**  
Unauthorized use is illegal and may result in **severe legal consequences.**

---

## 📜 Legal Disclaimer

Draven is provided for **educational and ethical purposes only**.  
The author is **not responsible** for any misuse or damage caused.  
By using Draven, you agree to comply with **all applicable laws** and regulations.

---

## 🧰 Features

- **OSINT Tools** — Username lookup, IP tracking, email investigation, and more.
- **Network Scanning** — Advanced Nmap scans, ARP spoof detection, packet sniffing.
- **Hacking Tools** — SSH brute force, network traffic analysis (for ethical use only).

---

## 📬 Contact

For questions, suggestions, or issues:

- Open an issue on the GitHub repository  
- Contact the author on Discord: **pharmyx**

---

Built by **Pharmyx** – see the [LICENSE](LICENSE.md)
