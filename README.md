Draven Tool

Draven is an advanced ethical hacking tool for authorized security testing.

Setup and Installation
Follow these steps to download, set up, and run the Draven tool:
1. Download the Project
On the GitHub repository page, click the green Code button.

Select Download ZIP to download the project as a ZIP file.

Extract the ZIP file to a folder on your computer.

2. Install Python (if not already installed)
Ensure you have Python 3 installed on your system. You can download it from python.org.

During installation, make sure to check the box to Add Python to PATH to run Python from the command line.

3. Install Dependencies
Open a command prompt (CMD on Windows, Terminal on macOS/Linux):
On Windows: Press Win + R, type cmd, and press Enter.

On macOS/Linux: Open the Terminal application.

Navigate to the extracted project folder using the cd command. For example:

cd path\to\extracted\folder

Install the required Python libraries by running:

pip install -r requirements.txt

This will install all necessary dependencies (e.g., colorama, python-nmap, scapy, etc.).

4. Run the Tool
In the same command prompt, run the script:

python draven.py

The Draven tool will start, and you can select options from the menu to use its features.

Notes
Dependencies: Ensure you have all dependencies installed correctly. If pip install -r requirements.txt fails, you may need to install some dependencies manually (e.g., python-nmap might require Nmap to be installed on your system).

Legal Warning: This tool is for ethical security testing only. Use it only on systems you have explicit permission to test. Unauthorized use is illegal.

