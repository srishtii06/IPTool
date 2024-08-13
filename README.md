# IP Tool
This Python script performs various checks on IP addresses, including identifying whether they are public or private, checking if they are VPN/Proxy IPs, and fetching IP address details from an external API.It also helps in giving the traceroute results for the given IP Address.

# Features
**IP Type Check** : Determines whether an IP address is IPv4 or IPv6.\
**Public/Private IP Check**: Identifies if an IP address is private, public, or reserved by ISP (CGNAT).\
**VPN/Proxy Detection**: Checks if an IP address is listed in a local file of proxy/VPN IPs.\
**IPv6 Range Check**: Determines if an IPv6 address falls within a range specified in a local file.\
**IP Details Retrieval**: Fetches detailed information about an IP address using an external API.\
**Traceroute**: Gives the traceroute for the given IP Address.\
**GUI**: Has an interactive user interface.

# Installation
**Windows Users**
For Windows users, a pre-compiled executable file is provided. You can download and use the .exe file directly:

1. Locate the .exe file: The executable is located in the dist directory.
2. Download and Run: Simply download the file from dist and double-click to run the tool.
   
**Other Platforms**
If you're using a different platform, you can run the tool by following these steps:
   

# Requirements
Before running the IP Analysis Tool, ensure you have the following dependencies installed:

1. Clone the repository:
git clone https://github.com/srishtii06/IPAnalysisTool.git

2. Navigate to the project directory:
cd IPAnalysisTool

3. Set up the virtual environment (optional but recommended):
python -m venv envIP
source envIP/bin/activate  # On Windows use `envIP\Scripts\activate`

4. Install dependencies:
pip install -r requirements.txt

5. Run the tool:
python IPAnalysisTool.py

# How to Use
**Running the Executable**: For Windows users, simply double-click the .exe file found in the dist directory.
**Running from Source**: If you're running from source, follow the installation steps above, then execute IPAnalysisTool.py using Python.

# Data Directory
The data/ directory contains files that the tool may use during its analysis. Ensure this directory is present in the project root when running the tool.

# Building from Source
To rebuild the .exe or modify the tool:

1. Ensure all dependencies are installed using the requirements.txt file.
2. Modify the IPAnalysisTool.spec file if necessary.
3. Build the executable:
   pyinstaller IPAnalysisTool.spec

# Contributing
Contributions are welcome! Please fork the repository and submit a pull request or open an issue for any bug reports or feature requests.

# License
This project is licensed under the MIT License. See the LICENSE file for more details.
   
