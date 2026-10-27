# VIPER-Strike
Advanced Automatic Web Exploitation Tool For Searching Vulnerability And It's Helpful. 
# Security Notice
VIPER-Strike operates strictly as an outbound client-side utility. The codebase contains no listening socket, remote command listeners, or external dependencies capable of facilitating inbound Remote Code Execution (RCE) on the host machine
As with any security utility, user are encouraged to audit the open-source code and execute the tool within an isolated environment.
# Supported OS:
- Blackarch Linux
- Kali Linux
- Parrot OS
# Installation (Recommended use ROOT directory):
1. git clone https://github.com/HarithBUGbounty/VIPER-Strike.git
2. cd VIPER-Strike
3. pip3 install -r requirements.txt
4. bash dependencies.sh
5. sudo apt install masscan nmap dirb -y
6. pip3 install requests beautifulsoup4
7. python3 VIPER-Strike.py
# Guide For (report.py):
1. python3 report.py ./reports/target.com_20250405_120000/
2. Generates:
report_interactive.html
report_final.pdf
/screenshots/ (simulated)

⚠ WARNING: Authorized testing only, Attacking website your not own or don't have permission is illegal, Use at you own risk.
