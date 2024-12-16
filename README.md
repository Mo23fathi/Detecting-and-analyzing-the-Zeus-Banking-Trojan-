# Detecting-and-analyzing-the-Zeus-Banking-Trojan
## **Objective**
The goal of this project is to **detect and analyze the Zeus Banking Trojan** using various tools and techniques, including malware simulation, network monitoring, memory analysis, and signature-based detection.

## **Tools and Techniques**
- **Suricata**: Network traffic monitoring and detection.
- **Splunk**: Centralized log analysis and visualizations.
- **Volatility**: Memory analysis.
- **YARA**: Signature-based detection.
- **VM Environment**: Safe malware execution.

## ** [1]  Steps to Implement suricata **

### 1. **Simulate Malware Execution**
- Use **Wireshark** to monitor traffic and identify malicious connections and DNS requests.
- Set up a virtual machine (VM) to safely run malware.
- Download the Zeus Trojan sample from [theZoo repository](https://github.com/ytisf/theZoo/tree/master/malware/Binaries/ZeusBankingVersion_26Nov2013).
- Execute the malware within the VM to observe its behavior.
![Screenshot 2024-12-13 135825](https://github.com/user-attachments/assets/d8634997-f8e2-480f-8a67-3e79f7795dbb)


### 2. **Capture IOC Information**
- From **Wireshark**, identify:
  - Malicious IP addresses the Trojan connects to.
  - DNS requests made by the Trojan.
- Example Findings:
  - Malicious IP: `85.114.128.127`
  - Malicious Domain: `fpdownload.macromedia.com`
- Search for the malware's hash in public analysis tools (e.g., **ANY.RUN**) to confirm Indicators of Compromise (IOCs):
  - File Hash (SHA256): `4644b5fb10fb84c0d47bec4b5a48d5e60165e8ae2130fca5c055633aaad73162`
  - Additional Malicious IP: `23.213.170.81`

### 3. **Write Suricata Rules for Detection and Blocking**
Based on the identified IOCs, the following **Suricata rules** were created to detect and block malicious activity:
