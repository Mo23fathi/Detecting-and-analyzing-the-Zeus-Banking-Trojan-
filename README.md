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
![Screenshot 2024-12-13 140259](https://github.com/user-attachments/assets/740805c2-899a-4e8d-8234-b2a71190fd01)

- Example Findings:
  - Malicious IP: `85.114.128.127`
  - Malicious Domain: `fpdownload.macromedia.com`
- Search for the malware's hash in public analysis tools (e.g., **ANY.RUN**) to confirm Indicators of Compromise (IOCs):
  - File Hash (SHA256): `4644b5fb10fb84c0d47bec4b5a48d5e60165e8ae2130fca5c055633aaad73162`
  - Additional Malicious IP: `23.213.170.81`
 Why we should Block the IP 85.114.128.127?
The IP belongs to a German hosting company called Fastwebserver.de.
It is not marked as "malicious" on major security websites.
Why it could be suspicious:

the DNS server is not part of your approved list (like Google 8.8.8.8 or Cloudflare 1.1.1.1), traffic to it might mean:
Malware or viruses are using this server.
Data is being secretly sent out (DNS tunneling).

![Screenshot 2024-12-13 141339](https://github.com/user-attachments/assets/987e09a6-c88d-4b47-aebd-79e30b7e92ea)
![Screenshot 2024-12-13 141350](https://github.com/user-attachments/assets/d7fba6a9-9b8b-4f77-aa73-47ee88aa3348)


### 3. **Write Suricata Rules for Detection and Blocking**
Based on the identified IOCs, the following **Suricata rules** were created to detect and block malicious activity:
![image](https://github.com/user-attachments/assets/cd264493-3dcb-409a-87ad-40d73fdc1f74)


### 4. ** here is sample of the log file  after adding the rules to the suricata  and running the trojan: **
![Screenshot 2024-12-13 151631](https://github.com/user-attachments/assets/00c8e2fd-0ce0-4295-913d-0ea69bbc1088)

![image](https://github.com/user-attachments/assets/0f5664c9-f352-44fe-b10a-d41d0328dda0)





## ** [4]  Steps to Implement yara rules **
### 1. ** To identify YARA rules for the Zeus Trojan,  I searched the **Open Threat Exchange ( websites that share threats  ) (example: OTX)  ** website for publicly available signatures. The following rule was obtained from [OTX YARA Database (https://otx.alienvault.com/indicator/yara/1bee7c83ba67483bfb34ad5fe6b08c7413ce2e00): **
![Screenshot 2024-12-13 152227](https://github.com/user-attachments/assets/2f716faa-afb0-479b-a6f3-c119706e6e9b)

### 2. ** here is output of the yara rules  after  running the yara rule on the malware file: **

![Screenshot 2024-12-13 051307](https://github.com/user-attachments/assets/a9de8d2d-e573-444f-85e7-7681343a29d3)

### 3. ** here is output of the yara rules  after  running the same yara rule on the memory dump file of the virtual machine: **
![image](https://github.com/user-attachments/assets/56ac24eb-2fc0-4551-a835-5684f3c6d859)


