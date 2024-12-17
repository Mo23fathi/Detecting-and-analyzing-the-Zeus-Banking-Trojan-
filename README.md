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


## ** [3]  Steps to Implement Volatility **
### 1.First we will download our vm  and python 3 and volatility And start scanning the operating system info and it's process 
![image](https://github.com/user-attachments/assets/8b267539-c413-4d92-a780-d28064fcd94f)

![image](https://github.com/user-attachments/assets/dda447f9-961c-482e-9eb7-79f7556e81ab)

![image](https://github.com/user-attachments/assets/c6658858-670d-4434-8e85-cbd9d39bbbe2)

### 2.There is nothing malicious so we will check the connections
![image](https://github.com/user-attachments/assets/bcdc8581-49d1-4f93-af11-9c4f6c004226)

![image](https://github.com/user-attachments/assets/7a169ca6-7321-4b83-9f41-52f73cf801e1)

![image](https://github.com/user-attachments/assets/4677be71-7896-451e-844d-adacd6d157b7)

### 3.we found only one file and we checked its path and we found nothing and now we will check the code if it's injected and we found that there is a mz header and we dumped it but we also found nothing
![image](https://github.com/user-attachments/assets/03fb638f-7f1e-4144-a029-c32bc17a5e37)

![image](https://github.com/user-attachments/assets/947ada9e-1e80-483f-b3f8-844cc63e7fa3)

![image](https://github.com/user-attachments/assets/0d7e12c8-1684-4227-b233-962ee44dfcee)


### 4.we will try to dump the section of the memory we think is injected and it was actually malicious 
![image](https://github.com/user-attachments/assets/5d671f1d-9fc7-47b6-9856-6827d0a2c806)

![image](https://github.com/user-attachments/assets/d141bad8-ab88-421d-bc3b-f0ae132be725)


### 5.we will check the most used mechanisms by malwares and we will find that this pid has a handle on another exe and we found that is a winlogon.exe

![image](https://github.com/user-attachments/assets/e55a9617-2e8b-4143-9eed-e24b96692561)

![image](https://github.com/user-attachments/assets/b4003d8a-23a0-4ec4-a2bc-648e126a23a8)

### 6.Now we will check if it’s injected and we will dump it and check it and we find that is malicious 
![image](https://github.com/user-attachments/assets/07b9fe23-e72f-4b7c-9182-3a5562d7a8e9)

![image](https://github.com/user-attachments/assets/7186c19b-36e0-48c1-a650-70ee2ec59bd6)

![image](https://github.com/user-attachments/assets/b043bef7-c85e-41c7-989a-4d8602af09d8)


### 7.We will check the mutants we find _AVIRA_2109 which looks suspicious and we will search for simillars and we found another one 
![image](https://github.com/user-attachments/assets/33ed8c26-b18e-489a-b325-7097d4abc2a5)


![image](https://github.com/user-attachments/assets/21eda713-94d8-46fb-8b84-256708ace49a)







## ** [4]  Steps to Implement yara rules **
### 1. ** To identify YARA rules for the Zeus Trojan,  I searched the **Open Threat Exchange ( websites that share threats  ) (example: OTX)  ** website for publicly available signatures. The following rule was obtained from [OTX YARA Database (https://otx.alienvault.com/indicator/yara/1bee7c83ba67483bfb34ad5fe6b08c7413ce2e00): **
![Screenshot 2024-12-13 152227](https://github.com/user-attachments/assets/2f716faa-afb0-479b-a6f3-c119706e6e9b)

### 2. ** here is output of the yara rules  after  running the yara rule on the malware file: **

![Screenshot 2024-12-13 051307](https://github.com/user-attachments/assets/a9de8d2d-e573-444f-85e7-7681343a29d3)

### 3. ** here is output of the yara rules  after  running the same yara rule on the memory dump file of the virtual machine: **
![image](https://github.com/user-attachments/assets/56ac24eb-2fc0-4551-a835-5684f3c6d859)


