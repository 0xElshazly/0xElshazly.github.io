---
title: "CyberTalents Certified SOC Analyst Challenges"

header:
  teaser: /assets/images/CyberTalents/SOC_Analyst/photo_2023-07-08_18-06-43.jpg
  overlay_image: /assets/images/CyberTalents/SOC_Analyst/photo_2023-07-08_18-06-43.jpg
  overlay_filter: 0.5

ribbon: Green
description: "CyberTalents Blue Team Scholarship 2023"
categories:
  - Challenges
  - SOC
  - CyberTalents
  - Tutorials
  - CTF
tags: 
  - SOC
  - CyberTalents
  - Trend Micro
  - CTF

toc: true
toc_sticky: true
toc_label: "On This Blog"
toc_icon: "biohazard"
classes: wide
last_modified_at: 
---
<span style="color: #909090">Category: SOC - CyberTalents - Trend Micro - CTF</span>


# 1. Competition

Q. Special kind of cybersecurity competition designed to challenge its participants to solve computer security problems

<details>
<summary>
Flag
</summary>
CTF
</details>

---

# 2. CVE Number

### Description
What is the CVE ID that is related to EternalBlue

Flag Format: XXX-XXXX-XXXX

### Lets Solve This..!

##### What is EternalBlue?
EternalBlue is a Microsoft exploit which was used by the NSA in intelligence gathering operations. The exploit, officially named MS17-010 by Microsoft — gave the US National Security Agency (NSA) backend access to devices running Windows operating systems like Windows XP and Windows 7.

💡Do you know more about CVE check this [Link](https://cve.mitre.org/index.html) or check this [Link](https://cvexploits.io/)
<details>
<summary>
Flag
</summary>
CVE-2017-0144
</details>

---

# 3. Smart Role

Q. skills of collecting information out of cyberspace that has been previously analysed and shared between organisations about different attack scenarios and vectors.What is the role name of the above definition 

<details>
<summary>
Flag
</summary>
flag{threat intelligence}
</details>

---
# 4. Backdoor
### Description

```python 
Our server compromised due to known vulnerability introduced from many years, Kindly check and identify this flow 
X: Attack source → EX. “Internal/External”
Y: The Source IP → x.x.x.x
Z: CVE Num of the attack → xxx
W: Destination Mac Address
Flag format: flag{X:Y:Z:w}
Link: https://to-be-uploaded
```

### Tools:
- Wireshark

🚩Challenge [Link](/assets/images/CyberTalents/SOC_Analyst/backdoor.pcap)


### 🧑🏻‍💻Lets Solve This..!
let’s open the ```backdoor.pcap``` file with wireshark first, then lets show the Protocol Hierarchy Statistics and start first by filtering FTP traffic.

<p align="center">
  <img src="/assets/images/CyberTalents/SOC_Analyst/6.png" alt="Protocol Hierarchy Statistics" style="width:1000px">
</p>

Filtering FTP traffic.
<p align="center">
  <img src="/assets/images/CyberTalents/SOC_Analyst/7.png" alt="FTP" style="width:1000px">
</p>

Selecting FTP protocol will generate search for subjected traffic and display fields like source, destination, destination port and info, From there we can see these traffic between two internal IP addresses 

💡Wireshark provides the feature of reassembling a stream of plain text protocol packets into an easy-to-understand format.

By selecting first packet (Right-Click) → Follow → TCP stream 
<p align="center">
  <img src="/assets/images/CyberTalents/SOC_Analyst/8.png" alt="FTP" style="width:1000px">
</p>
This is the result:
<p align="center">
  <img src="/assets/images/CyberTalents/SOC_Analyst/9.png" alt="FTP" style="width:1000px">
</p>
Here from the result we have useful information like:
- The FTP server receive the request from user and user name / password used for this authentication

##### Lets try to make this info useful 🤔

From the challenge description we know the the server is compromised by specific vulnerability and our task is to identify the root cause.

Googling the server ```version``` from the discovery result, we can notice its vulnerable to backdoor was introduced into the ```vsftpd-2.3.4.tar.gz``` archive.

Let's search about this vsFTPd 2.3.4 vulnerability in [Exploit DB](https://www.exploit-db.com/)

This is the result:
[vsftpd 2.3.4 - Backdoor Command Execution](https://www.exploit-db.com/exploits/49757)

<p align="center">
  <img src="/assets/images/CyberTalents/SOC_Analyst/10.png" alt="FTP" style="width:1000px">
</p>

Now lets try to cocatinating  the flag:
- From PCAP analysis Both attacker and server have internal IP address in the range 192.168.1.0/24 So the attack scope is Internal this is the ```X``` portion
- From PCAP analysis we can get the ```Y``` part that is the source IP of the attecker
- Now we can get the ```Z``` part from the flag from above ```CVE ID``` 
- The last part of this flag ```W``` lets back to wireshark packets list to get the details, We could extract all Src/Dest network traffic details.

<p align="center">
  <img src="/assets/images/CyberTalents/SOC_Analyst/11.png" alt="FTP" style="width:1000px">
</p>

<details>
<summary>
Flag
</summary>
flag{internal:192.168.1.58:CVE-2011-2523:08:00:27:66:e3:8b}
</details>
---
# 5. Creepy DNS
### Description

Our NMS detect a suspected traffic, your task is to investigate the captured traffic and find the anomaly reason.

### Tools:
- Wireshark
- Tshark
- CyberChef (Website)

🚩Challenge [Link](/assets/images/CyberTalents/SOC_Analyst/dns.pcapng)


### 🧑🏻‍💻Lets Solve This..!

let’s open the ```dns.pcapng``` file with wireshark first, then lets show the Protocol Hierarchy Statistics and start first by filtering DNS traffic.

<p align="center">
  <img src="/assets/images/CyberTalents/SOC_Analyst/1.png" alt="Protocol Hierarchy Statistics" style="width:1000px">
</p>

Filtering DNS traffic.

<p align="center">
  <img src="/assets/images/CyberTalents/SOC_Analyst/2.png" alt="DNS" style="width:1000px">
</p>

If we search through the traffic we can see at one point that there are many DNS requests to ```[x].cybertalents.com.```

<p align="center">
  <img src="/assets/images/CyberTalents/SOC_Analyst/3.png" alt="DNS" style="width:1000px">
</p>

Let’s use ```Tshark``` to filter and collect all the letters.

```python
tshark -r dns.pcapng -Y "dns.qry.type == 1" | grep 'cybertalents.com OPT' | cut -d 'A' -f 2 | uniq | cut -d '.' -f 1 | tr
```
- Dns.qry.type: filter only DNS requests (type ==1). 
- The rest of the commands are bash tricks to sort the input.

<p align="center">
  <img src="/assets/images/CyberTalents/SOC_Analyst/4.png" alt="DNS" style="width:1000px">
</p>

We got what seems like a flag encoded in base64.

Let's Decode the string by using [CyberChef](https://cyberchef.org/)

<p align="center">
  <img src="/assets/images/CyberTalents/SOC_Analyst/5.png" alt="DNS" style="width:1000px">
</p>

<details>
<summary>
Flag
</summary>
flag{tshArk_Is_Awes0me_Netw0rking_to0l}
</details>

---
# 6. IOSeen

### Description
Answer the following questions: 

1. What is the second process that gets created by this executable and what is its state? 
2. What is the registry key that this executable is trying to access and gets access denied? 
3. What will be a good host base IOC (Mutex Name)? 

Flag format: Flag{process name_state_registry key_Host base IOC} 

Notes:  
- The process state is in lowercase. 
- Don’t run the sample as administrator. 
- The flag doesn’t contain spaces

### Tools:
- 

🚩Challenge [Link](/assets/images/CyberTalents/SOC_Analyst/IOSeen.exe)


### 🧑🏻‍💻 Lets Solve This..!
