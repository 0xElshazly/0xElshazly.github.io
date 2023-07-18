---
title: "SOC145 - Ransomware Detected"

header:
  teaser: /assets/images/LetsDefend/SOC145/SOC145.jpg
  overlay_image: /assets/images/LetsDefend/SOC145/SOC145.jpg
  overlay_filter: 0.5

ribbon: DarkSlateBlue
description: "SOC145 - Ransomware Detected"
categories:
  - Challenges
  - LetsDefend
tags: 
  - Ransomware
  - SOC
  - LetsDefend
  - Challenges
  - Phishing
  - Excel

toc: false
toc_sticky: false
toc_label: "On This Blog"
toc_icon: "biohazard"
classes: wide
last_modified_at: 
---
<span style="color: #909090">Category: SOC - LetsDefend - Ransomware Detected </span>

| ![Phishing Mail Detected](/assets/images/LetsDefend/SOC145/SOC145.png) | 
|:--:| 
| *SOC145 - Ransomware Detected* |

> **In this writeup, we will investigate the Ransomware Detected. For those who are not aware of what Ransomware is, this [link](https://www.trellix.com/en-us/security-awareness/ransomware/what-is-ransomware.html) provides a comprehensive overview of the ransomware.**

| ![Screenshot For The Alert](/assets/images/LetsDefend/SOC145/SOC_145.png) | 
|:--:| 
| *Screenshot For The Alert* |

Metadata information of the event which triggered the SIEM alert:
- For this alert, we see that a suspicious behaviour that hit the `SOC145 - Ransomware Detected` rule, we can also see the file name, file hash, and file size.

---
## Let's get ready to investigate the alert..!

- For our first step, we can put the hash of the `0b486fe0503524cfe4726a4022fa6a68.zip` file in Virus Total to get a preliminary overview of whether the file is malicious or not and to see if there are any hits returned.

  ```html
  File Hash: 1228d0f04f0ba82569fc1c0609f9fd6c377a91b9ea44c1e7f9f84b2b90552da2
  ```

### Virus Total

| ![Screenshot For The Alert](/assets/images/LetsDefend/SOC145/1.png) | 
|:--:| 
| *<a href="https://www.virustotal.com/gui/file/1228d0f04f0ba82569fc1c0609f9fd6c377a91b9ea44c1e7f9f84b2b90552da2">0b486fe0503524cfe4726a4022fa6a68.zip</a> seems to be very malicious* |

After we submit the file hash in VirusTotal, there are total of 63 security vendors flagged this file as malicious.

---

| ![Virustotal](/assets/images/LetsDefend/SOC145/2.png) | 
|:--:| 
| *<a href='https://www.virustotal.com/gui/file/1228d0f04f0ba82569fc1c0609f9fd6c377a91b9ea44c1e7f9f84b2b90552da2/relations'>Relations</a>* |

- We can see C2 Adresses, Contacted Domains and URLs relation are also the key indicator for malicious file.

---
### ANY.RUN

Next, we will simulate this artefact’s behaviour on compromised system by submitting it to `ANY.RUN`

| ![ANY.RUN](/assets/images/LetsDefend/SOC145/3.png) |
|:--:| 
| *ANY.RUN* |

💡To show more ANY.RUN behaviour analysis result [Click Here](https://app.any.run/tasks/ad897f29-b781-42d2-bde3-ab0fbcdef302/)

---

### Hybrid Analysis 

Next, we will simulate this artefact’s behaviour on compromised system by submitting it to `Hybrid Analysis`

| ![Hybrid](/assets/images/LetsDefend/SOC145/4.png) | 
|:--:| 
| *Hybrid Analysis* |

Hybrid Analysis also flagged this file as malicious with detection reference to CrowdStrike Falcon, MetaDefender and VirusTotal.

💡To show more Hybrid Analysis result [Click Here](https://www.hybrid-analysis.com/sample/1228d0f04f0ba82569fc1c0609f9fd6c377a91b9ea44c1e7f9f84b2b90552da2)

---

### Let's start with playbook

| ![PlayBook](/assets/images/LetsDefend/SOC145/5.png) |
|:--:| 
| *PlayBook* |

#### Define Threat Indicator

| ![PlayBook](/assets/images/LetsDefend/SOC145/6.png) |
|:--:| 
| *PlayBook* |


#### Check if the malware is quarantined/cleaned

- First of all you will check Log Management:

| ![Log Management](/assets/images/LetsDefend/SOC145/7.png) |
|:--:| 
| *Log Management* |


- First we check the first log alert:

| ![Log Management](/assets/images/LetsDefend/SOC145/8.png) |
|:--:| 
| *RAW LOG* |

- we check this parent hash in virus total:

| ![Log Management](/assets/images/LetsDefend/SOC145/9.png) |


After we submit the file hash in VirusTotal, there are total of 48 security vendors flagged this file as malicious.

---

we will take this information as IoCs:
- Request URL: http://thuening.de/cgi-bin/uo9wm/
- Parent MD5: ac596d282e2f9b1501d66fce5a451f00
- Process: powershell.exe
- Parent Process: BAL_GB9684140238GE.doc

---

Then we will check the Destination Address:

| ![Log Management](/assets/images/LetsDefend/SOC145/10.png) |

- After we submit the file hash in VirusTotal, there are total of 3 security vendors flagged this IP Address as malicious.


---

- Now we check the second log alert:

| ![Log Management](/assets/images/LetsDefend/SOC145/11.png) |


- After we submit the file hash in VirusTotal, there are flagged this file is not malicious.

---

- Second you will check Endpoint Security:

| ![Endpoint Security](/assets/images/LetsDefend/SOC145/12.png) |
|:--:| 
| *Endpoint Security* |


- If we check this hash `0b486fe0503524cfe4726a4022fa6a68` in virus total:

| ![Screenshot For The Alert](/assets/images/LetsDefend/SOC145/1.png) | 
|:--:| 
| *<a href="https://www.virustotal.com/gui/file/1228d0f04f0ba82569fc1c0609f9fd6c377a91b9ea44c1e7f9f84b2b90552da2">Virus Total</a>* |


And this is basic properties and names of this file:

| ![Screenshot For The Alert](/assets/images/LetsDefend/SOC145/13.png) | 

| ![Screenshot For The Alert](/assets/images/LetsDefend/SOC145/14.png) | 

💡To show more details about this file [Click Here](https://www.virustotal.com/gui/file/1228d0f04f0ba82569fc1c0609f9fd6c377a91b9ea44c1e7f9f84b2b90552da2/details) and for relations [Click Here](https://www.virustotal.com/gui/file/1228d0f04f0ba82569fc1c0609f9fd6c377a91b9ea44c1e7f9f84b2b90552da2/relations)

---

Finally,
> It is True Positive alert, because ab.exe is ransomware and encrypted all files on the machine. There is no C2 address, if you do dynamic analysis, you can see how it is acting.

---

Protect Your Digital Presence & Stay Cyber Safe 💙

Thanks🌸
