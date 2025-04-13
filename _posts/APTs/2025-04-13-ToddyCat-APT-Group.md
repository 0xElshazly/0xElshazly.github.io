---
title: "ToddyCat APT Group"

header:
  teaser: /assets/images/APTs/ToddyAPT/toddy.png
  overlay_image: /assets/images/APTs/ToddyAPT/toddy.png
  overlay_filter: 0.5

ribbon: Orange
description: "ToddyCat APT Group"
categories:
  - APTs
tags: 
  - ToddyCat APT
  - SOC


toc: false
toc_sticky: false
toc_label: "On This Blog"
toc_icon: "biohazard"
classes: wide
last_modified_at: 
---
<span style="color: #909090">Category: ToddyCat APTs - APTs </span>

<!-- | ![ToddyCat APT](/assets/images/APTs/ToddyAPT/toddy.png) | 
|:--:| 
| *ToddyCat APT Group* | -->

# ToddyCat APT Group

As part of the assignment to analyze an APT group and develop a relevant detection rule, I selected **ToddyCAT APT** due to its exploitation of a known **ESET vulnerability**. Since **ESET** is integrated within our **ELK-based SIEM**, this made ToddyCAT a relevant and practical choice for deeper analysis, allowing me to align the threat research with our existing security stack.

- **Summary**
    
    The **ToddyCat** APT group, active since at least **2020**, has been observed exploiting a vulnerability in **ESET antivirus software** (CVE-2024-11859) (specifically in the `esets_shell` module) to stealthily deploy malware. 
    
    This vulnerability involves **insecure DLL** search order handling, allowing attackers to **load malicious DLLs** from unintended directories. The group has used this method to deploy a previously unseen malware **dubbed TCESB**, designed to execute malicious code undetected and **disable Windows kernel-level security** mechanisms. 
    
    The campaign primarily targets government and defense entities in the Asia-Pacific region.
    
- **Execution Flow of The Malware**
    
    ![image.png](/assets/images/APTs/ToddyAPT/image.png)
    
    ### **Normal Execution Flow (Expected Behavior)**
    
    - **Step 0 (Baseline)**:
        - Legitimate software normally loads a **Legitimate DLL**.
        - It imports required functions directly from the DLL.
    
    ### **Hijacked Execution Flow (Malicious Behavior)**
    
    1. **Step 1 – Malicious DLL Intercepts**
        - Instead of the legitimate DLL, a **Malicious DLL** is placed in a location where the legitimate software will load it first (e.g., same directory).
        - The software unknowingly loads this malicious DLL.
        - The malicious DLL **loads and imports functions from the legitimate DLL** to avoid detection.
    2. **Step 2 – Proxy Behavior**
        - The **Malicious DLL forwards function calls** to the legitimate DLL.
        - This allows it to behave like the real DLL and not break the application.
        - While doing this, it can also **execute arbitrary malicious code** silently.
    
    Researchers have discovered that the APT group ToddyCat, suspected to be linked to China, is exploiting a now-patched vulnerability (CVE-2024-11859) in ESET antivirus software to stealthily load and execute malware on target systems. The vulnerability, **fixed in January 2024**, stems from insecure DLL search order handling, allowing attackers to trick the system into **loading a malicious DLL** from an unintended directory instead of a legitimate system file. 
    
    > **Kaspersky** reported finding this flaw while analyzing a suspicious **`version.dll`** file hidden in the **temporary** folder of an infected machine. The file turned out to be a previously unseen ToddyCat malware **dubbed TCESB.**
    > 
    
    **TCESB** is designed to execute malicious code undetected, featuring capabilities to disable alerts and Windows kernel-level security mechanisms.
    
    - **TCESB**
        - **T**oddyCat → The APT group responsible for the attack
        - **C**at → Part of the group’s name
        - **ESET** → The targeted security software
        - **S**ideloading → Refers to the DLL sideloading technique used
        - **B**ackdoor → The nature of the malware (it provides remote access/control)
    
    - **CVE-2024-11859**
        
        The vulnerability tracked as **CVE-2024-11859** affects ESET's Command Line Scanner (`esets_cmd.exe`). It allows an attacker with existing **administrator privileges** to exploit **DLL sideloading** by placing a **malicious dynamic-link library (DLL)** in a specific directory. When the ESET scanner is executed, it **loads the attacker's DLL instead of the legitimate system DLL**, enabling stealthy execution of arbitrary code.
        
        While this attack **does not provide privilege escalation**, it **abuses a trusted and signed component** to evade detection, making it a powerful technique for **defense evasion and persistence** within compromised environments.
        
        **Vulnerability Details:**
        
        - **CVE ID**: CVE-2024-11859
        - **CVSS v4.0 Score**: 6.8
        - **CVSS Vector**: `AV:L/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`
        - **Impact**: High confidentiality and integrity impact (VC:H, VI:H), local attack vector (AV:L), low attack complexity (AC:L), and requires low privileges (PR:L) with user interaction (UI:P).
        
        This vulnerability served as the main entry point for **ToddyCat APT's TCESB backdoor**, enabling them to hijack the execution flow of trusted security software and maintain stealth.
        
    
- **Loading The Tools (DLLs)**
    1. DLL Proxying
        
        Static analysis of the DLL library showed that all functions exported by it import functions with the same names from the system file **`version.dll`** (Version Checking and File Installation Libraries).
        
        ![image.png](/assets/images/APTs/ToddyAPT/image%201.png)
        *List of functions exported by TCESB*
        
        This indicates that the attackers use a DLL-proxying technique (Hijack Execution Flow, [T1574](https://attack.mitre.org/techniques/T1574/)) to run the malicious code. 
        
    2. Command Line Scanner
        
        ![image.png](/assets/images/APTs/ToddyAPT/image%202.png)
        *Malicious and legitimate libraries in the memory of the ecls.exe process*
        
        During analysis, researchers discovered a suspicious executable named `ecls` located in the same folder as the TCESB malware. This file, lacking an extension, turned out to be a copy of ESET's **Command Line Scanner**. Dynamic analysis revealed that `ecls` insecurely loads `version.dll` by first searching in the current directory, making it vulnerable to **DLL sideloading**.
        
        This behavior allowed attackers to load a malicious `version.dll` (TCESB) instead of the legitimate system version, leading to stealthy code execution. 
        
    1. **Vulnerable driver**
        
        To modify the kernel structures that store callbacks used to notify applications of system events, **TCESB** deploys the **Bring Your Own Vulnerable Driver (BYOVD)** technique (Exploitation for Defense Evasion, [T1211](https://attack.mitre.org/techniques/T1211/)). It does this by installing a vulnerable driver in the system through the **Device Manager interface,** using an `INF file` with installation information.
        
        ![image.png](/assets/images/APTs/ToddyAPT/image%203.png)
        
        TCESB uses the Dell [DBUtilDrv2.sys](https://www.loldrivers.io/drivers/bb808089-5857-4df2-8998-753a7106cb44/) driver, which contains the [CVE-2021-36276](https://www.dell.com/support/kbdoc/en-us/000190106/additional-information-regarding-dsa-2021-152-dell-client-platform-security-update-for-an-insufficient-access-control-vulnerability-in-the-dell-dbutildrv2-sys-driver) vulnerability. This is a utility driver used to update PC drivers, BIOS and firmware.
        
    2. **Launching The Payload**
        
        ![image.png](/assets/images/APTs/ToddyAPT/image%204.png)
        
        - To detect the activity of such tools, it’s recommended to **monitor systems** for installation events involving **drivers** with known vulnerabilities.
            - Lists of such drivers can be found on the [loldrivers](https://www.loldrivers.io/) project website, for example. It’s also worth monitoring events associated with **loading Windows kernel debug symbols** on devices where debugging of the operating system kernel is not expected.
            - We also advise using **operating system tools** to check all loaded system library files for the presence of a digital signature.
            - The tool creates its own log file for recording all stages of execution in detail.
        
        ![image.png](/assets/images/APTs/ToddyAPT/image%205.png)
        ***Example of log file contents***
        
- **Indicators of compromise (IoCs)**
    - **Malicious Files Hashes**
        - [D38E3830C8BA3A00794EF3077942AD96](https://opentip.kaspersky.com/D38E3830C8BA3A00794EF3077942AD96/results?icid=gl_securelist_acq_ona_smm__onl_b2b_securelist_lnk_sm-team_______d2a2b0086f70e549&utm_source=SL&utm_medium=SL&utm_campaign=SL)        **version.dll**
        - [008F506013456EA5151DF779D3E3FF0F](https://opentip.kaspersky.com/008F506013456EA5151DF779D3E3FF0F/results?icid=gl_securelist_acq_ona_smm__onl_b2b_securelist_lnk_sm-team_______f407073d91cea0cf&utm_source=SL&utm_medium=SL&utm_campaign=SL)             **version.dll**
        - [dacb62578b3ea191ea37486d15f4f83c](https://www.virustotal.com/gui/file/dacb62578b3ea191ea37486d15f4f83c)               **DBUtilDrv2.sys**
    - **Legitimate file for DLL proxying**
        - 8795271F02B30980EBD9950FCC141304             **ESET Command-line scanner**
    - **Legitimate files for BYOVD**
        - B87944DCC444E4C6CE9BB9FB8A9C0DEF        **dbutildrv2.INF**
        - DE39EE41D03C97E37849AF90E408ABBE            **DBUtilDrv2.cat**
        - DACB62578B3EA191EA37486D15F4F83C           **dbutildrv2.sys**
- **Detection Rules**
    1. Sigma Rules For ELK
        - Search For:
            - `DLL sideloading`
            - `esets_cmd.exe`
            - `version.dll`
            - `T1574.002` (MITRE technique for DLL search order hijacking)
                
                ```yaml
                title: Suspicious DLL Sideloading via ESET Command Line Scanner (CVE-2024-11859)
                id: 6d12f5cc-235a-4b64-9c2b-cve202411859
                description: Detects potential abuse of ESET's esets_cmd.exe for DLL sideloading (as seen in ToddyCat APT's TCESB campaign)
                status: experimental
                author: 0x5l3uth
                date: 2025-04-13
                references:
                  - https://securelist.com/toddycat-apt-exploits-vulnerability-in-eset-software-for-dll-proxying/116086/
                  - https://attack.mitre.org/techniques/T1574/002/
                  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-11859
                logsource:
                  product: windows
                  category: process_creation
                detection:
                  selection:
                    Image|endswith: '\esets_cmd.exe'
                    CommandLine|contains: 'version.dll'
                  condition: selection
                fields:
                  - CommandLine
                  - Image
                  - ParentImage
                  - OriginalFileName
                  - Company
                  - Hashes
                  - Signature
                  - ProcessId
                  - ParentProcessId
                level: high
                tags:
                  - attack.defense_evasion
                  - attack.t1574.002
                  - cve.2024.11859
                  - todyycat
                  - eset
                  - dll_sideloading
                ```
                
            
            - If you're using **Sysmon**, also monitor for:
                - `Event ID 7`: DLL Image Load
                - `ImageLoaded` path containing `version.dll` loaded from unexpected or non-system paths
                - Parent process = `esets_cmd.exe`
    2. Threat Intel Sharing Platforms
        - Search for: `TCESB`, `ToddyCat`, or `CVE-2024-11859`.
            - [https://otx.alienvault.com/browse/global/pulses?q=TCESB&include_inactive=0&sort=-modified&page=1&limit=10&indicatorsSearch=TCESB](https://otx.alienvault.com/browse/global/pulses?q=TCESB&include_inactive=0&sort=-modified&page=1&limit=10&indicatorsSearch=TCESB)
    3. MITRE ATT&CK Framework
        - **T1574.002**: DLL Search Order Hijacking
        - **T1055**: Process Injection
        - **T1218**: Signed Binary Proxy Execution (living off the land)
- **Resources**
    - [https://attack.mitre.org/groups/G1022/](https://attack.mitre.org/groups/G1022/)
    - [https://nvd.nist.gov/vuln/detail/CVE-2024-11859](https://nvd.nist.gov/vuln/detail/CVE-2024-11859)
    - [https://securityaffairs.com/176364/security/an-apt-group-exploited-eset-flaw-to-execute-malware.html](https://securityaffairs.com/176364/security/an-apt-group-exploited-eset-flaw-to-execute-malware.html)
    - [https://www.darkreading.com/vulnerabilities-threats/toddycat-apt-eset-bug-silent-malware](https://www.darkreading.com/vulnerabilities-threats/toddycat-apt-eset-bug-silent-malware)
    - [https://support.eset.com/en/ca8810-dll-search-order-hijacking-vulnerability-in-eset-products-for-windows-fixed](https://support.eset.com/en/ca8810-dll-search-order-hijacking-vulnerability-in-eset-products-for-windows-fixed)
    - [https://securelist.com/toddycat-apt-exploits-vulnerability-in-eset-software-for-dll-proxying/116086/](https://securelist.com/toddycat-apt-exploits-vulnerability-in-eset-software-for-dll-proxying/116086/)
    - [https://www.loldrivers.io/drivers/bb808089-5857-4df2-8998-753a7106cb44/](https://www.loldrivers.io/drivers/bb808089-5857-4df2-8998-753a7106cb44/)
    - [https://www.loldrivers.io/](https://www.loldrivers.io/)
    - [https://www.dell.com/support/kbdoc/en-us/000190106/additional-information-regarding-dsa-2021-152-dell-client-platform-security-update-for-an-insufficient-access-control-vulnerability-in-the-dell-dbutildrv2-sys-driver](https://www.dell.com/support/kbdoc/en-us/000190106/additional-information-regarding-dsa-2021-152-dell-client-platform-security-update-for-an-insufficient-access-control-vulnerability-in-the-dell-dbutildrv2-sys-driver)