---
title: "FalconEye Challenge"
header:
  teaser: /assets/images/CyberDefenders/Falcon_Eye/c85.png
  overlay_image: /assets/images/CyberDefenders/Falcon_Eye/c85.png
  overlay_filter: 0.5

ribbon: DarkSlateGray
description: "FalconEye Blue Team Challenge"
tags: 
  - Cyber Defenders
  - SOC
  - INE
  - Splunk
  - SIEM
  - FalconEye
categories:
  - Digital Forensics

toc: false
toc_sticky: false
toc_label: "On This Blog"
toc_icon: "biohazard"
classes: wide
last_modified_at: 
---
<span style="color: #909090">Category: Cyber Defenders - FalconEye - SPLUNK </span>


### Scenario:

As a SOC analyst, you aim to investigate a security breach in an **Active Directory network** using **Splunk** SIEM (Security information and event management) solution to uncover the **attacker's steps** and **techniques** while creating a **timeline** of their activities. 
The investigation begins with **network enumeration** to identify potential vulnerabilities. Using a specialized **privilege escalation tool**, the attacker exploited an **unquoted service path vulnerability** in a specific process.

Once the attacker had elevated access, the attacker launched a **DCsync attack** to extract sensitive data from the **Active Directory domain controller**, compromising user accounts. 

The attacker employed **evasion techniques** to avoid detection and utilized **pass-the-hash (pth) attack** to gain unauthorized access to user accounts. 

Pivoting through the network, the attacker explored different systems and established **persistence**.

Throughout the investigation, **tracking the attacker's activities** and creating a comprehensive **timeline is crucial**. This will provide valuable insights into the attack and aid in identifying potential gaps in the network's security.

|![Untitled](/assets/images/CyberDefenders/Falcon_Eye/Untitled.png)|
|:--:|
||

> **JumpBox/Bastion Host** is a server used to **manage access to an internal or private network from an external network** - sometimes called a ju**mp box** or **jump server**. Because bastion hosts often sit on the Internet, they typically run a minimum amount of services in order to reduce their attack surface.
> 

---

### Tools:

- Splunk SIEM Solution

---

### Task 1: 
- 1.1. What is the name of the compromised account?
- 1.2. What is the name of the compromised machine?
- 1.3. What tool did the attacker use to enumerate the environment?

We can start the investigation by first identifying the indexes, hosts and log sources available to us, by setting the time range to “All Time” and running the Splunk Search Processing Language (SPL) query below.

```bash
index=*
| dedup index 
| table index
```

|![Untitled](/assets/images/CyberDefenders/Falcon_Eye/Untitled%201.png)|
|:--:|
||

There are one index called `folks`

---

Now lets try to identify the available log sources:

```bash
index="folks" 
| stats values(index) as index values(sourcetype) as sourcetype count by source
```


🎯 The **source** is the name of the file, stream, or other input from which a particular event originates. The **sourcetype** determines how Splunk software processes the incoming data stream into individual events according to the nature of the data.



|![Untitled](/assets/images/CyberDefenders/Falcon_Eye/Untitled%202.png)|
|:--:|
||

The log sources returned include:

- **“XmlWinEventLog:Security”**: Contain events related to Windows **authentication** and security processes.
- **“XmlWinEventLog:Application”**: Contain events logged by various applications and/or user programs, including any **errors** or info that an application is deigned to report.
- **“XmlWinEventLog:System”**: Contain events **logged** by various Windows system components.
- **“XmlWinEventLog:Mircrosoft-Windows-Sysmon/Operational”**: commonly used add-on for Windows **logging**. With Sysmon logs, you can detect malicious activity by tracking **code behavior** and network traffic, as well as create **detections** based on the malicious activity.
- **“XmlWinEventLog:Microsoft-Windows-PowerShell/Operational”**: logs PowerShell **activity**.

---

Finally, lets identify the hosts using this query:

```bash
index="folks" (NOT source=*Splunk*) (NOT source=*Perfmon*) 
| dedup host
| table host source sourcetype
| sort + host
```

|![Untitled](/assets/images/CyberDefenders/Falcon_Eye/Untitled%203.png)|
|:--:|
||

The available hosts:

- **ABDULLAH**
- **ALI**
- **CLIENT01**
- **CLIENT02**
- **CLIENT03**

---

Given our ongoing investigation into a security breach within an Active Directory (AD) network, I decided to start hunting for common tactics and techniques used by threat actors once they have gained an initial foothold inside an AD network.

Lets start investigation by looking at the PowerShell logs, specifically **Event ID 4104** and **4103** which is commonly used by adversaries ([MITRE T1059.001](https://attack.mitre.org/techniques/T1059/001/)).

> **Event ID 4103** – Module logging – Attackers uses several obfuscated commands and calls self-defined variables and system commands. Hunting these EventIDs provide SOC operations to record all the obfuscated commands as **pipeline** execution details under EventID 4103. It should be enabled to process and get the malicious commands.
> 

> **Event ID 4104** – Powershell Script Block Logging – Captures the entire scripts that are executed by remote machines. For example, obfuscated scripts that are decoded and executed at run time.
> 

I executed the following query to retrieve PowerShell event IDs 4104:

```bash
index=folks sourcetype=XmlWinEventLog source=XmlWinEventLog:Microsoft-Windows-PowerShell/Operational EventCode=4104
```

|![Untitled](/assets/images/CyberDefenders/Falcon_Eye/Untitled%204.png)|
|:--:|
||

From above output the attacker had used **PowerView - Bloodhound** to enumerate the active directory network. Now let's dig deeper through the event by using the following query**:**

```bash
index=folks sourcetype=XmlWinEventLog source=XmlWinEventLog:Microsoft-Windows-PowerShell/Operational EventCode=4104 
ScriptBlockText IN (*bloodhound*, *sharphound*, *powerview*)
| stats values(ScriptBlockText) as power_shell_script by _time host
```

|![Untitled](/assets/images/CyberDefenders/Falcon_Eye/Untitled%205.png)|
|:--:|
||


|![Untitled](/assets/images/CyberDefenders/Falcon_Eye/Untitled%206.png)|
|:--:|
||

---

From above screen the attacker used **BloodHound Tool** to enumerate the active directory network on the hostname `CLIENT02` that was the compromised machine at *`2023–05–10 03:28:41.`*

Now let's invistigate deeper through Sysmon events belongs to the compromised host `CLIENT02` by filtering for Sysmon `Event ID 1` and setting a filter for the parent process to be `PowerShell`. I also set the time range for event since *`2023–05–10`* using the following query:

```bash
index="folks" sourcetype="xmlwineventlog" source="xmlwineventlog:microsoft-windows-sysmon/operational"  host=CLIENT02 EventID=1 
ParentImage="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
| stats values(User) as user values(OriginalFileName) as file_executed values(CommandLine) as cmd_line by _time host
```

|![Untitled](/assets/images/CyberDefenders/Falcon_Eye/Untitled%207.png)|
|:--:|
||

Scroll down to reach the date **(2023–05–10)** that the **BloodHound Tool** was executed to enumerate the active directory network

|![Untitled](/assets/images/CyberDefenders/Falcon_Eye/Untitled%208.png)|
|:--:|
||

---

From above investigation, I can see that the attacker execute the `whoami.exe` at `2023-05-10 02:09:57` to displays the user you are currently logged in a system then use the `bloodhound` tool at `2023-05-10 03:27:51` to enumerate the active directory network then do additional enumerate using `net.exe` at `2023-05-10 03:27:51` and also used `mimikatz.exe` tool at `2023-05-10 05:10:30` for dumping the credentials. All these activities performed under the compromised account called `Abdullah-work\Helpdesk`.

---

### Task 2: 
- 2.1. The attacker used Unquoted Service Path to escalate privileges.
- 2.2. What is the name of the vulnerable service?
- 2.3. What is the SHA256 of the executable that escalates the attacker privileges?

An unquoted service path vulnerability occurs when the file path associated with a Windows service **does not have quotes (“”)** ([MITRE T1574.009](https://attack.mitre.org/techniques/T1574/009/)).

```bash
# Does't Use Quotes (Malicous)
C:\ProgramFiles\ATlTechnologies\ATl.ACE\Fuel\Fuel.Service.exe
	- In the case of the service on your right. Windows will search for the executable as follows.
			- "C:\Program.exe"Files\ATlTechnologies\ATl.ACE\Fuel\Fuel.Service.exe
			- "C:\ProgramFiles\ATl.exe"Technologies\ATl.ACE\Fuel\Fuel.Service.exe
			- "C:\ProgramFiles\ATlTechnologies\ATl.ACE\Fuel\Fuel.Service.exe"

# Use Quotes
"C:\ProgramFiles\ATlTechnologies\ATl.ACE\Fuel\Fuel.Service.exe"
```

An attacker could exploit this vulnerability by placing a malicious executable named `"C:\Program.exe"` to gain unauthorized access. As you can see there are some spaces in the **PATH** and Windows OS looks at the PATH like this when a service is starting.

```bash
- C:\Program.exe
- C:\Program Files.exe
- C:\Program Files\Unquoted.exe
- C:\Program Files\Unquoted Path.exe
- C:\Program Files\Unquoted Path Service.exe
- C:\Program Files\Unquoted Path Service\Common.exe
```

---

Now let's invistigate deeper through Sysmon events belongs to the compromised host `CLIENT02` by filtering for Sysmon `Event ID 1` and setting a filter for the parent process to be `services.exe`using the following query:

```bash
index="folks" sourcetype="xmlwineventlog" source="xmlwineventlog:microsoft-windows-sysmon/operational"  host=CLIENT02 EventID=1 
ParentImage="C:\\Windows\\System32\\services.exe" 
| stats values(Image) as Image values(CommandLine) as cmd_line values(Hashes) as MD5_Hash by _time host
```

|![Untitled](/assets/images/CyberDefenders/Falcon_Eye/Untitled%209.png)|
|:--:|
||

In the results above, the Image field does not accurately reflect the **full path** to the executable, indicating a potential **unquoted service path** vulnerability. The executed process is *`C:\Program Files\Basic Monitoring\Automate-Basic-Monitoring.exe`* is the vulnerable service, but it is running with the image name of *`program.exe`*, which suggests an **exploitation** attempt**.** 

---

Let’s try another method to find the **unquoted service path** vulnerability using [Splunk detection](https://research.splunk.com/endpoint/cbef820c-e1ff-407f-887f-0a9240a2d477/) (**Detect Path Interception By Creation Of program exe)** by using the following query:

```bash
index=folks sourcetype=XmlWinEventLog source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1 host=CLIENT02 
| rex field=CommandLine "^.*?\\\\(?<cmdline_process>[^\\\\]*\.(?:ps1|bat|com|exe))"
| rex field=Image "^.*?\\\\(?<child_process>[^\\\\]*\.(?:ps1|bat|com|exe))"
| eval cmdline_process=lower(cmdline_process), child_process=lower(child_process)
| where cmdline_process!=child_process
| table _time host User Image CommandLine Hashes
```

|![Untitled](/assets/images/CyberDefenders/Falcon_Eye/Untitled%2010.png)|
|:--:|
||

The `program.exe` SHA256 hash: 8ACC5D98CFFE8FE7D85DE218971B18D49166922D079676729055939463555BD2

---

### Task 3: 
- When did the attacker download fun.exe? (24H-UTC)

Now invistigate Sysmon **EventCode = 11** to return file create operations and filter for the file name *`fun.exe`* using the following query:

```bash
index=folks sourcetype=XmlWinEventLog source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational host=CLIENT02 EventCode=11
| search "fun.exe"
| table _time host TargetFilename
```

|![Untitled](/assets/images/CyberDefenders/Falcon_Eye/Untitled%2011.png)|
|:--:|
||

From above result the downloaded time for `fun.exe` is `2023-05-10 05:08:57`.**

---

### Task 4: 
- 4.1. What is the command line used to launch the DCSync attack?
- 4.2. What is the original name of fun.exe?

- DCSync Attack
    - A DCSync attack is a method used to extract password hashes of user accounts from an Active Directory domain controller ([MITRE T1003.006](https://attack.mitre.org/techniques/T1003/006/)).
    - Adversaries may attempt to access credentials and other sensitive information by abusing a Windows Domain Controller's application programming interface (API) to simulate the replication process from a remote domain controller using a technique called DCSync.
    - Members of the Administrators, Domain Admins, and Enterprise Admin groups or computer accounts on the domain controller are able to run DCSync to pull password data from Active Directory, which may include current and historical hashes of potentially useful accounts such as KRBTGT and Administrators.
    - The attacker impersonates a domain controller, requests replication data, specifically targeting user account objects, and retrieves the password hashes.
    - With the hashes, the attacker can attempt to crack or decrypt them to obtain the users’ passwords and gain unauthorized access to the network resources.
    - DCSync functionality has been included in the "lsadump" module in Mimikatz. Lsadump also includes NetSync, which performs DCSync over a legacy replication protocol

---

Now let's invistigate deeper through Sysmon events belongs to the compromised host `CLIENT02` by filtering for Sysmon `Event ID 1` and setting a filter for the parent process to be `PowerShell`.

```bash
index="folks" sourcetype="xmlwineventlog" source="xmlwineventlog:microsoft-windows-sysmon/operational"  host=CLIENT02 EventID=1 
ParentImage="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
| stats values(User) as user values(OriginalFileName) as file_executed values(CommandLine) as cmd_line by _time host
```

|![Untitled](/assets/images/CyberDefenders/Falcon_Eye/Untitled%2012.png)|
|:--:|
||

Or try to use the following query:

```bash
index="folks" sourcetype="xmlwineventlog" source="xmlwineventlog:microsoft-windows-sysmon/operational"  host=CLIENT02 EventID=1 
ParentImage="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
| search "*Lsadump::dcsync*"
| table _time host User OriginalFileName CommandLine
```

|![Untitled](/assets/images/CyberDefenders/Falcon_Eye/Untitled%2013.png)|
|:--:|
||

We can see that the attacker used `mimikatz.exe`, which is the original name for `fun.exe` to perform a **DCSync attack.**

---

### Task 5: 
- 5.1. The attacker performed the Over-Pass-The-Hash technique. What is the AES256 hash of the account he attacked?
- 5.2. What service did the attacker abuse to access the Client03 machine as Administrator?

**OverPass-the-Hash (PtH)** occurs when an attacker uses a password hash to authenticate as a user but also uses the password hash to create a valid Kerberos ticket ([MITRE T1550.002](https://attack.mitre.org/techniques/T1550/002/)).

The overpass-the-hash attack is a combination of two other attacks: **[pass-the-hash](https://blog.netwrix.com/2022/09/28/how-to-detect-pass-the-ticket-attacks/)** and [**pass-the-ticket](https://stealthbits.com/blog/how-to-detect-pass-the-ticket-attacks/).** All three techniques fall under the [Mitre category](https://attack.mitre.org/techniques/T1210/) “Exploitation of remote services.”

In an overpass-the-hash attack, an adversary leverages the **NTLM hash** of a user account to obtain a **Kerberos ticket** that can be used to access network resources. This technique is handy if you are not able to obtain the **cleartext password** for an account but require Kerberos authentication to reach your destination. This attack can be used to perform actions on **local or remote servers**. The most common tools used to perform this kind of attack are [`Mimikatz`](https://blog.netwrix.com/2021/11/30/passing-the-hash-with-mimikatz/)** and `Rubeus`.

Lets execute the previous query:

```bash
index="folks" sourcetype="xmlwineventlog" source="xmlwineventlog:microsoft-windows-sysmon/operational"  host=CLIENT02 EventID=1 
ParentImage="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
| search mimikatz OR rubeus
| stats values(User) as user values(OriginalFileName) as file_executed values(CommandLine) as cmd_line by _time host
```

> [Rubeus](https://github.com/GhostPack/Rubeus) is a tool that can be used to perform an Overpass the Hash attack ([HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/over-pass-the-hash-pass-the-key)). Using the query below, we can filter for `Rubeus.exe` and observe the `AES256` hash of the account that was attacked.
> 

|![Untitled](/assets/images/CyberDefenders/Falcon_Eye/Untitled%2014.png)|
|:--:|
||

If we want to get an idea of the AES256 Hash of the compromise machine, we can do that by following Search Query:

```bash
index="folks" sourcetype="xmlwineventlog" source="xmlwineventlog:microsoft-windows-sysmon/operational"  host=CLIENT02 EventID=1   
ParentImage="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" OriginalFileName="Rubeus.exe"
| stats values(User) as user values(OriginalFileName) as file_executed values(CommandLine) as cmd_line by _time host
```

|![Untitled](/assets/images/CyberDefenders/Falcon_Eye/Untitled%2015.png)|
|:--:|
||

Once again, we can use the above query for PowerShell command line activity and look through the events returned to know the service did the attacker abuse to access the Client03 machine as administrator.

```bash
index="folks" sourcetype="xmlwineventlog" source="xmlwineventlog:microsoft-windows-sysmon/operational"  host=CLIENT02 EventID=1   
ParentImage="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" OriginalFileName="Rubeus.exe"
| search CLIENT03
| stats values(User) as user values(OriginalFileName) as file_executed values(CommandLine) as cmd_line by _time host
```

|![Untitled](/assets/images/CyberDefenders/Falcon_Eye/Untitled%2016.png)|
|:--:|
||

The attacker exploit the `msdsspn:http` service on `Client03` as administrator.

> Constrained delegation is a legitimate feature in Active Directory that allows a service to impersonate a user and access resources on their behalf. However, if not properly configured, it can be abused by attackers to gain unauthorized access to sensitive resources. Based on the command structure, we can see that the attacker abused the `http/Client03` service.
> 

```bash
.\Rubeus.exe s4u /ticket:TGT_Ticket /msdsspn:"service/HOST" /impersonateuser:Administrator /ptt
```

---

### Task 6: 
- The Client03 machine spawned a new process when the attacker logged on remotely. What is the process name?

From above task the attacker performed the constrained delegation attack to gain access to the host `CLIENT03` using http service at `2023-05-10 06:18:19`.Next, we need to check for what processes were spawned after the attacker logged in and set the time range to after `2023-05-10 06:18:19` using the following query:

```bash
index=folks sourcetype=XmlWinEventLog source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1 host=CLIENT03 NOT CommandLine IN (*splunk*)
| table _time OriginalFileName Image CommandLine
```

Scroll down to reach a time include: `2023-05-10 06:**:`

|![Untitled](/assets/images/CyberDefenders/Falcon_Eye/Untitled%2017.png)|
|:--:|
||


|![Untitled](/assets/images/CyberDefenders/Falcon_Eye/Untitled%2018.png)|
|:--:|
||

I can see that the first process was run after `2023-05-10 06:18:19` is `wsmprovhost.exe` **was spawned at `2023–05–10 06:21:44`, which is an executable file that is associated with the **Windows Remote Management (WinRM)** service.

---

### Task 7: 
- The attacker compromises the it-support account. What was the logon type?

Once again, we can use the above query for PowerShell command line activity using search `it-support`:

```bash
index="folks" sourcetype="xmlwineventlog" source="xmlwineventlog:microsoft-windows-sysmon/operational"  host=CLIENT02 EventID=1   
ParentImage="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" 
| search "*it-support*"
| stats values(User) as user values(OriginalFileName) as file_executed values(CommandLine) as cmd_line by _time host
```

|![Untitled](/assets/images/CyberDefenders/Falcon_Eye/Untitled%2019.png)|
|:--:|
||

We can see that the account `it-support` was compromised via **Over-Pass-The-Hash-Attack** on **Client02** at *`2023–05–10 06:49:48`*.

> *A successful pass-the-hash operation will also generate event **4624**, which has the **login type 9** as its **logon**. The executing user’s Logon ID is recorded in this event, so we can cross-reference this event with the event that recorded the process creation.*
> 

Next, using the following search query to identify the `LogonID` field for this event 4624:

```bash
index="folks" sourcetype="xmlwineventlog" source="xmlwineventlog:security" EventCode=4624 Logon_Type=9 Logon_ID=0x22ab48
| table _time Logon_Type Target_User_Name host Logon_ID
```

|![Untitled](/assets/images/CyberDefenders/Falcon_Eye/Untitled%2020.png)|
|:--:|
||

---

### Task 8:
- What ticket name did the attacker generate to access the parent DC as Administrator?

Looking back at results for the query of PowerShell command line activity, we can see that the threat actor is using mimikatz to create [golden tickets](https://book.hacktricks.xyz/windows-hardening/stealing-credentials/credentials-mimikatz).

```bash
index=folks sourcetype=XmlWinEventLog source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational host=CLIENT02 EventCode=1 
ParentImage="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" 
| search */ticket:*
| stats values(User) as user values(OriginalFileName) as file_name values(CommandLine) as cmdline by _time host
```

|![Untitled](/assets/images/CyberDefenders/Falcon_Eye/Untitled%2021.png)|
|:--:|
||

The threat actor use ticket `trust-test2.kirbi` for the malicious activity.

**Notes:**

> *A Golden Ticket is a TGT using the KRBTGT NTLM password hash to encrypt and sign.*

> *A Golden Ticket (GT) can be created to impersonate any user (real or imagined) in the domain as a member of any group in the domain (providing a virtually unlimited amount of rights) to any and every resource in the domain.*

> The Mimikatz command to create a golden ticket includes the parameter “/ticket (optional)”, which provides a path and name for saving the Golden Ticket file to for later use. The attacker could also use /ptt to immediately inject the golden ticket into memory. The SPL query below is used to filter on this parameter and checking through the results, I can see the name of the ticket.


---

In conclusion, I really enjoyed working through this challenge and getting the opportunity to learn more about investigating incidents using Splunk. The challenge provides opportunities to learn about different log sources (e.g. Sysmon, Windows Events, etc.), different adversary techniques and threat hunting with Splunk.
