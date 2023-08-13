---
title: "Data Breach 01"

header:
  teaser: /assets/images/LetsDefend/PRIVATE-CASE-1/PRIVATE-CASE-1.jpg
  overlay_image: /assets/images/LetsDefend/PRIVATE-CASE-1/PRIVATE-CASE-1.jpg
  overlay_filter: 0.5

ribbon: DarkRed
description: "Unraveling the Enigma of Company Data Sale and Unveiling the Cryptic Clue"
categories:
  - Investigation
  - LetsDefend
tags: 
  - Data Breach
  - SOC
  - LetsDefend
  - Challenges
  - Security Analyst
  - Incident Response

toc: true
toc_sticky: true
toc_label: "Table Of Contents"
toc_icon: "biohazard"
classes: wide
last_modified_at: 
---
<span style = "color: #909090">Category: SOC - LetsDefend - Data Breach</span>

## Alert Phase

| ![alert](/assets/images/LetsDefend/PRIVATE-CASE-1/1.png) | 
|:--:|
| *In this writeup, we will investigate the  Mysterious Data Breach* |

## Answer This Questions

1. Malicious file Name? (Easy)
2. Which programming language is the backdoor written in? (Easy)
3. Backdoor name? (Medium)
4. Who is the author of backdoor? (Medium)
5. What is command&control IP address? (Medium)
6. Which user's password leaked except Administrator user? (Medium)
7. Which tool triggered the reverse shell? (Hard)
8. What is the MD5 of backdoor? (Hard)

    
## Detection Phase

- First we looking for anyone in company called `Anderson` by checking the **Endpoint Security**.

![alert](/assets/images/LetsDefend/PRIVATE-CASE-1/2.png)

- After we check the `Endpoint Security` we found the device called `Desktop-Anderson`.
- Now we check and analyis all Processes, Network Action, Terminal History and Browser History in `Desktop-Anderson`.

- Based on above information:
  - **Hostname:** Desktop-Anderson
  - **IP Address:** 172.16.17.54
  - **OS:** Windows 10
  - **Primary User:** Anderson

---

### First Let's Check Processes

| ![Processes](/assets/images/LetsDefend/PRIVATE-CASE-1/3.png) |
|:--:|
| *Processes* |

The path you've provided, `C:/Users/Anderson/Desktop/services.exe` is a file system path on a Windows operating system. This path points to a specific executable file located on the desktop of the user account named `Anderson`.

- **services.exe**: This is the specific executable file you're referencing. `services.exe` is a critical system process in Windows that manages various system services. It's an essential component of the Windows operating system.

> However, it's important to note that `services.exe` is also a commonly exploited filename used by malware. Legitimate "services.exe" is located in the `C:/Windows/System32` directory. If you encounter `services.exe` in an unusual location like a user's desktop, it could potentially indicate malware or suspicious activity.

---

Now lets go deep inside this process and see more information about this:

| ![Processes](/assets/images/LetsDefend/PRIVATE-CASE-1/4.png) |
|:--:|
| *service.exe* |

- Based on the provided strings, such as `Go build ID` and the `Go-specific` syntax used in the string annotations, it appears that the file `services.exe` is likely written in the **Go programming language**. 


### Then Let's Check Network Action

| ![Processes](/assets/images/LetsDefend/PRIVATE-CASE-1/5.png) |
|:--:|
| *Network Connections* |

- The IP Address that anderson interact with:
  - 🚩 172.16.17.49 (Malicious)
  - 74.6.143.25
  - 13.35.254.24
  - 172.67.202.151
  - 🚩 161.35.41.241 (Malicious)
  - 172.67.202.151

Later we check the `Log Management` to check this IPs Logs.

### Then Let's Check Terminal History

| ![Processes](/assets/images/LetsDefend/PRIVATE-CASE-1/6.png) |
|:--:|
| *Terminal History* |

It looks like you've provided a list of command-line commands along with timestamps. These commands are often used in the Windows Command Prompt to perform various system-related tasks. 

- I'll explain each command for you:
  - ipconfig:
    - This command is used to display the IP configuration settings of the computer, including information about network interfaces, IP addresses, subnet masks, and more.
  - dir:
    - The `dir` command is used to list the files and subdirectories in the current directory.
  - hostname:
    - This command displays the name of the computer within a network.
  - net user:
    - The `net user` command is used to manage user accounts on the system. Without additional parameters, it typically displays a list of user accounts on the computer.
  - whoami:
    - This command displays the username of the currently logged-in user.
  - tasklist:
    - The `tasklist` command displays a list of running processes and their associated information.
  - net user anderson:
    - This command queries the user account information for the user named `anderson.`
  - ping 172.16.20.1:
    - The `ping` command is used to test network connectivity to a specific IP address (in this case, 172.16.20.1). It sends a series of network packets to the specified IP address and measures the response time.



### Checking Log Management


🚩 Now we check the IP address 161.35.41.241:

| ![Processes](/assets/images/LetsDefend/PRIVATE-CASE-1/7.png) |
|:--:|
| *Log Management* |

From above logs, lets try to check logs:

<p align="center">
  <img src="/assets/images/LetsDefend/PRIVATE-CASE-1/8.png" alt="Terminal Shortcuts" style="width:700px">
</p>

This data encoded using Base64, lets try to decode this data by using `cyberchef`

| ![Processes](/assets/images/LetsDefend/PRIVATE-CASE-1/9.png) |
|:--:|
| *cyberchef* |

- Do above proccess for all above log and show secret data 😉

| ![Processes](/assets/images/LetsDefend/PRIVATE-CASE-1/10.png) |
|:--:|
| *cyberchef* |

| ![Processes](/assets/images/LetsDefend/PRIVATE-CASE-1/11.png) |
|:--:|
| *cyberchef* |


🚩 Checking the first log:

<p align="center">
  <img src="/assets/images/LetsDefend/PRIVATE-CASE-1/12.png" alt="Terminal Shortcuts" style="width:700px">
</p>

- Now we can take this content `aqlKZ7wjzg0iKM00E1WB/jq9_RA46w91EKl9A02Dv/nbNdZiLsB1ci8Ph0fb64/9Ks1YxAE86iz9A0dUiDl` and google it, and lets show the results

| ![Processes](/assets/images/LetsDefend/PRIVATE-CASE-1/13.png) |
|:--:|
| *Google* |

- Check this two links and use it for answering the hard questions.

Usefull links:
- [Link 1](https://www.reddit.com/r/PFSENSE/comments/mj6jjx/suricata_alert_backdoorhttpgorat_network_detected/)
- [Link 2](https://github.com/mandiant/red_team_tool_countermeasures/blob/master/all-snort.rules)
- [Link 3](https://github.com/mandiant/red_team_tool_countermeasures/blob/master/all-yara.yar)


## Artifacts

- IP Addresses
  - 161.35.41.241
  -	172.16.17.49
- Hashes
  -	f59095f0ab15f26a1ead7eed8cdb4902


## Flags

<details>
<summary>
1. Malicious file Name? (Easy)
</summary>
services.exe 
</details>

<details>
<summary>
2. Which programming language is the backdoor written in? (Easy)
</summary>
Go programming language
</details>

<details>
<summary>
3. Backdoor name? (Medium)
</summary>
HTTP.GORAT
</details>

<details>
<summary>
4. Who is the author of backdoor? (Medium)
</summary>
FireEye
</details>

<details>
<summary>
5. What is command&control IP address? (Medium)
</summary>
161.35.41.241
</details>

<details>
<summary>
6. Which user’s password leaked except Administrator user? (Medium)
</summary>
- Anderson:ander12son! <br>
- Administrator:mys3r3tP@ss!
</details>

<details>
<summary>
7. Which tool triggered the reverse shell? (Hard)
</summary>
impacket
</details>

<details>
<summary>
8. What is the MD5 of backdoor? (Hard)
</summary>
f59095f0ab15f26a1ead7eed8cdb4902
</details>


---

Protect Your Digital Presence & Stay Cyber Safe 💙

Thanks🌸
