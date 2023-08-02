---
title: "SOC175 - PowerShell Found in Requested URL"

header:
  teaser: /assets/images/LetsDefend/SOC175/SOC175.jpg
  overlay_image: /assets/images/LetsDefend/SOC175/SOC175.jpg
  overlay_filter: 0.5

ribbon: DarkRed
description: "This 0-day vulnerability (CVE-2022-41082) is being actively exploited in the wild."
categories:
  - Security Alert
  - LetsDefend
tags: 
  - FakeGPT
  - SOC
  - LetsDefend
  - Challenges
  - Security Analyst

toc: true
toc_sticky: true
toc_label: "On This Blog"
toc_icon: "biohazard"
classes: wide
last_modified_at: 
---
<span style="color: #909090">Category: SOC - LetsDefend - PowerShell</span>


| ![FakeGPT](/assets/images/LetsDefend/SOC175/SOC175.png) | 
|:--:| 
| *In this writeup, we will investigate the  SOC175 - PowerShell Found in Requested URL - Possible CVE-2022-41082 Exploitation* |


## Alert Phase

| ![Screenshot For The Alert](/assets/images/LetsDefend/SOC175/SOC_175.png) | 
|:--:| 
| *Screenshot For The Alert* |

-  We can take a quick look at the "Alert Trigger Reason" in the alert details and understand the root cause of the alert.
- It appears that there is a suspicious request URL contains PowerShell on a system named `Exchange Server 2` with an IP address of `172.16.20.8`, and this alert from IP address `58.237.200.6`.
- The Alert is triggered by the `SOC175 - PowerShell Found in Requested URL - Possible CVE-2022-41082 Exploitation`.
- Based on this information, it appears that the requested URL `/autodiscover/autodiscover.json?@evil.com/owa/&Email=autodiscover/autodiscover.json%3f@evil.com&Protocol=XYZ&FooProtocol=Powershell` from user-agent `Mozilla/5.0 zgrab/0.x`.


<details>
  <summary>
  (CVE-2022-41082)
  </summary>
    <br>
    In early August, the GTSC SOC team (Vietnamese company) discovered two new vulnerabilities that were reported to the Zero-day Initiative (ZDI) to enable further coordination with Microsoft.
    <br><br>
    The zero-day vulnerabilities affecting Microsoft Exchange Server, CVE-2022–41040 and CVE-2022–41082, were disclosed by Microsoft security researchers on September 29. When combined, the vulnerabilities permit remote code execution (RCE).
    <br><br>
    According to <a href="https://www.microsoft.com/en-us/security/blog/2022/09/30/analyzing-attacks-using-the-exchange-vulnerabilities-cve-2022-41040-and-cve-2022-41082/">MSTIC</a> the attack is made by chaining CVE-2022–41040 and CVE-2022–41082 in a small number of targeted attacks and observed these attacks in fewer than 10 organizations globally.
    <br><br>
    CVE-2022–41040 is a server-side request forgery (SSRF) vulnerability, while CVE-2022–41082, allows remote code execution (RCE) when <a href="https://msrc.microsoft.com/blog/2022/09/customer-guidance-for-reported-zero-day-vulnerabilities-in-microsoft-exchange-server/">Exchange PowerShell</a> is accessible to the attacker. It’s vital to remember that in order to be exploited, both require authenticated access to the desired server. The authentication needed for exploitation can be that of a standard user.
    <br><br>
    CVE-2022–41082 looks very similar to ProxyShell, a chain of three vulnerabilities in Exchange Server discovered by Orange Tsai in 2021. The original ProxyShell attack chain did not require authentication, while CVE-2022–41082 does.
    <br><br>
    <img src="/assets//images/LetsDefend/SOC175/1.png">
    Diagram of attacks using Exchange vulnerabilities CVE-2022-41040 and CVE-2022-41082
</details>

> In general, there are indications of potential malicious activity on the system, necessitating a thorough investigation to ascertain the full scope of the activity and to devise appropriate measures for remediation.

## Detection Phase

- As a security analyst, one of the first steps we take to **verify** the alert and determine whether it is a **false positive** or a **true positive** incident is to analyze the logs collected from the host by our security products.
- The first step we can take to investigate the alert is to examine the system logs of the `Exchange Server 2` host under **Log Management** to identify any **unusual** or **suspicious** activities that may be related to the reported incident.
- This includes looking for any **Request URL** and **Device Action** initiated around the **same time** as the suspicious extension installation.

---

### 📍 First Let's Check Log Management..

| ![Log Management](/assets/images/LetsDefend/SOC175/2.png) | 
|:--:| 
| *Log Management* |

- When examining the logs on the Exchange Server 2 host, we have discovered that some requests on port `443` by the source IP address `58.237.200.6`.

Now Lets check this IP address `58.237.200.6`:

## Analysis Phase

| ![VirusTotal](/assets/images/LetsDefend/SOC175/3.png) | 
|:--:| 
| *VirusTotal [Result](https://www.virustotal.com/gui/ip-address/58.237.200.6)* |

- After we submit the file hash in VirusTotal, there are total of 1 security vendors flagged this file as malicious.

<p align="center">
  <img src="/assets/images/LetsDefend/SOC175/4.png" alt="Terminal Shortcuts" style="width:700px">
</p>


- The vulnerability exploit remote code execution when Exchange PowerShell is accessible to the attacker.

<p align="center">
  <img src="/assets/images/LetsDefend/SOC175/5.png" alt="Terminal Shortcuts" style="width:700px">
</p>

- The type of the attack is `other` becouse the vulnerability exploit `remote code execution` when Exchange PowerShell is accessible to the attacker.

<p align="center">
  <img src="/assets/images/LetsDefend/SOC175/6.png" alt="Terminal Shortcuts" style="width:700px">
</p>


- It can be stated that there is no intention behind it. There is no available evidence of email communication or any exercises related to simulations.

<p align="center">
  <img src="/assets/images/LetsDefend/SOC175/7.png" alt="Terminal Shortcuts" style="width:700px">
</p>



- Based on our analysis of the logs, the traffic direction observed is from the Internet towards the company.

<p align="center">
  <img src="/assets/images/LetsDefend/SOC175/8.png" alt="Terminal Shortcuts" style="width:700px">
</p>



- Based on information this attack is unsuccessful becouse the AV was blocked it.

<p align="center">
  <img src="/assets/images/LetsDefend/SOC175/9.png" alt="Terminal Shortcuts" style="width:700px">
</p>


- No, there is no requirement for Tier 2 Escalation due to the fact that the attack has not been successful. Therefore, escalation to Tier 2 is unnecessary at this time.


## Artifacts

- IP Address : 58.237.200.6

## Closed Alert

| ![Containment](/assets/images/LetsDefend/SOC175/10.png) | 
|:--:| 
| *Closed Alert* |

> We see our results. Woohoo! All correct! No one is perfect all the time however, and if you missed anything you can always re-investigate the case.

<p align="center">
  <img src="/assets/images/LetsDefend/SOC202/5.jpeg" alt="Terminal Shortcuts" style="width:300px">
</p>

---

Protect Your Digital Presence & Stay Cyber Safe 💙

Thanks🌸