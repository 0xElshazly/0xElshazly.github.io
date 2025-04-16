---
title: "APT35 (Charming Kitten)"

header:
  teaser: /assets/images/APTs/CharmingKitten/ce38_Blog_CharmingKitten3_3.webp
  overlay_image: /assets/images/APTs/CharmingKitten/ce38_Blog_CharmingKitten3_3.webp
  overlay_filter: 0.5

ribbon: DarkRed
description: "APT35 has been active since at least 2013 and is recognized for its sophisticated use of social engineering tactics."
categories:
  - APTs
tags: 
  - APT35
  - Charming Kitten
  - SOC


toc: true
toc_sticky: true
toc_label: "On This Blog"
toc_icon: "biohazard"
classes: wide
last_modified_at: 
---
<span style="color: #909090">Category: Charming Kitten - APT35 - APTs</span>



# APT35 (Charming Kitten)

- **Summary**
    
    **APT35**, also known as ***Charming Kitten***, is a state-sponsored Advanced Persistent Threat (APT) group linked to the **Iranian government**. This group is primarily known for conducting cyber-espionage campaigns targeting political dissidents, government organizations, journalists, and academic institutions. Their operations often involve phishing campaigns, malware deployment, and strategic use of social engineering to exfiltrate sensitive data.
    
    **APT35** has been active since at least **2013** and is recognized for its sophisticated use of **social engineering tactics** to infiltrate its targets. Their objectives are often aligned with **Iranian** national interests, including monitoring dissent, gathering intelligence, and disrupting adversaries.
    
    **Aliases:** Charming Kitten, Phosphorus, Newscaster Team, Ajax Security Team
    
    **Target Sectors:** U.S., Western Europe, and Middle Eastern military, diplomatic, and government personnel organizations in the media, energy, and defense Industrial base, engineering, business services, and telecommunications sectors.
    
## Stages of the Attack Vector
- **Stages of the Attack Vector**
    1. **Initial Contact via Email**
        - The attacker sends a **phishing email** utilizing social engineering techniques.
        - The email impersonates a **reputable** individual, such as a **journalist** or **researcher**, inviting the target to a fabricated event supposedly organized by the impersonated person.
        - In some cases, the email is crafted in the recipient’s **native language** to increase credibility.
    2. **Redirection to Decoy Websites**
        - Victims are redirected to a fake website designed to **mimic legitimate** Google services, such as Gmail or Google Drive, through links in the phishing email.
        - This tactic has been observed in previous campaigns, emphasizing the group's consistent reliance on trusted brand impersonation.
    3. **Emergence of New Phishing Vectors**
        - APT35 introduced new phishing websites that impersonate non-Google services, such as **Instagram's** official login page.
        - This marks the first documented instance of the group targeting credentials outside of Google-related services, showcasing an evolution in their attack strategy.

## Phishing Email Analysis
- **Phishing Email Analysis**
    
    Phishing is one of the main tactics that has been used by the **Charming Kitten**, and social engineering and fake emails are the usual methods of executing it.
    
    In this campaign, the Charming Kitten has used the identity of a former **Wall Street Journal (WSJ)** journalist and created a fake interview scenario to target their victims.
    
    **Step 1: **Gaining** Trust**
    
    In a reported case, the attackers impersonated Farnaz Fassihi, a journalist for *The New York Times* and former *Wall Street Journal* reporter, to deceive their targets.
    
    They crafted fake interview request emails, claiming to represent her, and used these emails to lure victims to phishing websites. The emails were sent from the address `farnaz.fassihi [at] gmail [dot] com` to appear credible and build trust with the recipients. 
    
    Below is an example of the email content used in this campaign.
    
    ![**Fake interview request via an email**](/assets/images/APTs/CharmingKitten/image.png)
    
    Fake interview request via an email
    
    **Step 2: Executing the Main Attack**
    
    Once communication is established and the victim’s trust is secured through the initial email, the attackers proceed to the next phase. They send the victim a link, presented as a file containing interview questions.
    
    In the observed samples, Charming Kitten utilized phishing pages hosted on Google Sites, a tactic designed to exploit the trust associated with legitimate Google domains. 
    
    For example, a typical URL might resemble: `hxxps://sites.google[.]com/view/the-wall-street/xxxx`. This approach allows the attackers to bypass spam filters and evade detection mechanisms, leveraging the credibility of Google's infrastructure. 
    
    Below is a representation of such phishing pages:
    
    ![**Fake WSJ page that is hosted on Google Site**](/assets/images/APTs/CharmingKitten/image%201.png)
    
    Fake WSJ page that is hosted on Google Site
    
    **Step 3: Capturing Credentials**
    
    After the victim clicks the download button on the Google Sites phishing page, they are redirected to another fake page hosted on the domain `two-step-checkup[.]site`
    
    This page is designed to appear as a legitimate login page, requesting the victim’s email credentials, including their password and two-factor authentication (2FA) code.
    
    The structure of the phishing URLs is as follows:
    
    - `hxxps://two-step-checkup[.]site/securemail/secureLogin/challenge/url?ucode=xxxx-xxxx&service=mailservice&type=password`
    - `hxxps://two-step-checkup[.]site/securemail/secureLogin/challenge/url?ucode=xxxx-xxxx&service=mailservice&type=smscode`
    - `hxxps://two-step-checkup[.]site/ymail/secureLogin/challenge/url?ucode=xxxx-xxxx&service=mailservice&type=password`
    - `hxxps://two-step-checkup[.]site/ymail/secureLogin/challenge/url?ucode=xxxx-xxxx&service=mailservice&type=smscode`
    
    These phishing pages are built using advanced phishing kits, such as **Modlishka**, which enable attackers to intercept both passwords and 2FA codes. This method is critical for compromising accounts with multi-factor authentication enabled. **Charming Kitten** has been observed using this technique extensively in targeted attacks over the past year.
    
    Illustrates an example of a phishing page used to capture SMS authentication codes.
    
    ![Phishing attack to steal 2FA code via SMS](/assets/images/APTs/CharmingKitten/image%202.png)
    
    Phishing attack to steal 2FA code via SMS
    
## Execution of Malware
- **Execution of Malware**
    
    **Malware Development**
    
    A notable aspect of this campaign is the use of **“pdfreader.exe”**, a malware with backdoor functionality. The technical analysis of the malware indicates a direct link between its developers and the actors behind the recent phishing attacks. This correlation strongly suggests that these malicious activities are orchestrated by the same group, believed to be **Charming Kitten**.
    
    - **pdfreader.exe Functionality**
        
        The malware, identified by antivirus programs as a **Win32/Backdoor**, is a moderately sophisticated tool with the following harmful capabilities:
        
        - **System Modifications:**
            - Alters Windows Firewall and Registry settings to enable automatic execution.
        - **Information Gathering:**
            - Collects sensitive data from the victim’s device and transmits it to its developers.
        - **Remote Control:**
            - Enables attackers to deploy additional malware or spyware on the compromised system remotely.
        
        The malware’s process graph, showcasing its functionality and operational flow:
        
        ![**pdfReader.exe Process**](/assets/images/APTs/CharmingKitten/image%203.png)
        
        pdfReader.exe Process
        
    - **pdfReader.exe Connections**
        
        An important aspect of the **pdfreader.exe** malware is its communication with the IP address **51.89.237.234** over port 80. This connection highlights its reliance on external servers for malicious activities.
        
        - **Timeline of Submissions to VirusTotal**
            - **03 October 2019, 07:14:22 GMT:** The malware was first submitted to VirusTotal as a compressed file named `pdfreader.zip`.
            - **03 October 2019, 11:00:25 GMT:** The standalone executable version, `pdfreader.exe`, was uploaded to VirusTotal four hours later.
        
        These submissions are tied to the IP history of **51.89.237.233**, showing prior interactions related to the malware.
        
        **Malicious Server Connections**
        
        The server with IP address **51.89.237.234** was identified as hosting the following malicious domains:
        
        - `software-updating-managers[.]site`
        - `malcolmrifkind[.]site`
        
        These domains appear to serve as infrastructure supporting the malware’s operations, including possible distribution, command and control (C2), or further malicious payload delivery.
        
        This analysis reinforces the hypothesis that pdfreader.exe is a critical tool in the Charming Kitten campaign, designed to enable remote access and facilitate ongoing malicious activity.
        
        ![**IP history of 51.89.237.233 on VirusTotal**](/assets/images/APTs/CharmingKitten/image%204.png)
        
        **IP history of 51.89.237.233 on VirusTotal**
        

## Charming Kitten Server Footprints
- **Charming Kitten Server Footprints**
    
    An important finding in this campaign is the similar server setups used by Charming Kitten. During the second half of 2019, many of the servers linked to the group showed consistent patterns in their configurations.
    
    - **Common Server Features**
        - **Operating Systems and Tools:**
            - Most servers ran on Windows machines.
            - They used software like OpenSSL, PHP, Apache, and Microsoft-HTTP API.
        - **HTTP Responses:**
            - The way these servers responded to HTTP requests followed a consistent pattern, which could be a clue to identifying the group.
    
    While these setups alone don’t prove the servers belong to Charming Kitten, the repeated use of similar configurations suggests a connection.
    
    **Examples of Server Setups**
    
    1. **Example 1:** Windows OS, Apache 2.4.39, OpenSSL 1.1.1b, PHP 7.3.8.
    2. **Example 2:** Windows OS, Microsoft-HTTP API 2.0, PHP 7.3.7.
    
    These similarities help researchers track and link the group’s activities more effectively.
    
    ![Listed HTTP Requested](/assets/images/APTs/CharmingKitten/image%205.png)
    
    Listed HTTP Requested
    

## MITRE ATT&CK Mapping
- **MITRE ATT&CK Mapping**
    
    
    | **Technique ID** | **Description** |
    | --- | --- |
    | T1593.001 | Reconnaissance -> Social Media |
    | T1598 | Reconnaissance -> Phishing of Information |
    | T1199 | Initial Access -> Trusted Relationship |
    | T1133 | Initial Access -> External Remote Access |
    | T1204.02 | Execution -> Malicious File |
    | T1204.001 | Execution -> Malicious Link |
    | T1059.005 | Execution -> Visual Basic |
    | T1505.002 | Persistence -> Backdoor |

## Exploited Vulnerabilities
- **Exploited Vulnerabilities**
    
    
    | **Vulnerability** | **CVE** | **Versions Impacted** | **Description** | **Exploitation** |
    | --- | --- | --- | --- | --- |
    | Apache Log4j2 Remote Code Execution Vulnerability | **CVE-2021-44228** | Apache Log4j Versions: 2.0-beta9 to 2.14.1 | The vulnerability arises from the way Log4j processes log messages. When a specially crafted input containing JNDI lookup is logged, Log4j queries a remote server and executes the returned payload.  | Injecting payloads via web application logs, such as user-agent strings, form inputs, or API calls.
     |
    | Apache Log4j2 Deserialization of Untrusted Data Vulnerability | **CVE-2021-45046**  | Affects Apache Log4j2 versions: 2.0-beta9 to 2.15.0. | Apache Log4j2 that allows attackers to exploit JNDI lookups and perform deserialization of untrusted data, potentially leading to RCE or sensitive data exposure.  | Attacker sending malicious log data with crafted JNDI lookups. When processed by vulnerable Log4j2 versions, it triggers deserialization of the malicious payload, leading to RCE or system compromise. |

## Indicators of compromise (IoCs)
- **Indicators of compromise (IoCs)**
    
    **Hashes**
    
    | Hash | Type | **First_Seen** | **Name** |
    | --- | --- | --- | --- |
    | [bb700e1ef97e1eed56bb275fde2c5faed008c225](https://www.virustotal.com/gui/file/35a485972282b7e0e8e3a7a9cbf86ad93856378fd96cc8e230be5099c4b89208) | Win32 EXE | 2022-08-23 13:20:11 UTC | EmailDownloader.exe |
    
    **IP Addresses**
    
    | **Server IP** | **New Domains** | **Scope and Purpose** |
    | --- | --- | --- |
    | 51.38.87[.]199 | finance-usbnc[.]info | Baha'i Center Assistance (finance@usbnc.org) |
    | 51.38.87[.]199 | service-activity-checkup[.]site | Google |
    | Current IP: 51.38.87[.]199Previous IP: 51.89.237[.]235 | two-step-checkup[.]site | Yahoo!, Google, and Outlook |
    | 51.89.237[.]235 | service-issues[.]site | Yahoo!, Google, and Outlook |
    | 51.89.237[.]235 | phonechallenges-submit[.]site | Yahoo!, Google, and Outlook |
    | 51.89.237[.]234 | malcolmrifkind[.]site | Sir Malcolm Rifkind (Chairman of the Intelligence and Security Committee UK) |
    | 51.89.237[.]234 | software-updating-managers[.]site | Malware Command & Control (C&C) |
    | 51.89.237[.]233 | customers-service.ddns[.]net | Malware Command & Control (C&C) |
    | --- | yah00[.]site | Yahoo |
    | --- | cpanel-services[.]site | Hosting CPanel |
    | --- | instagram-com[.]site | Instagram |
    | --- | recovery-options[.]site | Yahoo!, Google, and Outlook |

## References
- **References**
    - [https://attack.mitre.org/groups/G0059/](https://attack.mitre.org/groups/G0059/)
    - [https://www.cyware.com/resources/threat-briefings/research-and-analysis/ten-years-top-charming-kittens-tale-of-cybercrime-ea43](https://www.cyware.com/resources/threat-briefings/research-and-analysis/ten-years-top-charming-kittens-tale-of-cybercrime-ea43)
    - [https://apt.etda.or.th/cgi-bin/showcard.cgi?g=Magic Hound%2C APT 35%2C Cobalt Illusion%2C Charming Kitten](https://apt.etda.or.th/cgi-bin/showcard.cgi?g=Magic%20Hound%2C%20APT%2035%2C%20Cobalt%20Illusion%2C%20Charming%20Kitten)
    - [https://www.darktrace.com/fr/blog/apt35-charming-kitten-discovered-in-a-pre-infected-environment](https://www.darktrace.com/fr/blog/apt35-charming-kitten-discovered-in-a-pre-infected-environment)
    - [https://www.avertium.com/resources/threat-reports/in-depth-look-at-apt35-aka-charming-kitten](https://www.avertium.com/resources/threat-reports/in-depth-look-at-apt35-aka-charming-kitten)
    - [https://www.stamus-networks.com/blog/the-hidden-claws-of-apt-35-charming-kitten](https://www.stamus-networks.com/blog/the-hidden-claws-of-apt-35-charming-kitten)
    - [https://www.banyansecurity.io/glossary/apt35/](https://www.banyansecurity.io/glossary/apt35/)
    - [https://www.helpag.com/charming-kitten-unravelling-the-innovative-tactics-of-the-cyber-espionage-group/](https://www.helpag.com/charming-kitten-unravelling-the-innovative-tactics-of-the-cyber-espionage-group/)