---
title: "SOC146 - Phishing Mail Detected - Excel 4.0 Macros"

header:
  teaser: /assets/images/LetsDefend/SOC146/SOC146.jpg
  overlay_image: /assets/images/LetsDefend/SOC146/SOC146.jpg
  overlay_filter: 0.5

ribbon: DarkSlateBlue
description: "SOC146 - Phishing Mail Detected - Excel 4.0 Macros"
categories:
  - Challenges
  - LetsDefend
tags: 
  - Follina
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
<span style="color: #909090">Category: SOC - LetsDefend - Phishing Mail </span>

| ![Phishing Mail Detected](/assets/images/LetsDefend/SOC146/1.png) | 
|:--:| 
| *SOC146 - Phishing Mail Detected - Excel 4.0 Macros* |

> **In this writeup, we will investigate the Excel 4.0 Macros vulnerability — Phishing Mail Detected. For those who are not aware of what Excel 4.0 Macros is, this [link](https://zvelo.com/excel-4-0-macros-another-old-school-attack-method/) provides a comprehensive overview of the vulnerability.**

| ![Screenshot For The Alert](/assets/images/LetsDefend/SOC146/2.png) | 
|:--:| 
| *Screenshot For The Alert* |

Metadata information of the event which triggered the SIEM alert:
- For this alert, we see that a suspicious behaviour that hit the `SOC146 - Phishing Mail Detected - Excel 4.0 Macros` rule, we can also see the Source Address, SMTP address, Destination Address and E-mail Subject.

---
## Let's get ready to investigate the alert..!

- The first step is to copy the sender address and look for it in our `Email Security`. we find the copy of the email that generated the alert.

| ![Screenshot For The Alert](/assets/images/LetsDefend/SOC146/3.png) | 
|:--:| 
| *Email Security* |

Lets open this mail:

| ![Screenshot For The Alert](/assets/images/LetsDefend/SOC146/4.png) | 
|:--:| 
| *MailBox of trenton* |

<details>
  <summary>
  ⛳Important information found in the email
  </summary>
  <ul>
  <li>Subject: RE: Meeting Notes</li>
  <li>From: trenton@tritowncomputers.com</li>
  <li>To: lars@letsdefend.com</li>
  <li>Attachment: 11f44531fb088d31307d87b01e8eabff.zip</li>
  </ul>
</details>

---

Next, we will download the attachment file in isolated environment and unzip the file, I'm using `ParrotOS`

After unzipping the attachment, we found three files:
- iroto.dll
- iroto1.dll
- research-1646684671.xls

| ![Screenshot For The Alert](/assets/images/LetsDefend/SOC146/5.png) | 
|:--:| 
| *11f44531fb088d31307d87b01e8eabff.zip files* |

By using sha256sum we will calculate the hash of each file in the attachment `11f44531fb088d31307d87b01e8eabff.zip`

| ![Screenshot For The Alert](/assets/images/LetsDefend/SOC146/6.png) | 
|:--:| 
| *sha256sum* |



Now we can put the hashs of the files in Virus Total to get a preliminary overview of whether the file is malicious or not and to see if there are any hits returned.

```html
  - e05c717b43f7e204f315eb8c298f9715791385516335acd8f20ec9e26c3e9b0b  iroto1.dll
  - 055b9e9af987aec9ba7adb0eef947f39b516a213d663cc52a71c7f0af146a946  iroto.dll
  - 1df68d55968bb9d2db4d0d18155188a03a442850ff543c8595166ac6987df820  research-1646684671.xls
```

### iroto1.dll

| ![Screenshot For The Alert](/assets/images/LetsDefend/SOC146/7.png) | 
|:--:| 
| *<a href="https://www.virustotal.com/gui/file/e05c717b43f7e204f315eb8c298f9715791385516335acd8f20ec9e26c3e9b0b">iroto1.dll</a> seems to be very malicious* |

### iroto.dll

| ![Screenshot For The Alert](/assets/images/LetsDefend/SOC146/8.png) | 
|:--:| 
| *<a href="https://www.virustotal.com/gui/file/055b9e9af987aec9ba7adb0eef947f39b516a213d663cc52a71c7f0af146a946">iroto.dll</a> seems to be very malicious* |

### research-1646684671.xls

| ![Screenshot For The Alert](/assets/images/LetsDefend/SOC146/9.png) | 
|:--:| 
| *<a href="https://www.virustotal.com/gui/file/1df68d55968bb9d2db4d0d18155188a03a442850ff543c8595166ac6987df820">research-1646684671.xls</a> seems to be very malicious* |

According to VT, the three files are flagged malicious:
  - The result reports 37 antivirus engines claiming the excel file has malicious. 
  - And 19 different antivirus engines claiming the DLL is malicious.

---
### ANY.RUN

Next, we will simulate this artefact’s behaviour on compromised system by submitting it to `ANY.RUN`

💡Look at `ANY.RUN` report from [here](https://any.run/report/1df68d55968bb9d2db4d0d18155188a03a442850ff543c8595166ac6987df820/c4210bc2-1ada-411f-a98f-040ac7f3a6f6)

| ![ANY.RUN](/assets/images/LetsDefend/SOC146/10.png) |
|:--:| 
| *<a href="https://app.any.run/tasks/c4210bc2-1ada-411f-a98f-040ac7f3a6f6/">research-1646684671.xls</a> ANY.RUN Analysis* |

#### Behavior Graph

| ![ANY.RUN](/assets/images/LetsDefend/SOC146/11.png) |
|:--:| 
| *Behavior Graph* |

The malicious use of `Regsvr32.exe` can bypass security tools that might not actively monitor the execution of the regsvr32.exe process or the modules loaded by it. This can occur due to allowlists or false positives from Windows, as regsvr32.exe is commonly used for legitimate operations.

<details>
  <summary>
  Regsvr32.exe 
  </summary>
  <ul>
  <li>Regsvr32.exe is a command-line utility in the Windows operating system used for registering and unregistering Dynamic Link Libraries (DLLs) and ActiveX controls. DLLs are shared libraries that contain code and data that multiple programs can use simultaneously. ActiveX controls are software components that allow web browsers and other applications to interact with and display multimedia content.</li>
  <li>The primary purpose of Regsvr32.exe is to register DLLs and ActiveX controls with the Windows Registry. When a DLL or ActiveX control is registered, it means that the operating system is made aware of its existence and its associated functionality. This allows applications to locate and use the registered components when needed.</li>
  <li>It's important to note that the use of Regsvr32.exe requires administrative privileges, as modifying the Windows Registry affects the system-wide settings. Improper use or modification of registered DLLs or ActiveX controls can cause issues with applications that rely on them, so caution should be exercised when using Regsvr32.exe.</li>
  </ul>
</details>

---

### Network Activity

#### Connections

| ![ANY.RUN](/assets/images/LetsDefend/SOC146/12.png) |
|:--:| 
| *Connections* |

#### DNS Request

| ![ANY.RUN](/assets/images/LetsDefend/SOC146/13.png) |
|:--:| 
| *DNS Request* |

#### HTTP Requests

| ![ANY.RUN](/assets/images/LetsDefend/SOC146/14.png) |
|:--:| 
| *HTTP Requests* |


The malicious excel is trying to communicate with two IPs known to be malicious. and also connected to malicious domains.

### Contacted Domains (3)
- nws.visionconsulting.ro
- royalpalm.sparkblue.lk
- ctldl.windowsupdate.com

### Contacted IP addresses (3)
- 2.16.186.56:80
- 188.213.19.81:443
- 192.232.219.67:443

### Contacted URLs (1)
- http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab?cb926953e41013fd

---

### Now Let's looking for the Log Management.

Now we will use the Log Management page and check if the C2s addresses were accessed `188.213.19.81` - `192.232.219.67`

| ![ANY.RUN](/assets/images/LetsDefend/SOC146/15.png) |
|:--:| 
| *188.213.19.81 accessed* |

| ![ANY.RUN](/assets/images/LetsDefend/SOC146/16.png) |
|:--:| 
| *RAW LOG* |

By clicking on the magnifying glass, we can see further details about the raw data. The malicious domain was reached by the user and the action was allowed based on the output.

---

| ![ANY.RUN](/assets/images/LetsDefend/SOC146/17.png) |
|:--:| 
| *192.232.219.67 accessed* |

| ![ANY.RUN](/assets/images/LetsDefend/SOC146/18.png) |
|:--:| 
| *RAW LOG* |

#### Request URL
- https://royalpalm.sparkblue.lk/vCNhYrq3Yg8/dot.html
- https://nws.visionconsulting.ro/N1G1KCXA/dot.html

---

### Now Let's looking for the Endpoint Security.

Go to Endpoint Security and Containment the `LarsPRD`. We can proceed to investigate further for other anomalies on LarsPRD's workstation.

| ![ANY.RUN](/assets/images/LetsDefend/SOC146/19.png) |
|:--:| 
| *Containment LarsPRD* |

Looking at more details given by the Endpoint Security, we have the option to dig deeper by looking at the Processes, Network Action, Terminal History and Browse History.

| ![ANY.RUN](/assets/images/LetsDefend/SOC146/20.png) |
|:--:| 
| *Terminal History* |

In the Terminal History, we can see that the commands:
```shell
regsvr32.exe -s ../iroto.dll
regsvr32.exe -s ../iroto1.dll
```
was executed on the victim machine.

---

| ![ANY.RUN](/assets/images/LetsDefend/SOC146/21.png) |
|:--:| 
| *Network Action* |

In the Network Action, we can see that the two malicious IPs were communicating with the victim machine.

---

| ![ANY.RUN](/assets/images/LetsDefend/SOC146/22.png) |
|:--:| 
| *Processes* |

In the Processes, we can see that the process `regsvr32.exe` was run by the parent process `excel.exe` and had a command line `regsvr32.exe -s iroto.dll`.


---

### Case Management

| ![Process List](/assets/images/LetsDefend/SOC146/23.png) | 
|:--:| 
| *Incident Details* |


> Playbook: A security playbook is a list of required steps and actions needed to successfully respond to any incident or threat. Playbooks provide a step-by-step approach to orchestration, helping security teams to establish standardized incident response processes and ensuring the steps are followed in compliance with regulatory frameworks.

---

<details>
  <summary>
  Parse Email
  </summary>
  <ul>
    <li>When was it sent?
        <ul>
            <li>Jun, 13, 2021, 02:11 PM </li>
        </ul>
    </li>
  </ul>
  <ul>
    <li>What is the email's SMTP address?
        <ul>
            <li>24.213.228.54 </li>
        </ul>
    </li>
  </ul>
  <ul>
    <li>What is the sender address? 
        <ul>
            <li>trenton@tritowncomputers.com</li>
        </ul>
    </li>
  </ul>
  <ul>
    <li>What is the recipient address?
        <ul>
            <li>lars@letsdefend.io</li>
        </ul>
    </li>
  </ul>
  <ul>
    <li>Is the mail content suspicious?
        <ul>
            <li>Yes</li>
        </ul>
    </li>
  </ul>
  <ul>
    <li>Are there any attachment?
        <ul>
            <li>Yes</li>
        </ul>
    </li>
  </ul>
</details>

<details>
  <summary>
    Are there attachments or URLs in the email?
  </summary>
  Yes
</details>

<details>
  <summary>
    Analyze Url/Attachment
  </summary>
  Malicious
</details>

<details>
  <summary>
    Check If Mail Delivered to User?
  </summary>
  Deliverd
</details>

<details>
  <summary>
    Check If Someone Opened the Malicios File/URL?
  </summary>
  Opened
</details>

---

| ![Process List](/assets/images/LetsDefend/SOC146/24.png) | 
|:--:| 
| *Playbook Answers* |



Protect Your Digital Presence & Stay Cyber Safe 💙

Thanks🌸
