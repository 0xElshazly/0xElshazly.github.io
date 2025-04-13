---
title: "eCIR - Effectively Using Splunk (Scenario 1)"

header:
  teaser: /assets/images/CyberDefenders/Boss_SOC_V1/logo.png
  overlay_image: /assets/images/CyberDefenders/Boss_SOC_V1/logo.png
  overlay_filter: 0.5

ribbon: DarkOrange
description: "eCIR - Effectively Using Splunk"
tags: 
  - Cyber Defenders
  - SOC
  - INE
  - Splunk
  - SIEM
  - eCIR
categories:
  - INE

toc: false
toc_sticky: false
toc_label: "On This Blog"
toc_icon: "biohazard"
classes: wide
last_modified_at: 
---
<span style="color: #909090">Category: eCIR - INE - SPLUNK </span>




### **Scenario**

The organization you work for (**Wayne Enterprises**) is using [Splunk](https://www.splunk.com/) as a SIEM solution to enhance its **intrusion detection** capabilities. The SOC manager informed you that the organization has been hit by an **APT group**. He tasked you with **responding** to this **incident** by heavily utilizing Splunk and all the data that it ingested.

> The data that Splunk has ingested consist of **Windows event logs**, **Sysmon logs**, **Fortinet next-generation firewall logs**, **Suricata logs**, etc.
> 


---

### **Tools**

- Splunk SIEM Solution
- OSINT Tools

---

## Tasks

### **Task 1: Identify any reconnaissance activities against your network through Splunk searches**

Using Splunk's capabilities, try to identify any reconnaissance activities performed by the APT group. Your organization's website is **imreallynotbatman.com.**

**Hints**:

- Focus on the **stream:http** sourcetype and identify the source IPs that are responsible for the majority of the traffic. Then, validate your findings using the **suricata** sourcetype.
- Move the investigation deeper by analyzing all important fields and sourcetypes

📌**Solution:**

First lets try that Splunk can successfully access the ingested/loaded data by change the time range picker to **All time** and then, submit the following query search.

```bash
index="botsv1" earliest=0
```

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled.png)

Now that we know everything worked as expected, let's identify any **reconnaissance activities** against Wayne Enterprises website **`imreallynotbatman.com`**

We should first determine the index and sourcetypes that are associated with **`imreallynotbatman.com`** by submit the following query search.

```bash
index="botsv1" 
| search "imreallynotbatman.com"
```

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%201.png)

Now let’s check all sourcetypes, simply click on **sourcetype** from left panel **selected fields**

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%202.png)

Let's also identify all source addresses. Scroll down and click on the **src** field, as follows:

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%203.png)

Focus on the **`stream:http`** sourcetype to identify how the reconnaissance activities was happened. 

> **Stream** is a free app for Splunk that collects wire data and can focus on a number of different protocols including smtp, tcp, ip, http and so on.
> 

**Search Query:**

```bash
index="botsv1" sourcetype="stream:http" 
| search "imreallynotbatman.com"
```

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%204.png)

Lets check the all source addresses:

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%205.png)

The sources will be narrowed down to two, **`40.80.148.42`** and **`23.22.63.114`**. 

- **`40.80.148.42`** is associated with **~95%** of the **http traffic**, so let's focus on this one for the time being.

An alternative way to identify all sources is the following Search Query:

```bash
index="botsv1" sourcetype=stream:*
| search "imreallynotbatman.com"
| stats count(src_ip) as Requests by src_ip 
| sort - Requests
```

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%206.png)

Now, we can only assume that **`40.80.148.42`** was the IP from where the **APT group** performed its **reconnaissance/scanning** activities. 

We can validate this finding, by checking with **Suricata**, as following Search Query:

```bash
index="botsv1" sourcetype="suricata" src="40.80.148.42"
| search "imreallynotbatman.com"
```

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%207.png)

We see Suricata logs related to **`40.80.148.42`**, but **no signature field**. We can see the signatures by scrolling down, clicking on **more fields** and choosing **signature**. If we do so, the signature field will be visible under the **SELECTED FIELDS** column.

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%208.png)

From the **Suricata signatures** that were triggered, we can conclude that **`40.80.148.42`** was actually scanning **`imreallynotbatman.com`**

---

Now, Let's take a look at the **submitted requests** to determine scanning techniques used by APT group by focus on **`src_headers`**

**Search Query:**

```bash
index="botsv1" sourcetype="stream:http" src="40.80.148.42"
| search "imreallynotbatman.com"
```

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%209.png)

The APT group utilized an instance of the reputable [**`Acunetix`**](https://www.acunetix.com/) vulnerability scanner.

We could have also identified the usage of this tool by looking for uncommon `user agents`.

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%2010.png)

We can easily identify which **server** was the target through the same search query and the **`dest`** field.

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%2011.png)

Now, We want to have a closer look at what has been **requested** by the APT group, we can do that by following Search Query:

```bash
index="botsv1" sourcetype="stream:http" src="40.80.148.42"
| search "imreallynotbatman.com"
```

The **URLs** being requested can be found inside the **`uri`** field.

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%2012.png)

Lets know the successful page loads. We can identify them by following Search Query:

```bash
index="botsv1" sourcetype="stream:http" dest_ip="192.168.250.70"
| search "imreallynotbatman.com" 
| timechart count by uri limit=10
| sort - count 
```

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%2013.png)

---

We could have achieved similar results through the **`iis`** sourcetype, by following Search Query:

```bash
index="botsv1" sourcetype="iis" sc_status=200
| stats values(cs_uri_stem)
```

This time we are using a transformational search command called **`stats`** that will allow us to count the number of events grouped by URI.

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%2014.png)

---

🚩**Below are our findings from reconnaissance phase:**

![Reconnaissance.jpg](/assets/images/CyberDefenders/Boss_SOC_V1/Reconnaissance.jpg)

---

### **Task 2: Identify any weaponization activities on your network**

Using **Open Source Intelligence (OSINT)**, try to identify any weaponization activities performed by the APT group.

**Hints**:

- Identify any IP addresses tied to domains that are pre-staged to attack Wayne Enterprises
- Try to understand the associations between IP addresses and domains among other things
- Do the same as above to associate attacker emails with infrastructure on the internet

📌**Solution:**

At this point, we need to understand that Splunk is not panacea. During our investigations, not every answer can be found within the SIEM. There will be times when we will need to pivot from the SIEM to other internal or open sources to find answers.

We gave the **`40.80.148.42`** IP address a good look through Splunk. Let's do the same for **`23.22.63.114`** but through open sources since Splunk doesn't contain too much information about it.

If we go to an open source like [http://www.robtex.com](http://www.robtex.com/) and submit the **`23.22.63.114`** IP, we will come across the following.

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%2015.png)

As we can see, this IP has a number of other **domain names associated** with it. These domain names are most probably **phishing domains** since their name is similar to the organization we work for, **Wayne Enterprises**.

Open sources like [https://threatcrowd.org](https://threatcrowd.org/) and [https://www.virustotal.com](https://www.virustotal.com/) can provide us with additional information.

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%2016.png)

Through `threatcrowd.org`, we identified additional domains associated with the APT group we are dealing with by simply submitting the **23.22.63.114** IP.

**REVERSE DNS**

| Domain | Date |
| --- | --- |
| 23.22.63.114 | 2023-09-07 |
| ec2-23-22-63-114.compute-1.amazonaws.com | 2023-08-12 |
| waynecorinc.com | 2019-12-01 |
| wanecorpinc.com | 2019-11-30 |
| wynecorpinc.com | 2019-11-29 |
| wayneorpinc.com | 2019-11-28 |
| wayncorpinc.com | 2019-11-05 |
| waynecrpinc.com | 2019-09-30 |
| waynecorpnc.com | 2019-09-28 |
| po1s0n1vy.com | 2018-07-18 |
| www.po1s0n1vy.com | 2018-05-19 |
| prankglassinebracket.jumpingcrab.com | 2018-05-02 |

---

Now, Lets check the whois information of every associated domain about the attacker.

- While checking the whois information of **wayncorpinc.com** we come across the following.

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%2017.png)

We can then proceed to reverse email searches and possibly identify additional infrastructure associated with the APT group. Find an example of a reverse email search below.

- [https://www.threatcrowd.org/email.php?email=LILLIAN.ROSE@PO1S0N1VY.COM](https://www.threatcrowd.org/email.php?email=LILLIAN.ROSE@PO1S0N1VY.COM)

---

🚩**Below are our findings from Weaponization phase:**

![Weaponization.jpg](/assets/images/CyberDefenders/Boss_SOC_V1/Weaponization.jpg)

---

### **Task 3: Identify any delivery activities on your network**

Using OSINT, try to identify any delivery activities performed by the APT group. Specifically, try to identify malware associated with the attacker infrastructure you have previously uncovered.

**Hints**:

- Submit any attacker-related IP address to open sources such as ThreatMiner, VirusTotal and Hybrid Analysis

📌**Solution:**

We need to know as much as possible about this **APT group's TTPs** and used **malware**, so let's dig deeper through open sources.

[**`https://www.threatminer.org`**](https://www.threatminer.org/) has a great capability of including related **malware samples** when searching for information about an IP address. This is what we will come across while searching for information about **23.22.63.114** on **threatminer.org**.

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%2018.png)

---

We can then submit these **MD5 hashes** to open sources like **threatminer**, **VirusTotal** or **hybrid-analysis.com** to identify additional **metadata** about the sample(s).

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%2019.png)

**🚩Below are our findings from Delivery phase:**

![Delivery.jpg](/assets/images/CyberDefenders/Boss_SOC_V1/Delivery.jpg)

---

### **Task 4: Identify any exploitation activities on your network through Splunk searches**

Using Splunk's capabilities, try to identify any exploitation activities performed by the APT group.

**Hints**:

- Focus on the **stream:http** and **iis** sourcetypes and identify which of your servers is the target as well as the Content Management System it uses
- Focus on the **stream:http** sourcetype and identify the source of a brute force attack
- Move the investigation deeper by analyzing all important fields and sourcetypes

📌**Solution:**

It is about time we go back to Splunk to identify any exploitation activities. Let's start by identifying source IP addresses that are associated with the largest number of http events. We can do that, by following Search Query:

```bash
index="botsv1" sourcetype="stream:http" dest="192.168.250.70" http_method=POST
```

The **`src`** field contains what we are looking for. We specified that we are interested in **POST** requests since logins are usually performed through **POST requests.**

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%2020.png)

---

First, Let's take a look at those POST requests made by **`40.80.148.42`**  and check the **`form_data`** field by following Search Query:

```bash
index="botsv1" sourcetype="stream:http" dest="192.168.250.70" http_method=POST src="40.80.148.42"
```

The **form_data** field contains information that we want to check when dealing with POST requests.

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%2021.png)

Nothing to justify successful exploitation activities. Let's check **`23.22.63.114`** and check the **`form_data`** field by following Search Query:

```bash
index="botsv1" sourcetype="stream:http" dest="192.168.250.70" http_method=POST src="23.22.63.114"
| stats count by form_data
| sort - count
```

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%2022.png)

It looks like **23.22.63.114** is brute forcing the web server's authentication.

Let's make sure, by following Search Query:

```bash
index="botsv1" sourcetype="stream:http" dest="192.168.250.70" http_method=POST
form_data=*username*passwd* 
| stats count by src_ip
```

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%2023.png)

Indeed **23.22.63.114** performed a brute force attack against the web server's authentication.

We are quite interested in knowing if the brute force attack was successful. We can determine that, by following Search Query:

```bash
index=botsv1 sourcetype=stream:http form_data=*username*passwd* dest_ip=192.168.250.70 
| rex field=form_data "passwd=(?<userpassword>\w+)" 
| stats count by userpassword 
| sort - count
```

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%2024.png)

The search above extracts every user password and counts the times it has been seen/used. If a password is seen more than one time, this probably means that attackers got a hit and used the password again to log in. This is why we are sorting on count.

If we want to get an idea of the time of the compromise and the URI that was targeted, we can do that by following Search Query:

```bash
index=botsv1 sourcetype=stream:http form_data=*username*passwd* dest_ip=192.168.250.70 src_ip=40.80.148.42 
| rex field=form_data "passwd=(?<userpassword>\w+)"
| search userpassword=* 
| table _time uri userpassword
```

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%2025.png)

Finally, if we want to view the two successful logins we can do so, by following Search Query:

```bash
index=botsv1 sourcetype=stream:http 
| rex field=form_data "passwd=(?<userpassword>\w+)" 
| search userpassword=batman 
| table _time userpassword src_ip
```

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%2026.png)

---

**🚩Below are our findings from Exploitation phase:**

![Exploitation.jpg](/assets/images/CyberDefenders/Boss_SOC_V1/Exploitation.jpg)

---

### **Task 5: Identify any installation activities on your network through Splunk searches**

Using Splunk's capabilities, try to identify any installation activities performed by the APT group.

**Hints**:

- Focus on the **stream:http** and **suricata** sourcetypes to identify any uploaded executables
- Leverage Sysmon logs to identify additional information about any uploaded executables

📌**Solution:**

As far as the **installation** phase of the cyber kill chain is concerned, we are mostly interested in **identifying** any **malware** being **uploaded**.

We can identify that through various sourcetypes, specifically, **stream:http** and **Suricata**.

**stream:http**

```bash
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" *.exe
```

The **`part_filename{}`**field contains the information we want to check. It won't be visible by default, so add it.

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%2027.png)

---

**suricata**

```bash
index=botsv1 sourcetype=suricata (dest=imreallynotbatman.com OR dest="192.168.250.70") 
http.http_method=POST .exe
```

The **`fileinfo.filename`** field contains the information we want to check.

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%2028.png)

---

**`3791.exe`** must be the uploaded malware.

The source from where the file was uploaded can easily be identified, as follows.

```bash
index=botsv1 sourcetype=suricata dest_ip="192.168.250.70" http.http_method=POST .exe
```

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%2029.png)

---

It would be great if we could also identify the **hash** of the uploaded file. But what sourcetype should we use? Let's find out, as follows.

```bash
index=botsv1 3791.exe
```

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%2030.png)

---

**Sysmon** is a good candidate since it logs information such as MD5, SHA1 and SHA256 hashes of files.

```bash
index=botsv1 3791.exe sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

The important fields, in this case, are **Hashes**, **CommandLine** and **ParentCommandLine**. You will have to add the last two ones since they are not visible by default.

Before analyzing the results, let's narrow things down a little bit.

```bash
index=botsv1 3791.exe sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1
```

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%2031.png)

---

The search above includes **EventCode 1** since this EventCode is related to **`process creation`** events. Unfortunately, to get the MD5 hash of the uploaded file, we need to narrow things down even further. Specifically, we will need to search for `3791.exe` inside the command line field, since this field captures the process starting.

```bash
index=botsv1 3791.exe sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational 
EventCode=1 CommandLine="3791.exe"
| stats count values(MD5)
```

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%2032.png)

---

**🚩Below are our findings from Installation phase:**

![Installation.jpg](/assets/images/CyberDefenders/Boss_SOC_V1/Installation.jpg)

---

### **Task 6: Identify any command and control-related activities on your network through Splunk searches**

Using Splunk's capabilities, try to identify any Command and Control (C2)-related activities performed by the APT group.

**Hints**:

- Focus on the **stream:http,** **fgt_utm,** and **stream:dns** sourcetypes to identify any domains acting as Command and Control.

📌**Solution:**

As far as the **Command and Control** phase of the cyber kill chain is concerned, we are mostly interested in identifying any **domain** used for command and control purposes.

We have a powerful ally inside Splunk to assist us in answering such questions. This ally is the **`stream.dns`** sourcetype. Since we already know that **`23.22.63.114`** is of concern, we can utilize Splunk and the **`stream.dns`** sourcetype to identify DNS events where **`22.23.63.114`** was the answer.

```bash
index=botsv1 sourcetype=stream:dns 23.22.63.114 | stats values("name{}")
```

![Untitled](/assets/images/CyberDefenders/Boss_SOC_V1/Untitled%2033.png)

If you look carefully enough, you will identify that the **`prankglassinebracket.jumpingcrab.com`** domain has been used by attackers to deface the web server.

---

**🚩Below are our findings from Command & Control phase:**

![Command & Control.jpg](/assets/images/CyberDefenders/Boss_SOC_V1/Command__Control.jpg)

---

**Resources:**

- [https://www.threatminer.org/host.php?q=23.22.63.114](https://www.threatminer.org/host.php?q=23.22.63.114)
- [https://ci-www.threatcrowd.org/ip.php?ip=23.22.63.114](https://ci-www.threatcrowd.org/ip.php?ip=23.22.63.114)
- [https://www.threatminer.org/sample.php?q=c99131e0169171935c5ac32615ed6261](https://www.threatminer.org/sample.php?q=c99131e0169171935c5ac32615ed6261)
- [https://www.virustotal.com/gui/file/9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8/detection](https://www.virustotal.com/gui/file/9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8/detection)
- [https://www.hybrid-analysis.com/sample/9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8](https://www.hybrid-analysis.com/sample/9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8)
- [https://www.virustotal.com/gui/file/ec78c938d8453739ca2a370b9c275971ec46caf6e479de2b2d04e97cc47fa45d](https://www.virustotal.com/gui/file/ec78c938d8453739ca2a370b9c275971ec46caf6e479de2b2d04e97cc47fa45d)