---
title: "Brute-Force Attacks Using ELK SIEM and PCAP Analysis"

header:
  teaser:  /assets/images/investigation/force/44-BruteForce.jpg
  overlay_image: /assets/images/investigation/force/a.webp
ribbon: Blue
description: "Detecting & Investigating Login Brute-Force Attacks Using ELK SIEM and PCAP Analysis"
categories:
  - Investigation
tags:
  - SOC
  - ELK
  - PCAP


toc: false
toc_sticky: false
toc_label: "On This Blog"
toc_icon: "biohazard"
classes: wide
last_modified_at: 
---
<span style="color: #909090">Category: SOC - Investigation - PCAP </span>



# **Detecting & Investigating Login Brute-Force Attacks Using ELK SIEM and PCAP Analysis**

Brute-force attacks against public-facing login portals are among the most common entry points for attackers. In this investigation, we walk through **a real-world simulation** of a brute-force attack using:

- Apache access logs ingested into **ELK SIEM**
- HTTP request analysis
- Event correlation & timeline mapping
- **Network forensics** using PCAP

This write-up documents **every step**, reasoning, and acquired evidence that led to identifying the threat.

# **1. Preparing the Investigation Environment**

Before diving into analysis, we identify our data sources:

| Source | Description | Purpose |
| --- | --- | --- |
| **Apache Access Logs (ELK)** | Web server logs containing URL paths, client IPs, HTTP methods, status codes | Detect patterns of login attempts |
| **PCAP File (Wireshark)** | Raw captured network traffic | Validate login attempts & payloads |
| **Kibana Discover / Dashboard** | Visual interface for querying log data | Correlation, filtering, and timeline reconstruction |

![image.png](/assets/images/investigation/force/image.png) 

# **2. Step-by-Step Investigation Workflow**

## **Step 2.1 – Identify Relevant Log Dataset (Apache Access Logs)**

The first step is isolating the log dataset that contains HTTP events.

**KQL Query**

```
event.dataset: "apache.access"
```

### **Why this step matters**

Attackers interact with the application through HTTP requests. Apache access logs provide:

- Client IP
- Targeted URI
- Authentication endpoints
- Response codes (401/403/404)
- Request methods (GET/POST)
- User agent strings

These fields are vital for pattern detection.

| ![**Apache Logs in Kibana Discover**](/assets/images/investigation/force/image%201.png) |
|:--:| 
| *Apache Logs in Kibana Discover* |


## **Step 2.2 – Hunt for Authentication Endpoints**

Next, we focus on URLs commonly used for login workflows.

**KQL Query**

```
url.path: *login* or url.path: *signin*
```

### **Data Acquired from this Stage**

Example findings (replace with your actual logs):

| Source IP | HTTP Method | Path | Status |
| --- | --- | --- | --- |
| 10.20.10.3 | POST | /login.php | 404 |

### **Findings**

- Repeated hits to `/login.php`
- Same client IP (`10.20.10.3`)
- High-frequency requests

| ![**Filtered Login Endpoint Logs**](/assets/images/investigation/force/image%202.png) |
|:--:| 
| *Filtered Login Endpoint Logs* |


## **Step 2.3 – Correlate With Failed Attempts (Brute-Force Signature)**

Attackers rarely succeed on the first attempt. A cluster of failed POST requests is a major red flag.

**KQL Query**

```
event.dataset: "apache.access"
and http.request.method: "POST"
and event.outcome: "failure"
and (http.response.status_code: 401 or 403 or 404)
```

### **What We’re Looking For**

- Sudden spike of POST requests
- Same IP hitting same endpoint
- Short time interval (seconds)
- Failed responses

### **Acquired Evidence**

Example extracted from logs:



| Time | Source IP | Method | URI | Status | User-Agent |
| --- | --- | --- | --- | --- | --- |
| Apr 25, 2025 @ 12:54:19.000 | 10.20.10.3 | POST | /login.php | 404 | Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0 |

- **Sequential timestamps** → brute force
- **Continuous failure** → incorrect credentials

| ![**Failed POST Request Logs**](/assets/images/investigation/force/image%203.png) |
|:--:| 
| *Failed POST Request Logs* |


## **Step 2.4 – Identify Attack Patterns (IP-Level Investigation)**

We pivot into analyzing attacker behavior per IP:

**Kibana Query**

```
source.ip: "10.20.10.3"
```

### **Behavior Observed**

- More than *100+* requests in under 1 minute (example)
- Target focused only on `/login.php`

| ![**Source IP Activity Summary**](/assets/images/investigation/force/image%204.png) |
|:--:| 
| *Source IP Activity Summary* |


# **3. Network Forensics Validation (PCAP)**

Apache logs show behavior — PCAP reveals content.

We load the provided PCAP in Wireshark.

**Wireshark Filter**

```
http.request.uri == "/login.php" and http.request.method == "POST"
```

### **What We Found in Packets**

- POST credentials attempted
- Destination: 172.16.25.12 (web server)
- Source: 10.20.10.3
- Multiple sequential packets with login attempts
- Payload fields such as:
    - username=admin
    - password=password123

| ![**Wireshark POST Request Capture**](/assets/images/investigation/force/image%205.png) |
|:--:| 
| *Wireshark POST Request Capture* |



# Correlation Summary (Full Evidence)

| Indicator | Observation | Meaning |
| --- | --- | --- |
| Endpoint | `/login.php` | Authentication page |
| HTTP Method | POST | Credential submission |
| Status Codes | 404 failures | Incorrect login attempts |
| Source IP | 10.20.10.3 | Attacker host |
| Frequency | Rapid, sequential POST | Brute-force signatures |
| PCAP | Repeated POST payloads | Confirms attack activity |

---

# **Final Conclusion**

This investigation confirms a **credential brute-force attack** against a PHP-based login form.

Key takeaways:

- ELK SIEM pinpointed **pattern anomalies** through filtering and correlation.
- Apache access logs revealed **repeated POST failures**.
- User-agent analysis identified **automation indicators**.
- IP-level review confirmed a **single-source attack**.
- PCAP analysis validated the **packet-level brute-force attempts**.