---
title: "SQLI UNION Attack Investigation"

header:
  teaser:  /assets/images/investigation/sql/sql-injection-attack.png
  overlay_image: /assets/images/investigation/sql/sql-injection-attack.png
ribbon: Blue
description: "SQLI UNION Attack Investigation"
categories:
  - SIEM Alert
tags:
  - SOC
  - ELK
  - SQL


toc: false
toc_sticky: false
toc_label: "On This Blog"
toc_icon: "biohazard"
classes: wide
last_modified_at: 
---
<span style="color: #909090">Category: SOC - Investigation - SQL </span>

**SQLI UNION Attack Investigation**

Investigating and Identifying SQLI Union activity required multiple correlation and analysis, below listed are some few correlation point which get to be used for proceed investigating the SQLI Investigation activity:

- Targeted Investigation of Apache Access Logs
- Identify and Prioritize URLs Associated with SQL Execution
- Unpack the Attack Execution Sequence

# **1. Preparing the Investigation Environment**

Before starting the investigation, ensure all required data sources, dashboards, and tools are prepared. The table below organizes the preparation phase using the format:

| **Source** | **Description** | **Purpose** |
| --- | --- | --- |
| **ELK – Apache Access Logs** | Primary dataset containing HTTP request logs, user agents, source IPs, URLs, referrers. | To identify suspicious SQL-related GET requests and trace attacker activity. |
| **ELK Query Console (Kibana Discover / SIEM Search)** | Investigative interface for running advanced Lucene/KQL searches. | To extract, filter, and correlate malicious SQLi indicators. |
| **CyberChef (Decode / URL Decode)** | External analysis tool to decode encoded payloads. | To decode URL-encoded SQLi payloads for readable analysis. |

![image.png](/assets/images/investigation/sql/image.png)

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
- URL Query
- User agent strings

These fields are vital for pattern detection.

![image.png](/assets/images/investigation/sql/image%201.png)

## **Step 2.2 – Validate the Alert**

Confirm the alert is legitimate and the SQL keywords appear in GET requests.

**Search Query**

```
event.dataset: "apache.access" AND http.request.method: "GET" AND url.query: ("UNION" OR "SELECT" OR "INTO" OR "AND" OR "OR")
```

- Review matched log entries
- Confirm SQL keywords appear in URL query string
- Verify presence of encoding (e.g., `%20`, `%27`, `%2B`)

![image.png](/assets/images/investigation/sql/image%202.png)

## **Step 2.3 – Scope and Pivot on Attacker IP**

Identify whether the activity is widespread or isolated to one actor.

**Search Query**

```
event.dataset: "apache.access" AND source.ip: "10.20.10.3"
```

- Check number of requests from the attacker
- Identify patterns: frequency, bursts, enumeration behavior
- Look for multiple endpoints probed by attacker

![image.png](/assets/images/investigation/sql/image%203.png)

## **Step 2.4 – Identify Targeted URLs and Parameters**

Determine what part of the application the attacker is probing.

**Search Query**

```
event.dataset: "apache.access" AND source.ip: "10.20.10.3"
```

- endpoints targeted
- which parameters appear vulnerable
- whether attacker is mapping database schema

![image.png](/assets/images/investigation/sql/image%204.png)

## **Step 2.5 – Extract URL-Encoded Payloads**

SQLi payloads are often encoded using URL encoding.

**Search Query**

```
event.dataset: "apache.access" AND url.original.keyword :*%*
```

![image.png](/assets/images/investigation/sql/image%205.png)

- Copy encoded URL parameters
- Paste into CyberChef
- Run **URL Decode** → **UTF-8 Decode**

![image.png](/assets/images/investigation/sql/image%206.png)

## **Step 2.6 – Determine SQL Injection Attack Type**

Look for UNION-based SQLi characteristics:

Indicators:

- presence of `UNION SELECT`
- multiple NULL placeholders
- enumeration statements:
    - `information_schema.tables`
    - `information_schema.columns`
    - `@@version`
    - `user()`
    - `database()`

![image.png](/assets/images/investigation/sql/image%207.png)

# **3. Final Conclusion**

The investigation successfully validated the alert and confirmed that the observed activity was a **targeted, multi-stage UNION-based SQL Injection (SQLi) attack** executed through malicious GET requests in Apache access logs. 

The attacker leveraged classic SQLi techniques—initial probing, column enumeration, schema discovery, and attempted data extraction—to manipulate backend SQL queries through vulnerable web parameters.

Through detailed log analysis, payload decoding, correlation of attacker behavior, and response code verification, it was determined that the adversary systematically attempted to enumerate database tables, columns, and version information using the `UNION SELECT` operator. 

Decoded payloads revealed clear intent to extract sensitive metadata from the `information_schema` tables, indicating active reconnaissance and exploitation rather than benign or automated scanning.

Several indicators, including repeated attempts from the same malicious IP, encoded payloads consistent with known SQLi exploit chains, and positive (200 OK) server responses to certain malicious requests, strongly suggest that the targeted web application is vulnerable to SQL injection. This poses a serious risk of unauthorized data disclosure and compromise of backend database contents.