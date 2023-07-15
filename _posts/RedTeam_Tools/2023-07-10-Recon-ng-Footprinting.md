---
title: "Recon-ng"

header:
  teaser: /assets/images/tools/recon-ng/recon-ng-logo.png
  overlay_image: /assets/images/tools/recon-ng/recon-ng-logo.png
  overlay_filter: 0.5

ribbon: DarkRed
description: "Open Source Intelligence gathering tool aimed at reducing the time spent harvesting information from open sources."
categories:
  - Red Team
  - Tools
  - Tutorials
tags: 
  - Linux
  - Tools
  - Red Team
toc: true
toc_sticky: true
toc_label: "On This Blog"
toc_icon: "biohazard"
classes: wide
last_modified_at: 
---
<span style="color: #909090">Category: Red Teaming - Tools - Recon-ng</span>

> **The more you know about your target’s infrastructure and personnel, the better you can orchestrate your attacks.**
> 

> **Reconnaissance (recon)** can be defined as a preliminary survey or observation of your target (client) without alerting them to your activities. If your recon activities create too much noise, the other party would be alerted, which might decrease the likelihood of your success.
> 

Some specific objectives by Reconnaissance: 

- Discovering subdomains related to our target company
- Gathering publicly available information about a host and IP addresses
- Finding email addresses related to the target
- Discovering login credentials and leaked passwords
- Locating leaked documents and spreadsheets

---

Reconnaissance can be broken down into two parts:

- **Passive reconnaissance:**  can be carried out by watching passively
- **Active reconnaissance:**    requires interacting with the target to provoke it in order to observe its response.

In this lab, we will be focusing on passive reconnaissance, i.e., **techniques that don’t alert the target or create 'noise'.**

---

## Recon-ng

**🚩Recon-ng** is a framework that helps automate the OSINT work. It uses modules from various authors and provides a multitude of functionality. Some modules require keys to work; the key allows the module to query the related online API.

Recon-ng can be used to find various bits and pieces of information that can aid in an operation or OSINT task. All the data collected is automatically saved in the database related to your workspace.For instance, you might **discover host addresses** to later **port-scan** or **collect contact email addresses** for phishing attacks.

At this stage, you need to select the installed module you want to use. However, if this is the first time you're running `recon-ng`, you will need to install the module(s) you need.

1. To run the programs as a `root` usertype `sudo su` and press Enter 

![Untitled](/assets/images/tools/recon-ng/1.png)

---

1. You can start Recon-ng by running the command `recon-ng`. Starting Recon-ng will give you a prompt like `[recon-ng][default] >`.

![Untitled](/assets/images/tools/recon-ng/2.png)

---

1. Type `help` to view all the commands that allow you to add/delete records to a database, query a database, etc.

![Untitled](/assets/images/tools/recon-ng/3.png)

---

1. 💡 If this is the first time you're running `recon-ng` , you will need to install the **module(s)** you need.
    
    `[recon-ng][default] > marketplace install all`
    

![Untitled](/assets/images/tools/recon-ng/4.png)

---

1. 💡 To displays all the modules available in recon-ng:
    
    `[recon-ng][default] > modules search`
    

![Untitled](/assets/images/tools/recon-ng/5.png)

---

**▶️ Steps:**

1. Create a workspace for your project
2. Insert the starting information into the database
3. Search the marketplace for a module and learn about it before installing
4. List the installed modules and load one
5. Run the loaded module

---

### Creating a Workspace

1. Create a workspace in which to perform network reconnaissance named **CEH**

- Run `workspaces create WORKSPACE_NAME` to create a new workspace for your investigation.
    
    For example, `workspaces create CEH` will create a workspace named `CEH`
    

▶️ To displays a list of workspaces type: 

`[recon-ng][CEH] > **workspaces list`

![Untitled](/assets/images/tools/recon-ng/6.png)

---

### Seeding the Database

In reconnaissance, you are starting with one piece of information and transforming it into new pieces of information. For instance, you might start your research with a company name and use that to discover the domain name(s), contacts and profiles. 

Then you would use the new information you obtained to transform it further and learn more about your target.

1. Add a domain in which you want to perform network reconnaissance
    
    Run `db insert domains` and press Enter
    
    add domain name: `certifiedhacker.com`
    
    ▶️ To displays a list of domains:
    
    `show domains`
    

![Untitled](/assets/images/tools/recon-ng/7.png)

---

> Harvest the hosts-related information associated with **certifiedhacker.com** by loading network reconnaissance **modules** such as:
> 
- **brute_hosts**
- **Netcraft**
- **Bing**

| Module  | Path |
| --- | --- |
| brute_hosts | recon/domains-hosts/brute_hosts  |
| Netcraft  | recon/domains-hosts/netcraft |
| Bing  | recon/domains-hosts/bing_domain_web |

---

1. To load the **recon/domains-hosts/brute_hosts** module, type the `modules load recon/domains-hosts/brute_hosts` command and press Enter.
    
    Result:
    
    ```python
    [recon-ng][CEH] > modules load recon/domains-hosts/brute_hosts
    [recon-ng][CEH][brute_hosts] > run
    
    -------------------
    CERTIFIEDHACKER.COM
    -------------------
    [*] No Wildcard DNS entry found.
    [*] 1.certifiedhacker.com => No record found.
    [*] 02.certifiedhacker.com => No record found.
    [*] 10.certifiedhacker.com => No record found.
    [*] 13.certifiedhacker.com => No record found.
    [*] 14.certifiedhacker.com => No record found.
    [*] 11.certifiedhacker.com => No record found.
    [*] 12.certifiedhacker.com => No record found.
    ...
    [*] www.certifiedhacker.com => (A) 162.241.216.11
    [*] Country: None
    [*] Host: www.certifiedhacker.com
    [*] Ip_Address: 162.241.216.11
    [*] Latitude: None
    [*] Longitude: None
    [*] Notes: None
    [*] Region: None
    [*] --------------------------------------------------
    ...
    -------
    SUMMARY
    -------
    [*] 22 total (19 new) hosts found.
    ```
    
    ▶️ To displays a list of hosts
    
    `show hosts`
    
    ![Untitled](/assets/images/tools/recon-ng/8.png)
    
    ---
    
2. To load the **recon/domains-hosts/bing_domain_web** module, type the `modules load recon/domains-hosts/bing_domain_web` command and press Enter.
    
    Result:
    
    ```python
    [recon-ng][CEH] > modules load recon/domains-hosts/bing_domain_web
    [recon-ng][CEH][bing_domain_web] > run
    
    -------------------
    CERTIFIEDHACKER.COM
    -------------------
    [*] URL: https://www.bing.com/search?first=0&q=domain%3Acertifiedhacker.com
    [*] Country: None
    [*] Host: webmail.certifiedhacker.com
    [*] Ip_Address: None
    [*] Latitude: None
    [*] Longitude: None
    [*] Notes: None
    [*] Region: None
    [*] --------------------------------------------------
    [*] Country: None
    [*] Host: www.certifiedhacker.com
    [*] Ip_Address: None
    [*] Latitude: None
    [*] Longitude: None
    [*] Notes: None
    [*] Region: None
    [*] --------------------------------------------------
    [*] Sleeping to avoid lockout...
    [*] URL: https://www.bing.com/search?first=0&q=domain%3Acertifiedhacker.com+-domain%3Awebmail.certifiedhacker.com+-domain%3Awww.certifiedhacker.com
    
    -------
    SUMMARY
    -------
    [*] 2 total (0 new) hosts found.**
    ```
    
    ▶️ To displays a list of hosts
    
    `show hosts`
    
    ---
    
    c. To load **recon/hosts-hosts/reverse_resolve** module, type the `modules load recon/hosts-hosts/reverse_resolve` command and press Enter.
    
    Result:
    
    ```python
    [recon-ng][CEH] > modules load recon/hosts-hosts/reverse_resolve
    [recon-ng][CEH][reverse_resolve] > run
    [*] Country: None
    [*] Host: box5331.bluehost.com
    [*] Ip_Address: 162.241.216.11
    [*] Latitude: None
    [*] Longitude: None
    [*] Notes: None
    [*] Region: None
    [*] --------------------------------------------------
    [*] 127.0.0.1 => No record found.
    
    -------
    SUMMARY
    -------
    [*] 1 total (1 new) hosts found.
    ```
    
    ▶️ N**ew record added by module:**
    
    ![Untitled](/assets/images/tools/recon-ng/9.png)
    
    ---
    

## Reporting

There are many type of reporting like:

```python
[recon-ng][CEH] > modules search report
[*] Searching installed modules for 'report'...

  Reporting
  ---------
    reporting/csv
    **reporting/html**
    reporting/json
    reporting/list
    reporting/proxifier
    reporting/pushpin
    reporting/xlsx
    reporting/xml
```

Type the `modules load reporting` command and press `Enter`

use `[recon-ng][CEH] > modules load reporting/html`

> you need to assign values for **CREATOR** and **CUSTOMER** options while the **FILENAME** value is already set, and you may change the value if required.
> 

![Untitled](/assets/images/tools/recon-ng/10.png)

Type:

- `options set FILENAME /home/attacker/Desktop/results.html` and press Enter. By issuing this command, you are setting the report name as results.html and the path to store the file as Desktop.
- `options set CREATOR [your name]`  and press Enter.
- `options set CUSTOMER Certifiedhacker Networks` (since you have performed network reconnaissance on certifiedhacker.com domain} and press Enter.

![Untitled](/assets/images/tools/recon-ng/11.png)

---

▶️ **HTML Report:**

![Untitled](/assets/images/tools/recon-ng/12.png)

---

### 💡Now, we will use Recon-ng to gather personnel information.

1. run `recon-ng` and create new workspaces called `reconnaissance`

![Untitled](/assets/images/tools/recon-ng/13.png)

![Untitled](/assets/images/tools/recon-ng/14.png)

---

1. run `modules load recon/domains-contacts/whois_pocs` 

![Untitled](/assets/images/tools/recon-ng/15.png)

---

1. run `show contacts`
    
    ![Untitled](/assets/images/tools/recon-ng/16.png)
    

---

### Now, we will validate the existence of names (usernames) on specific websites.

run modules `load recon/profiles-profiles/namechk`

show the result of profile command :

![Untitled](/assets/images/tools/recon-ng/17.png)

---

### 💡Report
![Untitled](/assets/images/tools/recon-ng/18.png)

---

Protect Your Digital Presence & Stay Cyber Safe 💙

☕[Buy Me a Coffee](https://www.buymeacoffee.com/0xelshazly)

Thanks🌸