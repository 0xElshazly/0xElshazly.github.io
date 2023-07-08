---
title: "CyberTalents Certified SOC Analyst 2023"

header:
  teaser: /assets/images/CyberTalents/SOC_Analyst/ms-icon-1200x1200.png
  overlay_image: /assets/images/CyberTalents/SOC_Analyst/ms-icon-1200x1200.png
  overlay_filter: 0.5

ribbon: Blue
description: "CyberTalents Blue Team Scholarship 2023"
categories:
  - CyberTalents
  - SOC
  - Tutorials
tags: 
  - SOC
  - CyberTalents
  - Trend Micro

toc: true
toc_sticky: true
toc_label: "On This Blog"
toc_icon: "biohazard"
classes: wide
last_modified_at: 
---
<span style="color: #909090">Category: SOC - CyberTalents - Trend Micro</span>

# Lesson 1: Introduction to Cybersecurity

## Cyber Attacks
is a threat that targets computer systems, infeastructure, computer networks, and/or personal computer devices. Cyber-attacks are occurring all the time. Cyber attackers 

Types of Common Attacks:
  - Zero-day Attack
  - Malicious Software
  - Phishing 
  - Insider Attacks



## Lateral Movement

Lateral Movement is a strategic intrusion that spreads across a network compromising resources searching for key assets and sensitive data. Lateral movement is difficult to stop once the infection spreads from the initial infected resource to other resources on the network.

## Denial of Service

Denial of Service, is an attack that floods a network with traffic to overwhelm the network's resources and prevent legitimate users from accessing resources on the network.

## Attack Stages

## Cyber Kill Chain
<p align="center">
  <img src="/assets/images/CyberTalents/SOC_Analyst/killchain.webp" alt="Cyber Kill Chain" style="width:1000px">
</p>



What is the Cyber Kill Chain?
- The Cyber Kill Chain is a model that was developed by Lockheed Martin back in 2011 with the purpose of helping organizations better understand the phases of various cyberattacks. However, while many may think this is simply a referential model, it's one that can be used to identify at which stages a security team can prevent, detect, or intercept an attack in progress.

- Cyber Kill Chain is used as a reference, a way to better understand our adversaries, but it can be used as a guide for implementing better defenses as well. Not only does the Cyber Kill Chain lay out the anatomy of a cyberattack, it also highlights the increased level of impact an attack has as it progresses through each stage

## Attackers Tools Vs Techniques

<table>
<thead>
    <tr style="border:2px solid #b3adad;">
        <td style="border:2px solid #b3adad;">Tools</td>
        <td style="border:2px solid #b3adad;">Techniques</td>
    </tr>
</thead>
<tbody>
    <tr style="border:2px solid #b3adad;">
        <td style="border:2px solid #b3adad;">&nbsp;MimiKatz</td>
        <td style="border:2px solid #b3adad;">Scanning</td>
    </tr>
    <tr style="border:2px solid #b3adad;">
        <td style="border:2px solid #b3adad;">&nbsp;Metasploit</td>
        <td style="border:2px solid #b3adad;">Phishing</td>
    </tr>
    <tr style="border:2px solid #b3adad;">
        <td style="border:2px solid #b3adad;">&nbsp;Cobalt Strike</td>
        <td style="border:2px solid #b3adad;">Credential Dumping</td>
    </tr>
    <tr style="border:2px solid #b3adad;">
        <td style="border:2px solid #b3adad;">&nbsp;Aircrack-NG	</td>
        <td style="border:2px solid #b3adad;">Data Exfil</td>
    </tr>
</tbody>
</table>

## Defense in Depth

Defence in Depth is a concept used to describe a defence strategy in which security controls in multiple layers work together to form a single, cohesive security structure.

## CVE

Common Vulnerabilities and Exposures (CVE) is a database of publicly disclosed information security issues. A CVE number uniquely identifies one vulnerability from the list. CVE provides a convenient, reliable way for vendors, enterprises, academics, and all other interested parties to exchange information about cyber security issues.



---

## What is SOC?
A SOC is Security Operation Center,is a combination of people, processes and technology protecting the information systems of an organization through: proactive design and configuration, ongoing monitoring of system state, detection of unintended actions or undesirable state, and minimizing damage from unwanted effects

<p align="center">
  <img src="/assets/images/CyberTalents/SOC_Analyst/leadspace.jpeg" alt="SOC" style="width:1000px">
</p>

## Cyber Defence
Cyber Defence provides the organization with foundational capabilities to detect, respond, and recover from cybersecurity incidents by identifying them in a timely manner, which reduces the impact to the organization. Cyber Defence efforts, while mostly technical in nature, require the ability to engage, collaborate with, and apprise leadership of incidents detected, the scope, and efforts being taken to contain and remediate.

<p align="center">
  <img src="/assets/images/CyberTalents/SOC_Analyst/soc-operator-image-1.jpg" alt="Cyber Defence" style="width:1000px">
</p>

## Objectives OF Cyber Security Operations Center

- Log Collection, Log Aggregation, Security Analytics and Correlation.
- Building Threat Intelligence and Early Warning Detection System Incident Response Handling
- Monitors the Cyber Security posture and reports deficiencies
- Performs Threat and Vulnerability Analysis
- Provide Alerts and Notifications to General and Specific Threats
- Coordinates with regulatory bodies

## Outsourced or In-house

<p align="center">
  <img src="/assets/images/CyberTalents/SOC_Analyst/OutsourceVSinsource.png" alt="Outsourced or In-house
" style="width:1000px">
</p>

## SOC Mission

<p align="center">
  <img src="/assets/images/CyberTalents/SOC_Analyst/Untitled.png" alt="SOC Mission" style="width:1000px">
</p>

## Understand the SOC Environment

<p align="center">
  <img src="/assets/images/CyberTalents/SOC_Analyst/soc-team.png" alt="SOC Team" style="width:1000px">
</p>

#### People
- mindset , burnout , building career
- The SoC crew should consist of people who are familiar with security alerts and threats and how to handle them, and also as security threats are constantly changing and evolving the SoC crew should be people who are willing to update their knowledge constantly.

#### Process
- Analysis, investigation theory, triage , escalation
- A professional SoC crew should have a standardized process of incident handling moving from tier 1 to 3 that ensures the effectiveness of the handling process.


#### Technology
- Protocols , SIEM , SOAR ,IMS , Detection Countermeasure
- A good SoC team should have an excellent toolkit of security audits and penetration testing tools and technologies such as Protocols, SIEM, SOAR, IMS, and Detection Countermeasures, updating your tools and following up with the recent security trends is needed with also the existence of a powerful documentation system to log incidents.

## SOC Roles and duties

- Analyst
  - SoC analysts are the first responders for any kind of cyberattack, their mission is to monitor, report, and implement powerful evasion techniques, they also do vulnerability analysis and product testing to identify any possible weaknesses and make suggestions based on their findings, they also have a major role in doing recovery plans and so on.
- SoC Admin
- SoC Lead
  - The role of this position is to lead the rest of the team in their activities like monitoring, identification, and reporting.
- SoC Manager
  - The SoC manager role is more comprehensive than the SoC lead as SoC managers manage the teams' operations and provide technical guidance besides training and evaluation, SoC managers are also responsible for reporting incidents to the chief information security officer.
- Cyber Threat Intelligence (CTI)
  - Cyber threat intelligence is the skill of collecting information out of cyberspace that has been previously analyzed and shared between organizations about different attack scenarios and vectors.

<p align="center">
  <img src="/assets/images/CyberTalents/SOC_Analyst/diagram-soc-systematic-study.webp" alt="SOC Team" style="width:1000px">
</p>

#### The SOC Team: Roles and Responsibilities

- Tier 1 — Triage Specialist: Tier 1 analysts are mainly responsible for collecting raw data as well as reviewing alarms and alerts.

- Tier 2 — Incident Responder: At the tier 2 level, analysts review the higher-priority security incidents escalated by triage specialists and do a more in-depth assessment using threat intelligence (indicators of compromise, updated rules, etc.).

- Tier 3 — Threat Hunter: Tier 3 analysts are the most experienced workforce in a SOC. They handle major incidents escalated to them by the incident responders.

- SOC Manager: SOC managers supervise the security operations team. They provide technical guidance if needed, but most importantly, they are in charge of adequately managing the team.


💡Useful [Notes](https://www.paloaltonetworks.com/cyberpedia/soc-roles-and-responsibilities)

## Incident Classification

- A documented process or standard exists, based on organizational policy, that provides clear guidance on how to classify events and their associated responses. 
- This standard is a core component of Incident Management that provides a sliding scale of engagement needs and asset allocations based on incident severity. 
- This classification standard must closely align with business continuity and disaster recovery planning to provide sufficient oversight and executive awareness based on the organizational strategy.


<p align="center">
  <img src="/assets/images/CyberTalents/SOC_Analyst/Impact_urgency1.png" alt="SOC Team" style="width:1000px">
</p>

- Impact – how critical the downtime is for the business. Usually, it is measured by the number of influenced users. If one or more services are down, the number can be determined from CMDB data or the service catalog.

- Urgency – it is usually defined in SLA for the specific IT service. If more than one service is impacted, parameters for the higher urgency service will be taken into account.

## SLA
[Notes](https://advisera.com/20000academy/knowledgebase/incident-classification/)
## Escalation Matrix

A documented process or standard exists, based on organizational policy, to document, manage, and publish a clearly defined escalation pathway with the associated authority for execution in the event of an incident. The escalation matrix must be understood by and centrally accessible to the workforce.


## SOC Wiki

<p align="center">
  <img src="/assets/images/CyberTalents/SOC_Analyst/soc-wiki.png" alt="SOC soc-wiki" style="width:1000px">
</p>

- Listed above is how Threat Cases are displayed in SOC-Wiki
- Threat Case Name, Severity, Status 
- Information Centralized, Detailed and Searchable
- Information updated by SIEM and SOC Teams

### SOC-Wiki - Goals
