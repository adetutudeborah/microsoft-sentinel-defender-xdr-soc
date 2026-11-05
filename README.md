# Microsoft Sentinel & Defender XDR SOC Lab: Threat Detection, Threat Hunting & Security Operations

**A hands-on project documenting the deployment, exploration, and use of Microsoft Sentinel and Defender XDR for SIEM, threat intelligence, incident response, threat hunting, and security operations.**

## Table of Contents

- [Project Overview](#project-overview)
- [Project Scope](#project-scope)
- [Project Objectives](#project-objectives)
- [Tools and Technologies](#tools-and-technologies)
- [Security Telemetry and Data Sources](#security-telemetry-and-data-sources)
- [Project Workflow](#project-workflow)
- [Repository Structure](#repository-structure)
- [Prerequisites](./00-prerequisites)
- [Environment Onboarding](./01-workspace-setup)
- [Exercises](#exercises)
  - [1: Data Exploration](./02-data-exploration)
  - [2: Threat Intelligence](./03-threat-intelligence)
  - [3: MITRE ATT&CK Coverage](./04-mitre-attack-coverage)
  - [4: Automation Rules](./05-automation-rules)
  - [5: Watchlist Integration](./06-watchlist-Integration)

## Project Overview

Microsoft Sentinel is a cloud-native Security Information and Event Management (SIEM) platform that helps organizations collect and analyze security data, detect threats, and investigate incidents.

Microsoft Defender provides a unified security operations experience for investigating incidents, analyzing alerts, hunting for threats, and coordinating response activities across supported security products.

This project explores selected capabilities across the Microsoft Sentinel and Microsoft Defender ecosystem.

Although Microsoft Sentinel provides SIEM capabilities and security data analytics, many security operations experiences are now accessed through the Microsoft Defender portal as Microsoft continues to unify its SecOps experience.

This repository documents my practical work with Microsoft Sentinel and the Microsoft Defender portal, using Microsoft's official [Microsoft Sentinel Training Lab](https://github.com/Azure/Azure-Sentinel/tree/master/Tools/Microsoft-Sentinel-Training-Lab) as the foundation.

I document the work through notes, relevant KQL queries, and screenshots captured from my own Microsoft Sentinel and Microsoft Defender environments.


## Project Scope

This portfolio covers the environment onboarding process and five selected exercises from Microsoft's official training lab.

The exercises covered are:

1. **Data Exploration** — Explore security data across multiple sources and create a custom detection rule.
2. **Threat Intelligence** — Enable Microsoft Defender Threat Intelligence integration and match indicators against environment data.
3. **MITRE ATT&CK Coverage** — Review detection coverage, identify gaps, and examine the lab's attack chain.
4. **Automation Rules** — Configure incident automation, tagging, and severity escalation.
5. **Watchlist Integration** — Create a watchlist and use its data to enrich detection queries.


## Project Objectives

The objectives of this project are to:

1. Set up a Microsoft Sentinel training environment.
2. Explore security telemetry from multiple data sources.
3. Use KQL to search, filter, and analyze security events.
4. Create a custom detection rule based on observed activity.
5. Integrate threat intelligence into security investigations.
6. Match threat indicators against available environment logs.
7. Review detection coverage using the MITRE ATT&CK framework.
8. Identify potential detection gaps and understand attack techniques.
9. Configure automation rules to support incident handling.
10. Use watchlists to enrich security data and detection logic.
11. Document technical work with screenshots, queries, and investigation notes.


## Tools and Technologies

| Tool / Technology | Purpose |
|---|---|
| Microsoft Sentinel | SIEM capabilities, security data exploration, analytics, and watchlists |
| Microsoft Defender portal | Unified security operations and investigation workflows |
| Azure Log Analytics | Log storage, querying, and analysis |
| Kusto Query Language (KQL) | Security event analysis, filtering, correlation, and hunting |
| Microsoft Defender Threat Intelligence (MDTI) | Threat intelligence indicators and enrichment |
| CrowdStrike | Endpoint security telemetry explored in the training environment |
| Palo Alto Networks | Network security telemetry explored in the training environment |
| Okta | Identity and authentication telemetry explored in the training environment |
| AWS | Cloud security telemetry explored in the training environment |
| MITRE ATT&CK | Adversary tactics, techniques, and detection coverage |
| Sentinel analytics rules | Custom security detections |
| Sentinel automation rules | Incident tagging, severity changes, and workflow automation |
| Sentinel watchlists | Reference data enrichment and correlation |
| Git and GitHub | Version control and project documentation |

*The data sources and features available depend on the deployed training environment, integrations, permissions, and licensing.*

## Security Telemetry and Data Sources

The table below identifies the data sources explored in this project and provides examples of the security telemetry they generate. This telemetry can be ingested into Microsoft Sentinel for security monitoring, investigation, and threat detection.

| Data Source | Examples of Security Telemetry |
|---|---|
| AWS | Console login events, API activity, and CloudTrail logs |
| Okta | User authentication events and login failures |
| Palo Alto Networks | Firewall traffic and blocked connections |
| CrowdStrike | Endpoint activity and detection events |
| Microsoft Entra ID | Sign-in logs and audit events |


## Project Workflow

The exercises follow a practical workflow that moves from understanding the available data to detection, threat context, incident handling, and data enrichment.

```text
             Environment Onboarding
                       |
                       v
Security Telemetry from Multiple Data Sources (AWS, Okta, Palo Alto Networks, CrowdStrike)
                       | 
                       v
              Microsoft Sentinel (Log Analytics)
                       | 
                       v
                Microsoft Defender
                       | 
                       v
                Data Exploration
                 (KQL Analysis)
                       |
                       v
              Threat Intelligence
               (IOC Enrichment)
                       |
                       v
             MITRE ATT&CK Coverage
              (Detection Review)
                       |
                       v
                Automation Rules
              (Incident Handling)
                       |
                       v
              Watchlist Integration
              (Data Enrichment)
```


## Repository Structure

The repository is organized into onboarding and the five exercises included in this repository.

```text
microsoft-sentinel-defender-soc-lab/
│
├── README.md
│
├── images/
│
├── 00-prerequisites/
│
├── 01-workspace-setup/
│
├── 02-data-exploration/
│
├── 03-threat-intelligence/
│
├── 04-mitre-attack-coverage/
│
├── 05-automation-rules/
│
└── 06-watchlist-integration/
```

The folders are intended to contain the documentation and evidence for each part of the project.


## Disclaimer 

*This is an independent learning portfolio based on Microsoft's open-source Microsoft Sentinel Training Lab. The official training materials are maintained in the Azure/Azure-Sentinel repository. Screenshots and findings published here represent my own work in my lab environment. Microsoft and the respective product owners retain ownership of their products and documentation.*