## 🧩 Suspicious Macro Activity — SOC Investigation Walkthrough using Google Chronicle

While monitoring my **Google Chronicle SIEM dashboard**, I noticed a new high-priority alert titled **“Suspicious Macro Activity.”**  
This immediately suggested that a **Microsoft Office process** might be involved in executing or downloading a malicious payload — a common indicator of a macro-based attack.

---

### 🕵️ Step 1: Initial Alert — AI Detection and Recommendation  
![Chronicle1](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle1.jpg)  
As soon as I opened the case, Chronicle’s **AI Investigation Assistant** automatically analyzed the detection and presented actionable insights.  
It identified that **Excel.exe** had established a suspicious network connection to an external host.  

**AI Summary included:**
- **MITRE Technique:** `T1204.002 – User Execution`
- **Malicious File:** `C:\Program Files\Microsoft Office\Office16\Excel.exe`
- **Domain:** `manygoodnews.com`
- **External IP:** `208.91.197.46`
- **User:** `STEVE-WATSON` | **Host:** `STEVE-WATSON-PC`

**Chronicle AI recommended:**
1. Quarantine the `Excel.exe` process  
2. Block the IP and domain  
3. Investigate the user session and spawned process tree  

These guided steps helped me immediately focus on containment.

---

### 📄 Step 2: Validating the Alert and Case Context  
![Chronicle2](https://github.com/SunilKumarPeela/cyberimages/blob/main/chronicle2.jpg)  
Next, I validated the alert details in the **Case Overview**.  
The alert **“SUSPICIOUS_DOWNLOAD_OFFICE”** was automatically categorized as *High Priority* and linked to a **Malware Detection playbook**, enabling automated enrichment and triage workflows.

---

### 🧱 Step 3: Documenting My Investigation — Case Wall and SLA Tracking  
![Chronicle3](https://github.com/SunilKumarPeela/cyberimages/blob/main/chronicle3.png)  
![Chronicle4](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle4.png)  
Within the **Case Wall**, I documented my findings, escalated the case priority to *Critical*, and created a new task titled **“Fix SLA”**.  
This ensured the response time remained within service-level targets and added accountability by assigning it directly to the SOC administrator.

---

### 🌐 Step 4: Entity Correlation — Uncovering the Full Picture  
![Chronicle5](https://github.com/SunilKumarPeela/cyberimages/blob/main/chronicle5.png)  
Using Chronicle’s **Entity Highlights**, I identified 15 entities linked to this case:
- User: `STEVE-WATSON`  
- Host: `STEVE-WATSON-PC`  
- Internal IPs: `10.205.11.20`, `10.205.11.2`  
- MITRE Technique: `T1204.002`  
- Domain: `manygoodnews.com`  
- Process ID: `22895`  

The repeated appearance of the same user, host, and IP combination confirmed this was not an isolated alert, but a **persistent infection** attempt.

---

### 🧠 Step 5: Visualizing the Attack Chain  
![Chronicle6](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle6.png)  
![Chronicle7](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle7.png)  
I visualized the incident in Chronicle’s **Case Graph**, which clearly mapped the entire infection chain:
Red nodes marked confirmed malicious indicators.  
Multiple connections from different hosts validated that the attack was **spreading via shared macro-laced documents**.

---

### 🎯 Step 6: Target Entities and Response Options  
![Chronicle8](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle8.png)  
Chronicle presented **Target Entities** (user, host, IPs, and domains) alongside **Response Options** such as:
- Deep investigation of host telemetry  
- Escalation to SOC Manager  
- Customer environment notification  

This step helped me align the immediate containment actions with escalation workflows.

---

### 🧩 Step 7: Validating Process and DNS Artifacts  
![Chronicle9](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle9.png)  
![Chronicle10](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle10.png)  
To confirm the scope, I reviewed **CrowdStrike Falcon** and **UDM** telemetry.  
Logs verified a **process start event** on `STEVE-WATSON-PC` and **five DNS requests** to `manygoodnews.com`.  
Interestingly, a second host, `mikeross-pc`, exhibited identical behavior, indicating lateral movement of the same macro payload.

---

## 🧠 Phase 2 — Deep Investigation, Threat Intelligence & SOAR Automation  


After identifying the **Suspicious Macro Activity**, I continued my investigation within **Google Chronicle**, diving deeper into rule-based events, threat intelligence feeds, and automation flows to confirm and mitigate the threat.

---

### 🧩 Step 8: Correlated Events and Rule Validation  
![Chronicle11](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle12.png)  
I opened the **Events tab** of the case `suspicious_download_office`. Two correlated rule events stood out:  
- **NETWORK_HTTP** — A malicious outbound connection.  
- **PROCESS_LAUNCH** — Execution of `C:\Program Files\Microsoft Office\Office16\Excel.exe`.  

Both were generated under the **RULE** source, confirming Chronicle detected not just a single anomaly but a **multi-vector correlation** between process execution and suspicious web activity.  
From the context menu, I reviewed **“Manage Alert Detection Rule”** to verify detection logic and thresholds.

![Chronicle20](https://github.com/SunilKumarPeela/cyberimages/blob/main/chronicle20.png)  

---

### 🌐 Step 9: MITRE Technique & Domain Association  
![Chronicle19](https://github.com/SunilKumarPeela/cyberimages/blob/main/chronicle19.png)   
Here, Chronicle automatically mapped the case to **MITRE ATT&CK T1204.002 – User Execution (Malicious File)**.  
- The domain **`manygoodnews.com`** was confirmed as contacted during execution.  
- Chronicle displayed **3 suggested mitigations**, including **User Training (M1017)**, to reduce recurrence.  

This step established **tactical context** — proving that the infection occurred via **user-triggered macro execution**.

---

### 🧬 Step 10: Threat Intelligence Enrichment (VirusTotal)  
![Chronicle13](https://github.com/SunilKumarPeela/cyberimages/blob/main/chronicle18.png)  
The **VT Augment** widget revealed the malicious file from the suspicious domain.  
- **48/69 security vendors** flagged it as **malicious**.  
- File type: `Win32 EXE`, size: **385 KB**, flagged under **Trojan.Loader** category.  
This correlation verified that the **downloaded payload** was already recognized across major vendors — confirming **high confidence** in the detection.

---

### 🧰 Step 11: Mandiant Intelligence Correlation  
![Chronicles14](https://github.com/SunilKumarPeela/cyberimages/blob/main/chronicle17.png)  
Cross-referencing with **Mandiant Threat Intelligence**, the domain `manygoodnews.com` was rated with a **score of 100** and had links to historical ransomware activity.  
While not directly attributing, the indicators matched profiles related to **Windows-based loaders** with **anti-VM and memory allocation evasion**.  
This suggested the macro chain was possibly delivering a **commodity loader** from known ransomware infrastructure.

---

### 🔄 Step 12: Similar Cases & Entity Correlation  
![Chronicle15](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle16.png)  
I examined **Similar Cases** in Chronicle SOAR.  
Multiple prior incidents had identical **entity matches** (`208.91.197.46`, `manygoodnews.com`) and **MITRE T1204.002** correlation.  
The majority were labeled **Critical**, confirming a **recurring attack pattern** in the organization.  

This validated that our **detection rule** was effectively catching repeat infections of the same malware variant.

---

### ⚙️ Step 13: Reviewing the Malware Detection Playbook  
![Chronicle16](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle15.png)  
I analyzed the **SOAR playbook** linked to the case — “Malware Detection.”  
It automated:
- Indicator enrichment via **VirusTotal & Mandiant APIs**  
- Artifact isolation  
- EDR containment triggers  
- Ticket escalation to SOC L2  

This workflow ensured **repeatable, low-latency containment** whenever similar detections arise.

---

### 🧭 Step 14: Event Mapping & Entity Extraction  
![Chronicle17](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicles14.png)  
In **Event Configuration → Ontology Mapping**, I validated that Chronicle correctly parsed entity relationships:
- **SourceUserName**, **SourceAddress**, and **DestinationDomain** were correctly extracted from UDM events.  
This confirmed our **rule visualization** aligned with Chronicle’s **entity graph**, ensuring process and network links were rendered accurately.

---

### ⏱️ Step 15: Event Timeline Reconstruction  
![Chronicle18](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle13.png)  
The **event timeline** displayed simultaneous hits:
- **PROCESS_LAUNCH** and **NETWORK_HTTP**  
Both referenced artifacts tied to `C:\PROGRAM FILES\MICROSOFT OFFICE\OFFICE16\EXCEL.EXE`, pinpointing that **Excel triggered network traffic** within seconds of launch.  
This timing validated the **macro execution sequence**.

---

### 📑 Step 16: Compact Correlation Summary  
![Chronicle19](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle12.png)  
In the **Compact Event View**, both process and network detections were grouped.  
This simplified visualization confirmed the **rule correlation** consistency — Chronicle’s logic was performing as intended across all ingestion windows.

---

### 🧩 Step 17: Endpoint-Level Forensics (UDM Query View)  
![Chronicle20](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle11.png)  
Finally, I executed a **UDM Query** for process and DNS artifacts.  
- Hostname: `mikeross-pc`  
- Event: `PROCESS_START` + `DnsRequest`  
- Source: **CrowdStrike Falcon**  
This indicated that **another internal endpoint** communicated with the same malicious domain — proof of **lateral exposure**.  

---
## ⚡ Phase 3 — Endpoint Telemetry & Final Correlation in Google Chronicle  

After confirming cross-host involvement, I pivoted deeper into **endpoint telemetry** to trace the **execution chain** that initiated the macro-based infection.

---

### 🧩 Step 18: Process Chain Validation — Outlook → Excel Execution  
![Chronicle21](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle21.png)  
This log shows **Outlook.exe launching Excel.exe** on **`mikeross-pc`**, a classic indicator of a **malicious email attachment executing a macro payload**.  
The process was flagged by **CrowdStrike Falcon** and linked to downloads from **`manygoodnews.com`**, confirming a **suspicious Office-based infection chain**.

And then moved to the Chronicle case graph which shows the full infection path — manygoodnews.com hosted the malicious file Client%20Update.exe, downloaded on mikeross-pc via Outlook-triggered Excel execution.

![Chronicle22](https://github.com/SunilKumarPeela/cyberimages/blob/main/chronicle22.png)  

And It shows both alerts marked Critical (Risk Score 95), confirming a coordinated malware download detected under the “suspicious_download_office” rule.

![Chronicle23](https://github.com/SunilKumarPeela/cyberimages/blob/main/chronicle23.png)  

---
### 🧠 Step 19: Domain Investigation — Chronicle SIEM Lookup on `manygoodnews.com`  

Next, I pivoted into **Google Chronicle’s SIEM search** to investigate the domain `manygoodnews.com`.  
The lookup revealed it was registered in Japan under **GMO Internet Group**, linked to multiple alerts and flagged in **VirusTotal (10/88 detections)** — confirming it as a **known malicious host** used in the infection chain.

![Chronicle23](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle24.png)  

### 🧩 Step 19: Network Correlation — UDM Query and Cross-Host Activity Validation  

After confirming the domain’s malicious background, I ran a UDM search query in Chronicle to correlate network events tied to manygoodnews.com.

![Chronicle23](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle25.png)  

The results showed multiple HTTP and DNS alerts from both mikeross-pc and steve-watson-pc, each downloading files around 514,605 bytes, indicating identical payloads.
Chronicle’s pivot and event viewer confirmed synchronized activity across both hosts, proving coordinated infection timing.

![Chronicle23](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle26.png)  

This correlation validated that the same macro-triggered malware spread through shared Office attachments within the network.

![Chronicle23](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle27.png)  

### 🧠 Step 20: Pivot Analysis & Alert Verification — Confirming Data Exfiltration Behavior  
To validate the infection’s impact, I performed a **pivot analysis** in Chronicle, grouping results by hostname, user, and network activity fields.  

![Chronicle23](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle28.png)  

The **pivot results** revealed identical **HTTP alert events** from both `mikeross-pc` and `steve-watson-pc`, each receiving data packets of **514,605 bytes**, suggesting consistent payload size. 

![Chronicle23](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle29.png)  

In the **Alerts tab**, a single high-risk event titled *“suspicious_download_office”* was flagged with a **risk score of 95 (Critical)**, confirming active communication with `manygoodnews.com`.  
This consolidated evidence verified that both endpoints were participating in **the same malicious download session**, reinforcing the **macro-based data exfiltration attempt**.

![Chronicle23](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle30.png)  

### 🧩 Step 21: Detection Overview — Confirming Consistent Macro-Based Triggers  
The **Detection Dashboard** shows multiple alerts under the rule *“suspicious_download_office”* triggered on both `mikeross-pc` and `steve-watson-pc`.  
Each event logs **Excel.exe launching via Outlook** followed by an **HTTP request to manygoodnews.com**, confirming repeated macro-triggered download attempts across endpoints.

![Chronicle23](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle35.png)  

## 🚨 Phase 4: Threat Rule Validation and Cross-System Correlation  

In **Phase 3**, the investigation transitioned from endpoint-level evidence to rule-level intelligence validation — confirming how the attack pattern was identified, triggered, and correlated across multiple telemetry sources within Google Chronicle.  

---

### 🧠 Step 22: Deep Process Telemetry — Verifying Execution and Payload Source  
The **Process_Launch log** from Tanium Stream confirms that **Excel.exe** was executed by **Outlook.exe** on both `steve-watson-pc` and `mikeross-pc`, sharing the same **parent PID (22895)**.  
The telemetry shows identical **file paths** and **MD5 hashes**, proving both systems executed the same malicious Office payload.  

![Chronicle23](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle36.png)  

This consistent process linkage validates that the macro-based infection originated from a **common Outlook-delivered Excel attachment**.

![Chronicle23](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle37.png) 

### ⚙️ Step 23: Rule Validation and Logic Confirmation  

the **“suspicious_download_office”** detection rule was reviewed and validated within Google Chronicle’s **Rules & Detections** panel.  
The rule, authored by *Google Cloud Security*, is configured as **Critical severity** and set to trigger on **multiple correlated events** combining both **PROCESS_LAUNCH** and **NETWORK_HTTP** telemetry.  

![Chronicle23](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle38.png) 

It specifically detects Office applications downloading executable files (`.exe`) or unusually large payloads (>100KB), matching **MITRE ATT&CK technique T1204.001 — User Execution: Malicious Link**.  

![Chronicle23](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle39.png) 

YARA-L **Retrohunt** runs confirmed its accuracy across historical data with no false positives.  
This validation ensured the rule effectively captures malicious macro download chains in real time, providing high-confidence detection and automated alerting for similar future threats.

![Chronicle23](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle40.png) 

## 🌍 Phase 5: SIEM Dashboard Correlation and Post-Incident Analytics  

In **Phase 4**, the investigation advanced into **SOC-level visualization and cross-environment analytics**, leveraging Chronicle’s SIEM dashboards to confirm the organization’s detection health, log integrity, and correlated threat visibility after the macro-based compromise.  

---

### 🌐 Step 24: SIEM Dashboard Correlation — Post-Incident Visibility  
The Chronicle **SIEM Dashboards** provided end-to-end operational insight linking directly to the earlier *suspicious_download_office* incident.  
The **Data Ingestion and Health** dashboard verified smooth telemetry flow from diverse log sources — including **WinEventLog**, **Sysmon**, **PowerShell**, and **AWS CloudTrail** — with **zero ingestion errors** and over **108K normalized events**, confirming that all relevant data for forensic validation was captured accurately.  

![Chronicle41](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle41.png)  

The **Context-Aware Detections – Risk** dashboard surfaced the same compromised entities — `steve-watson-pc`, `mikeross-pc`, and `manygoodnews.com` — now marked under **Critical Risk**, proving the Chronicle rule maintained continuous correlation and risk scoring across the event lifecycle.  

![Chronicle42](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle42.png)
Finally, the **Global IOC Threat Map** reflected a surge in alerts (**734 total**, +716 from baseline) and elevated ingestion throughput (**0.2 GB processed**), visually confirming active monitoring of related malicious IPs worldwide.  
This panoramic SOC-level visibility validated that all detections, telemetry, and IOC activity remained synchronized and transparent across Chronicle’s analytics layers — completing the full incident correlation chain from detection to organizational awareness.  

![Chronicle43](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle43.png)

## 🧩 Phase 6: Simulated SOC Response and Environment Validation  

In this phase, I initiated a **SOC simulation process** to validate that Chronicle’s alerting and response mechanisms function correctly in a live environment.  
My goal was to ensure the earlier *suspicious_download_office* detection chain seamlessly integrates with **real-time virus alerts**, automated ingestion, and multi-environment response scenarios.

---

### ⚙️ Step 25: Simulating Alert Workflow  
I simulated a **“Virus Found or Security Risk Found”** alert inside Chronicle’s **Default Environment** to test the behavior of real incident ingestion.  
This helped me confirm that Chronicle successfully captured and triaged alerts generated from integrated platforms like **Symantec** and **CrowdStrike**, creating a unified case for investigation.  

![Chronicle44](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle44.png)  
![Chronicle45](https://github.com/SunilKumarPeela/cyberimages/blob/main/chronicle45.png)  

---

### 🧠 Step 26: Validating Multi-Environment Simulation  
Next, I simulated multiple cases across environments such as **Cymbal Health**, **Cymbal Insurance**, and **Default Environment**, to verify cross-environment detection handling.  
I linked the **virus alert** with the ongoing *suspicious_download_office* case, validating that Chronicle correctly correlated both alerts under a single investigation path.  
This confirmed that the SOC’s environment logic and correlation rules are fully functional across distributed sources.  

![Chronicle46](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle46.png)  
![Chronicle47](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle47.png)  

---

### 🧩 Step 27: Verifying Integration Setup and Response Automation  
I then reviewed the **Integration Setup** section to ensure all modules — including **CSV ingestion, Email connectors, Enrichment, and Functions** — were configured properly within the Default Environment.  
This verification was critical to confirm that automated alert enrichment and incident workflows operate without manual intervention.  
It proved that the SOC pipeline is **response-ready** and capable of ingesting and correlating alerts instantly during real attacks or simulated exercises.  

![Chronicle48](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle48.png)  

---

## ⚙️ Phase 7: Playbook Automation — Integrating Threat Intelligence with Mandiant  

In the next stage of the investigation, I transitioned from manual case correlation to **automated incident response** by building a new Chronicle **SOAR playbook**.  
This playbook was designed to automatically enrich alerts like *Virus Found or Security Risk Found* using **Mandiant Threat Intelligence**, closing the loop between detection and contextual threat validation.

---

### 🧠 Step 28: Creating a New Playbook Environment  
I began by creating a **new playbook** under the *SecOps Training* folder in Chronicle, selecting the **Default Environment** to ensure consistency with the previous test simulations.  
This setup provides an isolated space where I can safely develop, test, and refine automated workflows before production deployment.  

![Chronicle49](https://github.com/SunilKumarPeela/cyberimages/blob/main/Screenshot%202025-10-15%20Chronicle49153800.png)  

---

### 🧩 Step 29: Defining the Trigger — Virus Alert Type  
I configured the trigger condition using the **Alert Type** module, specifying “Virus” as the parameter.  
This ensures the playbook activates automatically whenever a virus-related detection (like *Symantec EP Risk File*) appears in Chronicle’s case queue.  

![Chronicle50](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle50.png)  

![Chronicle51](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle51.png)

---

### 🔗 Step 30: Integrating Mandiant Threat Intelligence  
Next, I added the **MandiantThreatIntelligence** action to the workflow.  
This module retrieves detailed **IOC enrichment, malware attributes, and related entity context** directly from Mandiant’s global threat intelligence feed, providing analysts with instant insight into the detected malware’s origin, TTPs, and prevalence.  

  
![Chronicle52](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle52.png)  

---

### ⚙️ Step 31: Configuring IOC Enrichment Parameters  
I set the enrichment parameters to **analyze all file hashes** related to the detection and mapped them to the entity identifiers within Chronicle.  
This allows the playbook to automatically pull malware reports, related threat actors, and network indicators from Mandiant whenever a new case is ingested.  

![Chronicle53](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle53.png)  

---

### 🚀 Step 32: Running and Validating the Automation Flow  
After saving and enabling the **Simulator**, I ran the playbook linked to the “Virus Found or Security Risk Found” case.  
The playbook successfully executed the enrichment steps, validating the connection between **Chronicle SOAR** and **Mandiant Threat Intelligence**.  
As a result, every new virus detection now automatically enriches its context with verified IOC intelligence — accelerating triage and reducing analyst workload.  

![Chronicle54](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle54.png)  
![Chronicle55](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle55.png)  

---

### ✅ Phase 6 Summary  
Through this automation, I’ve operationalized the SOC workflow by linking **detection → enrichment → intelligence validation** in real time.  
This playbook now acts as a live bridge between Chronicle and Mandiant, ensuring every malware or virus alert receives instant contextual enrichment — enhancing precision, speed, and intelligence-driven decision-making within the SOC.


