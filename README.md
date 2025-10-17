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

![Chronicle21](https://github.com/SunilKumarPeela/cyberimages/blob/main/chronicle22.png)  

And It shows both alerts marked Critical (Risk Score 95), confirming a coordinated malware download detected under the “suspicious_download_office” rule.

![Chronicle21](https://github.com/SunilKumarPeela/cyberimages/blob/main/chronicle23.png)  
---


