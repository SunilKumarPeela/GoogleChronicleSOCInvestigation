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

### ✅ Investigation Outcome  
This investigation confirmed a **macro-enabled malware infection** that executed through Excel and reached out to an external command source.  

Through **AI-driven triage**, **entity correlation**, and **multi-source validation**, I was able to:
- Pinpoint infection origin and verify propagation.
- Block and quarantine malicious indicators.
- Validate both endpoint and network behavior across hosts.
- Escalate the case for automated SOAR playbook execution.

> This hands-on investigation demonstrates how **Google Chronicle** combines AI analytics, visualization, and automation to turn raw telemetry into a full attack narrative — reducing response time and increasing threat visibility.
