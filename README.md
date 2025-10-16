## 🧩 Suspicious Macro Activity — SOC Investigation Walkthrough using Google Chronicle

The **Google Chronicle SOC dashboard** lit up with an alert titled **“Suspicious Macro Activity”**, signaling possible malicious activity from a Microsoft Office application.

---

### 🕵️ Step 1: Alert Trigger — Initial Detection  
![Chronicle1](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle1.jpg)  
AI automatically assessed the case, identifying an **Office macro** that downloaded an executable file from a suspicious site.  
Key indicators surfaced:
- **Technique:** MITRE `T1204.002 – User Execution`
- **Malicious file:** `C:\Program Files\Microsoft Office\Office16\Excel.exe`
- **Malicious domain:** `manygoodnews.com`
- **External IP:** `208.91.197.46`
- **User:** `STEVE-WATSON`, **Host:** `STEVE-WATSON-PC`

Recommended actions:
1. Quarantine `Excel.exe`  
2. Block `208.91.197.46`  
3. Block `manygoodnews.com`  
4. Investigate user and process behavior  

---

### 📄 Step 2: Case Overview and Alert Summary  
![Chronicle2](https://github.com/SunilKumarPeela/cyberimages/blob/main/chronicle2.jpg)  
The SOC analyst reviewed the **case overview**, confirming the alert **SUSPICIOUS_DOWNLOAD_OFFICE**.  
The AI module flagged it as **High Priority**, attaching a **Malware Detection playbook** for automation.

---

### 🧱 Step 3: Case Wall and SLA Tasking  
![Chronicle3](https://github.com/SunilKumarPeela/cyberimages/blob/main/chronicle3.png)  
![Chronicle4](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle4.png)  
In the **Case Wall**, analysts logged internal actions:
- Escalated case priority from *High* to *Critical*.
- Added a task to **fix SLA compliance**, assigned to `@Administrator`.

These ensure accountability and workflow visibility during the triage.

---

### 🌐 Step 4: Entity Correlation  
![Chronicle5](https://github.com/SunilKumarPeela/cyberimages/blob/main/chronicle5.png)  
The **Entities Highlights** section mapped all relevant data points:
- User, host, processes, IPs, domains, MITRE technique, and file hashes.
- `STEVE-WATSON-PC` and internal IP `10.205.11.20` repeatedly appeared, confirming localized infection attempts.

---

### 🧠 Step 5: Visual Attack Graph  
![Chronicle6](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle6.png)  
![Chronicle7](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle7.png)  
Chronicle’s **graph view** linked the entire chain:
`STEVE-WATSON → EXCEL.EXE → manygoodnews.com → 208.91.197.46`  
Red nodes highlighted confirmed malicious entities, showing that **multiple hosts** accessed the same infected source.

---

### 🎯 Step 6: Target Entities and Response Actions  
![Chronicle8](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle8.png)  
The **Target Entities panel** allowed quick decision-making:  
Analysts could choose to investigate host activity, escalate to the SOC manager, or inform the customer.

---

### 🧩 Step 7: Process and DNS Evidence  
![Chronicle9](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle9.png)  
![Chronicle10](https://github.com/SunilKumarPeela/cyberimages/blob/main/Chronicle10.png)  
CrowdStrike Falcon logs confirmed:
- A **process start event** on `STEVE-WATSON-PC`.
- `5 DNS requests` to suspicious domains from the same asset (`mikeross-pc` also appeared laterally).

This validated both **endpoint and network correlation**, confirming that the macro-initiated Excel process communicated with an external malware domain.

---

### ✅ Summary  
This investigation revealed a **macro-enabled Office attack** that executed `Excel.exe` to fetch malicious payloads.  
Through Chronicle’s AI triage, entity graphing, and event correlation:
- The SOC team quickly traced infection sources.  
- Containment actions were initiated (quarantine, IP/domain block).  
- Cross-host evidence confirmed propagation risk, prompting escalation.

> The story of this case shows Chronicle’s power to transform raw telemetry into a clear, visualized threat narrative.
