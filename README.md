# Phishing Attack Incident Response Plan  

## **Project Overview**  
This project documents the **detection, analysis, and response** to a **phishing attack** targeting an organization's employees. The investigation involved **email header analysis, URL verification, malware scanning, and credential theft mitigation**. The report also outlines an **Incident Response Plan (IRP)** to strengthen defenses against future phishing threats.  

## **Objective**  
The primary goals of this project were to:  
✅ Identify phishing indicators in **suspicious emails**.  
✅ Analyze **phishing URLs and adversary tactics**.  
✅ Implement an **incident response plan** to contain and mitigate the attack.  
✅ Propose **preventive measures** to enhance security awareness.  

---

## **🛑 Phase 1: Identification & Detection**  
**Objective:** Detect the phishing attempt before it escalates.  

### **Indicators of Compromise (IoCs) Identified:**  
- **Suspicious Sender Email:** `Accounts.Payable@groupmarketingonline.icu`  
- **Malicious URL:** `hxxp://kennaroads[.]buzz/data/Update365.zip` (Hosting a phishing kit)  
- **Phishing Credentials Sent To:** `m3npat@yandex.com`, `jamestanner2299@gmail.com`  
- **Abnormal User Behavior:** Unusual login attempts from unknown IPs  

### **Detection Methods Used:**  
✅ **Email Header Analysis:** Verified sender details, SPF/DKIM/DMARC checks  
✅ **URL & File Analysis:** Inspected attachments and URLs using VirusTotal & Hybrid Analysis  
✅ **Network Traffic Monitoring:** Logged outbound requests to known phishing domains  

---

## **🚨 Phase 2: Containment & Mitigation**  
**Objective:** Stop the spread of the attack and prevent further compromise.  

### **Immediate Actions Taken:**  
🚫 **Block Malicious Domains & IPs:**  
   - Added `kennaroads[.]buzz` to firewall blocklists.  
   - Disabled access to suspicious email attachments.  

🔄 **Quarantine Suspicious Emails:**  
   - Removed the phishing email from all employee inboxes.  
   - Restricted email interactions from `groupmarketingonline.icu`.  

🔑 **Reset Credentials for Affected Users:**  
   - Forced password resets for users who clicked on the phishing link.  
   - Implemented **Multi-Factor Authentication (MFA)** for additional security.  

📢 **Employee Awareness Alert:**  
   - Notified employees about the phishing campaign.  
   - Encouraged users to report similar emails.  

---

## **🔍 Phase 3: Investigation & Root Cause Analysis**  
**Objective:** Understand the full scope of the attack and identify potential impact.  

🔎 **Email Log & Threat Intelligence Analysis:**  
📊 Investigated how many employees received the phishing email.  
🕵️ Checked if any credentials were entered on the phishing page.  
🌍 Traced IP addresses of **attackers' servers** and **compromised accounts**.  

🔬 **Forensic Examination of the Malicious Attachment:**  
📌 Examined the **PDF file** for embedded scripts and links.  
⚠️ Detected JavaScript code that redirected users to the phishing site.  

---

## **🛡️ Phase 4: Eradication & Recovery**  
**Objective:** Fully remove the attacker's presence and restore secure operations.  

🛑 **Remove & Patch Affected Systems:**  
✅ Scanned and removed malware from endpoints using Microsoft Defender for Endpoint.  
✅ Patched vulnerabilities that could have been exploited (e.g., outdated email security filters).  

🔄 **Restore Compromised Accounts:**  
✅ Verified password resets and checked for unauthorized changes.  
✅ Strengthened email security policies to **block lookalike domains**.  

---

## **📢 Phase 5: Lessons Learned & Preventive Measures**  
**Objective:** Strengthen defenses against future phishing attacks.  

📢 **Security Awareness Training:**  
✅ Conducted company-wide phishing awareness sessions.  
✅ Launched **simulated phishing campaigns** to educate employees.  

🛡 **Email Security Enhancements:**  
✅ Implemented **DKIM, SPF, and DMARC** for email authentication.  
✅ Enabled **AI-based email filtering** to detect phishing attempts.  

🔍 **Continuous Monitoring & Threat Intelligence:**  
✅ Set up **real-time alerts** for suspicious login attempts.  
✅ Integrated **SIEM tools** (e.g., Microsoft Sentinel) to detect and respond to threats faster.  

---

## **🎯 Key Takeaways from This Incident Response Plan:**  
🔹 **Early detection is key** – Email security tools **must** flag suspicious emails.  
🔹 **Containment must be immediate** – Affected accounts **must** be isolated quickly.  
🔹 **Recovery & education are ongoing** – Employees should receive regular security training.  

🚀 **By implementing this structured IRP, organizations can significantly reduce the risk of phishing attacks and ensure business continuity.**  


---

### **📝 Contributing**  
If you'd like to contribute to this project, feel free to submit a pull request with additional insights or remediation strategies.  

---

### **📜 License**  
This project is for educational and research purposes only. Unauthorized use of these techniques against live environments is illegal.  

---


