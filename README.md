# Web Application Penetration Testing Project

## 📌 Project Overview
This project focuses on practical **Web Application Penetration Testing** to identify, exploit, and document common security vulnerabilities using industry-standard tools and methodologies. 

The testing was conducted in a controlled lab environment using **Kali Linux**, targeting intentionally vulnerable web applications such as **DVWA (Damn Vulnerable Web Application)** and **testphp.vulnweb.com**.

The primary objective of this project is to understand real-world attack vectors and highlight the critical importance of secure software development practices.

---

## 🎯 Project Objectives
* **Standardized Testing Framework:** Implement standard phases of web penetration testing.
* **Vulnerability Mapping:** Identify and categorize vulnerabilities against the **OWASP Top 10**.
* **Controlled Exploitation:** Safely exploit findings in a sandboxed lab environment to demonstrate risk.
* **Remediation & Reporting:** Document technical findings and recommend practical engineering fixes.
* **Tool Proficiency:** Gain hands-on experience with professional offensive and defensive security tools.

---

## 🔄 Testing Methodology
The project follows a structured **5-Phase Penetration Testing Methodology**:

1. **Reconnaissance:** Passive and active information gathering (WHOIS, DNS lookup, tech stack identification).
2. **Scanning & Enumeration:** Port scanning, directory brute-forcing, service detection, and attack surface mapping.
3. **Vulnerability Assessment:** Analyzing application behaviors and identifying security flaws mapped to OWASP Top 10.
4. **Exploitation:** Executing practical attacks and building Proof of Concepts (PoC) to validate severity.
5. **Reporting & Remediation:** Documenting technical steps, business impact, and remediation guidelines.

---

## 🛠️ Tools Used

| Tool | Purpose |
| :--- | :--- |
| **Nmap** | Network discovery and service detection |
| **Nikto** | Web server vulnerability scanning |
| **Gobuster** | Directory and file brute-forcing |
| **Burp Suite** | Intercepting proxy, payload manipulation, and brute-force testing |
| **OWASP ZAP** | Automated web application vulnerability scanning |
| **Sublist3r** | Subdomain enumeration |
| **Amass** | Network mapping and asset discovery |
| **Wappalyzer** | Web technology stack fingerprinting |

---

## 🚨 Vulnerabilities Identified

The following vulnerabilities were successfully identified and verified through manual exploitation:

* **SQL Injection (SQLi)**
* **Cross-Site Scripting (XSS)** — Reflected, Stored, and DOM-based
* **Cross-Site Request Forgery (CSRF)**
* **Brute Force Login Attacks**
* **Security Misconfigurations**
* **Directory Listing & Sensitive File Exposure**
* **Missing Security Headers**

All findings were categorized in alignment with the **OWASP Top 10** vulnerabilities.

---

## 💥 Exploitation Highlights

### 1. SQL Injection (SQLi)
* **Execution:** Enumerated underlying database structures using `sqlmap`.
* **Impact:** Extracted sensitive database tables, credentials, and demonstrated full database compromise.

### 2. Cross-Site Request Forgery (CSRF)
* **Execution:** Successfully changed account passwords without user interaction or valid authentication verification.
* **Impact:** Token bypass achieved by combining logical session flaws.

### 3. Cross-Site Scripting (XSS)
* **Execution:** Stole session cookies using DOM-based JavaScript payloads and injected persistent scripts via Stored XSS.
* **Impact:** Client-side session hijacking and account takeover.

### 4. Brute Force Login Attacks
* **Execution:** Automated dictionary attacks against authentication endpoints using Burp Suite Intruder.
* **Impact:** Successful credential recovery due to the absence of rate limiting or account lockout policies.

---

## 🛡️ Remediation Recommendations

| Vulnerability | Recommended Action |
| :--- | :--- |
| **SQL Injection** | Use prepared statements / parameterized queries across all database calls. |
| **XSS** | Implement strict context-aware output encoding and input validation. |
| **CSRF** | Enforce anti-CSRF tokens with unique, unpredictable values per session. |
| **Brute Force** | Implement rate limiting, account lockout policies, and CAPTCHA mechanisms. |
| **Directory Listing** | Disable directory browsing (`Options -Indexes`) on web servers. |
| **Security Headers** | Configure HTTP response headers (e.g., CSP, X-Frame-Options, HSTS, X-Content-Type-Options). |
| **General Hardening** | Maintain routine software updates and patch management for all application dependencies. |

---

## 👤 Author
**Jo**  
*Web Application Penetration Testing*

---

> ⚠️ **Disclaimer**  
> *This project was performed exclusively on intentionally vulnerable systems for academic and educational purposes. Testing real-world targets without explicit written authorization is strictly illegal.*
