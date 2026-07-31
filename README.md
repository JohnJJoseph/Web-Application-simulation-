
# Web Application Security Testing – Penetration Testing Project
📌 Project Overview

This project focuses on practical Web Application Penetration Testing to identify, exploit, and document common security vulnerabilities using industry-standard tools and methodologies.
The testing was conducted in a controlled lab environment using Kali Linux, targeting intentionally vulnerable applications such as DVWA (Damn Vulnerable Web Application) and testphp.vulnweb.com 



The goal of this project is to understand real-world attack techniques and highlight the importance of secure development practices.

🎯 Objectives

Implement standard phases of penetration testing

Identify vulnerabilities in web applications

Exploit vulnerabilities in a safe lab environment

Document findings and recommend remediation

Gain hands-on experience with professional security tools



 Testing Methodology

The project follows a 5-Phase Penetration Testing Model:

Reconnaissance – Information gathering (WHOIS, DNS, tech stack)

Scanning & Enumeration – Port scans, directory brute force, service detection

Vulnerability Assessment – Mapping issues to OWASP Top 10

Exploitation – Practical attacks and proof of concept

Reporting & Remediation – Documentation and fix recommendations


🛠️ Tools Used
Tool	Purpose
Nmap	Network discovery and service detection
Nikto	Web server vulnerability scanning
Gobuster	Directory and file brute forcing
Burp Suite	Intercepting requests, brute force, intruder
OWASP ZAP	Web vulnerability scanning
Sublist3r	Subdomain enumeration
Amass	Asset discovery
Wappalyzer	Technology fingerprinting

Web_report_john

 Vulnerabilities Identified

The following vulnerabilities were successfully identified and exploited:

 SQL Injection (SQLi)

 Cross-Site Scripting (XSS) — Reflected, Stored, DOM

 Cross-Site Request Forgery (CSRF)

 Brute Force Login Attacks

 Security Misconfigurations

 Directory Listing & Sensitive File Exposure

 Missing Security Headers

All vulnerabilities were mapped to OWASP Top 10 categories and verified through exploitation.

Web_report_john

 Exploitation Highlights
 SQL Injection

Enumerated databases using SQLMap

Extracted sensitive data from backend tables

Demonstrated full database compromise

 CSRF

Password changed without user consent

Token bypass using combined vulnerabilities

 XSS

Cookie stealing via DOM-based scripts

Persistent payloads using stored XSS

 Brute Force

Successful login using Burp Intruder

No rate limiting or lockout protection

Web_report_john

 Remediation Recommendations

Use prepared statements / parameterized queries to prevent SQLi

Implement CSRF tokens with strict validation

Apply input validation and output encoding to stop XSS

Disable directory indexing on web servers

Add security headers (CSP, X-Frame-Options, etc.)

Enable rate limiting and account lockout mechanisms

Keep all software and dependencies up to date



 Author

John

⚠️ Disclaimer

This project was performed only on intentionally vulnerable systems for academic and learning purposes.
⚠️ Do NOT test real websites without proper authorization.
Unauthorized penetration testing is illegal.
