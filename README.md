# H4-tools
**This section covers the tools that are most commonly used in penetration testing engagements.

Penetration Testing-Focused Linux Distributions

Kali Linux: One of the most well-known penetration testing Linux distributions, Kali Linux is based on Debian GNU/Linux and has evolved from earlier distributions like WHoppiX, WHAX, and BackTrack. It comes preloaded with hundreds of tools for penetration testing, and the community continuously contributes new ones. Kali Linux is accessible through a Live image on a CD/DVD/USB/PXE, providing a bare-metal installation.
Parrot OS: This Debian-based Linux distribution focuses on penetration testing, digital forensics, and privacy protection.
BlackArch Linux: BlackArch Linux is packed with more than 1900 security penetration testing tools. This distribution can be downloaded from its official website, where its documentation is also available.
Tools for Passive Reconnaissance

Nslookup, Host, and Dig: These are DNS-based tools used for passive reconnaissance. They allow you to gather information about a domain, such as IP addresses associated with it.
Whois: The Whois utility is used to query the Whois database, which contains information about domain registrations. It provides details such as the domain owner, registration date, and contact information. However, due to GDPR restrictions, the amount of information available through Whois has been limited.
FOCA (Fingerprinting Organization with Collected Archives): FOCA is a tool designed to find metadata and hidden information in various types of documents, including websites, Microsoft Office files, PDFs, and more. It can be used to extract information such as EXIF data from graphics files and analyze URLs.
ExifTool: ExifTool is a popular tool for extracting EXIF (Exchangeable Image File Format) information from images. It can reveal details about the device used to capture the image, such as the camera model, date and time, GPS coordinates, and more.
theHarvester: theHarvester is a versatile tool used for DNS enumeration. It can query multiple data sources, including search engines like Google and Bing, social media platforms like Twitter and LinkedIn, PGP servers, and more. It helps gather information about a target domain, such as subdomains and associated email addresses.
Shodan: Shodan is a powerful search engine that scans and indexes devices connected to the Internet. It allows users to search for specific devices, services, or vulnerabilities. Shodan can help identify exposed and potentially vulnerable systems, such as misconfigured IoT devices or infrastructure devices.
Maltego: Maltego is a widely used tool for passive reconnaissance that gathers information from public records. It supports various integrations with third-party sources and offers different versions, including a free community edition. Maltego can be used to find information about individuals, companies, organizations, and more, presenting the results in a hierarchical and organized manner.
Recon-ng: Recon-ng is a menu-based tool specifically designed for automating OSINT information gathering. It comes with a wide range of modules that allow users to perform detailed searches on public records, files, DNS records, and other sources. Recon-ng supports querying third-party tools and sources like Shodan, social media platforms, and search engines.
Censys: Censys provides information about devices and networks on the Internet. Censys offers both a web interface and an API and provides free access with limitations on the number of queries.
Tools for Active Reconnaissance

Nmap and Zenmap: Nmap is a comprehensive tool for active reconnaissance, providing various scanning options to enumerate hosts and discover open ports. Zenmap is a graphical user interface (GUI) tool that enhances the usability of Nmap and offers features like network topology visualization.
Enum4linux: Enum4linux is specifically designed for enumerating SMB (Server Message Block) shares and vulnerable Samba implementations. It helps identify users and enumerate available SMB shares on a target host.
Common Tools for Vulnerability Scanning

These tools provide various capabilities for vulnerability scanning, web application security testing, and detecting common security flaws. They are widely used by security professionals and penetration testers to assess the security of systems and applications.

OpenVAS: OpenVAS is an open-source vulnerability scanner that allows detailed vulnerability scanning of hosts and networks. It offers various services and tools and can be used for scanning and identifying vulnerabilities. It can be scheduled and configured to perform scans using different methods and interfaces.
Nessus: Nessus is a vulnerability scanner that enables continuous monitoring and compliance analysis. It provides features for scanning and detecting vulnerabilities, and it supports integrations with other security products.
Nexpose: Nexpose, created by Rapid7, is a popular vulnerability scanner used by professional penetration testers. It offers features for vulnerability scanning and can integrate with other security tools.
Qualys: Qualys is a security company that provides a cloud-based vulnerability management and monitoring service. It offers continuous monitoring, vulnerability management, and compliance checking. Qualys interacts with different types of scanners and agents to provide comprehensive security assessments.
SQLmap: SQLmap is a tool used for automating the detection and exploitation of SQL injection vulnerabilities in web applications. It helps enumerate vulnerable applications and can exploit SQL injection techniques.
Nikto: Nikto is an open-source web vulnerability scanner that allows scanning for common web vulnerabilities. It can be used to detect security flaws in web applications and servers.
OWASP ZAP: OWASP Zed Attack Proxy (ZAP) is a widely used free security tool that provides web vulnerability scanning capabilities. It can also be used as a web proxy and a fuzzer. ZAP offers an API for automation and is actively maintained by a large community of contributors.
w3af: w3af is an open-source web application vulnerability scanner. It allows scanning for vulnerabilities in web applications and offers various plugins for different types of vulnerability testing.
DirBuster: DirBuster is a tool designed to perform brute-force directory and filename discovery on web application servers. It is an inactive project, and its functionality has been integrated and enhanced in OWASP ZAP as an add-on.
Common Tools for Credential Attacks

These tools provide different capabilities for password cracking, credential guessing, and generating wordlists, catering to various security testing and offensive purposes.

John the Ripper: John the Ripper is a popular tool for offline password cracking. It supports various cracking modes and can crack passwords using search patterns or wordlists. It can handle different ciphertext formats, including DES variants, MD5, and Blowfish. John the Ripper can be used to extract passwords from various sources, such as password files and Kerberos AFS.
Cain: Cain (or Cain and Abel) is a tool used for password recovery on Windows-based systems. It can perform packet captures, crack encrypted passwords using dictionary and brute-force attacks, and employ other techniques to recover user credentials.
Hashcat: Hashcat is a password-cracking tool that is particularly popular among penetration testers. It utilizes graphical processing units (GPUs) to accelerate the cracking process. It supports various algorithms and provides flexibility in using wordlists and different attack modes.
Hydra: Hydra is a tool for guessing and cracking credentials by attempting username/password combinations against target servers such as web servers, FTP servers, SSH servers, and file servers. It supports both dictionary and brute-force attacks and can be used to automate credential cracking.
RainbowCrack: RainbowCrack is a tool that automates password cracking using precomputed tables known as rainbow tables. Rainbow tables accelerate the cracking process by providing a way to reverse cryptographic hash functions and derive passwords from hashed values.
Medusa and Ncrack: Medusa and Ncrack are similar tools to Hydra, used for performing brute-force credential attacks against systems. Medusa can be installed on Debian-based Linux systems, while Ncrack can be downloaded from the official Nmap website. Both tools support various protocols and can perform dictionary and brute-force attacks.
CeWL: CeWL is a tool used to create wordlists by crawling websites. It retrieves words from the target website, allowing users to generate custom wordlists for password cracking or other purposes.
Mimikatz: Mimikatz is a versatile tool used by penetration testers, attackers, and even malware for retrieving password hashes from memory. It is commonly used as a post-exploitation tool and can be downloaded from GitHub. Mimikatz is also integrated into Metasploit as a Meterpreter script.
Patator: Patator is a tool designed for brute-force attacks on various types of credentials, such as SNMPv3 usernames and VPN passwords. It offers multiple modules and can be used to automate credential attacks.
Common Tools for Persistence

PowerSploit: A collection of PowerShell modules that can be used for post- exploitation and other phases of an assessment.
Empire: A PowerShell-based open-source post-exploitation framework that includes a PowerShell Windows agent and a Python Linux agent.
Common Tools for Evasion

Veil: Veil is a framework that works in conjunction with Metasploit to bypass antivirus checks and other security controls. It offers evasion techniques and can generate payloads that are less likely to be detected by antivirus software. Veil is available for download from GitHub and provides detailed documentation on its website.
Tor: Tor is a free tool that enables users to browse the web anonymously by routing their IP traffic through a network of Tor relays. It utilizes "onion routing" to encrypt and route data through multiple relays, making it difficult to trace the user's location. Tor is commonly used for privacy purposes and can help evade security monitoring and controls.
Proxychains: Proxychains is a tool that forces specified applications to use Tor or other proxy types for TCP connections. It can be used to redirect network traffic through proxies and enhance evasion techniques. Proxychains is available for download from GitHub.
Encryption: Encryption plays a vital role in security and privacy, but it can also pose challenges in incident response and forensics. While encryption protects sensitive information, it can be used by threat actors to evade detection and obfuscate their activities. Security products can intercept and inspect encrypted traffic, and other logs and metadata can be leveraged for investigation purposes.
Encapsulation and Tunneling Using DNS: Threat actors have exploited nontraditional techniques like DNS tunneling to exfiltrate data from corporate networks. DNS tunneling involves using DNS protocols to send unauthorized data, such as stolen credit card information, intellectual property, or confidential documents. Several tools have been developed to perform DNS tunneling, enabling cybercriminals to bypass security monitoring and controls.
Exploitation Frameworks

Metasploit: Metasploit is a widely-used exploitation framework created by H.D. Moore and now owned by Rapid7. It offers a community (free) edition and a professional edition. Metasploit has a robust architecture, written in Ruby, and comes pre-installed in Kali Linux. It provides various modules for exploits, auxiliary tasks, encoders, payloads, and more. The Metasploit console (msfconsole) is used to interact with the framework, and it supports a PostgreSQL database for indexing and accelerating tasks.
BeEF: BeEF is an exploitation framework specifically designed for web application testing. It exploits browser vulnerabilities and interacts with web browsers to launch directed command modules. BeEF allows for targeting multiple browsers in different security contexts, enabling security professionals to deploy specific attack vectors and modules in real-time. It has an extensive library of command modules and supports the development of custom modules.
Common Decompilation, Disassembly, and Debugging Tools

These debugger tools provide capabilities for debugging, analyzing, and reverse engineering software and binaries.

GNU Project Debugger (GDB): A popular debugger used for troubleshooting and finding bugs in software. Supports multiple programming languages.
Windows Debugger (WinDbg): Used for analyzing kernel and user-mode code in Windows, crash dump analysis, and CPU register analysis.
OllyDbg: Debugger for analyzing Windows 32-bit applications, commonly used in penetration testing and reverse engineering.
edb Debugger: Cross-platform debugger supporting AArch32, x86, and x86-64 architectures, included in Kali Linux.
Immunity Debugger: Tool popular among penetration testers and security researchers, used for writing exploits, analyzing malware, and reverse engineering binary files.
IDA: Commercial disassembler, debugger, and decompiler widely used for analyzing binary files and reverse engineering.
Objdump: Linux program for displaying information about object files, commonly used for quick checks and disassembly of binaries.
Common Tools for Forensics

These tools aid forensic investigators in analyzing digital evidence, recovering data, and extracting valuable information for investigations.

Autopsy: Open-source digital forensics platform with a graphical interface for analyzing digital evidence.
The Sleuth Kit: Collection of command-line tools for disk image and file system analysis.
Volatility: Memory forensics framework for analyzing volatile memory in a system.
EnCase: Commercial digital forensics tool with features like disk imaging, file recovery, and email analysis.
FTK (Forensic Toolkit): Commercial digital forensics tool for disk imaging, file analysis, and data carving.
Wireshark: Network protocol analyzer for network forensics and capturing network traffic.
Cellebrite UFED: Mobile forensic tool for extracting and analyzing data from mobile devices.
X-Ways Forensics: Comprehensive forensic tool with features for disk imaging, file analysis, and registry analysis.
Common Tools for Software Assurance

These tools aid in ensuring software quality and security by detecting bugs, vulnerabilities, and potential issues.

SpotBugs: Formerly known as FindBugs, SpotBugs is a static analysis tool for Java applications that helps identify bugs and potential issues in Java code.
Findsecbugs: Findsecbugs is a Java-specific tool that focuses on finding security-related bugs in Java applications. It integrates well with continuous integration systems like Jenkins and SonarQube.
SonarQube: SonarQube is a comprehensive tool for identifying vulnerabilities and quality issues in code. It supports continuous integration and DevOps environments.
Fuzzers and Fuzz Testing: Fuzz testing is a technique used to identify software errors and security vulnerabilities by injecting random or malformed data. Fuzzers are the tools used for fuzz testing. Here are some examples:
Peach: Peach is a popular fuzzer that offers both a free (open-source) version called Peach Fuzzer Community Edition and a commercial version.
Mutiny Fuzzing Framework: Developed by Cisco, the Mutiny Fuzzing Framework is an open-source fuzzer that replays packet capture files (pcaps) through a mutational fuzzer.
American Fuzzy Lop (AFL): AFL is a widely used fuzzer that incorporates compile-time instrumentation and genetic algorithms to enhance fuzzing test cases' functional coverage.
Wireless Tools

Wifite2: A Python program to test wireless networks.
Rogue access points: You can easily create rogue access points by using open-source tools such as hostapd.
EAPHammer: This tool can be used to perform evil twin attacks.
mdk4: This tool is used to perform fuzzing, IDS evasions, and other wireless attacks.
Spooftooph: This tool is used to spoof and clone Bluetooth devices.
Reaver: This tool is used to perform brute-force attacks against Wi-Fi Protected Setup (WPS) implementations.
Wireless Geographic Logging Engine (WiGLE): This is a war driving tool.
Fern Wi-Fi Cracker: This tool is used to perform different attacks against wireless networks, including cracking WEP, WPA, and WPS keys.
Steganography Tools

OpenStego: You can download this steganography tool from https://www.openstego.com.
snow: Text-based steganography tool.
Coagula: This program can be used to make sound from an image.
Sonic Visualiser: This tool can be used to analyze embedded information in music or audio recordings.
TinEye: A reverse image search website.
metagoofil: This tool can be used to extract metadata information from documents and images.
Cloud Tools

ScoutSuite: Tools can be used to reveal vulnerabilities in AWS, Azure, Google Cloud Platform, and other cloud platforms.
CloudBrute: A cloud enumeration tool.
Pacu: A framework for AWS exploitation.
Cloud Custodian: A cloud security, governance, and management tool.**
