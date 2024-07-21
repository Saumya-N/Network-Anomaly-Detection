# Cybersecurity

Problem Statement

Network Anomaly Detection is one of the most important and an ever evolving field in the domain of cybersecurity. With the improvisation of existing methodologies and the advent of new ones for identifying and mitigating cyber risk, the advancement in threats have also increased. 
The task at hand is to have a detailed understanding of the domain and to identify the areas of cybersecurity where one can leverage the capabilities of the various available machine learning algorithms like supervised, unsupervised and deep learning and to combine them together to identify existing and new threats with high precision and in time.

About the Dataset:

Attack Column:
The attacks listed in the provided data correspond to several categories of common cyberattacks. Here's how each attack aligns with the known categories of cyberattacks:
The list of attack types mentioned can be categorized into four main categories of cyberattacks: Denial-of-Service (DoS), Probe, Remote-to-Local (R2L), and User-to-Root (U2R) attacks. Here's the categorization of each attack:

	1. Denial-of-Service (s) Attacks
		○ neptune: SYN flood DoS attack.
		○ teardrop: Fragmented packet DoS attack.
		○ smurf: ICMP flood DoS attack.
		○ pod: Ping of Death DoS attack.
		○ back: Backdoor attack that can be used to initiate a DoS.
		○ land: DoS attack where the source and destination IP addresses are the same.

	2. Probe Attacks
		○ ipsweep: Network scanning to discover active hosts.
		○ portsweep: Scanning ports to find open services.
		○ nmap: Network scanning using the Nmap tool.
		○ satan: Network vulnerability scanning.

	3. Remote-to-Local (R2L) Attacks
		○ warezclient: Unauthorized access to a local machine.
		○ guess_passwd: Password guessing attack.
		○ ftp_write: Exploiting FTP to write to the system.
		○ imap: Exploiting IMAP vulnerabilities.
		○ warezmaster: Unauthorized access to a local machine.
		○ phf: Exploiting a CGI script vulnerability.
		○ spy: Unauthorized access to a local machine.
	
	4. User-to-Root (U2R) Attacks
		○ rootkit: Gaining root access.
		○ buffer_overflow: Exploiting buffer overflow vulnerabilities to gain root access.
		○ loadmodule: Exploiting vulnerabilities to load malicious modules.
		○ perl: Exploiting Perl script vulnerabilities.
		○ multihop: Using multiple hops to exploit vulnerabilities and gain root access.
	
Normal Traffic
normal: Represents non-attack traffic or normal network behavior.

This categorization helps in understanding the nature of each attack type and assists in developing appropriate detection and mitigation strategies for network security.
