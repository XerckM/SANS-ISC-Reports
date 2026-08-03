# SANS ISC Attack Observation Reports

GitHub-ready Markdown conversions of Attack Observations 2-4, with individually extracted and descriptively named evidence screenshots.

## Reports

- [Attack Observation 2 - Automated Telnet Malware Loader Attempt](attack-observation-2/README.md)
- [Attack Observation 3 - Multi-Architecture SOCKS5 Proxy Deployment Attempt](attack-observation-3/README.md)
- [Attack Observation 4 - Automated Mirai Malware Loader Attempt](attack-observation-4/README.md)

## Folder structure

```text
attack-observation-2/
  README.md
  Attack_Observation_2.md
  images/
attack-observation-3/
  README.md
  Attack_Observation_3.md
  images/
attack-observation-4/
  README.md
  Attack_Observation_4.md
  images/
EVIDENCE_MANIFEST.csv
```

Each folder contains a `README.md` so GitHub automatically displays the report when the folder is opened. The separately named `Attack_Observation_N.md` file contains the same content for direct linking or reuse.

## Public-repository safety

- URLs in the Markdown reports are defanged.
- No executable payloads, raw malware, PCAPs, private keys, or Base64 payload files are included.
- The public/NAT address shown in the original Attack Observation 2 PDF is omitted from the Markdown conversion.
- Evidence images are screenshots extracted from the submitted reports and may still display attack-source IPs, honeypot-private addresses, commands, and hashes necessary to understand the investigation.
