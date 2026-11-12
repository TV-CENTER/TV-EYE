# TV-EYE v1.0.0

**Offensive Security & Bug Bounty Console**

> Author: **Mr_TV**  |  Telegram: **@Mr_TV_ir**  |  GitHub: **https://github.com/TV-CENTER**

TV-EYE is a professional, dependency-free (pure Python standard library) console
framework for **authorized** penetration testing and bug-bounty work. It runs on
**Windows** (cmd.exe / PowerShell / Windows Terminal / Git Bash) and
**Linux/macOS** with zero installation steps beyond having Python 3.8+.

---

## Quick start

Windows (double click `TV-EYE.bat`) or:

```
python tveye.py
```

Linux/macOS:

```
chmod +x TV-EYE.sh
./TV-EYE.sh
```

Non-interactive one-liners:

```
python tveye.py -e "quick http://target.local"
python tveye.py -m security_headers -o target=http://10.0.0.5 --run
python tveye.py --authors
```

## Console commands

| Command | Description |
|---|---|
| `help` | full command help |
| `modules` | list every module grouped by category |
| `search <kw>` | find modules by keyword |
| `use <module>` | select the active module |
| `info <module>` | module description and options |
| `set <opt> <value>` | set an option (e.g. `set target http://10.0.0.5`) |
| `run` / `run <module>` | execute a module |
| `quick <target>` | fast recon chain (dns, tech, headers, secrets) |
| `deep <target>` | adds subdomains, dir-buster and port scan |
| `target add/list/clear` | manage target list |
| `findings` / `findings clear` | view / reset findings |
| `report md/html/json/all` | write report files to workspace |
| `save` / `load` | persist or restore a session |
| `status` | options, targets, finding summary |
| `tools` | detect optional external tools (nmap, sqlmap, ffuf...) |
| `authors` / `legal` / `version` | credits and authorized-use notice |
| `shell <cmd>` / `! <cmd>` | run an OS command |
| `exit` | quit |

## Global options

```
set threads 20        # concurrency
set timeout 8         # request timeout
set proxy http://127.0.0.1:8080   # route all traffic through Burp/ZAP
set cookie "SESSION=..."          # authenticated testing
set user-agent "custom-agent"
set verify-tls 0      # allow self-signed targets
set delay 0.5         # polite pacing between requests
```

## Module catalog (25)

**recon** – dns_recon, whois_lookup, reverse_dns, subdomain_enum, takeover_check,
wayback_urls

**web** – tech_fingerprint, waf_detect, security_headers, tls_audit, cors_scan,
header_recon

**osint** – osint_harvest, email_hunt, github_dorks, js_secrets

**inject** – xss_scan, sqli_scan, lfi_scan, ssti_scan, open_redirect, crlf_scan,
ssrf_scan, xxe_probe

**logic** – jwt_audit, graphql_scan, rate_limit_check, idor_hunt

**network** – port_scan, host_discovery

**auth** – login_brute

**tools** – hash_id, encoder, jwt_decode, header_gen, cve_hints, payload_gen

## Typical bug bounty flow

```
quick https://example.com            # surface level in one shot
use subdomain_enum   -> set domain example.com -> run
use takeover_check   -> set domain example.com -> run
use param_miner      -> set target https://example.com/search?q=1 -> run
use xss_scan         -> set target https://example.com/search?q=1 -> run
use jwt_audit        -> set token <jwt> -> run
findings             # review
report html myreport # deliverable
```

## Authorized use only

TV-EYE is built for authorized security work only: bug bounty programs inside
their published scope, penetration tests with written permission, and your own
lab. Anything outside explicit permission is illegal. You are responsible for
how you use this tool.
