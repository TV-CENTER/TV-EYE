# TV-EYE
Dependency-free Python pentest and bug bounty console: recon, injection tests, header/TLS audits, port scan and reports. Authorized use only.

کنسول تست نفوذ و باگ‌بانتی با پایتون (بدون وابستگی): شناسایی، تست تزریق، بررسی هدر و TLS، اسکن پورت و گزارش‌گیری. فقط برای تست مجاز.


# TV-EYE

**Offensive Security & Bug Bounty Console**

> Author: **Mr_TV** | Telegram: **@Mr_TV_ir** | GitHub: https://github.com/TV-CENTER

TV-EYE is a professional console framework for **authorized** penetration testing and **bug bounty** work. It is written in pure Python standard library (nothing to install) and runs on **Windows**, **Linux** and **macOS** with Python 3.8+.

## What does TV-EYE do?

Use TV-EYE to assess the security of a website, API or server: from initial reconnaissance to testing common vulnerabilities, ending with a ready-to-submit report. It does nothing on its own; you choose the target and run each module yourself.

## Features (25 modules)

- **Recon:** dns_recon, whois_lookup, reverse_dns, subdomain_enum, takeover_check, wayback_urls
- **Web:** tech_fingerprint, waf_detect, security_headers, tls_audit, cors_scan, header_recon
- **OSINT:** osint_harvest, email_hunt, github_dorks, js_secrets (finds leaked keys and secrets in JS files)
- **Injection:** xss_scan, sqli_scan, lfi_scan, ssti_scan, open_redirect, crlf_scan, ssrf_scan, xxe_probe
- **Logic:** jwt_audit, graphql_scan, rate_limit_check, idor_hunt
- **Network:** port_scan, host_discovery
- **Auth:** login_brute (for authorized testing, capped at 500 attempts per run)
- **Utilities:** hash_id, encoder, jwt_decode, header_gen, cve_hints, payload_gen
- **Reporting:** Markdown, HTML and JSON output
- **Extras:** session save/load, proxy support (Burp/ZAP), custom cookie and User-Agent, adjustable threads and delay, detection of optional external tools (nmap, sqlmap, ffuf, ...)

## Quick start

Windows: double-click `TV-EYE.bat`, or:

```
python tveye.py
```

Linux/macOS:

```
chmod +x TV-EYE.sh
./TV-EYE.sh
```

Non-interactive:

```
python tveye.py -e "quick http://target.local"
python tveye.py -m security_headers -o target=http://10.0.0.5 --run
python tveye.py --authors
```

## Console commands

| Command | Description |
|---|---|
| `help` | full help |
| `modules` / `search <kw>` | list and search modules |
| `use <module>` / `info <module>` | select a module, view description and options |
| `set <opt> <value>` | set an option (e.g. `set target http://10.0.0.5`) |
| `run` | execute the module |
| `quick <target>` | fast recon chain (dns, tech, headers, secrets) |
| `deep <target>` | adds subdomains, dir-buster and port scan |
| `findings` / `report md/html/json/all` | view findings and write reports |
| `save` / `load` | persist or restore a session |
| `shell <cmd>` | run an OS command (only what you type yourself) |

## Global options

```
set threads 20
set timeout 8
set proxy http://127.0.0.1:8080
set cookie "SESSION=..."
set user-agent "custom-agent"
set verify-tls 0
set delay 0.5
```

## Privacy and safety

- No external dependencies, no obfuscated code, no telemetry.
- Your data is not sent to any server. It only requests the target you choose, plus public lookup services (crt.sh, web.archive.org, api.github.com), and webhook.site only if you supply a token for SSRF testing.
- The `tests` folder is a lab server bound to `127.0.0.1` only, with fake data, used for the tool's self-test.

## Authorized use only

TV-EYE is built for authorized security work only: bug bounty programs inside their published scope, penetration tests with written permission, and your own lab. Anything outside explicit permission is illegal, and you are responsible for how you use this tool. Some antivirus products may flag it as a "hacktool", which is typical for security tools.



# TV-EYE

**کنسول امنیت تهاجمی و باگ‌بانتی (Offensive Security & Bug Bounty Console)**

> نویسنده: **Mr_TV** | تلگرام: **@Mr_TV_ir** | گیت‌هاب: https://github.com/TV-CENTER

TV-EYE یک فریم‌ورک کنسولی حرفه‌ای برای **تست نفوذ مجاز** و برنامه‌های **باگ‌بانتی** است. فقط با کتابخانه‌ی استاندارد پایتون نوشته شده (بدون نیاز به نصب هیچ پکیج) و روی **ویندوز**، **لینوکس** و **macOS** با Python 3.8 یا بالاتر اجرا می‌شود.

## TV-EYE چه کاری می‌کند؟

با TV-EYE می‌توانید امنیت یک وب‌سایت، API یا سرور را بررسی کنید: از جمع‌آوری اطلاعات اولیه تا تست آسیب‌پذیری‌های رایج، و در پایان یک گزارش آماده تحویل بگیرید. خودش به‌تنهایی هیچ کاری نمی‌کند؛ هدف را شما تعیین می‌کنید و هر ماژول را خودتان اجرا می‌کنید.

## قابلیت‌ها (۲۵ ماژول)

- **شناسایی (recon):** dns_recon، whois_lookup، reverse_dns، subdomain_enum، takeover_check، wayback_urls
- **وب:** tech_fingerprint، waf_detect، security_headers، tls_audit، cors_scan، header_recon
- **OSINT:** osint_harvest، email_hunt، github_dorks، js_secrets (پیدا کردن کلید و رمز لو رفته در فایل‌های JS)
- **تزریق (inject):** xss_scan، sqli_scan، lfi_scan، ssti_scan، open_redirect، crlf_scan، ssrf_scan، xxe_probe
- **منطق برنامه:** jwt_audit، graphql_scan، rate_limit_check، idor_hunt
- **شبکه:** port_scan، host_discovery
- **احراز هویت:** login_brute (برای تست مجاز، حداکثر ۵۰۰ تلاش در هر اجرا)
- **ابزارهای کمکی:** hash_id، encoder، jwt_decode، header_gen، cve_hints، payload_gen
- **گزارش‌گیری:** خروجی Markdown، HTML و JSON
- **سایر:** ذخیره و بازیابی نشست، پشتیبانی از پراکسی (Burp/ZAP)، کوکی و User-Agent دلخواه، تعداد thread و تأخیر قابل تنظیم، تشخیص ابزارهای خارجی اختیاری (nmap، sqlmap، ffuf و ...)

## اجرا

ویندوز: روی `TV-EYE.bat` دوبار کلیک کنید، یا:

```
python tveye.py
```

لینوکس/macOS:

```
chmod +x TV-EYE.sh
./TV-EYE.sh
```

اجرای غیرتعاملی:

```
python tveye.py -e "quick http://target.local"
python tveye.py -m security_headers -o target=http://10.0.0.5 --run
python tveye.py --authors
```

## دستورات اصلی کنسول

| دستور | توضیح |
|---|---|
| `help` | راهنمای کامل |
| `modules` / `search <kw>` | فهرست و جستجوی ماژول‌ها |
| `use <module>` / `info <module>` | انتخاب ماژول و دیدن توضیح و گزینه‌ها |
| `set <opt> <value>` | تنظیم گزینه (مثلاً `set target http://10.0.0.5`) |
| `run` | اجرای ماژول |
| `quick <target>` | بررسی سریع (dns، tech، headers، secrets) |
| `deep <target>` | بررسی عمیق‌تر (زیردامنه، dir-buster، اسکن پورت) |
| `findings` / `report md/html/json/all` | مشاهده یافته‌ها و ساخت گزارش |
| `save` / `load` | ذخیره و بازیابی نشست |
| `shell <cmd>` | اجرای دستور سیستم‌عامل (فقط چیزی که خودتان بنویسید) |

## گزینه‌های سراسری

```
set threads 20
set timeout 8
set proxy http://127.0.0.1:8080
set cookie "SESSION=..."
set user-agent "custom-agent"
set verify-tls 0
set delay 0.5
```

## حریم خصوصی و امنیت

- بدون وابستگی خارجی، بدون کد مبهم‌سازی‌شده و بدون telemetry.
- داده‌های شما به هیچ سروری ارسال نمی‌شود. فقط به هدفی که تعیین می‌کنید درخواست می‌زند، به‌علاوه سرویس‌های عمومی crt.sh، web.archive.org و api.github.com برای جستجو، و webhook.site فقط اگر خودتان برای تست SSRF توکن بدهید.
- پوشه‌ی `tests` یک سرور آزمایشی فقط روی `127.0.0.1` با داده‌های جعلی است که برای خودآزمایی ابزار استفاده می‌شود.

## استفاده‌ی مجاز

TV-EYE فقط برای کار امنیتی مجاز ساخته شده است: برنامه‌های باگ‌بانتی داخل محدوده‌ی اعلام‌شده، تست نفوذ با اجازه‌ی کتبی، و آزمایشگاه شخصی خودتان. هر استفاده‌ی خارج از اجازه‌ی صریح غیرقانونی است و مسئولیت آن با شماست. ممکن است آنتی‌ویروس‌ها این ابزار را به‌عنوان «hacktool» علامت بزنند؛ این رفتار معمول ابزارهای امنیتی است.
