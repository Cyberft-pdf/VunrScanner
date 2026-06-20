# Vulnerability Scanner

Modulární síťový a webový vulnerability scanner napsaný v Pythonu s live terminal UI.

```
 __   ___   _  _ _    _  _     ___  ___   _   _  _
 \ \ / / | | || | |  | \| |   / __|/ __| /_\ | \| |
  \ V /| |_| __ | |__| .` |   \__ \ (__ / _ \| .` |
   \_/ |_(_)_||_|____|_|\_|   |___/\___/_/ \_\_|\_|
```

## Funkce

| Modul | Popis |
|---|---|
| **Port Scanner** | Async TCP sken nejčastějších portů s detekcí služby |
| **Web Analyzer** | HTTP hlavičky, SSL/TLS validace, cookies, přesměrování |
| **Subdomain Enum** | DNS brute-force 80+ běžných subdomén |
| **Tech Detector** | Fingerprinting technologií z hlaviček, cookies a HTML |
| **Dir Bruteforce** | Hledání skrytých cest, admin panelů a citlivých souborů |
| **Vuln Checker** | SQLi, XSS, chybějící security headers, exposed paths |

### Live packet log

Během skenování vidíš v reálném čase každý odeslaný paket / request:

```
╭──────────────────   live packets   ──────────────────╮
│  TCP   ▶  192.168.1.1:22        OPEN     SSH         │
│  TCP   ·  192.168.1.1:21        closed               │
│  DNS   ▶  admin.example.com     93.184.216.34        │
│  GET   ▶  http://example.com/   200      nginx/1.18  │
│  TECH  ▶  nginx v1.18           Web Server           │
│  DIR   ·  /admin.php            404                  │
│  DIR   ▶  /.htaccess            403      SENSITIVE!  │
│  CHK   ▶  Security Headers      5 missing            │
│  CHK   ·  SQL Injection         clean                │
╰──────────────────────────────────────────────────────╯
```

## Instalace

**Požadavky:** Python 3.11+

```bash
git clone https://github.com/tvoje-repo/vuln-scanner
cd vuln-scanner
pip install -r requirements.txt
```

## Použití

```bash
# Základní scan
py scanner.py example.com

# Vlastní porty
py scanner.py example.com -p 80,443,8080,3000

# Hlubší dir bruteforce (větší wordlist)
py scanner.py example.com --deep

# Uložit výsledky
py scanner.py example.com --json report.json
py scanner.py example.com --html report.html

# Vše najednou
py scanner.py example.com --deep --json r.json --html r.html
```

### Přepínače

| Přepínač | Popis |
|---|---|
| `target` | Cíl: doména, IP nebo URL |
| `-p, --ports` | Čárkou oddělené porty: `80,443,8080` |
| `--deep` | Hlubší dir bruteforce (větší wordlist) |
| `--json SOUBOR` | Export výsledků do JSON |
| `--html SOUBOR` | Export výsledků do HTML reportu |

## Struktura projektu

```
vuln-scanner/
├── scanner.py              ← vstupní bod, CLI, live UI
├── engine.py               ← orchestrace modulů (asyncio)
├── models.py               ← datové třídy (ScanResult, Vuln, Port...)
├── packet_log.py           ← live packet log systém
├── modules/
│   ├── port_scanner.py     ← async TCP port scan
│   ├── web_scanner.py      ← HTTP analýza, SSL check
│   ├── subdomain_enum.py   ← DNS brute-force subdomén
│   ├── tech_detector.py    ← fingerprinting technologií
│   ├── dir_bruteforce.py   ← hledání skrytých cest
│   └── vuln_checker.py     ← SQLi, XSS, security headers
└── reporter/
    ├── terminal.py         ← rich terminal výstup
    ├── json_report.py      ← JSON export
    └── html_report.py      ← HTML report
```

## Výstup

### Terminál
Barevně formátované tabulky se severity badges:

```
  HIGH   1    MED   2    LOW   2
```

### HTML report
Tmavý hacker-style report se všemi výsledky.

### JSON
Strojově čitelný výstup pro integraci s jinými nástroji.

## Závažnost zranitelností

| Úroveň | Barva | Příklad |
|---|---|---|
| CRITICAL | červená | SQL Injection |
| HIGH | červená | Chybí HSTS, Exposed .env |
| MEDIUM | oranžová | Chybí CSP, X-Frame-Options |
| LOW | žlutá | Chybí Referrer-Policy |
| INFO | modrá | Informační nálezy |

## Právní upozornění

> Tento nástroj je určen **výhradně pro testování vlastních systémů** nebo systémů, ke kterým máš výslovné písemné svolení vlastníka. Neoprávněné skenování cizích systémů je v rozporu se zákonem.

## Závislosti

- [aiohttp](https://docs.aiohttp.org/) — async HTTP klient
- [rich](https://rich.readthedocs.io/) — terminálové UI
