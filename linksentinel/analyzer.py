# Copyright (c) 2026 SevenMatt. Todos os direitos reservados.
# Licenciado sob os termos do arquivo LICENSE na raiz do projeto.

import os
import re
import ssl
import socket
import urllib.parse
from datetime import datetime

import requests
import tldextract

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/124.0 Safari/537.36")
REQUEST_TIMEOUT = 15

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "account", "update", "secure",
    "banking", "paypal", "confirm", "password", "credential",
    "download", "free", "invoice", "payment", "wallet", "seed",
    "btc", "crypto", "webscr", "authorize", "recover",
]

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq",
    "work", "click", "rest", "country", "stream", "download",
    "loan", "review", "kim", "date", "faith",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "shorturl.at",
    "rb.gy", "rebrand.ly", "tiny.cc", "lnkd.in",
}

DANGEROUS_EXT = r"\.(exe|scr|bat|cmd|msi|vbs|js|jar|apk|ps1|hta|dll|iso|lnk)$"


def heuristic_analysis(url):
    score, flags = 0, []
    parsed = urllib.parse.urlparse(url)
    ext = tldextract.extract(url)
    hostname = parsed.hostname or ""

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        score += 35
        flags.append("URL usa endereço IP bruto (sem domínio)")

    if ext.suffix.lower() in SUSPICIOUS_TLDS:
        score += 25
        flags.append(f"TLD de alto risco: .{ext.suffix}")

    subparts = [p for p in ext.subdomain.split(".") if p]
    if len(subparts) >= 3:
        score += 20
        flags.append(f"Muitos subdomínios ({len(subparts)})")

    if ext.domain.count("-") >= 3:
        score += 15
        flags.append("Domínio com muitos hífens")

    found_kw = [k for k in SUSPICIOUS_KEYWORDS if k in url.lower()]
    if found_kw:
        score += min(len(found_kw) * 8, 24)
        flags.append(f"Palavras-chave sensíveis: {', '.join(found_kw)}")

    if "@" in parsed.netloc:
        score += 30
        flags.append("URL contém '@' (possível obfuscação de host)")

    if hostname.lower() in URL_SHORTENERS:
        score += 20
        flags.append("URL encurtada (destino real oculto)")

    if len(url) > 100:
        score += 10
        flags.append(f"URL muito longa ({len(url)} caracteres)")

    if url.count("%") > 5:
        score += 10
        flags.append("Muitos caracteres codificados (%)")

    if re.search(DANGEROUS_EXT, parsed.path.lower()):
        score += 30
        flags.append("Link aponta para arquivo executável/instalável")

    if parsed.port and parsed.port not in (80, 443):
        score += 10
        flags.append(f"Porta não padrão: {parsed.port}")

    if parsed.scheme == "http":
        score += 10
        flags.append("Conexão sem HTTPS (HTTP puro)")

    return score, flags


def check_ssl(hostname, port=443):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=REQUEST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", []))
                return {"valid": True,
                        "issuer": issuer.get("organizationName", "?"),
                        "expires": cert.get("notAfter", "?")}
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "error": f"Certificado inválido: {e}"}
    except Exception as e:
        return {"valid": False, "error": str(e)}


def follow_redirects(url):
    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT},
                            allow_redirects=True, timeout=REQUEST_TIMEOUT, stream=True)
        chain = [r.url for r in resp.history] + [resp.url]
        resp.close()
        return chain
    except requests.exceptions.RequestException:
        return []


def check_virustotal(url, api_key):
    if not api_key:
        return {"available": False, "reason": "VT_API_KEY não definida"}
    headers = {"x-apikey": api_key}
    try:
        resp = requests.post("https://www.virustotal.com/api/v3/urls",
                             headers=headers, data={"url": url}, timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            return {"available": False, "reason": f"HTTP {resp.status_code}"}
        analysis_id = resp.json()["data"]["id"]
        analysis = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers, timeout=REQUEST_TIMEOUT).json()
        stats = analysis["data"]["attributes"]["stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.get(k, 0) for k in
                    ("malicious", "suspicious", "harmless", "undetected"))
        return {"available": True, "malicious": malicious,
                "suspicious": suspicious, "total": total,
                "permalink": f"https://www.virustotal.com/gui/url/{analysis_id}"}
    except Exception as e:
        return {"available": False, "reason": str(e)}


def check_google_safebrowsing(url, api_key):
    if not api_key:
        return {"available": False, "reason": "GSB_API_KEY não definida"}
    try:
        resp = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json={
                "client": {"clientId": "linksentinel", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING",
                                    "UNWANTED_SOFTWARE",
                                    "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            }, timeout=REQUEST_TIMEOUT)
        matches = resp.json().get("matches", [])
        return {"available": True, "flagged": bool(matches),
                "types": [m.get("threatType") for m in matches]}
    except Exception as e:
        return {"available": False, "reason": str(e)}


def check_whois(domain):
    if not HAS_WHOIS:
        return {"available": False, "reason": "módulo whois não instalado"}
    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            age = (datetime.now() - created).days
            return {"available": True, "created": str(created.date()),
                    "age_days": age, "is_new": age < 180}
        return {"available": False, "reason": "data de criação indisponível"}
    except Exception as e:
        return {"available": False, "reason": str(e)}


def analyze(url, vt_key=None, gsb_key=None, do_whois=True, do_redirects=True):
    """Executa a análise completa e devolve um dicionário com o resultado."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ""
    ext = tldextract.extract(url)

    result = {"url": url, "score": 0, "verdict": "", "sections": {}}

    h_score, flags = heuristic_analysis(url)
    result["sections"]["heuristic"] = {"score": h_score, "flags": flags}
    result["score"] += h_score

    if hostname:
        ssl_info = check_ssl(hostname)
        result["sections"]["ssl"] = ssl_info
        if not ssl_info.get("valid"):
            result["score"] += 15

    if do_redirects:
        chain = follow_redirects(url)
        result["sections"]["redirects"] = chain
        if len(chain) > 3:
            result["score"] += 10

    if do_whois and hostname:
        w = check_whois(ext.registered_domain)
        result["sections"]["whois"] = w
        if w.get("available") and w.get("is_new"):
            result["score"] += 15

    vt = check_virustotal(url, vt_key)
    result["sections"]["virustotal"] = vt
    if vt.get("available"):
        result["score"] += min(vt["malicious"] * 15, 60)

    gsb = check_google_safebrowsing(url, gsb_key)
    result["sections"]["gsb"] = gsb
    if gsb.get("available") and gsb.get("flagged"):
        result["score"] += 60

    result["score"] = min(result["score"], 100)
    if result["score"] >= 70:
        result["verdict"] = "ALTO RISCO"
    elif result["score"] >= 40:
        result["verdict"] = "SUSPEITO"
    else:
        result["verdict"] = "PROVAVELMENTE SEGURO"

    return result