# Copyright (c) 2026 SevenMatt. Todos os direitos reservados.
# Licenciado sob os termos do arquivo LICENSE na raiz do projeto.

import os
import sys
import json
import argparse

from linksentinel import TOOL_NAME, __version__
from linksentinel.analyzer import analyze


class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def use_color():
    return sys.stdout.isatty() and os.getenv("NO_COLOR") is None


def col(text, c):
    return f"{c}{text}{C.RESET}" if use_color() else str(text)


def banner():
    if not use_color():
        return
    print(col(f"""
  ============================================================
    {TOOL_NAME} v{__version__}  -  Identificador de links maliciosos
  ============================================================""", C.BOLD))


def verdict_color(verdict):
    return {"ALTO RISCO": C.RED, "SUSPEITO": C.YELLOW}.get(verdict, C.GREEN)


def print_report(res):
    print()
    print(col("=" * 60, C.BOLD))
    print(f"  URL: {res['url']}")
    print(col("=" * 60, C.BOLD))

    h = res["sections"].get("heuristic", {})
    print(col("[1] Análise heurística", C.BLUE))
    if h.get("flags"):
        for f in h["flags"]:
            print(f"    - {f}")
    else:
        print("    Nenhum padrão suspeito encontrado.")
    print(f"    Pontuação parcial: {h.get('score', 0)}\n")

    ssl_info = res["sections"].get("ssl")
    print(col("[2] Certificado SSL", C.BLUE))
    if ssl_info:
        if ssl_info.get("valid"):
            print(f"    Válido | Emissor: {ssl_info['issuer']} | Expira: {ssl_info['expires']}")
        else:
            print(col(f"    {ssl_info.get('error')}", C.RED))
    else:
        print("    Não verificado.")
    print()

    chain = res["sections"].get("redirects")
    if chain is not None:
        print(col("[3] Redirecionamentos", C.BLUE))
        if len(chain) > 1:
            for i, c in enumerate(chain):
                print(("    -> " if i else "    ") + c)
            if len(chain) > 3:
                print(col("    Muitos redirecionamentos!", C.YELLOW))
        elif chain:
            print("    Nenhum redirecionamento.")
        else:
            print("    Não foi possível acessar (host offline ou bloqueado).")
        print()

    w = res["sections"].get("whois")
    if w:
        print(col("[4] WHOIS (idade do domínio)", C.BLUE))
        if w.get("available"):
            print(f"    Criado: {w['created']} ({w['age_days']} dias)")
            if w.get("is_new"):
                print(col("    Domínio recente (< 180 dias) - risco elevado", C.YELLOW))
        else:
            print(f"    Indisponível: {w.get('reason')}")
        print()

    vt = res["sections"].get("virustotal", {})
    print(col("[5] VirusTotal", C.BLUE))
    if vt.get("available"):
        print(f"    Malicioso: {vt['malicious']}/{vt['total']} | Suspeito: {vt['suspicious']}/{vt['total']}")
        print(f"    Relatório: {vt['permalink']}")
    else:
        print(f"    Indisponível: {vt.get('reason')}")
    print()

    gsb = res["sections"].get("gsb", {})
    print(col("[6] Google Safe Browsing", C.BLUE))
    if gsb.get("available"):
        if gsb.get("flagged"):
            print(col(f"    SINALIZADO: {', '.join(gsb['types'])}", C.RED))
        else:
            print("    Nenhuma ameaça registrada.")
    else:
        print(f"    Indisponível: {gsb.get('reason')}")
    print()

    color = verdict_color(res["verdict"])
    print(col("-" * 60, C.BOLD))
    print(f"  PONTUAÇÃO DE RISCO: {col(str(res['score']), C.BOLD)}/100")
    print(f"  VEREDITO: {col(res['verdict'], color)}")
    print(col("-" * 60, C.BOLD))


def build_parser():
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME.lower(),
        description=f"{TOOL_NAME} - identifica links potencialmente maliciosos.",
        epilog='Exemplo: linksentinel "https://dominio-suspeito.com/login"',
    )
    parser.add_argument("urls", nargs="*", metavar="URL",
                        help="uma ou mais URLs a analisar")
    parser.add_argument("-f", "--file", metavar="ARQUIVO",
                        help="arquivo com uma URL por linha")
    parser.add_argument("--vt-key", default=os.getenv("VT_API_KEY"),
                        help="API key do VirusTotal (ou env VT_API_KEY)")
    parser.add_argument("--gsb-key", default=os.getenv("GSB_API_KEY"),
                        help="API key do Google Safe Browsing (ou env GSB_API_KEY)")
    parser.add_argument("--no-whois", action="store_true",
                        help="pular consulta WHOIS")
    parser.add_argument("--no-redirects", action="store_true",
                        help="não seguir redirecionamentos")
    parser.add_argument("--json", action="store_true",
                        help="saída em formato JSON")
    parser.add_argument("--quiet", action="store_true",
                        help="mostrar apenas o veredito final")
    parser.add_argument("-V", "--version", action="version",
                        version=f"{TOOL_NAME} {__version__}")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    urls = list(args.urls)
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as fh:
                urls += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        except OSError as e:
            parser.error(f"não foi possível ler o arquivo: {e}")

    if not urls:
        parser.print_help()
        sys.exit(1)

    if not args.json:
        banner()

    results = []
    for url in urls:
        res = analyze(
            url,
            vt_key=args.vt_key,
            gsb_key=args.gsb_key,
            do_whois=not args.no_whois,
            do_redirects=not args.no_redirects,
        )
        results.append(res)

        if args.json:
            print(json.dumps(res, ensure_ascii=False, indent=2))
        elif args.quiet:
            print(f"{res['score']:>3}/100  {res['verdict']:<20}  {res['url']}")
        else:
            print_report(res)

    if len(results) > 1 and not args.json and not args.quiet:
        print(col("\n=== RESUMO ===", C.BOLD))
        for r in results:
            print(f"  {r['score']:>3}/100  {col(r['verdict'], verdict_color(r['verdict'])):<24}  {r['url']}")


if __name__ == "__main__":
    main()