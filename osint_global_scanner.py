
import os
import requests
import json
import time
import ipaddress
from datetime import datetime
from typing import List, Dict
import streamlit as st
from fpdf import FPDF
from dotenv import load_dotenv
import shodan

# Carica le variabili locali da .env (se in locale) oppure usa st.secrets (se su Streamlit Cloud)
load_dotenv()

HUNTER_API_KEY = os.getenv("HUNTER_API_KEY", st.secrets.get("HUNTER_API_KEY", ""))
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", st.secrets.get("SHODAN_API_KEY", ""))
APP_PASSWORD = os.getenv("APP_PASSWORD", st.secrets.get("APP_PASSWORD", ""))

# Configurazione della pagina Streamlit con layout reattivo
st.set_page_config(
    page_title="OSINT Global - Secure Suite",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="auto"
)

# --- SISTEMA DI AUTENTICAZIONE PASSWORD ---
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

def check_password():
    """Verifica la password inserita dall'utente rispetto a quella nei secrets."""
    entered_password = st.session_state.get("password_input", "")
    if APP_PASSWORD and entered_password == APP_PASSWORD:
        st.session_state.authenticated = True
        st.session_state["password_input"] = ""
    else:
        st.session_state.authenticated = False
        st.error("❌ Password errata o non configurata nei secrets.")

if not st.session_state.authenticated:
    st.title("🔐 Accesso Protetto - OSINT Global Suite")
    st.markdown("Questa applicazione contiene strumenti di ricognizione avanzata. Inserisci la password per procedere.")

    st.text_input("Password di accesso:", type="password", key="password_input", on_change=check_password)
    st.button("🔑 Accedi", on_click=check_password)
    st.stop()

# --- STILI CSS RESPONSIVE PER SMARTPHONE, TABLET E PC ---
st.markdown("""
    <style>
    [data-testid="stDataFrame"] {
        width: 100% !important;
        overflow-x: auto;
    }
    @media (max-width: 768px) {
        .block-container {
            padding-left: 1rem;
            padding-right: 1rem;
            padding-top: 2rem;
        }
        .dork-btn {
            display: block;
            margin-bottom: 8px;
        }
    }
    a {
        text-decoration: none;
        font-weight: 500;
    }
    a:hover {
        text-decoration: underline;
    }
    </style>
""", unsafe_allow_html=True)

if "history" not in st.session_state:
    st.session_state.history = {}

# --- FUNZIONE DI SUPPORTO PER VALIDARE IP ---
def is_valid_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False

# --- 1. MODULO DI GENERAZIONE PDF DEFINITIVO ---
class PDFReportGenerator(FPDF):
    def header(self):
        self.set_font('helvetica', 'B', 14)
        self.set_text_color(26, 82, 118)
        self.cell(0, 10, 'OSINT Global - Advanced Recon & IoT Report', 0, 1, 'C')
        self.set_font('helvetica', 'I', 9)
        self.set_text_color(100, 100, 100)
        self.cell(0, 5, 'Attack Surface, SSL, Tech Stack, IoT, InternetDB & Contacts Intelligence', 0, 1, 'C')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def clean_for_pdf(text: str) -> str:
    if not text:
        return ""
    cleaned = str(text).replace('✅', '[OK]').replace('❌', '[NO]').replace('🟢', '[ACTIVE]').replace('🔴', '[OFFLINE]')
    return cleaned.encode('latin-1', 'replace').decode('latin-1')

def generate_pdf_report(target: str, is_ip: bool, dns_info: Dict, email_security: Dict, dmarc_check: Dict, subdomains_data: List[Dict], iot_data: List[Dict], hunter_data: Dict, company_data: Dict, contacts_table: List[Dict]) -> bytes:
    pdf = PDFReportGenerator()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    org_name = clean_for_pdf(company_data.get("name", hunter_data.get("organization", "N/D")))
    spf_clean = clean_for_pdf(email_security.get("SPF", "N/D"))
    dmarc_clean = clean_for_pdf(email_security.get("DMARC", "N/D"))
    dmarc_policy = clean_for_pdf(dmarc_check.get("policy", "N/D"))

    pdf.set_font('helvetica', 'B', 11)
    pdf.set_text_color(0, 0, 0)
    target_label = f'Target IP: {target}' if is_ip else f'Target Domain: {target}'
    pdf.cell(0, 7, clean_for_pdf(target_label), 0, 1)
    pdf.set_font('helvetica', '', 9)
    pdf.cell(0, 5, f'Organization: {org_name}', 0, 1)
    pdf.cell(0, 5, f'Total Subdomains Discovered: {len(subdomains_data)}', 0, 1)
    pdf.cell(0, 5, f'Total IoT/Exposed Assets: {len(iot_data)}', 0, 1)
    pdf.cell(0, 5, f'Total Contacts Discovered: {len(contacts_table)}', 0, 1)
    pdf.ln(4)

    pdf.set_font('helvetica', 'B', 11)
    pdf.cell(0, 7, '1. Email Security & Advanced Anti-Spoofing', 0, 1)
    pdf.set_font('helvetica', '', 9)
    pdf.cell(0, 5, f' - SPF Protection: {spf_clean}', 0, 1)
    pdf.cell(0, 5, f' - DMARC Protection: {dmarc_clean} (Policy: {dmarc_policy})', 0, 1)
    pdf.ln(4)

    pdf.set_font('helvetica', 'B', 11)
    pdf.cell(0, 7, '2. Discovered IoT Devices & Exposed Assets (Shodan API)', 0, 1)
    pdf.set_font('helvetica', '', 8)
    if iot_data:
        for idx, iot in enumerate(iot_data, 1):
            ip = clean_for_pdf(iot.get('IP'))
            port = clean_for_pdf(str(iot.get('Porta')))
            prod = clean_for_pdf(iot.get('Prodotto / Dispositivo'))
            line = f"{idx}. IP: {ip} | Port: {port} | Product: {prod}"
            pdf.cell(0, 5, line, 0, 1)
    else:
        pdf.cell(0, 5, ' No public IoT devices indexed.', 0, 1)
    pdf.ln(4)

    pdf.set_font('helvetica', 'B', 11)
    pdf.cell(0, 7, '3. Discovered Contacts, Emails & Socials (Hunter.io)', 0, 1)
    pdf.set_font('helvetica', '', 7)
    if contacts_table:
        for idx, contact in enumerate(contacts_table, 1):
            mail = clean_for_pdf(contact.get('mail'))
            name = clean_for_pdf(contact.get('nome-cognome'))
            pos = clean_for_pdf(contact.get('posizione'))
            lin = clean_for_pdf(contact.get('profilo linkedin'))
            ig = clean_for_pdf(contact.get('instagram'))
            fb = clean_for_pdf(contact.get('facebook'))
            tk = clean_for_pdf(contact.get('tiktok'))
            line = f"{idx}. {mail} | {name} | {pos} | LI: {lin} | IG: {ig} | FB: {fb} | TK: {tk}"
            pdf.cell(0, 4, line, 0, 1)
    else:
        pdf.cell(0, 5, ' No public emails discovered.', 0, 1)
    pdf.ln(4)

    pdf.set_font('helvetica', 'B', 11)
    pdf.cell(0, 7, '4. Subdomains, SSL, Tech Stack & InternetDB Intelligence', 0, 1)
    pdf.set_font('helvetica', 'I', 7)
    pdf.cell(0, 4, 'Note: CVEs and ports are indexed passive intelligence, not verified active exploits.', 0, 1)
    pdf.set_font('helvetica', '', 8)
    if subdomains_data:
        for sub in subdomains_data[:30]:
            sub_name = clean_for_pdf(sub.get('Sottodominio'))
            ip_addr = clean_for_pdf(sub.get('IP', 'N/D'))
            ports = clean_for_pdf(str(sub.get('Porte Aperte', 'N/D')))
            cves = clean_for_pdf(str(sub.get('Vulnerabilità CVE', 'N/D')))
            line = f" - {sub_name} (IP: {ip_addr}) | Ports: {ports} | CVEs: {cves}"
            pdf.cell(0, 5, line, 0, 1)
    else:
        pdf.cell(0, 5, ' No subdomains discovered.', 0, 1)

    return bytes(pdf.output(dest='S'))

# --- 2. MODULO DI RICOGNIZIONE PASSIVA E INTERNETDB ---
class PassiveReconGlobal:

    @staticmethod
    def get_passive_subdomains_and_ssl(domain: str) -> List[Dict]:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        subdomains_map = {}
        headers = {"User-Agent": "OSINT-Global-Research-Tool/1.0"}

        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = requests.get(url, timeout=25, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    for entry in data:
                        name_value = entry.get('name_value', '')
                        not_after = entry.get('not_after', 'N/D')
                        if not_after != 'N/D':
                            try:
                                not_after = datetime.strptime(not_after.split('T')[0], "%Y-%m-%d").strftime("%d/%m/%Y")
                            except Exception:
                                pass

                        for sub in name_value.split('\n'):
                            sub = sub.strip().lower()
                            if sub and '*' not in sub and sub.endswith(domain):
                                if sub not in subdomains_map or subdomains_map[sub] == 'N/D':
                                    subdomains_map[sub] = not_after
                    break
            except requests.exceptions.Timeout:
                if attempt < max_retries - 1:
                    time.sleep(2)
                    continue
            except Exception:
                break

        if not subdomains_map:
            try:
                backup_url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
                resp = requests.get(backup_url, timeout=10)
                if resp.status_code == 200 and "API count exceeded" not in resp.text:
                    for line in resp.text.splitlines():
                        parts = line.split(',')
                        if parts:
                            sub = parts[0].strip().lower()
                            if sub.endswith(domain):
                                subdomains_map[sub] = 'N/D'
            except Exception:
                pass

        formatted_subs = [{"subdomain": sub, "ssl_expiry": exp} for sub, exp in sorted(subdomains_map.items())]
        return formatted_subs

    @staticmethod
    def resolve_domain_to_ip(subdomain: str) -> str:
        try:
            resp = requests.get(
                f"https://cloudflare-dns.com/dns-query?name={subdomain}&type=A",
                headers={"Accept": "application/dns-json"},
                timeout=3
            )
            if resp.status_code == 200:
                data = resp.json()
                if "Answer" in data:
                    for ans in data["Answer"]:
                        if ans.get("type") == 1:
                            return ans.get("data")
        except Exception:
            pass
        return "N/D"

    @staticmethod
    def check_shodan_internetdb(ip_address: str) -> Dict:
        result = {"ports": [], "cves": []}
        if not ip_address or ip_address == "N/D":
            return result
        try:
            url = f"https://internetdb.shodan.io/{ip_address}"
            response = requests.get(url, timeout=4)
            if response.status_code == 200:
                data = response.json()
                result["ports"] = data.get("ports", [])
                result["cves"] = data.get("vulns", [])
        except Exception:
            pass
        return result

    @staticmethod
    def search_shodan_iot_devices(query_str: str, shodan_key: str, is_ip: bool = False) -> List[Dict]:
        iot_results = []
        if not shodan_key:
            return iot_results
        try:
            api = shodan.Shodan(shodan_key)
            query = f"ip:{query_str}" if is_ip else f"hostname:{query_str}"
            results = api.search(query, limit=10)

            for match in results.get('matches', []):
                iot_results.append({
                    "IP": match.get('ip_str', 'N/D'),
                    "Porta": match.get('port', 'N/D'),
                    "Organizzazione": match.get('org', 'N/D'),
                    "Prodotto / Dispositivo": match.get('product', 'N/D'),
                    "OS / Info": match.get('os', 'N/D') or "N/D",
                    "Banner": match.get('data', '')[:150].replace('\n', ' ')
                })
        except Exception:
            pass
        return iot_results

    @staticmethod
    def get_public_dns_info(domain: str) -> Dict:
        results = {"mx": [], "txt": []}
        try:
            mx_resp = requests.get(
                f"https://cloudflare-dns.com/dns-query?name={domain}&type=MX",
                headers={"Accept": "application/dns-json"},
                timeout=5
            )
            if mx_resp.status_code == 200:
                data = mx_resp.json()
                if "Answer" in data:
                    for ans in data["Answer"]:
                        raw_data = ans.get("data", "").strip()
                        clean_mx = raw_data.strip('"').rstrip('.')
                        if clean_mx:
                            results["mx"].append(clean_mx)
        except Exception:
            pass

        try:
            txt_resp = requests.get(
                f"https://cloudflare-dns.com/dns-query?name={domain}&type=TXT",
                headers={"Accept": "application/dns-json"},
                timeout=5
            )
            if txt_resp.status_code == 200:
                data = txt_resp.json()
                if "Answer" in data:
                    results["txt"] = [ans.get("data").strip('"') for ans in data["Answer"]]
        except Exception:
            pass

        return results

    @staticmethod
    def check_dmarc_record(domain: str) -> Dict[str, str]:
        dmarc_result = {
            "status": "❌ Assente (Rischio Spoofing Elevato)",
            "policy": "N/D",
            "rua": "N/D",
            "ruf": "N/D",
            "raw": ""
        }
        target_host = f"_dmarc.{domain}"
        try:
            resp = requests.get(
                f"https://cloudflare-dns.com/dns-query?name={target_host}&type=TXT",
                headers={"Accept": "application/dns-json"},
                timeout=5
            )
            if resp.status_code == 200:
                data = resp.json()
                if "Answer" in data:
                    for ans in data["Answer"]:
                        txt_val = ans.get("data", "").strip('"')
                        if "v=dmarc1" in txt_val.lower():
                            dmarc_result["raw"] = txt_val
                            dmarc_result["status"] = "✅ Configurato correttamente"

                            if "p=reject" in txt_val.lower():
                                dmarc_result["policy"] = "Reject (Massima Sicurezza)"
                            elif "p=quarantine" in txt_val.lower():
                                dmarc_result["policy"] = "Quarantine (In Spam)"
                            elif "p=none" in txt_val.lower():
                                dmarc_result["policy"] = "None (Solo Monitoraggio)"

                            if "rua=" in txt_val.lower():
                                try:
                                    rua_part = [p for p in txt_val.split(';') if 'rua=' in p.lower()][0]
                                    dmarc_result["rua"] = rua_part.split('=')[1].strip()
                                except Exception:
                                    pass
                            if "ruf=" in txt_val.lower():
                                try:
                                    ruf_part = [p for p in txt_val.split(';') if 'ruf=' in p.lower()][0]
                                    dmarc_result["ruf"] = ruf_part.split('=')[1].strip()
                                except Exception:
                                    pass
                            break
        except Exception:
            pass
        return dmarc_result

    @staticmethod
    def analyze_email_security(txt_records: List[str], dmarc_info: Dict[str, str]) -> Dict[str, str]:
        security = {
            "SPF": "❌ Assente (Rischio Spoofing Elevato)",
            "DMARC": dmarc_info["status"]
        }
        for txt in txt_records:
            txt_lower = txt.lower()
            if "v=spf1" in txt_lower:
                mechanisms = txt_lower.count("include:") + txt_lower.count("a") + txt_lower.count("mx") + txt_lower.count("ptr") + txt_lower.count("exists") + txt_lower.count("redirect")
                if mechanisms > 10:
                    security["SPF"] = "⚠️ Configurato (Attenzione: Lookup DNS potenzialmente > 10)"
                else:
                    security["SPF"] = "✅ Configurato correttamente"
        return security

    @staticmethod
    def check_security_headers_and_tech(subdomain: str) -> Dict[str, str]:
        result = {
            "Status": "Unreachable",
            "HSTS": "❌ Absent",
            "X-Frame-Options": "❌ Absent",
            "Content-Security-Policy": "❌ Absent",
            "Tecnologia Web": "N/D"
        }
        for proto in ["https://", "http://"]:
            try:
                resp = requests.head(proto + subdomain, timeout=4, allow_redirects=True, headers={"User-Agent": "OSINT-Global-Research-Tool"})
                result["Status"] = f"🟢 Active ({resp.status_code})"
                h = resp.headers

                if "Strict-Transport-Security" in h:
                    result["HSTS"] = "✅ Present"
                if "X-Frame-Options" in h:
                    result["X-Frame-Options"] = f"✅ ({h.get('X-Frame-Options')})"
                if "Content-Security-Policy" in h:
                    result["Content-Security-Policy"] = "✅ Present"

                techs = []
                if "Server" in h:
                    techs.append(h.get("Server"))
                if "X-Powered-By" in h:
                    techs.append(h.get("X-Powered-By"))

                if techs:
                    result["Tecnologia Web"] = " / ".join(techs)
                else:
                    resp_get = requests.get(proto + subdomain, timeout=3, headers={"User-Agent": "OSINT-Global-Research-Tool"})
                    html_snippet = resp_get.text[:2000].lower()
                    detected = []
                    if "wp-content" in html_snippet: detected.append("WordPress")
                    if "react" in html_snippet: detected.append("React")
                    if "shopify" in html_snippet: detected.append("Shopify")
                    if detected:
                        result["Tecnologia Web"] = ", ".join(detected)
                    else:
                        result["Tecnologia Web"] = "Generico / Sconosciuto"
                break
            except requests.RequestException:
                continue
        return result

    @staticmethod
    def get_hunter_domain_search(domain: str, api_key: str, limit: int = 100) -> Dict:
        result_data = {"organization": "N/D", "pattern": "N/D", "emails": []}
        if not api_key:
            return result_data

        limits_to_try = [limit, 10]
        for current_limit in limits_to_try:
            try:
                url = f"https://api.hunter.io/v2/domain-search?domain={domain}&limit={current_limit}&api_key={api_key}"
                response = requests.get(url, timeout=12)
                if response.status_code == 200:
                    res_json = response.json()
                    data = res_json.get("data", {})
                    if data:
                        result_data["organization"] = data.get("organization", "N/D")
                        result_data["pattern"] = data.get("pattern", "N/D")
                        raw_emails = data.get("emails", [])
                        formatted_emails = []
                        for e in raw_emails:
                            fname = e.get("first_name") or ""
                            lname = e.get("last_name") or ""
                            full_name = f"{fname} {lname}".strip()
                            if not full_name:
                                full_name = "N/D"

                            formatted_emails.append({
                                "email": e.get("value"),
                                "name": full_name,
                                "position": e.get("position", "N/D"),
                                "confidence": e.get("confidence", 0),
                                "type": e.get("type", "N/D")
                            })
                        result_data["emails"] = formatted_emails
                    return result_data
                elif response.status_code == 400 and current_limit != 10:
                    continue
                else:
                    break
            except Exception:
                pass
        return result_data

    @staticmethod
    def get_hunter_companies_find(domain: str, api_key: str) -> Dict:
        comp_data = {}
        if not api_key:
            return comp_data
        try:
            url = f"https://api.hunter.io/v2/companies/find?domain={domain}&api_key={api_key}"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                comp_data = response.json().get("data", {})
        except Exception:
            pass
        return comp_data

    @staticmethod
    def get_hunter_people_find(email: str, api_key: str) -> Dict:
        people_result = {}
        if not api_key or not email:
            return people_result
        try:
            url = f"https://api.hunter.io/v2/people/find?email={email}&api_key={api_key}"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                people_result = response.json().get("data", {})
        except Exception:
            pass
        return people_result

# --- 3. INTERFACCIA UTENTE PRINCIPALE ---
st.title("🌍 OSINT Global Suite")
st.markdown(
    "Framework OSINT protetto e multi-dispositivo (Smartphone, Tablet, PC): "
    "**1.** Ricognizione dominio o indirizzo IP con Shodan/InternetDB. **2.** Contatti, social e Dorking avanzato."
)

st.sidebar.header("⚙️ Target & Configuration")
target_input = st.sidebar.text_input("Target (Dominio o IP):", value="", placeholder="es. stripe.com o 8.8.8.8")

if HUNTER_API_KEY:
    st.sidebar.success("🔑 Hunter.io attiva")
else:
    st.sidebar.warning("⚠️ Hunter.io mancante nei secrets.")

if SHODAN_API_KEY:
    st.sidebar.success("🔑 Shodan attiva")
else:
    st.sidebar.warning("⚠️ Shodan mancante nei secrets.")

if st.sidebar.button("📂 Storico Sessione"):
    if st.session_state.history:
        st.sidebar.write("### Target Analizzati:")
        for past_target in st.session_state.history.keys():
            st.sidebar.text(f"• {past_target}")
    else:
        st.sidebar.info("Nessuna memoria.")

st.sidebar.divider()
if st.sidebar.button("🔒 Logout"):
    st.session_state.authenticated = False
    st.rerun()

st.sidebar.divider()
st.sidebar.info("💡 **Etica:** Solo OSINT passivo.")

if st.sidebar.button("🚀 Avvia Analisi Completa", type="primary"):
    if not target_input:
        st.warning("⚠️ Inserisci un dominio o un indirizzo IP target nella barra laterale.")
    else:
        clean_target = target_input.strip().lower()
        is_ip = is_valid_ip(clean_target)

        dns_info = {"mx": [], "txt": []}
        subdomain_records = []
        dmarc_check = {"status": "N/D", "policy": "N/D", "rua": "N/D", "ruf": "N/D", "raw": ""}
        email_sec = {"SPF": "N/D", "DMARC": "N/D"}
        iot_devices = []
        hunter_data = {"organization": "N/D", "pattern": "N/D", "emails": []}
        company_data = {}
        unified_email_table = []

        if is_ip:
            # --- SCENARIO TARGET: INDIRIZZO IP ---
            with st.spinner(f"Analisi mirata per l'indirizzo IP `{clean_target}` tramite Shodan InternetDB..."):
                internetdb_info = PassiveReconGlobal.check_shodan_internetdb(clean_target)
                iot_devices = PassiveReconGlobal.search_shodan_iot_devices(clean_target, SHODAN_API_KEY, is_ip=True)

                ports_list = ", ".join(map(str, internetdb_info["ports"])) if internetdb_info["ports"] else "Nessuna porta"
                cves_list = ", ".join(internetdb_info["cves"]) if internetdb_info["cves"] else "Nessuna CVE"

                subdomain_records = [{
                    "subdomain": f"IP Diretto ({clean_target})",
                    "ssl_expiry": "N/D"
                }]
        else:
            # --- SCENARIO TARGET: DOMINIO ---
            with st.spinner(f"Fase 1/2: Ricognizione avanzata e Shodan per il dominio `{clean_target}`..."):
                dns_info = PassiveReconGlobal.get_public_dns_info(clean_target)
                subdomain_records = PassiveReconGlobal.get_passive_subdomains_and_ssl(clean_target)
                dmarc_check = PassiveReconGlobal.check_dmarc_record(clean_target)
                email_sec = PassiveReconGlobal.analyze_email_security(dns_info["txt"], dmarc_check)
                iot_devices = PassiveReconGlobal.search_shodan_iot_devices(clean_target, SHODAN_API_KEY, is_ip=False)

            if not subdomain_records and not dns_info["mx"]:
                st.error(f"❌ Impossibile raccogliere dati pubblici per `{clean_target}`. Verifica il nome del dominio.")
            else:
                with st.spinner(f"Fase 2/2: Interrogazione Hunter.io..."):
                    hunter_data = PassiveReconGlobal.get_hunter_domain_search(clean_target, HUNTER_API_KEY)
                    company_data = PassiveReconGlobal.get_hunter_companies_find(clean_target, HUNTER_API_KEY)

                    if HUNTER_API_KEY and hunter_data.get("emails"):
                        for e_obj in hunter_data.get("emails"):
                            email_addr = e_obj.get("email")
                            if email_addr:
                                name_val = e_obj.get("name", "N/D")
                                pos_val = e_obj.get("position", "N/D")
                                linkedin_val, instagram_val, facebook_val, tiktok_val = "N/D", "N/D", "N/D", "N/D"

                                p_res = PassiveReconGlobal.get_hunter_people_find(email_addr, HUNTER_API_KEY)
                                if p_res:
                                    if not name_val or name_val == "N/D":
                                        fn, ln = p_res.get('first_name', ''), p_res.get('last_name', '')
                                        if fn or ln: name_val = f"{fn} {ln}".strip()
                                    if not pos_val or pos_val == "N/D":
                                        pos_val = p_res.get('position', 'N/D')

                                    linkedin_val = p_res.get('linkedin', 'N/D') or "N/D"
                                    instagram_val = p_res.get('instagram', 'N/D') or "N/D"
                                    facebook_val = p_res.get('facebook', 'N/D') or "N/D"
                                    tiktok_val = p_res.get('tiktok', 'N/D') or "N/D"

                                unified_email_table.append({
                                    "mail": email_addr, "nome-cognome": name_val, "posizione": pos_val,
                                    "profilo linkedin": linkedin_val, "instagram": instagram_val,
                                    "facebook": facebook_val, "tiktok": tiktok_val
                                })

        st.session_state.history[clean_target] = {
            "is_ip": is_ip,
            "dns": dns_info, "email_sec": email_sec, "dmarc": dmarc_check,
            "subdomains": subdomain_records, "iot": iot_devices, "contacts": unified_email_table
        }

        st.success(f"✅ Analisi completata per il target: `{clean_target}`!")

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Target Type", "IP Address" if is_ip else "Domain")
        col2.metric("Target", clean_target)
        col3.metric("Asset / Sottodomini", len(subdomain_records))
        col4.metric("Email Trovate", len(unified_email_table))

        st.divider()

        if not is_ip:
            # --- FASE 1: DATI PUBBLICI E EMAIL (Solo per Domini) ---
            st.subheader("🌐 Fase 1: Ricognizione & Sicurezza Email")
            st.markdown("**Server MX:**")
            if dns_info["mx"]:
                for mx in dns_info["mx"]:
                    st.code(mx, language="text")
            else:
                st.info("Nessun MX trovato.")

            ec1, ec2 = st.columns(2)
            with ec1:
                st.markdown("##### SPF")
                if "correttamente" in email_sec["SPF"]:
                    st.success(email_sec["SPF"])
                else:
                    st.warning(email_sec["SPF"])
            with ec2:
                st.markdown("##### DMARC")
                if "correttamente" in email_sec["DMARC"]:
                    st.success(f"{email_sec['DMARC']} — **Policy:** {dmarc_check['policy']}")
                else:
                    st.error(email_sec["DMARC"])

            st.divider()

        # --- DISPOSITIVI IOT & INTERNETDB ---
        st.subheader("🤖 IoT, Porte Aperte & Asset (Shodan / InternetDB)")
        if iot_devices:
            st.dataframe(iot_devices, use_container_width=True)
        else:
            st.info("Nessun asset IoT o dispositivo indicizzato trovato per questo target.")

        st.divider()

        if not is_ip:
            # --- INTELLIGENCE HUNTER.IO ---
            st.subheader("🕵️‍♂️ Contatti & Social (Hunter.io)")
            if HUNTER_API_KEY:
                if company_data:
                    cc1, cc2, cc3, cc4 = st.columns(4)
                    cc1.metric("Azienda", company_data.get("name", "N/D"))
                    cc2.metric("Settore", company_data.get("industry", "N/D"))
                    cc3.metric("Staff", company_data.get("employees", "N/D"))
                    cc4.metric("Paese", company_data.get("country", "N/D"))

                if unified_email_table:
                    st.dataframe(unified_email_table, use_container_width=True)
                else:
                    st.warning("Nessuna email restituita.")

            st.divider()

            # --- GOOGLE DORKING AVANZATO RESPONSIVE ---
            st.subheader("🔎 Google Dorking Avanzato (Mobile Friendly)")
            st.markdown(f"Query mirate per il dominio: `{clean_target}`")

            domain_parts = clean_target.split('.')
            brand_query = domain_parts[0] if len(domain_parts) <= 2 else f"{domain_parts[0]} {domain_parts[1]}"

            if unified_email_table:
                for idx, contact in enumerate(unified_email_table, 1):
                    emp_name = contact.get("nome-cognome", "N/D")
                    emp_pos = contact.get("posizione", "N/D")
                    emp_mail = contact.get("mail", "N/D")

                    if emp_name != "N/D":
                        with st.expander(f"👤 {idx}. {emp_name} — *{emp_pos}* ({emp_mail})"):
                            url_linkedin = f"https://www.google.com/search?q=site%3alinkedin.com%2fin%2F+%22{emp_name}%22+AND+%22{brand_query}%22"
                            url_social = f"https://www.google.com/search?q=%28site%3ainstagram.com+OR+site%3afacebook.com+OR+site%3atiktok.com%29+%22{emp_name}%22+AND+%22{brand_query}%22"
                            url_github = f"https://www.google.com/search?q=%28site%3agithub.com+OR+site%3agitlab.com%29+%22{emp_name}%22"
                            url_docs = f"https://www.google.com/search?q=site%3a{clean_target}+filetype%3apdf+AND+%22{emp_name}%22"
                            url_sheets = f"https://www.google.com/search?q=site%3a{clean_target}+%28filetype%3axlsx+OR+filetype%3acsv+OR+filetype%3axls%29+%22{emp_name}%22"
                            url_cv = f"https://www.google.com/search?q=%22{emp_name}%22+AND+%22{brand_query}%22+AND+%28%22curriculum%22+OR+%22CV%22+OR+%22formazione%22+OR+%22relatore%22%29"

                            rc1, rc2 = st.columns(2)
                            with rc1:
                                st.markdown(f'<div class="dork-btn"><a href="{url_linkedin}" target="_blank">🔗 LinkedIn Ufficiale</a></div>', unsafe_allow_html=True)
                                st.markdown(f'<div class="dork-btn"><a href="{url_social}" target="_blank">📸 Social (IG/FB/TikTok)</a></div>', unsafe_allow_html=True)
                                st.markdown(f'<div class="dork-btn"><a href="{url_github}" target="_blank">💻 Code (GitHub/GitLab)</a></div>', unsafe_allow_html=True)
                            with rc2:
                                st.markdown(f'<div class="dork-btn"><a href="{url_docs}" target="_blank">📄 Documenti PDF Dominio</a></div>', unsafe_allow_html=True)
                                st.markdown(f'<div class="dork-btn"><a href="{url_sheets}" target="_blank">📊 Fogli di Calcolo (XLSX/CSV)</a></div>', unsafe_allow_html=True)
                                st.markdown(f'<div class="dork-btn"><a href="{url_cv}" target="_blank">📜 CV & Background Storico</a></div>', unsafe_allow_html=True)
            else:
                st.info("Nessun dipendente disponibile.")

            st.divider()

        # --- SOTTODOMINI E ESPORTAZIONE ---
        st.subheader("📋 Analisi Infrastruttura & Esportazione Report")
        if subdomain_records and not is_ip:
            results_data = []
            with st.spinner("Analisi sottodomini e InternetDB..."):
                for item in subdomain_records:
                    sub = item["subdomain"]
                    ssl_exp = item["ssl_expiry"]
                    ip_addr = PassiveReconGlobal.resolve_domain_to_ip(sub)
                    internetdb_info = PassiveReconGlobal.check_shodan_internetdb(ip_addr)

                    ports_list = ", ".join(map(str, internetdb_info["ports"])) if internetdb_info["ports"] else "Nessuna porta"
                    cves_list = ", ".join(internetdb_info["cves"]) if internetdb_info["cves"] else "Nessuna CVE"
                    sec_headers = PassiveReconGlobal.check_security_headers_and_tech(sub)

                    results_data.append({
                        "Sottodominio": sub, "IP": ip_addr, "Stato": sec_headers["Status"],
                        "Porte": ports_list, "CVEs": cves_list, "SSL": ssl_exp, "Tech": sec_headers["Tecnologia Web"]
                    })

            st.dataframe(results_data, use_container_width=True)

            col_btn1, col_btn2 = st.columns(2)
            with col_btn1:
                json_export = json.dumps({
                    "target": clean_target, "subdomains_analysis": results_data, "contacts": unified_email_table
                }, indent=4, ensure_ascii=False)
                st.download_button("📥 Scarica JSON", data=json_export, file_name=f"osint_{clean_target}.json", mime="application/json")
            with col_btn2:
                pdf_bytes = generate_pdf_report(clean_target, is_ip, dns_info, email_sec, dmarc_check, results_data, iot_devices, hunter_data, company_data, unified_email_table)
                st.download_button("📄 Scarica PDF", data=pdf_bytes, file_name=f"osint_{clean_target}.pdf", mime="application/pdf")
        elif is_ip:
            # Esportazione specifica per target IP
            internetdb_direct = PassiveReconGlobal.check_shodan_internetdb(clean_target)
            results_data = [{
                "Target IP": clean_target,
                "Porte Aperte": ", ".join(map(str, internetdb_direct["ports"])) if internetdb_direct["ports"] else "Nessuna porta",
                "CVEs Rilevate": ", ".join(internetdb_direct["cves"]) if internetdb_direct["cves"] else "Nessuna CVE"
            }]
            st.dataframe(results_data, use_container_width=True)

            col_btn1, col_btn2 = st.columns(2)
            with col_btn1:
                json_export = json.dumps({
                    "target": clean_target, "is_ip": True, "internetdb": internetdb_direct, "iot": iot_devices
                }, indent=4, ensure_ascii=False)
                st.download_button("📥 Scarica JSON", data=json_export, file_name=f"osint_ip_{clean_target}.json", mime="application/json")
            with col_btn2:
                pdf_bytes = generate_pdf_report(clean_target, is_ip, dns_info, email_sec, dmarc_check, subdomain_records, iot_devices, hunter_data, company_data, unified_email_table)
                st.download_button("📄 Scarica PDF", data=pdf_bytes, file_name=f"osint_ip_{clean_target}.pdf", mime="application/pdf")
        else:
            st.info("Nessun dato da esportare.")
else:
    st.info("👈 Inserisci un dominio o un indirizzo IP nella barra laterale e avvia l'analisi.")
