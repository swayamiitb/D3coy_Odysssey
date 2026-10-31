"""Deterministic simulated national estate: fictional organisations across the six NCIIPC CII sectors,
their asset inventories (CPE-tagged), network zones and reachability edges.

All organisations, hostnames and domains are fictional. IPs come from RFC 1918 / RFC 5737 ranges.
Run: python -m backend.app.sim.world   -> data/sim/world.json
"""

from __future__ import annotations

import json
import random
from pathlib import Path

SEED = 1031
OUT = Path(__file__).resolve().parents[3] / "data" / "sim" / "world.json"

SECTORS = ["Power & Energy", "BFSI", "Telecom", "Transport", "Government", "Strategic & Public Enterprises"]

ORGS = [
    ("PWR-01", "Vidyut Grid West Corp", "Power & Energy", "Maharashtra", "vgwc.example"),
    ("PWR-02", "Tapti Thermal Energy Ltd", "Power & Energy", "Gujarat", "tapti-energy.example"),
    ("PWR-03", "Sahyadri Hydro Power Ltd", "Power & Energy", "Karnataka", "sahyadrihydro.example"),
    ("BFS-01", "Navnidhi Bank", "BFSI", "Maharashtra", "navnidhibank.example"),
    ("BFS-02", "Kshitij Finance & Insurance", "BFSI", "Tamil Nadu", "kshitijfin.example"),
    ("BFS-03", "Suvarnarekha Co-operative Bank", "BFSI", "Odisha", "suvarnarekhabank.example"),
    ("TEL-01", "Sanchar Link Telecom", "Telecom", "Delhi", "sancharlink.example"),
    ("TEL-02", "Tarang Fibre Networks", "Telecom", "Telangana", "tarangfibre.example"),
    ("TRN-01", "Indrayani Metro Rail Corp", "Transport", "Maharashtra", "indrayanimetro.example"),
    ("TRN-02", "Godavari Port Authority", "Transport", "Andhra Pradesh", "godavariport.example"),
    ("TRN-03", "Vayupath Airports Ltd", "Transport", "Kerala", "vayupath.example"),
    ("GOV-01", "Lokseva Digital Services Directorate", "Government", "Rajasthan", "lokseva.example"),
    ("GOV-02", "State Treasury Computing Centre", "Government", "West Bengal", "stcc.example"),
    ("SPE-01", "Shakti Precision Defence Works", "Strategic & Public Enterprises", "Uttar Pradesh", "shaktipdw.example"),
    ("SPE-02", "Aryabhata Space Components Ltd", "Strategic & Public Enterprises", "Karnataka", "aryabhatasc.example"),
]

# key: (part, vendor, product, label, role, default zone, version pool)
CATALOG = {
    "ivanti_cs": ("a", "ivanti", "connect_secure", "Ivanti Connect Secure", "vpn", "internet",
                  ["22.7R2.12", "22.8R2.4", "25.1.3.0"]),
    "cisco_asa": ("o", "cisco", "adaptive_security_appliance_software", "Cisco Secure Firewall ASA", "firewall",
                  "internet", ["9.18.4", "9.20.2", "9.22.1"]),
    "cisco_esa": ("o", "cisco", "asyncos", "Cisco Secure Email Gateway", "mail-gateway", "dmz",
                  ["15.0.1", "15.5.2", "16.0.0"]),
    "fortios": ("o", "fortinet", "fortios", "Fortinet FortiGate (FortiOS)", "firewall", "internet",
                ["7.2.8", "7.4.4", "7.6.1"]),
    "panos": ("o", "paloaltonetworks", "pan-os", "Palo Alto PAN-OS", "firewall", "internet",
              ["10.2.9", "11.1.4", "11.2.3"]),
    "netscaler": ("a", "citrix", "netscaler_application_delivery_controller", "Citrix NetScaler ADC", "adc",
                  "internet", ["13.1-55.29", "14.1-29.72", "14.1-43.50"]),
    "exchange": ("a", "microsoft", "exchange_server", "Microsoft Exchange Server", "mail", "dmz",
                 ["2019_cu14", "se_rtm"]),
    "win2022": ("o", "microsoft", "windows_server_2022", "Windows Server 2022", "server", "internal",
                ["10.0.20348.2700", "10.0.20348.3207"]),
    "esxi": ("o", "vmware", "esxi", "VMware ESXi", "hypervisor", "internal", ["7.0.3", "8.0.2", "8.0.3"]),
    "httpd": ("a", "apache", "http_server", "Apache HTTP Server", "web", "dmz", ["2.4.58", "2.4.62", "2.4.63"]),
    "nginx": ("a", "f5", "nginx", "NGINX", "web", "dmz", ["1.24.0", "1.26.2", "1.27.3"]),
    "tomcat": ("a", "apache", "tomcat", "Apache Tomcat", "app", "dmz", ["9.0.85", "10.1.24", "11.0.2"]),
    "php": ("a", "php", "php", "PHP", "app", "dmz", ["8.1.29", "8.2.20", "8.3.12"]),
    "gitlab": ("a", "gitlab", "gitlab", "GitLab", "devops", "internal", ["17.3.2", "17.8.1", "18.2.0"]),
    "confluence": ("a", "atlassian", "confluence_data_center", "Atlassian Confluence", "wiki", "internal",
                   ["8.5.11", "9.2.1"]),
    "oracle_db": ("a", "oracle", "database_server", "Oracle Database", "database", "internal", ["19c", "23ai"]),
    "postgres": ("a", "postgresql", "postgresql", "PostgreSQL", "database", "internal", ["14.12", "16.4"]),
    "openssh": ("a", "openbsd", "openssh", "OpenSSH", "remote-admin", "internal", ["8.9p1", "9.6p1", "9.8p1"]),
    "linux": ("o", "linux", "linux_kernel", "Linux Kernel", "server", "internal", ["5.15.0", "6.1.0", "6.8.0"]),
    "beyondtrust": ("a", "beyondtrust", "remote_support", "BeyondTrust Remote Support", "remote-admin", "dmz",
                    ["24.2.1", "24.3.2"]),
    "siemens_wincc": ("a", "siemens", "simatic_wincc", "Siemens SIMATIC WinCC (SCADA HMI)", "ot-hmi", "internal",
                      ["7.5_sp2", "8.0"]),
    "schneider_scada": ("a", "schneider-electric", "ecostruxure_power_scada_operation",
                        "Schneider EcoStruxure Power SCADA", "ot-scada", "internal", ["2022", "2023_cu1"]),
    "core_banking": ("a", "temenos", "transact", "Temenos Transact (core banking)", "core-banking", "internal",
                     ["R22", "R24"]),
    "swift": ("a", "swift", "alliance_access", "SWIFT Alliance Access", "payments", "internal", ["7.6", "7.7"]),
    "sap": ("a", "sap", "netweaver_application_server_java", "SAP NetWeaver AS Java", "erp", "internal",
            ["7.50"]),
    "magento": ("a", "adobe", "commerce", "Adobe Commerce (Magento)", "web-portal", "dmz", ["2.4.6-p8", "2.4.7-p3"]),
}

COMMON = ["cisco_asa", "fortios", "panos", "netscaler", "exchange", "cisco_esa", "win2022", "esxi", "httpd",
          "nginx", "tomcat", "php", "gitlab", "confluence", "oracle_db", "postgres", "openssh", "linux", "sap"]
SECTOR_EXTRA = {
    "Power & Energy": ["siemens_wincc", "schneider_scada", "beyondtrust"],
    "BFSI": ["core_banking", "swift", "magento"],
    "Telecom": ["beyondtrust", "magento"],
    "Transport": ["siemens_wincc", "magento"],
    "Government": ["magento", "beyondtrust"],
    "Strategic & Public Enterprises": ["siemens_wincc", "beyondtrust"],
}
CROWN_ROLES = {"ot-hmi", "ot-scada", "core-banking", "payments", "database", "erp"}

# Story pins: these assets must exist exactly as written (see backend/app/sim/stories.py).
PINNED = [
    ("PWR-01", "ivanti_cs", "22.8R2.4", "vpn-gw01", "internet", 1),
    ("PWR-02", "ivanti_cs", "22.8R2.4", "sslvpn", "internet", 1),
    ("BFS-01", "ivanti_cs", "25.1.3.0", "remote", "internet", 2),   # patched: proves we do not over-alert
    ("TEL-01", "ivanti_cs", "22.7R2.12", "vpn", "internet", 2),     # older branch: not affected by the bypass
    ("PWR-01", "siemens_wincc", "7.5_sp2", "scada-hmi01", "internal", 1),
    ("PWR-01", "schneider_scada", "2023_cu1", "pscada01", "internal", 1),
    ("TEL-02", "cisco_asa", "9.18.4", "edge-fw01", "internet", 2),
    ("TRN-02", "cisco_esa", "15.0.1", "mailgw", "dmz", 2),
]


def _ip(rng: random.Random, zone: str) -> str:
    if zone == "internet":
        net = rng.choice(["203.0.113", "198.51.100", "192.0.2"])
        return f"{net}.{rng.randint(2, 254)}"
    if zone == "dmz":
        return f"172.16.{rng.randint(0, 31)}.{rng.randint(2, 254)}"
    return f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(2, 254)}"


def _tier(role: str, zone: str) -> int:
    """1 = crown jewel, 2 = high, 3 = medium, 4 = low."""
    if role in CROWN_ROLES:
        return 1
    if zone == "internet" or role in {"vpn", "mail-gateway", "remote-admin"}:
        return 2
    return 3 if role in {"server", "hypervisor", "devops", "wiki", "mail"} else 4


def _cpe(part: str, vendor: str, product: str, version: str) -> str:
    return f"cpe:2.3:{part}:{vendor}:{product}:{version.lower()}:*:*:*:*:*:*:*"


def build() -> dict:
    rng = random.Random(SEED)
    orgs, assets, edges = [], [], []

    def add_asset(org: dict, key: str, version: str, host: str, zone: str, tier: int | None = None) -> dict:
        part, vendor, product, label, role, _, _ = CATALOG[key]
        asset = {
            "id": f"{org['id']}-A{len([a for a in assets if a['org_id'] == org['id']]) + 1:03d}",
            "org_id": org["id"],
            "hostname": f"{host}.{org['domain']}",
            "ip": _ip(rng, zone),
            "zone": zone,
            "role": role,
            "product_key": key,
            "label": label,
            "vendor": vendor,
            "product": product,
            "version": version,
            "cpe": _cpe(part, vendor, product, version),
            "tier": tier or _tier(role, zone),
            "owner": f"{role.split('-')[0]}-team@{org['domain']}",
        }
        assets.append(asset)
        return asset

    for oid, name, sector, state, domain in ORGS:
        org = {"id": oid, "name": name, "sector": sector, "state": state, "domain": domain,
               "ciso": f"ciso@{domain}", "cii": True}
        orgs.append(org)

        for p_oid, key, version, host, zone, tier in PINNED:
            if p_oid == oid:
                add_asset(org, key, version, host, zone, tier)

        pool = COMMON + SECTOR_EXTRA[sector]
        for i in range(rng.randint(32, 46)):
            key = rng.choice(pool)
            _, _, _, _, role, zone, versions = CATALOG[key]
            if zone == "internet" and rng.random() < 0.5:
                zone = "dmz"
            add_asset(org, key, rng.choice(versions), f"{role.split('-')[0]}{i:02d}", zone)

    # Reachability: internet -> dmz -> internal within each org; remote-access gear reaches crown jewels.
    by_org: dict[str, list[dict]] = {}
    for a in assets:
        by_org.setdefault(a["org_id"], []).append(a)
    for org_assets in by_org.values():
        internet = [a for a in org_assets if a["zone"] == "internet"]
        dmz = [a for a in org_assets if a["zone"] == "dmz"]
        internal = [a for a in org_assets if a["zone"] == "internal"]
        for a in internet:
            for b in rng.sample(dmz, min(3, len(dmz))):
                edges.append({"src": a["id"], "dst": b["id"], "kind": "network"})
            if a["role"] in {"vpn", "remote-admin"}:
                for b in [x for x in internal if x["tier"] == 1] + rng.sample(internal, min(4, len(internal))):
                    edges.append({"src": a["id"], "dst": b["id"], "kind": "remote-access"})
        for a in dmz:
            for b in rng.sample(internal, min(2, len(internal))):
                edges.append({"src": a["id"], "dst": b["id"], "kind": "network"})

    return {"seed": SEED, "sectors": SECTORS, "orgs": orgs, "assets": assets, "edges": edges}


def main() -> None:
    world = build()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(world, indent=1), encoding="utf-8")
    print(f"{len(world['orgs'])} orgs, {len(world['assets'])} assets, {len(world['edges'])} edges -> {OUT}")


if __name__ == "__main__":
    main()
