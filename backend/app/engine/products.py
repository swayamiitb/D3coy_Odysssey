"""Product identity: CPE vendor/product names plus the display names vendors, KEV and advisories actually use.

Strict by design: normalised equality or a known alias. No subset/fuzzy-set matching, which made
"Windows" match "Windows Server 2022" and "Server" match "Exchange Server".
"""

from __future__ import annotations

import re

# (cpe vendor, cpe product) -> display aliases (vendor aliases, product aliases)
ALIASES: dict[tuple[str, str], tuple[set[str], set[str]]] = {
    ("ivanti", "connect_secure"): ({"ivanti"}, {"connect secure", "ivanti connect secure", "ics", "pulse connect secure"}),
    ("cisco", "adaptive_security_appliance_software"): (
        {"cisco"}, {"adaptive security appliance", "secure firewall asa", "asa", "secure firewall asa software",
                    "adaptive security appliance asa software",
                    "secure firewall adaptive security appliance asa software"}),
    ("cisco", "asyncos"): ({"cisco"}, {"secure email gateway", "email security appliance", "asyncos",
                                       "asyncos software"}),
    ("fortinet", "fortios"): ({"fortinet"}, {"fortios", "fortigate", "fortios ssl vpn"}),
    ("paloaltonetworks", "pan-os"): ({"palo alto networks", "paloaltonetworks"}, {"pan os", "pan-os", "globalprotect"}),
    ("citrix", "netscaler_application_delivery_controller"): (
        {"citrix", "netscaler"}, {"netscaler adc", "netscaler", "netscaler adc and netscaler gateway",
                                  "application delivery controller adc and gateway"}),
    ("microsoft", "exchange_server"): ({"microsoft"}, {"exchange server", "exchange"}),
    ("microsoft", "windows_server_2022"): ({"microsoft"}, {"windows server 2022"}),
    ("vmware", "esxi"): ({"vmware", "broadcom"}, {"esxi", "vmware esxi"}),
    ("apache", "http_server"): ({"apache", "apache software foundation"}, {"http server", "apache http server", "httpd"}),
    ("f5", "nginx"): ({"f5", "nginx", "f5 networks"}, {"nginx", "nginx open source", "nginx plus"}),
    ("apache", "tomcat"): ({"apache", "apache software foundation"}, {"tomcat", "apache tomcat"}),
    ("php", "php"): ({"php", "php group"}, {"php"}),
    ("gitlab", "gitlab"): ({"gitlab"}, {"gitlab", "community edition and enterprise edition", "gitlab ce ee"}),
    ("atlassian", "confluence_data_center"): ({"atlassian"}, {"confluence", "confluence data center",
                                                               "confluence server and data center"}),
    ("oracle", "database_server"): ({"oracle"}, {"database server", "oracle database"}),
    ("postgresql", "postgresql"): ({"postgresql", "postgresql global development group"}, {"postgresql"}),
    ("openbsd", "openssh"): ({"openbsd", "openssh"}, {"openssh"}),
    ("linux", "linux_kernel"): ({"linux"}, {"kernel", "linux kernel"}),
    ("beyondtrust", "remote_support"): ({"beyondtrust"}, {"remote support", "remote support rs",
                                                          "privileged remote access"}),
    ("siemens", "simatic_wincc"): ({"siemens"}, {"simatic wincc", "wincc"}),
    ("schneider-electric", "ecostruxure_power_scada_operation"): (
        {"schneider electric", "schneider-electric"}, {"ecostruxure power scada operation", "power scada operation"}),
    ("temenos", "transact"): ({"temenos"}, {"transact", "temenos transact"}),
    ("swift", "alliance_access"): ({"swift"}, {"alliance access"}),
    ("sap", "netweaver_application_server_java"): ({"sap"}, {"netweaver", "netweaver as java",
                                                             "netweaver application server java"}),
    ("adobe", "commerce"): ({"adobe", "magento"}, {"commerce", "adobe commerce", "magento", "commerce and magento",
                                                   "magento open source"}),
}


def norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", name.lower()).strip()


def same_product(asset_vendor: str, asset_product: str, vendor: str, product: str) -> bool:
    av, ap, v, p = norm(asset_vendor), norm(asset_product), norm(vendor), norm(product)
    vendor_aliases, product_aliases = ALIASES.get((asset_vendor, asset_product), (set(), set()))
    vendor_ok = v == av or v in {norm(x) for x in vendor_aliases}
    product_ok = p == ap or p in {norm(x) for x in product_aliases}
    return vendor_ok and product_ok


GENERIC = {"php", "kernel", "linux kernel", "commerce", "transact", "database server", "exchange", "asa",
           "ics", "netscaler", "remote support", "gitlab", "nginx", "postgresql", "openssh", "tomcat"}


def mentions(asset_vendor: str, asset_product: str, text: str) -> bool:
    """Does free text (an unanalysed CVE description) name this product? Candidate selection only.
    Requires a specific product name (generic words like "php" or "kernel" never count on their own) and,
    for multi-word names, the vendor or a vendor-prefixed alias, so "PHP" web apps do not match PHP itself."""
    t = f" {norm(text)} "
    vendor_aliases, product_aliases = ALIASES.get((asset_vendor, asset_product), (set(), set()))
    vendors = {norm(asset_vendor)} | {norm(x) for x in vendor_aliases}
    names = {norm(x) for x in product_aliases | {asset_product}} - GENERIC
    for n in names:
        if f" {n} " not in t:
            continue
        if any(n.startswith(v + " ") for v in vendors) or any(f" {v} " in t for v in vendors):
            return True
    return False
