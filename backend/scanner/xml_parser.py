# xml_parser.py
import xml.etree.ElementTree as ET
from typing import List, Dict, Any

def parse_nmap_xml(xml_text: str) -> List[Dict[str, Any]]:
    """
    Parse nmap -oX XML string into list of host dicts:
    { 'ip': '1.2.3.4', 'hostname': 'host', 'os': 'name', 'ports': [ {proto, portid, state, service, product, version, cpe, scripts} ] }
    """
    hosts = []
    if not xml_text:
        return hosts

    # try direct parse; if fails, extract <nmaprun> fragment
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        idx1 = xml_text.find("<nmaprun")
        idx2 = xml_text.rfind("</nmaprun>")
        if idx1 != -1 and idx2 != -1:
            fragment = xml_text[idx1: idx2 + len("</nmaprun>")]
            root = ET.fromstring(fragment)
        else:
            raise

    for host_el in root.findall("host"):
        ip = None
        # addresses
        for a in host_el.findall("address"):
            at = a.get("addrtype")
            if at in ("ipv4", "ipv6"):
                ip = a.get("addr")
                break

        # hostname
        hn = host_el.find("hostnames/hostname")
        hostname = hn.get("name") if hn is not None else None

        # os
        osmatch = host_el.find("os/osmatch")
        os_name = osmatch.get("name") if osmatch is not None else None

        # ports
        ports = []
        ports_parent = host_el.find("ports")
        if ports_parent is not None:
            for p in ports_parent.findall("port"):
                try:
                    portid = int(p.get("portid"))
                except Exception:
                    continue
                proto = p.get("protocol")
                state_el = p.find("state")
                state = state_el.get("state") if state_el is not None else "unknown"
                service_el = p.find("service")
                svc = {}
                if service_el is not None:
                    for k, v in service_el.items():
                        svc[k] = v
                    # cpe under service element (text)
                    cpe_el = service_el.find("cpe")
                    if cpe_el is not None:
                        svc['cpe'] = cpe_el.text or svc.get('cpe') or ''
                # scripts
                scripts = {}
                for script_el in p.findall("script"):
                    sid = script_el.get("id")
                    out = script_el.get("output") or ""
                    # append any nested text as fallback
                    try:
                        nested = "".join([ET.tostring(c, encoding='unicode', method='text') for c in list(script_el)])
                        if nested:
                            out = (out or "") + "\n" + nested
                    except Exception:
                        pass
                    scripts[sid] = out
                ports.append({
                    "protocol": proto,
                    "port": portid,
                    "state": state,
                    "service": svc,
                    "scripts": scripts
                })
        hosts.append({
            "ip": ip,
            "hostname": hostname,
            "os": os_name,
            "ports": ports
        })
    return hosts
