# cve_parser.py
import re
from typing import List, Dict

CVE_RE = re.compile(r'(CVE-\d{4}-\d{4,7})', re.IGNORECASE)
CVSS_RE = re.compile(r'(?<!\d)(\d{1,2}\.\d)(?!\d)')  # matches 0.0 - 10.0 like patterns

def extract_cves_from_text(text: str) -> List[Dict]:
    """
    Returns list of {'cve_id':str, 'cvss_score':float|None, 'description':str}
    Deduplicates by CVE keeping first occurrence.
    """
    if not text:
        return []

    results = []
    seen = set()
    lines = [l.strip() for l in text.splitlines() if l.strip()]

    for ln in lines:
        cves = CVE_RE.findall(ln)
        if not cves:
            continue
        for cve in cves:
            cve_id = cve.upper()
            if cve_id in seen:
                continue
            seen.add(cve_id)
            # find CVSS nearby in the line
            cvss = None
            m = CVSS_RE.search(ln)
            if m:
                try:
                    cvss = float(m.group(1))
                except Exception:
                    cvss = None
            # fallback checks e.g., "CVSS: 7.8" or "(CVSS 7.8)"
            if cvss is None:
                m2 = re.search(r'cvss[:=]?\s*([0-9]{1,2}\.[0-9])', ln, re.IGNORECASE)
                if m2:
                    try:
                        cvss = float(m2.group(1))
                    except Exception:
                        cvss = None
            results.append({'cve_id': cve_id, 'cvss_score': cvss, 'description': ln})
    return results
