#!/usr/bin/env python3
# =============================================================================
# AIRS correlation-id matrix probe  (LIVE tenant — no mocks)
#
# Question: Cursor gives us a *conversation ID* (= AIRS session_id in Palo
# language) and no per-turn id. We send transaction_id + session_id today; the
# old field is tr_id. How does the DEPLOYED AIRS sync-scan API treat each of
# {session_id, transaction_id, tr_id} — alone and in every combination?
#   * which fields does it accept (no 4xx)?
#   * which value does it BIND + echo back in the response?
#   * when tr_id and transaction_id disagree, which one wins?
#   * what does it MINT (pan_...) for the fields we omit?
#   * what does it actually STORE (Scan-Results-by-ID API)?
#
# Each variation uses sentinel-PREFIXED values so the echoed value's prefix
# tells us unambiguously which of OUR fields AIRS bound:
#   SID-*   -> our session_id       TXNID-* -> our transaction_id
#   TRID-*  -> our tr_id            pan_*   -> server-minted (ours ignored)
# =============================================================================
import json, os, sys, time, uuid, urllib.request, urllib.error, urllib.parse

BASE = os.environ.get("PRISMA_AIRS_URL", "https://service.api.aisecurity.paloaltonetworks.com").rstrip("/")
SCAN_URL    = BASE + "/v1/scan/sync/request"
RESULTS_URL = BASE + "/v1/scan/results"          # ?scan_ids=<id>
KEY  = os.environ.get("PRISMA_AIRS_API_KEY", "")
PROF = os.environ.get("PRISMA_AIRS_PROFILE_NAME", "")
if not KEY or not PROF:
    sys.exit("missing PRISMA_AIRS_API_KEY / PRISMA_AIRS_PROFILE_NAME in env")

HDRS = {"Content-Type": "application/json", "Accept": "application/json", "x-pan-token": KEY}

# One constant, benign content across every variation — the ONLY variable is the
# id block, so any difference in the response is attributable to the ids.
CONTENT = [{"prompt": "What time do most banks open on weekdays?"}]
AI_PROFILE = {"profile_name": PROF}

def sid(tag):   return f"SID-{tag}-{uuid.uuid4().hex[:8]}"
def txnid(tag): return f"TXNID-{tag}-{uuid.uuid4().hex[:8]}"
def trid(tag):  return f"TRID-{tag}-{uuid.uuid4().hex[:8]}"

# (name, description, id-fields-to-include)
VARIATIONS = [
    ("V0", "none (baseline — what does AIRS mint?)",     lambda t: {}),
    ("V1", "session_id only (the Cursor case)",          lambda t: {"session_id": sid(t)}),
    ("V2", "transaction_id only",                        lambda t: {"transaction_id": txnid(t)}),
    ("V3", "tr_id only (the legacy/SDK field)",          lambda t: {"tr_id": trid(t)}),
    ("V4", "session_id + transaction_id (our engine)",   lambda t: {"session_id": sid(t), "transaction_id": txnid(t)}),
    ("V5", "session_id + tr_id (legacy pairing)",        lambda t: {"session_id": sid(t), "tr_id": trid(t)}),
    ("V6", "transaction_id + tr_id (DISTINCT — tiebreak)", lambda t: {"transaction_id": txnid(t), "tr_id": trid(t)}),
    ("V7", "all three (DISTINCT — full tiebreak)",       lambda t: {"session_id": sid(t), "transaction_id": txnid(t), "tr_id": trid(t)}),
]

def post(url, body):
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=HDRS, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, {"_http_error": e.read().decode()[:500]}
    except Exception as e:
        return None, {"_error": repr(e)}

def get(url):
    req = urllib.request.Request(url, headers=HDRS, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, {"_http_error": e.read().decode()[:500]}
    except Exception as e:
        return None, {"_error": repr(e)}

def origin(val):
    """Classify an echoed id value by our sentinel prefix."""
    if val is None: return "(absent)"
    s = str(val)
    if s.startswith("SID-"):   return "OURS:session_id"
    if s.startswith("TXNID-"): return "OURS:transaction_id"
    if s.startswith("TRID-"):  return "OURS:tr_id"
    if s.startswith("pan_"):   return "SERVER-minted(pan_)"
    return "other"

records = []
print(f"== AIRS correlation-id matrix  [LIVE — profile {PROF}] ==")
print(f"== endpoint {SCAN_URL} ==\n")

for tag, desc, mk in VARIATIONS:
    ids = mk(tag)
    body = dict(ids)
    body["ai_profile"] = AI_PROFILE
    body["metadata"] = {"app_name": "corr-test", "app_user": "corr-test", "source": tag}
    body["contents"] = CONTENT

    status, resp = post(SCAN_URL, body)
    time.sleep(0.4)

    rec = {"variation": tag, "desc": desc, "sent": ids, "http": status, "response": resp}
    print(f"--- {tag}: {desc}")
    print(f"    SENT     : {json.dumps(ids)}")
    print(f"    HTTP     : {status}")
    if isinstance(resp, dict) and "_http_error" not in resp and "_error" not in resp:
        for f in ("transaction_id", "tr_id", "session_id"):
            v = resp.get(f)
            print(f"    resp.{f:<15}= {str(v):<28} [{origin(v)}]")
        print(f"    scan_id  : {resp.get('scan_id')}   report_id: {resp.get('report_id')}")
        print(f"    action   : {resp.get('action')}   category: {resp.get('category')}")
        rec["echo"] = {f: {"value": resp.get(f), "origin": origin(resp.get(f))}
                       for f in ("transaction_id", "tr_id", "session_id")}
        rec["scan_id"] = resp.get("scan_id"); rec["report_id"] = resp.get("report_id")
    else:
        print(f"    ERROR    : {resp}")
    print()
    records.append(rec)

# ---- Phase 2: what did AIRS actually STORE? query Scan-Results-by-ID --------
print("== Phase 2: Scan-Results-by-ID (what AIRS stored / correlated) ==\n")
time.sleep(3)  # results can lag a few seconds
for rec in records:
    sid_ = rec.get("scan_id")
    if not sid_:
        continue
    url = RESULTS_URL + "?" + urllib.parse.urlencode({"scan_ids": sid_})
    status, resp = get(url)
    rec["results_api"] = {"http": status, "body": resp}
    print(f"--- {rec['variation']}  scan_id={sid_}  HTTP {status}")
    print(f"    {json.dumps(resp)[:600]}")
    print()

OUT = os.environ.get("CORR_OUT", "airs-corr-results.jsonl")
with open(OUT, "w") as f:
    for rec in records:
        f.write(json.dumps(rec) + "\n")
print(f"== raw JSONL written to {OUT} ==")
