from __future__ import annotations
import argparse, datetime as dt, ipaddress, json, re, sys
from collections import defaultdict
from pathlib import Path

STAMP=re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<clock>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<msg>.*)$")
FAIL=re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port \d+")
ACCEPT=re.compile(r"Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port \d+")

def parse_line(line, year):
    m=STAMP.match(line.strip())
    if not m: return None
    try: stamp=dt.datetime.strptime(f"{year} {m['mon']} {m['day']} {m['clock']}","%Y %b %d %H:%M:%S")
    except ValueError: return None
    msg=m["msg"]; match=FAIL.search(msg); outcome="failure"
    if not match: match=ACCEPT.search(msg); outcome="success"
    if not match: return None
    try: ip=str(ipaddress.ip_address(match["ip"]))
    except ValueError: return None
    return {"time":stamp.isoformat(),"host":m["host"],"source_ip":ip,"user":match["user"],"outcome":outcome}

def analyze(lines,year,threshold=5,window_minutes=15):
    rows=[x for line in lines if (x:=parse_line(line,year))]
    rows.sort(key=lambda x:x["time"]); failures=defaultdict(list); findings=[]
    for r in rows:
        key=(r["host"],r["source_ip"])
        if r["outcome"]=="failure": failures[key].append(r)
        else:
            recent=[f for f in failures[key] if (dt.datetime.fromisoformat(r["time"])-dt.datetime.fromisoformat(f["time"])).total_seconds()<=window_minutes*60]
            if len(recent)>=threshold:
                findings.append({"severity":"high","code":"success_after_failure_burst","host":r["host"],
                                 "source_ip":r["source_ip"],"success_time":r["time"],"failure_count":len(recent)})
    for (host,ip),group in failures.items():
        group.sort(key=lambda x:x["time"])
        for i,first in enumerate(group):
            window=[x for x in group[i:] if (dt.datetime.fromisoformat(x["time"])-dt.datetime.fromisoformat(first["time"])).total_seconds()<=window_minutes*60]
            if len(window)>=threshold:
                findings.append({"severity":"medium","code":"ssh_failure_burst","host":host,"source_ip":ip,"count":len(window),"window_start":first["time"]}); break
    return {"records_parsed":len(rows),"findings":findings,"timezone":"host local time (not encoded in RFC 3164 line)"}

def main():
    p=argparse.ArgumentParser(description="Analyze a local sshd auth.log; no network calls.")
    p.add_argument("log",type=Path); p.add_argument("--year",type=int,required=True); p.add_argument("--threshold",type=int,default=5); a=p.parse_args()
    try:
        if a.threshold<1: raise ValueError("Threshold must be positive.")
        result=analyze(a.log.read_text(encoding="utf-8",errors="replace").splitlines(),a.year,a.threshold)
    except (OSError,ValueError) as e: print(json.dumps({"error":str(e)}),file=sys.stderr); return 2
    print(json.dumps(result,indent=2)); return 1 if result["findings"] else 0

if __name__ == "__main__": raise SystemExit(main())
