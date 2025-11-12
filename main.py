#!/usr/bin/env python3
from __future__ import annotations
import argparse, ipaddress, re
from dataclasses import dataclass
from typing import Any, List, Optional, Sequence, Tuple, Dict, Set
from netfilterqueue import NetfilterQueue  # type: ignore
from scapy.all import IP, UDP, DNS, DNSQR, DNSRROPT  # type: ignore

Token = Tuple[str, str, str]

@dataclass
class Rule:
    tokens: List[Token]
    action: str
    raw: str

_QTYPE_NAMES = {1:"A",2:"NS",5:"CNAME",6:"SOA",12:"PTR",15:"MX",16:"TXT",28:"AAAA",255:"ANY"}
_QTYPE_BY_NAME = {v:k for k,v in _QTYPE_NAMES.items()}

def _split_clauses(line: str) -> List[str]:
    return [p.strip() for p in line.split(";") if p.strip()]

def _normalize_op(op: str) -> str:
    op = op.strip().lower()
    if op in {"=","=="}: return "="
    if op in {"!=", "<>"}: return "!="
    if op in {"~","regex"}: return "~"
    if op in {"in","∈"}: return "in"
    if op in {"not in","∉"}: return "not in"
    if op in {">",">=","<","<="}: return op
    raise ValueError("bad operator")

def _parse_set(text: str) -> List[str]:
    t = text.strip()
    if t.startswith("{") and t.endswith("}"):
        inner = t[1:-1].strip()
        return [] if not inner else [x.strip() for x in inner.split(",")]
    return [x.strip() for x in t.split(",")]

def parse_rule_line(line: str) -> Optional[Rule]:
    s = line.strip()
    if not s or s.startswith(("#",";")): return None
    tokens: List[Token] = []
    action: Optional[str] = None
    for c in _split_clauses(s):
        m = re.match(r"^([a-zA-Z0-9_]+)\s*(!=|==|=|~|not\s+in|in|>=|<=|>|<)\s*(.+?)\s*$", c)
        if not m: raise ValueError(f"bad clause: {c!r}")
        lhs,op,rhs = m.group(1), _normalize_op(m.group(2)), m.group(3)
        if lhs.lower()=="action":
            if action is not None: raise ValueError("duplicate action")
            v = rhs.strip().lower()
            if v not in {"accept","drop"}: raise ValueError("action must be accept/drop")
            action = v
        else:
            tokens.append((lhs,op,rhs))
    if action is None: raise ValueError("no action")
    return Rule(tokens, action, line.rstrip("\n"))

def load_rules(path: str) -> List[Rule]:
    out: List[Rule] = []
    with open(path,"r",encoding="utf-8",errors="ignore") as f:
        for i,line in enumerate(f,1):
            r = parse_rule_line(line)
            if r: out.append(r)
    return out

def qtype_to_num(v: str) -> int:
    t = v.strip().upper()
    if t.isdigit(): return int(t)
    if t in _QTYPE_BY_NAME: return _QTYPE_BY_NAME[t]
    raise ValueError("bad qtype")

def parse_bool(v: str) -> int:
    t = v.strip().lower()
    if t in {"1","true","yes","on"}: return 1
    if t in {"0","false","no","off"}: return 0
    raise ValueError("bad bool")

@dataclass
class DnsFeatures:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    qr: int
    rcode: int
    qname: str
    qtype: int
    qdcount: int
    edns: int
    length: int
    @classmethod
    def from_packet(cls, p: Any) -> "DnsFeatures":
        ip, udp, dns = p[IP], p[UDP], p[DNS]
        qn = dns.qd.qname.decode("utf-8","ignore").rstrip(".") if dns.qd else ""
        qt = int(dns.qd.qtype) if dns.qd else 0
        ed = 1 if DNSRROPT in dns and dns[DNSRROPT] else 0
        return cls(ip.src, ip.dst, int(udp.sport), int(udp.dport),
                   int(dns.qr), int(dns.rcode), qn, qt, int(dns.qdcount), ed, int(len(udp.payload)))

def _cmp(op: str, a: int, b: int) -> bool:
    if op==">": return a>b
    if op==">=": return a>=b
    if op=="<": return a<b
    if op=="<=": return a<=b
    return False

def _eval_token(f: DnsFeatures, t: Token) -> bool:
    field, op, rhs = t
    k = field.lower()
    if not hasattr(f,k): raise ValueError(f"unknown field {field}")
    val = getattr(f,k)

    if k in {"src_ip","dst_ip"} and op in {"in","not in"}:
        net = ipaddress.ip_network(rhs.strip(), strict=False)
        res = ipaddress.ip_address(val) in net
        return res if op=="in" else (not res)

    if op in {"in","not in"}:
        members = _parse_set(rhs)
        if k=="qtype":
            S: Set[int] = set(qtype_to_num(x) if not x.isdigit() else int(x) for x in members if x)
            res = int(val) in S
        else:
            res = str(val) in set(members)
        return res if op=="in" else (not res)

    if op=="~":
        return re.search(rhs.strip(), str(val)) is not None

    if op in {"=","!="}:
        if k in {"qr","rcode","src_port","dst_port","qdcount","length"}:
            r = int(rhs.strip())
            res = int(val)==r
        elif k=="edns":
            res = int(val)==parse_bool(rhs)
        elif k=="qtype":
            res = int(val)==qtype_to_num(rhs)
        else:
            res = str(val)==rhs.strip()
        return res if op=="=" else (not res)

    if op in {">",">=","<","<="}:
        return _cmp(op, int(val), int(rhs.strip()))

    return False

def rule_matches(f: DnsFeatures, r: Rule) -> bool:
    try:
        return all(_eval_token(f,t) for t in r.tokens)
    except Exception:
        return False

class Engine:
    def __init__(self, rules: List[Rule], default_action: str="accept"):
        self.rules = rules
        self.hits: Dict[int,int] = {i:0 for i in range(len(rules))}
        self.default = default_action
    def decide(self, f: DnsFeatures) -> Tuple[str, Optional[int]]:
        for i,r in enumerate(self.rules):
            if rule_matches(f,r):
                self.hits[i]+=1
                return r.action, i
        return self.default, None

def run(queue: int, rules_path: str, quiet: bool=False, dry_run: bool=False) -> None:
    rules = load_rules(rules_path)
    eng = Engine(rules)

    def on_pkt(pkt) -> None:
        try:
            sp = IP(pkt.get_payload())
            if UDP not in sp or DNS not in sp:
                pkt.accept(); return
            f = DnsFeatures.from_packet(sp)
            action, idx = eng.decide(f)
            if not quiet:
                tag = f"#{idx}" if idx is not None else "default"
                print(f"{action.upper()} {tag} q={f.qname}/{f.qtype} {f.src_ip}:{f.src_port}->{f.dst_ip}:{f.dst_port} len={f.length} edns={f.edns}")
            if action=="drop" and not dry_run: pkt.drop()
            else: pkt.accept()
        except Exception:
            pkt.accept()

    nfq = NetfilterQueue()
    try:
        nfq.bind(queue, on_pkt)
        if not quiet: print(f"NFQUEUE {queue}, rules={len(rules)}")
        nfq.run()
    finally:
        try: nfq.unbind()
        except Exception: pass

def main(argv: Optional[Sequence[str]]=None) -> None:
    p = argparse.ArgumentParser(prog="dns-guard")
    p.add_argument("--queue", type=int, default=5)
    p.add_argument("--rules", type=str, default="rules.dns")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    a = p.parse_args(argv)
    run(queue=a.queue, rules_path=a.rules, quiet=a.quiet, dry_run=a.dry_run)

if __name__ == "__main__":
    main()
