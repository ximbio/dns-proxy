from enum import Enum

import dns.rdatatype
from pydantic import BaseModel

from src.config import Rules

class Action(Enum):
    BLOCK = "BLOCK"
    REDIRECT = "REDIRECT"
    BYPASS = "BYPASS"
    NODATA = "NODATA"


class Decision(BaseModel):
    action: Action
    redirect_ip: str | None = None


class Policy():
    def __init__(self, rules: Rules):
        self.rules: Rules = rules

        self.redirect_exact = {}
        self.redirect_wildcard = {}

        for domain, target in rules.redirect_map.items():
            domain = self._norm(domain)
            if domain.startswith("*."):
                self.redirect_wildcard[domain[2:]] = target
            else:
                self.redirect_exact[domain] = target

        self.block_exact = set()
        self.block_wildcard = set()

        for domain in rules.blocklist:
            domain = self._norm(domain)
            if domain.startswith("*."):
                self.block_wildcard.add(domain[2:])
            else:
                self.block_exact.add(domain)
    
    def decide(self, qname: str, rdtype: dns.rdatatype.RdataType) -> Decision:
        qname = self._norm(qname)

        redirect_ip = self.redirect_exact.get(qname) 

        if redirect_ip is None:
            base = self._check_wildcard(qname, self.redirect_wildcard)
            if base:
                redirect_ip = self.redirect_wildcard.get(base)
            
        if redirect_ip is not None:
            if rdtype == dns.rdatatype.HTTPS:
                return Decision(action=Action.NODATA)

            return Decision(action=Action.REDIRECT, redirect_ip=redirect_ip)
        
        if qname in self.block_exact:
            return Decision(action=Action.BLOCK)    
        if self._check_wildcard(qname, self.block_wildcard):
            return Decision(action=Action.BLOCK)
        
        return Decision(action=Action.BYPASS)

    @staticmethod
    def _check_wildcard(qname: str, table: dict[str, str] | set[str]) -> str | None:
        labels = qname.rsplit(".")
        for i in range(1, len(labels)):
            base = ".".join(labels[i:])
            if base in table:
                return base

    @staticmethod
    def _norm(domain: str) -> str:
        return domain.strip('.').lower()
