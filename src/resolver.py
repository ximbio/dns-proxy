from itertools import cycle
 
from loguru import logger
from dns.edns import ECSOption
import dns.message
import dns.exception
import dns.rcode
import dns.rrset
import dns.rdataclass
import dns.rdatatype
import dns.asyncquery
import dns.flags
 
from src.policy import Policy, Action
 
log_colors = {
    "BLOCK": "red",
    "BYPASS": "green",
    "REDIRECT": "yellow",
    "NODATA": "white"
}
 
class Resolver:
    def __init__(self, policy: Policy, upstream_dns: list[str]):
        self.policy = policy
        self.upstream_dns = cycle(upstream_dns)
 
    async def resolve(self, q: bytes) -> bytes | None:
        message = self._parse_wire(q)
        if not message:
            return self._error_response(q, dns.rcode.FORMERR)
 
        if not message.question:
            return self._error_response(q, dns.rcode.FORMERR)
 
        question = message.question[0]
        question_name = question.name.to_text()
 
        decision = self.policy.decide(question_name, question.rdtype)
        decision_name = decision.action.name
 
        self._log_action(decision_name, question.rdtype, question_name)

        if decision.action == Action.NODATA:
            return self._empty_response(q)
    
        if decision.action == Action.BLOCK:
            return self._error_response(q, dns.rcode.NXDOMAIN)
        elif question.rdtype == dns.rdatatype.A and decision.action == Action.REDIRECT:
            return self._redirect_response(message, decision.redirect_ip)
        else:
            return await self._proxy_response(message)
 
    async def _proxy_response(self, message: dns.message.Message):
        message.flags |= dns.flags.RD
        message.use_edns(edns=0, payload=1232)
 
        if message.options:
            opts = [opt for opt in message.options if not isinstance(opt, ECSOption)]
            if len(opts) != len(message.options):
                message.use_edns(edns=0, payload=1232, options=opts)
 
        upstream = self._get_upstream_dns() 
        resp = await dns.asyncquery.tcp(message, upstream, timeout=2.0)
        return resp.to_wire() 
 
    def _get_upstream_dns(self) -> str:
        return next(self.upstream_dns)
 
    @staticmethod
    def _parse_wire(q: bytes) -> dns.message.Message | None:
        try:
            message = dns.message.from_wire(q)
        except dns.exception.FormError:
            return None
 
        return message
 
    @staticmethod
    def _empty_response(q: bytes):
        try:
            query = dns.message.from_wire(q)
            response = dns.message.make_response(query, recursion_available=True)
        except dns.exception.FormError:
            return None
 
        return response.to_wire()
 
    @staticmethod
    def _error_response(q: bytes, rcode: dns.rcode.Rcode) -> bytes | None:
        try:
            query = dns.message.from_wire(q)
            response = dns.message.make_response(query, recursion_available=True)
        except dns.exception.FormError:
            return None
 
        response.set_rcode(rcode)
        return response.to_wire()
 
    @staticmethod
    def _redirect_response(message: dns.message.Message, ip: str) -> bytes:
        q = message.question[0]
 
        response = dns.message.make_response(message, recursion_available=True)
        response.use_edns(edns=0, payload=1232)
        if q.rdtype in (dns.rdatatype.A, dns.rdatatype.ANY):
            rrset = dns.rrset.from_text(q.name.to_text(), 60, dns.rdataclass.IN, dns.rdatatype.A, ip)
            response.answer.append(rrset)
 
        response.set_rcode(dns.rcode.NOERROR)
        return response.to_wire()
 
    @staticmethod
    def _log_action(decision_name: str, rdtype: dns.rdatatype.RdataType, question: str):
        color = log_colors.get(decision_name)
        logger.opt(colors=True).info(f"<{color}>{decision_name:<9}</{color}> | {dns.rdatatype.to_text(rdtype):<6}| {question}")
