from itertools import cycle

from loguru import logger
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
    "REDIRECT": "yellow"
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
        decision = self.policy.decide(question.name.to_text())

        color = log_colors.get(decision.action.name)
        logger.opt(colors=True).info(f"<{color}>{decision.action.name:<8}</{color}> | {question.name}")

        if decision.action == Action.BLOCK:
            return self._error_response(q, dns.rcode.NXDOMAIN)
        elif question.rdtype == dns.rdatatype.A and decision.action == Action.REDIRECT:
            return self._redirect_response(message, decision.redirect_ip)
        else:
            return await self._proxy_response(message)

    async def _proxy_response(self, message: dns.message.Message):
        message.flags |= dns.flags.RD

        result = await dns.asyncquery.udp(message, self._get_upstream_dns())
        return result.to_wire()

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
    def _error_response(q: bytes, rcode: int) -> bytes | None:
        try:
            query = dns.message.from_wire(q)
            response = dns.message.make_response(query, recursion_available=True)
        except dns.exception.FormError:
            return None
        
        response.set_rcode(rcode)
        return response.to_wire()

    @staticmethod
    def _redirect_response(message: dns.message.Message, ip: str) -> bytes:
        question = message.question[0]

        response = dns.message.make_response(message, recursion_available=True)
        rrset = dns.rrset.from_text(question.name.to_text(), 60, dns.rdataclass.IN, dns.rdatatype.A, ip)

        response.answer.append(rrset)
        response.set_rcode(dns.rcode.NOERROR)
        
        return response.to_wire()
