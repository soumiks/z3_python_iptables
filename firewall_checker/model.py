"""Data structures shared by the firewall checker stack."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv4Address, IPv4Network, ip_network
from typing import Iterable, List, Optional, Sequence, Set


class Protocol(Enum):
    ANY = 0
    TCP = 6
    UDP = 17
    ICMP = 1

    @classmethod
    def from_token(cls, token: str) -> "Protocol":
        token_lower = token.lower()
        if token_lower in {"tcp", "6"}:
            return cls.TCP
        if token_lower in {"udp", "17"}:
            return cls.UDP
        if token_lower in {"icmp", "1"}:
            return cls.ICMP
        if token_lower in {"all", "any", "0"}:
            return cls.ANY
        raise ValueError(f"Unsupported protocol token: {token}")


class RuleAction(Enum):
    ACCEPT = "ACCEPT"
    DROP = "DROP"
    REJECT = "REJECT"
    RETURN = "RETURN"
    JUMP = "JUMP"
    LOG = "LOG"

    @property
    def is_terminal(self) -> bool:
        return self in {RuleAction.ACCEPT, RuleAction.DROP, RuleAction.REJECT}


@dataclass(frozen=True)
class AddressRange:
    start: int
    end: int

    @staticmethod
    def from_cidr(text: str) -> "AddressRange":
        network = ip_network(text, strict=False)
        return AddressRange(
            int(network.network_address),
            int(network.broadcast_address),
        )

    @staticmethod
    def any() -> "AddressRange":
        return AddressRange(0, 0xFFFFFFFF)

    def contains(self, address: int) -> bool:
        return self.start <= address <= self.end


@dataclass(frozen=True)
class PortRange:
    start: int
    end: int

    @staticmethod
    def any() -> "PortRange":
        return PortRange(0, 65535)

    def contains(self, port: int) -> bool:
        return self.start <= port <= self.end


@dataclass
class RuleMatch:
    source: List[AddressRange] = field(default_factory=lambda: [AddressRange.any()])
    destination: List[AddressRange] = field(default_factory=lambda: [AddressRange.any()])
    source_ports: List[PortRange] = field(default_factory=lambda: [PortRange.any()])
    destination_ports: List[PortRange] = field(default_factory=lambda: [PortRange.any()])
    protocol: Protocol = Protocol.ANY
    states: Set[str] = field(default_factory=set)

    def clone(self) -> "RuleMatch":
        return RuleMatch(
            source=list(self.source),
            destination=list(self.destination),
            source_ports=list(self.source_ports),
            destination_ports=list(self.destination_ports),
            protocol=self.protocol,
            states=set(self.states),
        )


@dataclass
class Rule:
    chain: str
    match: RuleMatch
    action: RuleAction
    jump_target: Optional[str] = None
    description: Optional[str] = None

    def summary(self) -> str:
        target = self.jump_target if self.jump_target else self.action.value
        return f"{self.chain}: {target} ({self.description or 'rule'})"


@dataclass
class Chain:
    name: str
    policy: RuleAction
    rules: List[Rule] = field(default_factory=list)
    builtin: bool = True

    def add_rule(self, rule: Rule) -> None:
        self.rules.append(rule)


@dataclass
class RuleSet:
    name: str
    table: str
    chains: List[Chain]
    warnings: List[str] = field(default_factory=list)

    def chain_map(self) -> dict[str, Chain]:
        return {chain.name: chain for chain in self.chains}

    def builtin_chains(self) -> Sequence[str]:
        return [chain.name for chain in self.chains if chain.builtin]

    def append_warning(self, message: str) -> None:
        self.warnings.append(message)


@dataclass
class Packet:
    source: IPv4Address
    destination: IPv4Address
    protocol: Protocol
    source_port: int | None = None
    destination_port: int | None = None
    state: Optional[str] = None


@dataclass
class PacketTrace:
    chain: str
    rule: Optional[Rule]
    decision: RuleAction


@dataclass
class PacketQueryResult:
    allowed: bool
    decision: RuleAction
    trace: List[PacketTrace] = field(default_factory=list)


def parse_ipv4(value: str) -> IPv4Address:
    return IPv4Address(value)


def parse_cidr(text: str) -> AddressRange:
    if "/" in text:
        return AddressRange.from_cidr(text)
    return AddressRange(int(IPv4Address(text)), int(IPv4Address(text)))


def parse_port(text: str) -> PortRange:
    if ":" in text:
        start, end = text.split(":", 1)
        return PortRange(int(start), int(end))
    value = int(text)
    return PortRange(value, value)


def parse_states(text: str) -> Set[str]:
    return {state.strip().upper() for state in text.split(",") if state.strip()}
