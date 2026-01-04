"""High-level orchestration across parser, model, and solver layers."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence

from . import solver
from .model import (
    Packet,
    PacketQueryResult,
    PacketTrace,
    PortRange,
    Protocol,
    Rule,
    RuleAction,
    RuleMatch,
    RuleSet,
)
from .parser import read_iptables_file


class FirewallChecker:
    """Bundle rule parsing, packet evaluation, and solver-backed queries."""

    def __init__(self, ruleset: RuleSet):
        self.ruleset = ruleset
        self._chain_map = ruleset.chain_map()
        self._solver_context = solver.FirewallSolver(ruleset)

    @classmethod
    def from_file(cls, path: Path) -> "FirewallChecker":
        return cls(read_iptables_file(path))

    def evaluate_packet(self, packet: Packet, chain: str = "INPUT") -> PacketQueryResult:
        trace: List[PacketTrace] = []
        decision = self._evaluate_chain(chain, packet, trace, stack=tuple())
        allowed = decision == RuleAction.ACCEPT
        return PacketQueryResult(allowed=allowed, decision=decision, trace=trace)

    def equivalence_counterexamples(
        self,
        other: "FirewallChecker",
        chain: str = "INPUT",
        limit: int = 1,
    ) -> List[Packet]:
        return solver.find_equivalence_counterexamples(
            self._solver_context,
            other._solver_context,
            chain=chain,
            limit=limit,
        )

    def _evaluate_chain(
        self,
        chain_name: str,
        packet: Packet,
        trace: List[PacketTrace],
        stack: Sequence[str],
    ) -> RuleAction:
        if chain_name in stack:
            raise RuntimeError(f"Cycle detected in chain traversal: {' -> '.join(stack + (chain_name,))}")
        chain = self._chain_map.get(chain_name)
        if not chain:
            raise RuntimeError(f"Unknown chain {chain_name}")
        for rule in chain.rules:
            if _rule_matches(packet, rule.match):
                trace.append(PacketTrace(chain=chain_name, rule=rule, decision=rule.action))
                if rule.action == RuleAction.JUMP:
                    if not rule.jump_target:
                        continue
                    jump_decision = self._evaluate_chain(
                        rule.jump_target,
                        packet,
                        trace,
                        stack=(*stack, chain_name),
                    )
                    if jump_decision == RuleAction.RETURN:
                        continue
                    return jump_decision
                if rule.action == RuleAction.RETURN:
                    return chain.policy if chain.builtin else RuleAction.RETURN
                return rule.action
        trace.append(PacketTrace(chain=chain_name, rule=None, decision=chain.policy))
        return chain.policy if chain.builtin else RuleAction.RETURN


@dataclass
class EquivalenceResult:
    equivalent: bool
    counterexamples: List[Packet]
    chain: str


def _rule_matches(packet: Packet, match: RuleMatch) -> bool:
    src_int = int(packet.source)
    dst_int = int(packet.destination)
    if not any(r.contains(src_int) for r in match.source):
        return False
    if not any(r.contains(dst_int) for r in match.destination):
        return False
    if match.protocol != Protocol.ANY and packet.protocol != match.protocol:
        return False
    if not _port_matches(packet.source_port, match.source_ports):
        return False
    if not _port_matches(packet.destination_port, match.destination_ports):
        return False
    if match.states and (packet.state or "").upper() not in match.states:
        return False
    return True


def _port_matches(value: int | None, ranges: Sequence[PortRange]) -> bool:
    if ranges and len(ranges) == 1 and ranges[0].start == 0 and ranges[0].end == 65535:
        # Any-range matches even when packet port is missing.
        return True
    if value is None:
        return False
    return any(r.contains(value) for r in ranges)
