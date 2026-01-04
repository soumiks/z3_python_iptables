"""Translation utilities that map normalized rules into Z3 constraints."""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address
from typing import Dict, Iterable, List, Sequence

import z3

from .model import AddressRange, Chain, Packet, PortRange, Protocol, Rule, RuleAction, RuleMatch, RuleSet

DecisionSort, (DECISION_RETURN, DECISION_DROP, DECISION_ACCEPT) = z3.EnumSort(
    "Decision",
    ["RETURN", "DROP", "ACCEPT"],
)


@dataclass
class PacketVariables:
    src_ip: z3.BitVecRef
    dst_ip: z3.BitVecRef
    protocol: z3.BitVecRef
    src_port: z3.BitVecRef
    dst_port: z3.BitVecRef
    has_src_port: z3.BoolRef
    has_dst_port: z3.BoolRef
    state_new: z3.BoolRef
    state_established: z3.BoolRef
    state_related: z3.BoolRef

    def iter_all(self) -> List[z3.ExprRef]:
        return [
            self.src_ip,
            self.dst_ip,
            self.protocol,
            self.src_port,
            self.dst_port,
            self.has_src_port,
            self.has_dst_port,
            self.state_new,
            self.state_established,
            self.state_related,
        ]


def build_packet_variables(prefix: str = "pkt") -> PacketVariables:
    return PacketVariables(
        src_ip=z3.BitVec(f"{prefix}_src_ip", 32),
        dst_ip=z3.BitVec(f"{prefix}_dst_ip", 32),
        protocol=z3.BitVec(f"{prefix}_protocol", 8),
        src_port=z3.BitVec(f"{prefix}_src_port", 16),
        dst_port=z3.BitVec(f"{prefix}_dst_port", 16),
        has_src_port=z3.Bool(f"{prefix}_has_src"),
        has_dst_port=z3.Bool(f"{prefix}_has_dst"),
        state_new=z3.Bool(f"{prefix}_state_new"),
        state_established=z3.Bool(f"{prefix}_state_established"),
        state_related=z3.Bool(f"{prefix}_state_related"),
    )


class FirewallSolver:
    """Caches symbolic expressions for all chains in a rule set."""

    def __init__(self, ruleset: RuleSet):
        self.ruleset = ruleset
        self._chain_map = ruleset.chain_map()

    def decision_expr(self, chain: str, packet_vars: PacketVariables) -> z3.ExprRef:
        memo: Dict[str, z3.ExprRef] = {}
        stack: List[str] = []
        return _chain_decision_expr(chain, packet_vars, self._chain_map, memo, stack)


def find_equivalence_counterexamples(
    solver_a: FirewallSolver,
    solver_b: FirewallSolver,
    chain: str = "INPUT",
    limit: int = 1,
) -> List[Packet]:
    packet_vars = build_packet_variables()
    expr_a = solver_a.decision_expr(chain, packet_vars)
    expr_b = solver_b.decision_expr(chain, packet_vars)
    sat_solver = z3.Solver()
    sat_solver.add(expr_a != expr_b)
    counterexamples: List[Packet] = []
    while len(counterexamples) < limit and sat_solver.check() == z3.sat:
        model = sat_solver.model()
        packet = _model_to_packet(model, packet_vars)
        counterexamples.append(packet)
        sat_solver.add(_block_model(packet_vars, model))
    return counterexamples


def _block_model(packet_vars: PacketVariables, model: z3.ModelRef) -> z3.ExprRef:
    clauses = []
    for var in packet_vars.iter_all():
        value = model.eval(var, model_completion=True)
        clauses.append(var != value)
    return z3.Or(clauses)


def _model_to_packet(model: z3.ModelRef, packet_vars: PacketVariables) -> Packet:
    def _eval(expr: z3.ExprRef) -> z3.ExprRef:
        return model.eval(expr, model_completion=True)

    src_ip = int(_eval(packet_vars.src_ip).as_long())
    dst_ip = int(_eval(packet_vars.dst_ip).as_long())
    protocol_value = int(_eval(packet_vars.protocol).as_long())
    src_port_val = int(_eval(packet_vars.src_port).as_long())
    dst_port_val = int(_eval(packet_vars.dst_port).as_long())
    has_src = z3.is_true(_eval(packet_vars.has_src_port))
    has_dst = z3.is_true(_eval(packet_vars.has_dst_port))
    state = _state_from_model(
        z3.is_true(_eval(packet_vars.state_new)),
        z3.is_true(_eval(packet_vars.state_established)),
        z3.is_true(_eval(packet_vars.state_related)),
    )
    protocol = _protocol_from_value(protocol_value)
    return Packet(
        source=IPv4Address(src_ip),
        destination=IPv4Address(dst_ip),
        protocol=protocol,
        source_port=src_port_val if has_src else None,
        destination_port=dst_port_val if has_dst else None,
        state=state,
    )


def _protocol_from_value(value: int) -> Protocol:
    for protocol in Protocol:
        if protocol.value == value:
            return protocol
    return Protocol.ANY


def _state_from_model(is_new: bool, is_established: bool, is_related: bool) -> str | None:
    if is_new:
        return "NEW"
    if is_established:
        return "ESTABLISHED"
    if is_related:
        return "RELATED"
    return None


def _chain_decision_expr(
    chain: str,
    packet_vars: PacketVariables,
    chain_map: Dict[str, Chain],
    memo: Dict[str, z3.ExprRef],
    stack: List[str],
) -> z3.ExprRef:
    if chain in memo:
        return memo[chain]
    if chain in stack:
        cycle = " -> ".join(stack + [chain])
        raise RuntimeError(f"Cycle detected in chains: {cycle}")
    chain_obj = chain_map.get(chain)
    if not chain_obj:
        raise RuntimeError(f"Unknown chain {chain}")
    stack.append(chain)
    base_expr = _decision_from_action(chain_obj.policy) if chain_obj.builtin else DECISION_RETURN
    result = base_expr
    for rule in reversed(chain_obj.rules):
        residual = result
        match_expr = _rule_match_expr(rule.match, packet_vars)
        rule_expr = _rule_decision_expr(rule, packet_vars, chain_map, memo, stack, residual)
        result = z3.If(match_expr, rule_expr, residual)
    memo[chain] = result
    stack.pop()
    return result


def _rule_decision_expr(
    rule: Rule,
    packet_vars: PacketVariables,
    chain_map: Dict[str, Chain],
    memo: Dict[str, z3.ExprRef],
    stack: List[str],
    residual: z3.ExprRef,
) -> z3.ExprRef:
    if rule.action == RuleAction.JUMP:
        if not rule.jump_target:
            return residual
        jump_expr = _chain_decision_expr(rule.jump_target, packet_vars, chain_map, memo, stack)
        return z3.If(jump_expr == DECISION_RETURN, residual, jump_expr)
    if rule.action == RuleAction.RETURN:
        current_chain = chain_map[rule.chain]
        if current_chain.builtin:
            return _decision_from_action(current_chain.policy)
        return DECISION_RETURN
    if rule.action == RuleAction.LOG:
        return residual
    return _decision_from_action(rule.action)


def _decision_from_action(action: RuleAction) -> z3.ExprRef:
    if action == RuleAction.ACCEPT:
        return DECISION_ACCEPT
    if action in {RuleAction.DROP, RuleAction.REJECT}:
        return DECISION_DROP
    if action == RuleAction.RETURN:
        return DECISION_RETURN
    raise ValueError(f"Action {action} cannot be turned into a decision directly")


def _rule_match_expr(rule_match: RuleMatch, packet_vars: PacketVariables) -> z3.ExprRef:
    parts: List[z3.ExprRef] = []
    parts.append(_address_expr(rule_match.source, packet_vars.src_ip))
    parts.append(_address_expr(rule_match.destination, packet_vars.dst_ip))
    if rule_match.protocol != Protocol.ANY:
        parts.append(packet_vars.protocol == z3.BitVecVal(rule_match.protocol.value, 8))
    if not _is_any_port(rule_match.source_ports):
        src_port_expr = _port_expr(rule_match.source_ports, packet_vars.src_port)
        parts.append(z3.And(packet_vars.has_src_port, src_port_expr))
    if not _is_any_port(rule_match.destination_ports):
        dst_port_expr = _port_expr(rule_match.destination_ports, packet_vars.dst_port)
        parts.append(z3.And(packet_vars.has_dst_port, dst_port_expr))
    if rule_match.states:
        state_exprs = []
        for state in rule_match.states:
            if state == "NEW":
                state_exprs.append(packet_vars.state_new)
            elif state == "ESTABLISHED":
                state_exprs.append(packet_vars.state_established)
            elif state == "RELATED":
                state_exprs.append(packet_vars.state_related)
            else:
                # Unsupported state results in unsatisfiable predicate for this rule.
                state_exprs.append(z3.BoolVal(False))
        parts.append(z3.Or(*state_exprs))
    return z3.And(*parts)


def _address_expr(ranges: Sequence[AddressRange], value: z3.BitVecRef) -> z3.ExprRef:
    exprs = [z3.And(z3.UGE(value, r.start), z3.ULE(value, r.end)) for r in ranges]
    return z3.Or(*exprs) if exprs else z3.BoolVal(True)


def _port_expr(ranges: Sequence[PortRange], value: z3.BitVecRef) -> z3.ExprRef:
    exprs = [z3.And(z3.UGE(value, r.start), z3.ULE(value, r.end)) for r in ranges]
    return z3.Or(*exprs) if exprs else z3.BoolVal(True)


def _is_any_port(ranges: Sequence[PortRange]) -> bool:
    return len(ranges) == 1 and ranges[0].start == 0 and ranges[0].end == 65535
