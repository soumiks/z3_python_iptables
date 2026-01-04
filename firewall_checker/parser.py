"""iptables-save parser and normalization utilities."""
from __future__ import annotations

import shlex
from pathlib import Path
from typing import Iterable, List, Tuple

from .model import (
    AddressRange,
    Chain,
    Packet,
    PacketQueryResult,
    PacketTrace,
    PortRange,
    Protocol,
    Rule,
    RuleAction,
    RuleMatch,
    RuleSet,
    parse_cidr,
    parse_port,
    parse_states,
    parse_ipv4,
)

TERMINAL_TARGETS: dict[str, RuleAction] = {
    "ACCEPT": RuleAction.ACCEPT,
    "DROP": RuleAction.DROP,
    "REJECT": RuleAction.REJECT,
}


class ParserError(RuntimeError):
    pass


def read_iptables_file(path: Path) -> RuleSet:
    """Load a file containing iptables-save contents."""
    return parse_iptables_save(path.read_text())


def parse_iptables_save(text: str, table: str = "filter") -> RuleSet:
    lines = text.splitlines()
    current_table = None
    chains: dict[str, Chain] = {}
    warnings: List[str] = []

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            current_table = line[1:].strip()
            continue
        if line == "COMMIT":
            current_table = None
            continue
        if current_table != table:
            continue
        if line.startswith(":"):
            chain = _parse_chain_def(line, warnings)
            chains[chain.name] = chain
            continue
        if line.startswith("-A") or line.startswith("-I"):
            tokens = shlex.split(line)
            if len(tokens) < 3:
                warnings.append(f"Skipping malformed rule line: {line}")
                continue
            _, chain_name, *rule_tokens = tokens
            chain = chains.get(chain_name)
            if not chain:
                warnings.append(f"Rule references unknown chain {chain_name}: {line}")
                continue
            rule = _parse_rule(chain_name, rule_tokens, chains, warnings)
            chain.add_rule(rule)
            continue
        warnings.append(f"Unsupported line: {line}")

    return RuleSet(name="iptables", table=table, chains=list(chains.values()), warnings=warnings)


def _parse_chain_def(line: str, warnings: List[str]) -> Chain:
    # Format: :CHAIN POLICY [packet:byte]
    try:
        header, policy_token, *_ = line[1:].split()
    except ValueError as exc:
        raise ParserError(f"Invalid chain definition: {line}") from exc
    name = header.strip()
    builtin = policy_token != "-"
    if builtin:
        action = TERMINAL_TARGETS.get(policy_token.upper())
        if not action:
            warnings.append(f"Chain {name} has unsupported policy {policy_token}, defaulting DROP")
            action = RuleAction.DROP
    else:
        action = RuleAction.RETURN
    return Chain(name=name, policy=action, builtin=builtin)


def _parse_rule(
    chain_name: str,
    tokens: List[str],
    chain_map: dict[str, Chain],
    warnings: List[str],
) -> Rule:
    match = RuleMatch()
    description = None
    action = None
    jump_target = None
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token == "!":
            warnings.append(
                f"Negation operator in chain {chain_name} is not supported; rule may be imprecise",
            )
            i += 1
            continue
        if token in {"-p", "--protocol"}:
            match.protocol = Protocol.from_token(tokens[i + 1])
            i += 2
            continue
        if token in {"-s", "--source"}:
            match.source = [parse_cidr(tokens[i + 1])]
            i += 2
            continue
        if token in {"-d", "--destination"}:
            match.destination = [parse_cidr(tokens[i + 1])]
            i += 2
            continue
        if token in {"--sport", "--source-port"}:
            match.source_ports = _parse_ports(tokens[i + 1])
            i += 2
            continue
        if token in {"--dport", "--destination-port"}:
            match.destination_ports = _parse_ports(tokens[i + 1])
            i += 2
            continue
        if token == "-m":
            module = tokens[i + 1]
            i += 2
            if module == "state":
                if i < len(tokens) and tokens[i] == "--state":
                    match.states.update(parse_states(tokens[i + 1]))
                    i += 2
            else:
                warnings.append(f"Module -m {module} is not fully supported; continuing")
            continue
        if token == "--state":
            match.states.update(parse_states(tokens[i + 1]))
            i += 2
            continue
        if token in {"-j", "--jump"}:
            target = tokens[i + 1]
            action, jump_target = _resolve_target(target, chain_map, warnings)
            i += 2
            continue
        if token == "--comment":
            description = tokens[i + 1]
            i += 2
            continue
        if token in {"-g", "--goto"}:
            action, jump_target = _resolve_target(tokens[i + 1], chain_map, warnings)
            i += 2
            continue
        warnings.append(f"Token {token} is not supported; ignoring")
        i += 1

    if not action:
        warnings.append(f"Rule in chain {chain_name} missing jump/target; default DROP")
        action = RuleAction.DROP

    return Rule(
        chain=chain_name,
        match=match,
        action=action,
        jump_target=jump_target,
        description=description,
    )


def _parse_ports(token: str) -> List[PortRange]:
    segments = token.split(",")
    return [parse_port(segment) for segment in segments]


def _resolve_target(
    target: str,
    chain_map: dict[str, Chain],
    warnings: List[str],
) -> Tuple[RuleAction, str | None]:
    upper = target.upper()
    if upper in TERMINAL_TARGETS:
        return TERMINAL_TARGETS[upper], None
    if upper == "RETURN":
        return RuleAction.RETURN, None
    if upper not in chain_map:
        warnings.append(f"Jump target {target} is unknown; treating as DROP")
        return RuleAction.DROP, None
    return RuleAction.JUMP, upper


def packet_from_cli_args(**kwargs: str) -> Packet:
    protocol = Protocol.from_token(kwargs["protocol"]) if "protocol" in kwargs else Protocol.ANY
    return Packet(
        source=parse_ipv4(kwargs.get("src", "0.0.0.0")),
        destination=parse_ipv4(kwargs.get("dst", "0.0.0.0")),
        protocol=protocol,
        source_port=int(kwargs["sport"]) if kwargs.get("sport") else None,
        destination_port=int(kwargs["dport"]) if kwargs.get("dport") else None,
        state=kwargs.get("state"),
    )
