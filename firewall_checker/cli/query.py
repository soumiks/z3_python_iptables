"""CLI for querying firewall rule decisions for a single packet."""
from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console

from ..analysis import FirewallChecker
from ..parser import packet_from_cli_args

app = typer.Typer(help="Evaluate a single packet against an iptables rule set")
console = Console()


@app.command()
def main(
    rules: Path = typer.Option(..., exists=True, readable=True, help="Path to iptables-save file"),
    chain: str = typer.Option("INPUT", help="Chain to evaluate"),
    src: str = typer.Option(..., help="Source IPv4 address"),
    dst: str = typer.Option(..., help="Destination IPv4 address"),
    protocol: str = typer.Option("tcp", help="Protocol (tcp/udp/icmp)"),
    sport: int | None = typer.Option(None, help="Source port"),
    dport: int | None = typer.Option(None, help="Destination port"),
    state: str | None = typer.Option(None, help="Connection state"),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON instead of text"),
) -> None:
    checker = FirewallChecker.from_file(rules)
    packet = packet_from_cli_args(src=src, dst=dst, protocol=protocol, sport=sport, dport=dport, state=state)
    result = checker.evaluate_packet(packet, chain)
    if json_output:
        typer.echo(_result_to_json(result))
    else:
        console.print(f"Decision: [bold]{result.decision.value}[/bold] (allowed={result.allowed})")
        for trace in result.trace:
            rule_desc = trace.rule.summary() if trace.rule else f"{trace.chain} (policy)"
            console.print(f"  - {trace.chain}: {trace.decision.value} via {rule_desc}")


def _result_to_json(result) -> str:
    payload = {
        "allowed": result.allowed,
        "decision": result.decision.value,
        "trace": [
            {
                "chain": trace.chain,
                "decision": trace.decision.value,
                "rule": trace.rule.summary() if trace.rule else None,
            }
            for trace in result.trace
        ],
    }
    return json.dumps(payload, indent=2)
