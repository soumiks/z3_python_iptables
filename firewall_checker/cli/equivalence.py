"""CLI tool for equivalence checking between two firewalls."""
from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console

from ..analysis import FirewallChecker

app = typer.Typer(help="Find counterexamples between two iptables rule sets")
console = Console()


@app.command()
def main(
    rules_a: Path = typer.Option(..., exists=True, readable=True, help="Left firewall iptables-save"),
    rules_b: Path = typer.Option(..., exists=True, readable=True, help="Right firewall iptables-save"),
    chain: str = typer.Option("INPUT", help="Chain to compare"),
    limit: int = typer.Option(1, min=1, help="Max counterexamples to emit"),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    fw_a = FirewallChecker.from_file(rules_a)
    fw_b = FirewallChecker.from_file(rules_b)
    counterexamples = fw_a.equivalence_counterexamples(fw_b, chain=chain, limit=limit)
    equivalent = len(counterexamples) == 0
    if json_output:
        typer.echo(_to_json(equivalent, counterexamples, chain))
    else:
        if equivalent:
            console.print(f"[green]Firewalls are equivalent for chain {chain}[/green]")
        else:
            console.print(
                f"[red]Found {len(counterexamples)} counterexample(s) for chain {chain}[/red]",
            )
            for idx, packet in enumerate(counterexamples, start=1):
                console.print(f"  [{idx}] {packet}")


def _to_json(equivalent: bool, packets, chain: str) -> str:
    payload = {
        "chain": chain,
        "equivalent": equivalent,
        "counterexamples": [
            {
                "source": str(packet.source),
                "destination": str(packet.destination),
                "protocol": packet.protocol.name,
                "source_port": packet.source_port,
                "destination_port": packet.destination_port,
                "state": packet.state,
            }
            for packet in packets
        ],
    }
    return json.dumps(payload, indent=2)
