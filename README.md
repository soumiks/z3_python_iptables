# Firewall Checker (Python iptables Edition)

This repository hosts the Python port of the FirewallChecker tooling backed by Z3. The port is
based on the original Microsoft [FirewallChecker](https://github.com/Z3Prover/FirewallChecker/tree/master).
The implementation consumes `iptables-save` output, normalizes the rules into a solver friendly
intermediate representation, and offers both a reusable library and CLI utilities for comparing
or querying firewalls. Curious about how the translation was done? See `PYTHON_IPTABLES_PORT_PLAN.md`
for the end-to-end port plan and decision log.

## Features

- Parser for `iptables-save` filter tables (IPv4 TCP/UDP/ICMP focus).
- Dataclasses describing addresses, ports, packets, and rules with deterministic normalization.
- Solver translation layer that mirrors first-match semantics, chain jumps, and returns with z3
  expressions.
- CLI utilities powered by [Typer](https://typer.tiangolo.com/) for equivalence checking and
  single packet queries.
- Sample rules plus unit tests/parity checks for the parser and solver behaviors.

## Quick Start

```bash
pip install -e .[dev]
printf "<iptables dump>" > firewall.rules
iptables-equivalence firewall.rules other.rules
iptables-query --rules firewall.rules --chain INPUT --src 10.0.0.1 --dst 10.0.0.2 \\
    --protocol tcp --dport 22
```

See `examples/iptables/` for sample rule files and `tests/` for usage patterns.

## Usage Examples

### Compare two rule sets

Check whether two saved firewalls behave the same for the `INPUT` chain:

```bash
iptables-equivalence examples/iptables/basic.rules examples/iptables/basic_with_block.rules --chain INPUT
```

If they differ you will see a counterexample packet with the actions taken by each ruleset.

### Query a single packet

Ask how a specific packet would be handled:

```bash
iptables-query --rules examples/iptables/basic.rules --chain INPUT \
  --src 10.0.0.10 --dst 10.0.0.20 --protocol tcp --sport 51514 --dport 22 --state NEW
```

The command prints whether the packet is accepted, the matching rule, and any chain jumps taken.

## Testing

Install dev dependencies (`pip install -e .[dev]`) and run the test suite with:

```bash
python -m pytest
```

## Current Limitations
- Only `iptables-save` filter tables are parsed today; NAT/mangle tables and nftables exports
  are on the roadmap.
- Stateful matches currently support `NEW/ESTABLISHED/RELATED` and treat other states as
  unmatched. Unsupported modules emit warnings instead of halting the parse.
- IPv6 and connection tracking helpers are intentionally out-of-scope for this initial drop.
