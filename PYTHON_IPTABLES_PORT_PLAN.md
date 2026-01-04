# Python Port & iptables Support Plan

## 1. Goals & Scope
- Rebuild the FirewallChecker analysis pipeline in Python while preserving feature parity: parsing firewall rules, building Z3 constraint models, equivalence checking, and packet queries.
- Replace the Windows Firewall TSV input format with iptables rules (initially IPv4 `filter` table; extensions later).
- Deliver production-ready CLI tools plus a reusable library that other Python projects can call.
- Maintain solver-backed verification fidelity comparable to the .NET version.

## 2. Research & Requirements Capture
1. **Feature inventory** – Document all existing C# capabilities (rule fields, logging, CLI options, error handling, solver abstractions).
2. **iptables domain study** – Decide which iptables input representation to support first (`iptables-save`, `iptables -S`, or nftables compatibility). Map constructs (tables, chains, matches, targets) to analysis-friendly concepts.
3. **Protocol/IP scope** – Start with IPv4 TCP/UDP/ICMP, note iptables features that will be ignored initially (stateful matches, modules, NAT).
4. **Z3 feasibility** – Confirm parity between .NET and Python bindings for arrays/bitvectors used today; spike a prototype model for one rule.
5. **Performance targets** – Measure current .NET tool runtime on sample rules; set acceptable range for Python implementation.

## 3. High-Level Architecture Design
1. **Module layout**
   - `firewall_checker/` package with submodules: `parser`, `model`, `analysis`, `cli`.
   - Use `dataclasses`/`pydantic` for structured rule/packet models.
2. **Intermediate Representation**
   - Normalize iptables rules into an IR similar to `WindowsFirewallRule` (fields: chain, action, matches).
   - Define canonical ordering + pre-processing (explode port ranges, expand CIDRs, flatten multi-protocol rules).
3. **Z3 Integration**
   - Wrap Python z3 objects behind helper functions mirroring the C# library for consistency.
   - Provide serialization utilities for counterexample packets to map back to human-readable form.
4. **Configuration**
   - Provide settings object for toggling features (e.g., max counterexamples, solver timeouts, IPv6 enable toggle).

## 4. Implementation Workstreams
1. **Parser & Normalization**
   - Choose parser strategy: start with `iptables-save` text parser; later add JSON via `iptables -S -v -j`.
   - Tokenize commands, support default chains (INPUT/FORWARD/OUTPUT), handle `-p`, `-s`, `-d`, `--dport`, `--sport`, `-m state --state NEW`.
   - Normalize policy (ACCEPT/DROP) and modules (initial support for `tcp`, `udp`, `icmp`).
   - Emit warnings for unsupported matches, mirroring current behavior.
2. **Rule Model & Packet Abstractions**
   - Implement dataclasses for `AddressRange`, `PortRange`, `Protocol`, `RuleAction`.
   - Provide conversion helpers from iptables tokens to IR, e.g., CIDR -> start/end ints, port lists -> intervals.
   - Define `Packet` representation aligned with solver variables.
3. **Solver Translation Layer**
   - Build functions that turn normalized rules into Z3 predicates.
   - Implement rule ordering semantics (iptables is first-match); encode chain traversal, jumps, returns.
   - Provide APIs for:
     - `evaluate_packet(rule_set, packet)` returning allow/deny with matched rule trace.
     - `find_equivalence_counterexamples(firewall_a, firewall_b, limit)`.
4. **CLI Utilities**
   - Use `argparse` or `typer`/`click` for ergonomics.
   - Tools:
     - `iptables-equivalence` – mirrors current equivalence checker CLI.
     - `iptables-query` – single packet evaluation.
   - Provide JSON output mode for easier integration in automation.
5. **Performance Optimizations**
   - Cache shared Z3 sub-expressions (e.g., port comparisons).
   - Allow parallel solver instances for multiple packets (multiprocessing).
   - Introduce incremental solving when exploring counterexamples.

## 5. Testing Strategy
1. **Unit Tests**
   - Parser tests for each iptables construct; golden samples from `Examples/iptables/*.rules`.
   - Solver translation tests verifying expected predicates for simple rules.
2. **Integration Tests**
   - Compare Python tool outputs against known truths (e.g., synthetic firewalls with known inequivalences).
   - Cross-check: convert Windows TSV -> iptables equivalents to ensure parity with original C# logic where possible.
3. **Property/Model-Based Tests**
   - Use `hypothesis` to generate random rules/packets ensuring solver output matches an imperative simulator for small rulesets.
4. **Performance Benchmarks**
   - Script to measure solver runtime vs .NET version on real Azure-like rule dumps (if accessible).

## 6. Tooling, Packaging, and CI
1. **Project Scaffolding**
   - `pyproject.toml` with `poetry` or `hatch`; declare dependency on `z3-solver`.
   - `tox`/`nox` environments for lint (ruff), type checking (mypy), tests (pytest).
2. **Examples & Docs**
   - Provide iptables sample files and CLI walkthrough analogous to current README.
   - Document unsupported features and roadmap for iptables modules/NFT.
3. **Continuous Integration**
   - GitHub Actions pipeline: setup Python + Z3, run lint/type/test suites, cache solver artifacts.
   - Include security scanning (pip-audit) if distributing widely.
4. **Distribution**
   - Publish to PyPI once stable; provide versioning strategy (semantic versioning) and changelog.

## 7. Migration / Rollout Considerations
1. **Coexistence Period**
   - Keep C# version for Windows Firewall support while Python targets iptables; document boundaries.
   - Optionally expose Python bindings as a service for other languages.
2. **User Education**
   - Update README to explain the new Python tooling, install steps, and iptables focus.
   - Provide conversion guide for Windows users wanting iptables equivalents.
3. **Future Enhancements**
   - Extend parser to ip6tables/nftables.
   - Support stateful matches, connection tracking, NAT tables once base port is stable.
   - Explore GUI or web service interface powered by Python backend.

## 8. Risks & Mitigations
- **Z3 feature gaps** – Mitigate by prototyping early and contributing patches/upstream docs if needed.
- **iptables complexity** – Start with constrained subset; implement warning + skip semantics for unsupported matches.
- **Performance regression vs .NET** – Profile Python implementation, exploit vectorized constraint generation, and fall back to PyPy or C extensions if required.
- **Solver soundness** – Validate against iptables simulator and, for critical deployments, run both solvers in parallel until confidence is high.

