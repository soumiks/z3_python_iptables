from pathlib import Path

from firewall_checker.model import RuleAction
from firewall_checker.parser import parse_iptables_save


def test_parse_sample_file():
    text = Path("examples/iptables/sample.rules").read_text()
    ruleset = parse_iptables_save(text)
    chain_map = ruleset.chain_map()
    assert set(chain_map) >= {"INPUT", "SSH"}
    ssh_chain = chain_map["SSH"]
    assert ssh_chain.builtin is False
    assert ssh_chain.policy == RuleAction.RETURN
    assert ssh_chain.rules[0].action == RuleAction.ACCEPT
    assert ssh_chain.rules[1].action == RuleAction.RETURN
