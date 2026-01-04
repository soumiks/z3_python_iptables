from firewall_checker.analysis import FirewallChecker
from firewall_checker.parser import parse_iptables_save


_SAMPLE_A = """*filter
:INPUT DROP [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -j DROP
COMMIT
"""

_SAMPLE_B = """*filter
:INPUT DROP [0:0]
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -j DROP
COMMIT
"""


def test_equivalence_finds_difference():
    fw_a = FirewallChecker(parse_iptables_save(_SAMPLE_A))
    fw_b = FirewallChecker(parse_iptables_save(_SAMPLE_B))
    packets = fw_a.equivalence_counterexamples(fw_b, limit=1)
    assert packets, "Expected counterexample when allow rules differ"
    packet = packets[0]
    assert packet.destination_port in {22, 80}
