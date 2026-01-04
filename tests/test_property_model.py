from ipaddress import IPv4Address

import hypothesis.strategies as st
from hypothesis import given

from firewall_checker.model import AddressRange


@given(st.integers(min_value=0, max_value=2**32 - 1))
def test_cidr_contains_endpoints(value: int):
    addr = IPv4Address(value)
    rng = AddressRange.from_cidr(f"{addr}/32")
    assert rng.start == rng.end == int(addr)
    assert rng.contains(int(addr))
