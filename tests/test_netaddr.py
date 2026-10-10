"""Unit tests for sentinel_link/api/netaddr.py."""
import importlib.util
import pathlib

spec = importlib.util.spec_from_file_location("netaddr_t", pathlib.Path(__file__).resolve().parents[1] / "custom_components" / "sentinel_link" / "api" / "netaddr.py")
na = importlib.util.module_from_spec(spec)
spec.loader.exec_module(na)

NODE = [("lo", ["127.0.0.1"]), ("enp4s0", ["192.168.1.101", "fe80::1"]), ("tailscale0", ["100.112.126.109"]), ("docker0", ["172.17.0.1"]),
        ("br-da2af0cbbad1", ["172.18.0.1"]), ("vethf413b2e", [])]


def test_only_real_lan_address_listed():
    assert na.local_addresses(NODE) == [{"interface": "enp4s0", "ip": "192.168.1.101"}]


def test_urls_default_port_and_custom():
    a = na.local_addresses(NODE)
    assert na.local_urls(a) == ["https://192.168.1.101"] and na.local_urls(a, 8443) == ["https://192.168.1.101:8443"]


def test_wired_before_wifi_and_multiple():
    r = na.local_addresses([("wlan0", ["10.0.0.7"]), ("enp3s0", ["192.168.5.2"]), ("eth1", ["192.168.9.2"])])
    assert [x["interface"] for x in r] == ["enp3s0", "eth1", "wlan0"]


def test_public_cgnat_linklocal_ipv6_and_junk_dropped():
    r = na.local_addresses([("eth0", ["8.8.8.8", "100.100.1.1", "169.254.3.3", "fe80::1", "not-an-ip", "10.1.2.3"])])
    assert r == [{"interface": "eth0", "ip": "10.1.2.3"}]


def test_empty_and_no_adapters():
    assert na.local_addresses([]) == [] and na.local_urls([]) == []
