import ipaddress
import random

from bota.filter import IPListFilter, IPRangeFilter, ListFilter, MACListFilter


def test_listfilter():
    items = ["a", "x", "b", "y", "c"]

    f = ListFilter(items)

    assert f.items == sorted(items)

    assert f.apply("a")
    assert f.apply("x")
    assert f.apply("b")
    assert f.apply("y")
    assert f.apply("c")

    assert not f.apply("d")
    assert not f.apply("w")


def test_iplistfilter():
    ip_list = [
        "192.168.0.1",
        "192.168.0.5",
        "192.168.0.2",
        "192.168.0.3",
        "192.168.0.4",
    ]

    f = IPListFilter(ip_list)

    assert f.items == [3232235521, 3232235522, 3232235523, 3232235524, 3232235525]

    assert f.apply("192.168.0.1")
    assert f.apply("192.168.0.5")
    assert f.apply("192.168.0.2")
    assert f.apply("192.168.0.3")
    assert f.apply("192.168.0.4")

    assert not f.apply("192.168.0.6")
    assert not f.apply("192.168.0.50")


def test_maclistfilter():
    mac_list = [
        "aa:aa:aa:aa:aa:aa",
        "cc:cc:cc:cc:cc:cc",
        "bb:bb:bb:bb:bb:bb",
        "dd:dd:dd:dd:dd:dd",
        "ff:ff:ff:ff:ff:ff",
    ]

    f = MACListFilter(mac_list)

    assert f.items == [
        187649984473770,
        206414982921147,
        225179981368524,
        243944979815901,
        281474976710655,
    ]

    assert f.apply("aa:aa:aa:aa:aa:aa")
    assert f.apply("cc:cc:cc:cc:cc:cc")
    assert f.apply("bb:bb:bb:bb:bb:bb")
    assert f.apply("dd:dd:dd:dd:dd:dd")
    assert f.apply("ff:ff:ff:ff:ff:ff")

    assert not f.apply("ee:ee:ee:ee:ee:ee")
    assert not f.apply("ab:ab:ab:ab:ab:ab")


def test_iprangefilter():
    ip_range = "192.168.0.0/24"

    f = IPRangeFilter(ip_range)

    assert f.apply("192.168.0.1")
    assert f.apply("192.168.0.25")
    assert f.apply("192.168.0.50")
    assert f.apply("192.168.0.100")
    assert f.apply("192.168.0.254")

    assert not f.apply("10.0.0.1")
    assert not f.apply("192.168.1.1")


def test_iprangefilter_all():
    ip_range = "0.0.0.0/0"

    f = IPRangeFilter(ip_range)

    for _ in range(50):
        i = random.randint(1, 2 ** 32 - 1)
        assert f.apply(str(ipaddress.ip_address(i)))
