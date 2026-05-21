"""
test_analyze.py

Run with: python -m pytest tests/test_analyze.py -v
Or:       python tests/test_analyze.py
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
from analyze_pcap import strip_telnet_negotiation, SERVICE_PORTS


class TestIACStripping(unittest.TestCase):
    """Make sure telnet negotiation bytes get removed properly."""

    def test_plain_text_unchanged(self):
        self.assertEqual(strip_telnet_negotiation(b"hello"), b"hello")

    def test_will_removed(self):
        # FF FB 01 = IAC WILL ECHO
        self.assertEqual(strip_telnet_negotiation(b"\xff\xfb\x01hello"), b"hello")

    def test_do_removed(self):
        self.assertEqual(strip_telnet_negotiation(b"\xff\xfd\x03typed"), b"typed")

    def test_wont_removed(self):
        self.assertEqual(strip_telnet_negotiation(b"\xff\xfc\x01data"), b"data")

    def test_dont_removed(self):
        self.assertEqual(strip_telnet_negotiation(b"\xff\xfe\x01stuff"), b"stuff")

    def test_escaped_ff(self):
        # FF FF should become a single FF
        self.assertEqual(strip_telnet_negotiation(b"a\xff\xffb"), b"a\xffb")

    def test_subnegotiation(self):
        # FF FA <data> FF F0
        raw = b"start\xff\xfa\x18\x00VT100\xff\xf0end"
        self.assertEqual(strip_telnet_negotiation(raw), b"startend")

    def test_multiple_commands(self):
        raw = b"\xff\xfb\x01\xff\xfd\x03hello\xff\xfc\x01 world"
        self.assertEqual(strip_telnet_negotiation(raw), b"hello world")

    def test_empty(self):
        self.assertEqual(strip_telnet_negotiation(b""), b"")

    def test_only_iac(self):
        raw = b"\xff\xfb\x01\xff\xfd\x03\xff\xfe\x05"
        self.assertEqual(strip_telnet_negotiation(raw), b"")


class TestServicePorts(unittest.TestCase):
    """Sanity checks on the port mapping."""

    def test_common_ports(self):
        self.assertEqual(SERVICE_PORTS[22], "SSH")
        self.assertEqual(SERVICE_PORTS[23], "Telnet")
        self.assertEqual(SERVICE_PORTS[80], "HTTP")
        self.assertEqual(SERVICE_PORTS[443], "HTTPS")

    def test_port_range(self):
        for port in SERVICE_PORTS:
            self.assertGreater(port, 0)
            self.assertLess(port, 65536)


if __name__ == "__main__":
    unittest.main()
