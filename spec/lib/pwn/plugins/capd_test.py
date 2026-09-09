"""Unprivileged broker protocol tests; no packets transmitted."""
import importlib.machinery
import importlib.util
import pathlib
import socket
import tempfile
import threading
import unittest
import sys
sys.dont_write_bytecode = True

path = pathlib.Path(__file__).resolve().parents[4] / 'lib/pwn/plugins/capability_broker/daemon.py'

class BrokerTest(unittest.TestCase):
    def test_peer_and_operation_boundaries(self):
        loader = importlib.machinery.SourceFileLoader('capd', str(path))
        spec = importlib.util.spec_from_loader('capd', loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        broker = module.Broker(uid=12345, interfaces=['lo'])
        self.assertFalse(broker.dispatch({'operation': 'status'}, peer_uid=9)['ok'])
        self.assertFalse(broker.dispatch({'operation': 'exec', 'command': 'id'}, peer_uid=12345)['ok'])
        self.assertFalse(broker.dispatch({'operation': 'raw_send', 'iface': 'eth0', 'frame': ''}, peer_uid=12345)['ok'])
        self.assertTrue(broker.dispatch({'operation': 'status'}, peer_uid=12345)['ok'])

if __name__ == '__main__':
    unittest.main()
