"""Safe local sandbox acceptance; docker opt-in, bwrap auto when installed."""
import importlib.util
import pathlib
import shutil
import tempfile
import unittest
import sys
sys.dont_write_bytecode = True

path = pathlib.Path(__file__).resolve().parents[4] / 'lib/pwn/plugins/sandbox/driver.py'
spec = importlib.util.spec_from_file_location('sandbox_driver', path)
assert spec
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class SandboxTest(unittest.TestCase):
    def test_binary_fuzz_input_preserved(self):
        with tempfile.TemporaryDirectory() as corpus:
            pathlib.Path(corpus, 'seed').write_bytes(b'\xff')
            observed = []
            original = module.execute
            def capture(request):
                observed.append(request)
                return {'signal': 'SIGSEGV'}
            module.execute = capture
            try:
                module.main({'action': 'fuzz', 'binary': '/bin/true', 'corpus': corpus, 'minutes': .001})
            finally:
                module.execute = original
            self.assertIn('stdin_base64', observed[0])

    @unittest.skipUnless(shutil.which('bwrap'), 'bwrap unavailable')
    def test_isolated_fixture_crash_timeout_and_read_only(self):
        # /bin/sh is a trusted fixture; no network request is made.
        result = module.execute({'binary': '/bin/sh', 'backend': 'bwrap', 'argv': ['-c', 'test ! -e /home/ninp0 && ! touch /artifacts/new && cat /proc/net/route'], 'timeout': 2})
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['exit'], 0)
        self.assertEqual(len(result['stdout'].strip().splitlines()), 1)
        crash = module.execute({'binary': '/bin/sh', 'backend': 'bwrap', 'argv': ['-c', 'kill -SEGV $$'], 'timeout': 2})
        self.assertEqual(crash['signal'], 'SIGSEGV')
        self.assertIn('strace', crash)
        self.assertIn('gdb', crash)
        timeout = module.execute({'binary': '/bin/sleep', 'backend': 'bwrap', 'argv': ['5'], 'timeout': .1})
        self.assertTrue(timeout['timed_out'])

if __name__ == '__main__':
    unittest.main()
