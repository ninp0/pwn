"""Disposable sandbox controller and in-isolation worker (stdlib only)."""
import base64
import hashlib
import json
import os
import pathlib
import random
import re
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid


def bounded(command, timeout, stdin=b'', memory=None):
    def limits():
        if memory:
            resource.setrlimit(resource.RLIMIT_AS, (memory * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_FSIZE, (8 * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=out, stderr=err, start_new_session=True, preexec_fn=limits)
        expired = False
        try:
            process.communicate(stdin, timeout=timeout)
        except subprocess.TimeoutExpired:
            expired = True
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
        out.seek(0)
        err.seek(0)
        return {'exit': process.returncode, 'stdout': out.read(65536).decode(errors='replace'), 'stderr': err.read(65536).decode(errors='replace'), 'timed_out': expired}


def inside(request):
    command = ['/artifacts/target'] + request.get('argv', [])
    data = base64.b64decode(request['input'])
    timeout = request['timeout']
    memory = request['memory_mb']
    result = bounded(command, timeout, data, memory)
    sig = -result['exit'] if result['exit'] < 0 else None
    result.update(ok=True, signal=signal.Signals(sig).name if sig else None, faulting_address=None, backtrace=[], exploitability='unknown')
    # Instrumentation is a separate replay, explicitly not the original run.
    if shutil.which('strace'):
        trace = bounded(['strace', '-f', '-qq', '-s', '128', '--'] + command, timeout, data, memory)
        result['strace'] = trace['stderr']
    else:
        result['strace_error'] = 'strace unavailable in sandbox image'
    if sig and shutil.which('gdb'):
        pathlib.Path('/tmp/pwn-input').write_bytes(data)
        # GDB's run uses a shell: quote every argument; --args alone is not sufficient.
        import shlex
        run = 'run ' + ' '.join(shlex.quote(arg) for arg in command[1:]) + ' < /tmp/pwn-input'
        gdb = bounded(['gdb', '-q', '-nx', '-nh', '-batch', '-iex', 'set auto-load off', '-ex', run,
                       '-ex', 'p/x $pc', '-ex', 'bt', '-ex', 'exploitable', '--args', command[0]], timeout, memory=memory)
        text = gdb['stdout'] + gdb['stderr']
        result['gdb'] = text
        match = re.search(r'\$\d+ = (0x[0-9a-f]+)', text)
        result['faulting_address'] = match.group(1) if match else None
        result['backtrace'] = [line for line in text.splitlines() if re.match(r'#\d+\s', line)]
        classification = re.search(r'Exploitability Classification:\s*(\S+)', text)
        result['exploitability'] = classification.group(1) if classification else 'unknown: GDB exploitable plugin unavailable or failed'
    elif sig:
        result['gdb_error'] = 'gdb unavailable in sandbox image'
    return result


def snapshot(request):
    root = pathlib.Path.home() / '.pwn' / 'sandbox_snapshots'
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    target = pathlib.Path(request['binary']).resolve(strict=True)
    if not target.is_file():
        raise ValueError('binary must be a regular file')
    data = target.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    dest = root / uuid.uuid4().hex
    dest.mkdir(mode=0o700)
    (dest / 'target').write_bytes(data)
    (dest / 'target').chmod(0o500)
    (dest / 'manifest.json').write_text(json.dumps({'sha256': digest}))
    return {'ok': True, 'snapshot': str(dest), 'sha256': digest, 'semantics': 'immutable input snapshot; rollback creates a fresh disposable environment, not a live process checkpoint'}


def execute(request):
    backend = request.get('backend', 'docker')
    if backend not in ('docker', 'bwrap') or not shutil.which(backend):
        raise ValueError('sandbox backend unavailable: ' + backend)
    if backend == 'docker':
        probe = bounded(['docker', 'info', '--format', '{{.ServerVersion}}'], 10)
        if probe['exit']:
            raise ValueError('docker backend unavailable: ' + probe['stderr'])
    seconds = float(request.get('timeout', 10))
    memory = int(request.get('memory_mb', 256))
    if not 0 < seconds <= 300 or not 32 <= memory <= 4096:
        raise ValueError('timeout or memory budget out of range')
    argv = request.get('argv', [])
    if not isinstance(argv, list) or not all(isinstance(arg, str) and '\0' not in arg for arg in argv):
        raise ValueError('argv must be an array of strings without NUL')
    binary = pathlib.Path(request['binary']).resolve(strict=True)
    if not binary.is_file():
        raise ValueError('binary must be a regular file')
    with tempfile.TemporaryDirectory(prefix='pwn-sandbox-') as temp:
        artifacts = pathlib.Path(temp)
        shutil.copyfile(binary, artifacts / 'target')
        (artifacts / 'target').chmod(0o555)
        shutil.copyfile(__file__, artifacts / 'worker.py')
        payload = dict(request, timeout=seconds, memory_mb=memory, input=request.get('stdin_base64', base64.b64encode(request.get('stdin', '').encode()).decode()))
        container = 'pwn-sandbox-' + uuid.uuid4().hex
        if backend == 'docker':
            image = request.get('image', 'pwn-sandbox:local')
            if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_./:@-]*', image):
                raise ValueError('invalid image')
            cmd = ['docker', 'run', '--rm', '--pull=never', '--name', container, '-i', '--network=none', '--read-only', '--cap-drop=ALL',
                   '--security-opt=no-new-privileges', '--pids-limit=64', '--memory', str(memory)+'m', '--memory-swap', str(memory)+'m',
                   '--cpus=1', '--user=65534:65534', '--tmpfs=/tmp:rw,nosuid,nodev,size=64m',
                   '--mount', 'type=bind,src='+str(artifacts)+',dst=/artifacts,readonly', '--entrypoint=/usr/bin/python3', image, '-I', '/artifacts/worker.py', '--inside']
            artifacts.chmod(0o755)
        else:
            cmd = ['bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--cap-drop', 'ALL', '--clearenv', '--setenv', 'PATH', '/usr/bin:/bin',
                   '--ro-bind', '/usr', '/usr']
            for name in ('/lib', '/lib64', '/bin', '/sbin'):
                if pathlib.Path(name).exists():
                    cmd += ['--ro-bind', name, name]
            cmd += ['--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--ro-bind', str(artifacts), '/artifacts', '--chdir', '/tmp', '/usr/bin/python3', '-I', '/artifacts/worker.py', '--inside']
        try:
            result = bounded(cmd, seconds * 3 + 10, json.dumps(payload).encode())
        finally:
            if backend == 'docker':
                bounded(['docker', 'rm', '-f', container], 10)
        if result['exit'] or result['timed_out']:
            raise ValueError('sandbox backend failed: ' + result['stderr'])
        response = json.loads(result['stdout'])
        response.update(backend=backend, network='none', artifact_mount='ro', memory_mb=memory, timeout=seconds,
                        isolation_limitations='bwrap uses per-process RLIMIT_AS, not aggregate cgroup memory/pid limits' if backend == 'bwrap' else None)
        return response


def main(request):
    action = request.get('action', 'run')
    if action == 'snapshot':
        return snapshot(request)
    if action == 'rollback':
        path = pathlib.Path(request['snapshot']).resolve(strict=True)
        root = (pathlib.Path.home() / '.pwn' / 'sandbox_snapshots').resolve()
        if path.parent != root:
            raise ValueError('unknown snapshot')
        expected = json.loads((path / 'manifest.json').read_text())['sha256']
        if hashlib.sha256((path / 'target').read_bytes()).hexdigest() != expected:
            raise ValueError('snapshot integrity failure')
        return execute(dict(request, binary=str(path / 'target')))
    if action == 'fuzz':
        minutes = float(request.get('minutes', 1))
        if not 0 < minutes <= 60:
            raise ValueError('minutes must be 0..60')
        corpus = pathlib.Path(request['corpus']).resolve(strict=True)
        seeds = [p.read_bytes()[:65536] for p in sorted(corpus.iterdir()) if p.is_file() and not p.is_symlink()][:256]
        if not seeds:
            raise ValueError('empty corpus')
        rng = random.Random(request.get('seed', 0))
        deadline = time.monotonic() + minutes * 60
        crashes = []
        iterations = 0
        while time.monotonic() < deadline:
            data = bytearray(rng.choice(seeds) or b'\0')
            data[rng.randrange(len(data))] ^= 1 << rng.randrange(8)
            # Preserve byte-exact mutated inputs across the JSON transport.
            result = execute(dict(request, stdin_base64=base64.b64encode(data).decode(), timeout=min(float(request.get('timeout', 2)), max(.01, (deadline-time.monotonic())/3))))
            iterations += 1
            if result.get('signal'):
                crashes.append(dict(result, input_base64=base64.b64encode(data).decode()))
                if len(crashes) >= 16:
                    break
        return {'ok': True, 'backend': request.get('backend', 'docker'), 'iterations': iterations, 'crashes': crashes, 'seed': request.get('seed', 0)}
    return execute(request)


if __name__ == '__main__':
    try:
        request = json.load(sys.stdin)
        response = inside(request) if '--inside' in sys.argv else main(request)
    except Exception as error:
        response = {'ok': False, 'error': str(error)}
    print(json.dumps(response))
