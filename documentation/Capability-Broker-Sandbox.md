# Capability broker and disposable sandbox

## pwn-capd (P8)

The Python stdlib helper speaks one bounded JSON request per Unix connection.
Linux SO_PEERCRED authenticates the configured caller UID; the client also
checks the daemon UID. The socket is mode 0600. Only explicitly configured
interfaces are accepted. Operations: `status`, `raw_send` (base64 Ethernet
frame), `capture` (bounded in-memory pcap), `arp` / `nd` (typed IP kernel
neighbor-cache queries). There is no command endpoint, arbitrary privileged
output path, firewall mutation, or implicit sudo. ARP/ND currently query cache;
they do not actively solicit neighbors or mutate entries.

Operator installation (NOT executed by the application): install
`lib/pwn/plugins/capability_broker/daemon.py` (not the Ruby packaging driver)
root-owned under `/usr/local/libexec/pwn-capd`, mode 0755, in a root-owned
non-writable directory. Do **not** setcap the system Ruby/Python interpreter
or this script: Linux ignores script file capabilities, and granting a shared
interpreter network privileges exposes every script. Use a dedicated systemd
service with `User=<operator>`,  `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN`,
`CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN`, `NoNewPrivileges=yes`,
`ProtectSystem=strict`, `ProtectHome=yes`, `RuntimeDirectory=pwn-capd`,
`RestrictAddressFamilies=AF_UNIX AF_PACKET AF_NETLINK`, and the reviewed helper
as ExecStart. The socket owner and configured peer UID must match that operator.
Enable a preconfigured unit with `sudo systemctl start pwn-capd`.
For an audited one-shot sudo launch use:

```
sudo /usr/local/libexec/pwn-capd --uid "$(id -u)" --interface lo
```

Never authorize unrestricted sudo access to arbitrary helper arguments. Pin
UID, socket and interface in sudoers. Only add engagement interfaces after
operator review. CAP_NET_ADMIN is reserved for future neighbor management;
current operations need CAP_NET_RAW, while neighbor queries are read-only.

Ruby API (explicit require until central autoload is integrated):

```ruby
require 'pwn/plugins/capability_broker'
PWN::Plugins::CapabilityBroker.request(operation: 'status')
PWN::Plugins::CapabilityBroker.request(operation: 'arp', iface: 'lo', address: '127.0.0.1')
PWN::Plugins::CapabilityBroker.request(operation: 'nd', iface: 'lo', address: '::1')
# Packet.send(pkt:, iface:, socket:) and Packet.capture(path:, count:, timeout:, iface:, socket:)
```

`PWN_CAPD_SOCKET` overrides `/run/pwn-capd/control.sock`. Capture artifacts are
written and read back by the unprivileged client, never by the daemon.
Absent broker returns degraded error and missing local CAP_NET_RAW accurately;
there is no fabricated capture path or privileged Ruby remediation.

## Sandbox (P13)

```ruby
require 'pwn/plugins/sandbox'
PWN::Plugins::Sandbox.run(binary: '/path/safe-fixture', argv: [], stdin: '', timeout: 10, memory_mb: 256)
PWN::Plugins::Sandbox.fuzz(target: '/path/safe-fixture', corpus: '/path/seeds', minutes: 1, seed: 0)
s = PWN::Plugins::Sandbox.snapshot(binary: '/path/safe-fixture')
PWN::Plugins::Sandbox.rollback(snapshot: s[:snapshot], backend: 'bwrap')
```

Docker is default, image `pwn-sandbox:local`; it must be provisioned locally,
with `/usr/bin/python3`, strace, GDB, and target runtime libraries. No implicit
pull, installation, daemon startup or host-execution fallback occurs. Use the
included `lib/pwn/plugins/sandbox/Dockerfile` to build explicitly. Network none,
read-only root/artifacts, unprivileged UID, all caps dropped, no-new-privileges,
pid/cpu/memory/swap constraints, disposable bounded tmpfs, forced cleanup.
Instrumentation runs are separate replays with the same input, not observation
of the original execution. Signals, PC, backtrace, raw GDB output are returned;
exploitable classification is `unknown` if the GDB plugin is absent. No invented
classification. Current `-nx` configuration deliberately does not load arbitrary
user GDB startup scripts. Install a reviewed exploitable plugin into the image
and extend its explicit initialization if classification is required.

Explicit `backend: 'bwrap'` works without a Docker daemon where unprivileged
user namespaces are permitted. It exposes only read-only system runtime trees
and target artifact, creates fresh user/network/PID/mount namespaces, and hides
home. It is a **weaker resource tier**: per-process RLIMIT_AS, not an aggregate
cgroup budget or fork-bomb protection. Use Docker/microVM for hostile samples.
No automatic backend fallback. Snapshot/rollback means verified immutable input
copies and fresh disposable environments, **not live process/VM checkpoints**.
Fuzzing is bounded seeded bit-flip stdin mutation, not coverage-guided AFL.

Tools register via `require 'pwn/ai/agent/tools/sandbox'`: `sandbox_run` and
`sandbox_fuzz`; normal Registry discovery finds that file.

Verification:
```
bundle exec rspec spec/lib/pwn/plugins/{packet,capability_broker,sandbox}_spec.rb
python3 spec/lib/pwn/plugins/capd_test.py
python3 spec/lib/pwn/plugins/sandbox_test.py
```

Safe real Docker smoke after explicit provisioning:
```
bundle exec ruby -Ilib -rpwn/plugins/sandbox -e 'p PWN::Plugins::Sandbox.run(binary: "/bin/true")'
```
