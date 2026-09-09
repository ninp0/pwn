---
name: pwn-plugins-capabilitybroker-daemon
description: Drive PWN::Plugins::CapabilityBroker::Daemon from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::CapabilityBroker::Daemon
  source: pwn/plugins/capability_broker/daemon.rb
---

# PWN::Plugins::CapabilityBroker::Daemon

Linux-only, bounded network capability service. Never acquires privileges.

## When to use

Call `PWN::Plugins::CapabilityBroker::Daemon` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/capability_broker/daemon.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::CapabilityBroker::Daemon.help
PWN::Plugins::CapabilityBroker::Daemon.dispatch(opts)
```

## Public methods

- `dispatch`
- `serve_client`
- `run`
- `main`
- `authors`
- `help`

## Source

`pwn/plugins/capability_broker/daemon.rb`

## Verification

`PWN::Plugins::CapabilityBroker::Daemon.respond_to?(:dispatch)` after the
module is loaded. Read the source for parameter names.
