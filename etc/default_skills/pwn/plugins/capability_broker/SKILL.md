---
name: pwn-plugins-capabilitybroker
description: Drive PWN::Plugins::CapabilityBroker from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::CapabilityBroker
  source: pwn/plugins/capability_broker.rb
---

# PWN::Plugins::CapabilityBroker

Bounded, peer-authenticated client; never starts or elevates the helper.

## When to use

Call `PWN::Plugins::CapabilityBroker` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/capability_broker.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::CapabilityBroker.help
PWN::Plugins::CapabilityBroker.request(opts)
```

## Public methods

- `request`
- `authors`
- `help`

## Source

`pwn/plugins/capability_broker.rb`

## Verification

`PWN::Plugins::CapabilityBroker.respond_to?(:request)` after the
module is loaded. Read the source for parameter names.
