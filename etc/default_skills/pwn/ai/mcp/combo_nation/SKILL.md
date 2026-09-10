---
name: pwn-ai-mcp-combonation
description: Drive PWN::AI::MCP::ComboNation from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::MCP::ComboNation
  source: pwn/ai/mcp/combo_nation.rb
---

# PWN::AI::MCP::ComboNation

JSON-RPC 2.0 / MCP 2024-11-05 stdio client for combo.nation. Speaks the native menu-oriented tools over newline-delimited JSON; it does not scrape a terminal or enable hardware unless requested.

## When to use

Call `PWN::AI::MCP::ComboNation` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/mcp/combo_nation.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::MCP::ComboNation.help
PWN::AI::MCP::ComboNation.required_bins(opts)
```

## Public methods

- `required_bins`
- `argv`
- `connect`
- `disconnect`
- `request`
- `notify`
- `ping`
- `list_tools`
- `call_tool`
- `menu_catalog`
- `menu_main`
- `menu_dial_calibration`
- `menu_guess`
- `hardware_connect`
- `operation_status`
- `operation_answer`
- `operation_cancel`
- `servo_pause`
- `poll_until`
- `authors`
- `help`

## Source

`pwn/ai/mcp/combo_nation.rb`

## Verification

`PWN::AI::MCP::ComboNation.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
