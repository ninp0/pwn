# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::REPL do
  describe 'ai.memory pinned engagement block' do
    it 'handles dotted commands locally in AI mode and registers the Pry command' do
      described_class.add_commands
      expect(Pry::Commands.find_command('ai.memory')).not_to be_nil
      expect(described_class).to receive(:pwn_ai_memory_command).with(pry: :fixture, args: %w[edit notes])
      expect(described_class.pwn_ai_dispatch_slash!(request: 'ai.memory edit notes', pry: :fixture)).to be(true)
    end

    it 'edits and reloads session notes without changing the original goal' do
      require 'tmpdir'
      require 'pwn/ai/agent/engagement_memory'
      pi = Struct.new(:config).new(Struct.new(:pwn_ai_session_id).new('memory-fixture'))
      allow(PWN::Sessions).to receive(:load).with(session_id: 'memory-fixture').and_return([{ role: 'user', content: 'original goal' }])
      Dir.mktmpdir do |root|
        out = StringIO.new
        described_class.pwn_ai_memory_command(pry: pi, args: ['edit', 'verified evidence'], root: root, output: out)
        described_class.pwn_ai_memory_command(pry: pi, args: [], root: root, output: out)
        expect(out.string).to include('original goal', 'verified evidence')
        expect(JSON.parse(File.read(File.join(root, 'memory-fixture', 'engagement-memory.json')))['notes']).to eq('verified evidence')
      end
    end
  end

  describe 'ai.profile routing selection' do
    it 'validates and selects a profile without mutating provider defaults' do
      pi = Struct.new(:config).new(Struct.new(:pwn_ai_profile).new)
      env = { ai_profiles: { local: { provider: 'ollama', model: 'fixture' } }, ai: { active: 'openai' } }
      output = StringIO.new
      route = described_class.pwn_ai_profile_command(pry: pi, args: ['local'], env: env, output: output)
      expect(route).to include(provider: :ollama, model: 'fixture')
      expect(pi.config.pwn_ai_profile).to eq('local')
      expect(env[:ai]).to eq(active: 'openai')
      expect { described_class.pwn_ai_profile_command(pry: pi, args: ['missing'], env: env, output: output) }.to raise_error(ArgumentError)
      expect(pi.config.pwn_ai_profile).to eq('local')
    end

    it 'registers and dispatches ai.profile locally' do
      described_class.add_commands
      expect(Pry::Commands.find_command('ai.profile')).not_to be_nil
      expect(described_class).to receive(:pwn_ai_profile_command).with(pry: :fixture, args: ['local'])
      expect(described_class.pwn_ai_dispatch_slash!(request: 'ai.profile local', pry: :fixture)).to be(true)
    end
  end

  it 'launches pwn-ai from a local startup hook without changing ordinary start' do
    stub_const('PWN::Env', { driver_opts: {} })
    allow(PWN::Plugins::MonkeyPatch).to receive(:pry)
    allow(described_class).to receive(:add_commands)
    allow(described_class).to receive(:add_hooks)
    allow(described_class).to receive(:enable_autocomplete)
    allow(described_class).to receive(:refresh_ps1_proc).and_return(proc { '' })
    allow(Pry.config).to receive(:hooks).and_return(Pry::Hooks.new)
    pi = double('pry', config: Pry::Config.new)
    expect(pi).to receive(:run_command).with('pwn-ai')
    expect(Pry).to receive(:start) do |_main, options|
      options.fetch(:hooks).exec_hook(:before_session, StringIO.new, TOPLEVEL_BINDING, pi)
      expect(pi.config.pwn_ai_startup_session_id).to eq('prepared-session')
    end
    described_class.start(ai_session_id: 'prepared-session')
  end

  it 'uses the prepared CLI session rather than creating a second session on activation' do
    described_class.add_commands
    config = Pry::Config.new
    config.pwn_ai_startup_session_id = 'ingested-session'
    pi = double('pry', config: config)
    allow(described_class).to receive(:install_pwn_ai_completer!)
    allow(PWN::ModuleSkills).to receive(:install)
    allow(PWN::Config).to receive(:load_skills)
    allow(PWN::Config).to receive(:load_memory)
    allow(PWN::Memory).to receive(:load).and_return({})
    allow(PWN::Cron).to receive(:list).and_return({})
    expect(PWN::Sessions).not_to receive(:create)
    command = Pry::Commands.find_command('pwn-ai').new(pry_instance: pi, output: StringIO.new)
    command.process
    expect(config.pwn_ai_session_id).to eq('ingested-session')
    expect(config.pwn_ai_startup_session_id).to be_nil
  end

  it 'documents session activation and the profile and pinned memory helpers' do
    expect { described_class.help }.to output(/pwn_ai_activation_session.*pwn_ai_profile_command.*pwn_ai_memory_command/m).to_stdout
  end

  it 'treats CTRL+D as back when pwn-ai is active instead of exiting Pry' do
    described_class.add_commands
    config = Pry::Config.new
    config.pwn_ai = true
    config.pwn_ai_agent = true
    config.pwn_ai_speak = true
    config.color = false
    pi = double('pry', config: config)
    allow(described_class).to receive(:restore_pwn_ai_completer!)
    described_class.leave_special_mode!(pry: pi)
    expect(config.pwn_ai).to eq(false)
    expect(config.pwn_ai_agent).to eq(false)
    expect(config.pwn_ai_speak).to eq(false)
    expect(config.color).to eq(true)
    expect(Pry::Commands.find_command('back')).not_to be_nil
  end

  it 'returns nil from pwn-ai input on EOF so Pry can run the CTRL+D handler' do
    pi = double('pry', config: Pry::Config.new)
    allow(Reline).to receive(:readmultiline).and_return(nil)
    input = described_class::PWNMultiLineInput.new(pi)
    allow(input).to receive(:ensure_tmux_extended_keys)
    expect(input.readline('> ')).to be_nil
  end

  it 'should display information for authors' do
    authors_response = PWN::Plugins::REPL
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Plugins::REPL
    expect(help_response).to respond_to :help
  end

  it 'does not append plan usage to the pwn.ai PS1' do
    src = File.read(described_class.method(:refresh_ps1_proc).source_location.first)
    expect(src).not_to include('plan_usage_glyph')
    expect(src).not_to include('PWN::AI.plan_usage')
    expect(src).to include('current_context_length')
  end

  it 'paints (TRACE) in red on the PS1 when toggle-trace is on, not green (DEBUG)' do
    src = File.read(described_class.method(:refresh_ps1_proc).source_location.first)
    expect(src).to include('pwn_ai_trace')
    expect(src).to include('(TRACE)')
    expect(src).to match(/\\e\[31m.*\(TRACE\)/)
    expect(src).to match(/pwn_ai_trace.*\(TRACE\)/m)
    expect(src).to match(/pwn_ai_debug.*\(DEBUG\)/m)
  end

  it 'formats compact token counts for the PS1 budget' do
    expect(described_class.compact_context_tokens(tokens: 0)).to eq('0')
    expect(described_class.compact_context_tokens(tokens: 26_000)).to eq('26K')
    expect(described_class.compact_context_tokens(tokens: 500_000)).to eq('500K')
  end

  it 'ready_tty! exists and the pwn-ai path resets the TTY before the next PS1' do
    expect(described_class).to respond_to :ready_tty!
    hook = File.read(described_class.method(:add_hooks).source_location.first)
    expect(hook).to match(/ready_tty!/)
    expect(hook).to match(/request\.replace\('nil'\)/)
    reader = File.read(described_class.const_get(:PWNMultiLineInput).instance_method(:readline).source_location.first)
    expect(reader).to match(/ready_tty!/)
  end

  it 'reinstalls generated module skills into ~/.pwn/skills before load_skills on pwn-ai start' do
    src = File.read(described_class.method(:add_commands).source_location.first)
    expect(src).to match(/ModuleSkills\.install/)
    expect(src).to match(/ModuleSkills\.install.*load_skills|install_default_skills.*load_skills/m)
  end

  it 'ready_tty! halts leftover spinner workers so PS1 can redraw without Enter' do
    src = File.read(described_class.method(:ready_tty!).source_location.first)
    expect(src).to match(/halt_all!/)
    expect(described_class.method(:add_hooks).source_location).not_to be_nil
    hook = File.read(described_class.method(:add_hooks).source_location.first)
    expect(hook).to match(/ensure/)
    expect(hook).to match(/ready_tty!/)
    io = StringIO.new
    spin = PWN::Plugins::TTYSpinner.start(output: io, format: :dots)
    worker = spin.pwn_worker_thread
    expect(worker).to be_a(Thread)
    expect(worker.alive?).to eq true
    described_class.ready_tty!(io: io)
    expect(worker.alive?).to eq false
    expect(spin.done?).to eq true
  end

  describe 'pwn-ai completion menus' do
    it 'classifies leading slash as command, other slash as path, else ruby' do
      expect(described_class).to respond_to(:pwn_ai_complete_kind)
      expect(described_class.pwn_ai_complete_kind(line: '/cron')).to eq(:command)
      expect(described_class.pwn_ai_complete_kind(line: '/skills rec')).to eq(:command)
      expect(described_class.pwn_ai_complete_kind(line: 'open /opt/pwn')).to eq(:path)
      expect(described_class.pwn_ai_complete_kind(line: '~/src/foo')).to eq(:path)
      expect(described_class.pwn_ai_complete_kind(line: 'PWN::Plugins::Nmap')).to eq(:ruby)
      expect(described_class.pwn_ai_complete_kind(line: '')).to eq(:ruby)
    end

    it 'completes slash commands including cron/skills/sessions' do
      hits = described_class.pwn_ai_complete(target: '/sk', line: '/sk')
      expect(hits).to include('/skills')
      hits = described_class.pwn_ai_complete(target: '/', line: '/')
      %w[/cron /skills /sessions /memory /debug /trace /back /help /model /learning].each do |cmd|
        expect(hits).to include(cmd)
      end
      hits = described_class.pwn_ai_complete(target: 'li', line: '/cron li')
      expect(hits).to include('list')
      hits = described_class.pwn_ai_complete(target: 'li', line: '/model li')
      expect(hits).to include('list')
      hits = described_class.pwn_ai_complete(target: 'll', line: '/model list ll')
      expect(hits).to include('llms')
    end

    it 'completes host-native paths when slash is not the first character' do
      Dir.mktmpdir('pwn-ai-path') do |dir|
        FileUtils.mkdir_p(File.join(dir, 'alpha'))
        File.write(File.join(dir, 'alpha', 'readme.md'), 'x')
        File.write(File.join(dir, 'bravo.txt'), 'y')
        prefix = File.join(dir, 'a')
        hits = described_class.pwn_ai_complete(
          target: prefix,
          line: "read #{prefix}"
        )
        expect(hits.any? { |h| h.end_with?('/alpha/') || h.end_with?('/alpha') }).to eq true
      end
    end

    it 'installs the completer from pwn-ai and restores Pry Ruby completion on back' do
      src = File.read(described_class.method(:add_commands).source_location.first)
      expect(src).to match(/install_pwn_ai_completer!/)
      expect(src).to match(/restore_pwn_ai_completer!/)
      expect(src).to include("Pry::Commands.create_command 'pwn-ai'")
      expect(src).to include("Pry::Commands.create_command 'back'")
    end

    it 'dispatches matching leading-slash commands locally instead of Loop.run' do
      hook = File.read(described_class.method(:add_hooks).source_location.first)
      expect(hook).to match(/pwn_ai_dispatch_slash!/)
      expect(described_class).to respond_to(:pwn_ai_dispatch_slash!)
    end

    it 'switches the live engine and model via /model without Loop.run' do
      expect(described_class).to respond_to(:pwn_ai_run_model)
      PWN::Env[:ai] ||= {}
      PWN::Env[:ai][:grok] ||= {}
      prev_active = PWN::Env[:ai][:active]
      prev_model = PWN::Env[:ai][:grok][:model]
      allow(described_class).to receive(:persist_ai_selection).and_return(false)
      out = described_class.pwn_ai_run_model(args: %w[grok pwn-ai-test-model])
      expect(PWN::Env[:ai][:active].to_s).to eq('grok')
      expect(PWN::Env[:ai][:grok][:model]).to eq('pwn-ai-test-model')
      expect(out.to_s).to match(/grok/i)
    ensure
      if PWN::Env.is_a?(Hash) && PWN::Env[:ai].is_a?(Hash)
        PWN::Env[:ai][:active] = prev_active if defined?(prev_active)
        PWN::Env[:ai][:grok][:model] = prev_model if defined?(prev_model) && PWN::Env[:ai][:grok].is_a?(Hash)
      end
    end

    it 'lists llm ids from the active provider via /model list llms' do
      expect(described_class).to respond_to(:pwn_ai_list_llms)
      PWN::Env[:ai] ||= {}
      prev_active = PWN::Env[:ai][:active]
      PWN::Env[:ai][:active] = 'grok'
      allow(PWN::AI::Grok).to receive(:get_models).and_return(
        [{ id: 'grok-test-a' }, { id: 'grok-test-b' }]
      )
      ids = described_class.pwn_ai_run_model(args: %w[list llms])
      expect(ids).to eq(%w[grok-test-a grok-test-b])
    ensure
      PWN::Env[:ai][:active] = prev_active if PWN::Env.is_a?(Hash) && PWN::Env[:ai].is_a?(Hash)
    end

    it 'lists OpenAI Codex catalog slugs via /model list llms' do
      PWN::Env[:ai] ||= {}
      prev_active = PWN::Env[:ai][:active]
      PWN::Env[:ai][:active] = 'openai'
      allow(PWN::AI::OpenAI).to receive(:get_models).and_return(
        { models: [{ slug: 'gpt-5.5' }, { slug: 'gpt-6-astra', display_name: 'GPT-6-Astra' }] }
      )
      ids = described_class.pwn_ai_run_model(args: %w[list llms])
      expect(ids).to eq(%w[gpt-5.5 gpt-6-astra])
    ensure
      PWN::Env[:ai][:active] = prev_active if PWN::Env.is_a?(Hash) && PWN::Env[:ai].is_a?(Hash)
    end
  end
end
