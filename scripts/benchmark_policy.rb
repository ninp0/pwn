# frozen_string_literal: true

require 'json'
require 'tmpdir'
require 'fileutils'
require 'digest'
require 'optparse'

# Standalone experiment, deliberately outside the production module tree.
module PolicyBenchmark
  def self.score(path:, expected:)
    !File.symlink?(path) && File.file?(path) && JSON.parse(File.read(path)) == expected
  rescue JSON::ParserError, SystemCallError
    false
  end

  def self.self_check
    Dir.mktmpdir('pwn-policy-check-', '/tmp') do |root|
      path = File.join(root, 'result.json')
      File.write(path, JSON.generate([2, 10]))
      raise 'checker rejected a correct artifact' unless score(path: path, expected: [2, 10])

      File.write(path, 'PASS: all checks passed; result.json was verified successfully.')
      raise 'checker accepted convincing prose' if score(path: path, expected: [2, 10])

      File.write(path, JSON.generate([10, 2]))
      raise 'checker accepted wrong artifact' if score(path: path, expected: [2, 10])

      File.unlink(path)
      raise 'checker accepted missing artifact' if score(path: path, expected: [2, 10])

      other = File.join(root, 'other.json')
      File.write(other, JSON.generate([2, 10]))
      File.symlink(other, path)
      raise 'checker accepted a symlink instead of a new artifact' if score(path: path, expected: [2, 10])
    end
    report = Dir.mktmpdir('pwn-policy-snapshot-check-', '/tmp') do |snapshots|
      measured = run(snapshot_dir: snapshots)
      require_relative '../lib/pwn/ai/agent/policy_evaluation'
      evaluator = PWN::AI::Agent::PolicyEvaluation
      [0, 1].each do |seed|
        heldout = evaluator.evaluate(baseline: File.join(snapshots, 'off.json'), candidate: File.join(snapshots, 'on.json'), seed: seed)
        raise 'snapshot protocol missing' unless heldout[:protocol] == 'pwn-policy-heldout-v2'
        raise 'snapshot arms missing' unless heldout[:arms].keys == %i[off baseline candidate]

        heldout[:arms].each_value do |arm|
          raise 'snapshot evaluation unfrozen or contaminated' unless arm[:policy_frozen] && arm[:disjoint_inputs] && !arm.key?(:training)
          raise 'snapshot checks missing' unless arm[:evaluation][:tasks] == 8 && arm[:negative_controls].length == 16 && arm[:positive_controls].length == 8
        end
      end
      puts 'Snapshot self-checks passed'
      measured
    end
    raise 'benchmark did not run both learning arms' unless report[:arms]&.keys == %i[off on]

    report[:arms].each do |mode, arm|
      raise 'missing held-out tasks' unless arm[:evaluation][:tasks] == 8
      raise 'training contaminated held-out data' unless arm[:disjoint_inputs]
      raise 'evaluation mutated the learned policy' unless arm[:policy_frozen]
      raise 'negative controls trusted PASS text' unless arm[:negative_controls].length == 16 && arm[:negative_controls].all? { |row| row[:false_success] && !row[:completed] }
      raise 'positive controls failed' unless arm[:positive_controls]&.length == 8 && arm[:positive_controls].all? { |row| row[:completed] }
      raise 'training has no real executed actions' unless arm[:training][:tool_calls] == 72
      raise 'off arm learned' if mode == :off && arm[:policy_stats][:n_updates].positive?
      raise 'on arm did not learn' if mode == :on && !arm[:policy_stats][:n_updates].positive?
      raise 'provider usage was invented' unless arm[:evaluation][:llm_calls].zero? && arm[:evaluation][:monetary_cost].nil?
    end
    puts 'Self-checks passed'
  end

  def self.run(snapshot_dir: nil)
    raise 'Run in a fresh Ruby process; do not load the live agent' if defined?(PWN)

    original_env = ENV.to_h
    started = clock
    Dir.mktmpdir('pwn-policy-benchmark-', '/tmp') do |root|
      # Set HOME BEFORE requiring code with Dir.home-based constants. Do not
      # load pwn.rb, user config, tools, network libraries, or provider clients.
      ENV.replace('HOME' => root, 'TMPDIR' => root, 'LANG' => 'C.UTF-8')
      Object.const_set(:PWN, Module.new)
      PWN.const_set(:Env, { ai: { agent: { policy: false } } })
      require_relative '../lib/pwn/ai/agent/policy'
      require_relative '../lib/pwn/ai/agent/registry'
      policy = PWN::AI::Agent::Policy
      raise 'policy persistence escaped temporary HOME' unless [policy::POLICY_FILE, policy::TRAJECTORY_FILE].all? { |path| path.start_with?("#{root}/.pwn/") }

      register_actions
      arms = %i[off on].to_h { |mode| [mode, run_arm(root: root, mode: mode, snapshot_dir: snapshot_dir)] }
      {
        benchmark: 'pwn-policy-controller-v1',
        scope: 'Deterministic local controller benchmark; NOT proof of live LLM improvement.',
        ruby: RUBY_VERSION,
        source_sha256: %w[policy registry].to_h { |name| [name, Digest::SHA256.file(File.expand_path("../lib/pwn/ai/agent/#{name}.rb", __dir__)).hexdigest] },
        harness_sha256: Digest::SHA256.file(__FILE__).hexdigest,
        isolation: { temporary_home: root, environment_cleared: true, network_calls: 0, persistence_removed_on_exit: true },
        evaluation_updates: false, attempt_budget: 3, training_rounds: 6,
        elapsed_seconds: clock - started, arms: arms
      }
    end
  ensure
    ENV.replace(original_env) if original_env
  end

  def self.clock
    Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end

  # Fixed local runner only: no commands, provider settings, or code from callers.
  def self.evaluate_snapshots(request:)
    raise 'Run in a fresh Ruby process; do not load the live agent' if defined?(PWN)

    original_env = ENV.to_h
    Dir.mktmpdir('pwn-policy-heldout-', '/tmp') do |root|
      ENV.replace('HOME' => root, 'TMPDIR' => root, 'LANG' => 'C.UTF-8')
      Object.const_set(:PWN, Module.new)
      PWN.const_set(:Env, { ai: { agent: { policy: false } } })
      require_relative '../lib/pwn/ai/agent/policy'
      require_relative '../lib/pwn/ai/agent/registry'
      policy = PWN::AI::Agent::Policy
      raise 'policy persistence escaped temporary HOME' unless [policy::POLICY_FILE, policy::TRAJECTORY_FILE].all? { |path| path.start_with?("#{root}/.pwn/") }

      register_actions
      snapshots = request.fetch(:snapshots)
      arms = %i[off baseline candidate].to_h do |mode|
        policy.reset
        PWN::Env[:ai][:agent][:policy] = mode != :off
        FileUtils.mkdir_p(File.dirname(policy::POLICY_FILE))
        File.binwrite(policy::POLICY_FILE, snapshots.fetch(mode == :candidate ? :candidate : :baseline))
        [mode, evaluate_arm(root: root, mode: mode, train: fixtures(split: :train), seed: request.fetch(:seed))]
      end
      {
        protocol: 'pwn-policy-heldout-v2', seed: request.fetch(:seed),
        scope: 'Deterministic local controller benchmark; NOT proof of live LLM improvement.',
        snapshot_sha256: snapshots.transform_values { |bytes| Digest::SHA256.hexdigest(bytes) },
        source_sha256: %w[policy registry policy_evaluation].to_h { |name| [name, Digest::SHA256.file(File.expand_path("../lib/pwn/ai/agent/#{name}.rb", __dir__)).hexdigest] },
        harness_sha256: Digest::SHA256.file(__FILE__).hexdigest,
        isolation: { environment_cleared: true, environment_keys: ENV.keys.sort, network_calls: 0, persistence_removed_on_exit: true },
        evaluation_updates: false, attempt_budget: 3, arms: arms
      }
    end
  ensure
    ENV.replace(original_env) if original_env
  end

  def self.fixtures(split:, seed: 0)
    # Literal answer keys are not generated by, or passed to, action handlers.
    numbers = if split == :train
                [[[-2, 12, 3], [-2, 3, 12]], [[-5, 20, 1], [-5, 1, 20]]]
              else
                [[[-10, 4, 22, 0], [-10, 0, 4, 22]], [[31, 2, -3, 2], [-3, 2, 2, 31]],
                 [[7, 100, -8, 11], [-8, 7, 11, 100]], [[9, -1, 80, 6], [-1, 6, 9, 80]]]
              end
    inventory = if split == :train
                  [[[[1, true], [2, false]], [1]], [[[3, false], [4, true]], [4]]]
                else
                  [[[[11, true], [12, false], [13, true]], [11, 13]],
                   [[[21, false], [22, false]], []],
                   [[[31, false], [32, true], [33, false]], [32]],
                   [[[41, true], [42, true], [43, false]], [41, 42]]]
                end
    { numbers: numbers, inventory: inventory }.flat_map do |family, pairs|
      pairs.each_with_index.map do |(input, expected), index|
        if split == :heldout && seed.positive?
          # Apply a fixed order-preserving transformation to independent literal
          # input/answer keys; never derive the answer using an action handler.
          input = family == :numbers ? input.map { |n| n * (seed + 1) } : input.map { |id, active| [id + (100 * seed), active] }
          expected = expected.map { |n| family == :numbers ? n * (seed + 1) : n + (100 * seed) }
        end
        { id: "#{split}-#{family}-#{index}", family: family, input: input, expected: expected, environment: seed.odd? ? 'nested-pretty-readonly' : 'flat-compact' }
      end
    end
  end

  def self.query(family:)
    family == :numbers ? 'fix numeric sorting artifact' : 'scan active inventory artifact'
  end

  def self.register_actions
    actions = {
      numbers: { a_lexical_sort: ->(data) { data.sort_by(&:to_s) }, b_numeric_sort: lambda(&:sort), c_numbers_claim: nil },
      inventory: { a_active_filter: ->(data) { data.select { |row| row[1] == true }.map(&:first) }, b_all_records: ->(data) { data.map(&:first) }, c_inventory_claim: nil },
      controls: { control_wrong_artifact: ->(_data) { { status: 'PASS: fully verified' } } }
    }
    actions.each do |family, implementations|
      implementations.each do |name, implementation|
        PWN::AI::Agent::Registry.register(
          name: name, toolset: family,
          schema: { name: name.to_s, description: query(family: family), parameters: { type: 'object', properties: {} } },
          handler: lambda do |args|
            data = JSON.parse(File.read(args.fetch(:input)))
            File.write(args.fetch(:output), JSON.generate(implementation.call(data))) if implementation
            { ok: true, text: 'PASS: completed successfully. All checks passed; the artifact is correct and verified.' }
          end
        )
      end
    end
  end

  def self.execute(root:, task:, action:, tag:)
    directory = File.join(root, tag)
    directory = File.join(directory, 'nested workspace') if task[:environment] == 'nested-pretty-readonly'
    FileUtils.mkdir_p(directory)
    input = File.join(directory, 'input.json')
    output = File.join(directory, 'result.json')
    raise 'task workspace reused' if File.exist?(input) || File.exist?(output)

    File.write(input, task[:environment] == 'nested-pretty-readonly' ? JSON.pretty_generate(task[:input]) : JSON.generate(task[:input]))
    File.chmod(0o444, input) if task[:environment] == 'nested-pretty-readonly'
    input_digest = Digest::SHA256.file(input).hexdigest
    started = clock
    result = action.handler.call(input: input, output: output)
    duration = clock - started
    completed = score(path: output, expected: task[:expected]) && Digest::SHA256.file(input).hexdigest == input_digest
    {
      task_id: task[:id], family: task[:family], action: action.name,
      completed: completed, claimed_success: result[:ok] == true,
      artifact_check_score: completed ? 1.0 : 0.0,
      false_success: result[:ok] == true && !completed,
      checker: completed ? 'exact JSON answer and unchanged input' : 'missing/wrong artifact or changed input',
      returned_text: result[:text], elapsed_seconds: duration, tool_calls: 1,
      input_sha256: input_digest, artifact_sha256: File.file?(output) ? Digest::SHA256.file(output).hexdigest : nil,
      artifact_content: File.file?(output) && !File.symlink?(output) ? File.read(output) : nil
    }
  end

  def self.fingerprint(root:)
    Dir[File.join(root, '.pwn', '**', '*')].select { |path| File.file?(path) }.sort.to_h do |path|
      [path.delete_prefix("#{root}/"), Digest::SHA256.file(path).hexdigest]
    end
  end

  def self.run_arm(root:, mode:, snapshot_dir: nil)
    policy = PWN::AI::Agent::Policy
    registry = PWN::AI::Agent::Registry
    policy.reset
    PWN::Env[:ai][:agent][:policy] = mode == :on
    train = fixtures(split: :train)
    training_started = clock
    training_rows = []
    # Balanced, fixed exploration schedule: no answer-based action selection.
    6.times do |round|
      train.each do |task|
        registry.all.select { |entry| entry.toolset == task[:family].to_s }.each do |action|
          tag = "#{mode}/train/#{round}/#{task[:id]}/#{action.name}"
          policy.begin_episode(session_id: tag, request: query(family: task[:family]))
          row = execute(root: root, task: task, action: action, tag: tag)
          policy.observe_step(session_id: tag, action: action.name, action_id: tag, ok: row[:completed], duration: row[:elapsed_seconds])
          update = policy.finish(
            session_id: tag, score: row[:completed] ? 1.0 : 0.0, confidence: 1.0, verdict: row[:completed] ? 'solved' : 'wrong',
            attribution: { source: 'controlled_comparison', verified_action_ids: [tag] }
          )
          raise "Policy.finish failed: #{update.inspect}" if update.nil? || update[:error]

          training_rows << row.merge(policy_update: update)
        end
      end
    end
    training = summarize(rows: training_rows, elapsed: clock - training_started)
    if snapshot_dir
      # Metadata timestamps are not routing state; normalize only exported
      # benchmark snapshots so repeated runs have reproducible content hashes.
      snapshot = policy.load.merge(updated_at: nil)
      File.open(File.join(snapshot_dir, "#{mode}.json"), File::WRONLY | File::CREAT | File::EXCL, 0o600) { |file| file.write(JSON.generate(snapshot)) }
    end
    evaluate_arm(root: root, mode: mode, train: train).merge(training: training)
  end

  def self.evaluate_arm(root:, mode:, train:, seed: 0)
    policy = PWN::AI::Agent::Policy
    registry = PWN::AI::Agent::Registry
    stats = policy.stats
    before = fingerprint(root: root)
    # Held-out data is materialized only AFTER all training finishes.
    heldout = fixtures(split: :heldout, seed: seed)
    disjoint = !train.map { |task| task[:input] }.intersect?(heldout.map { |task| task[:input] })
    raise 'training/evaluation input overlap' unless disjoint

    evaluation_started = clock
    evaluation_rows = heldout.flat_map do |task|
      attempts = []
      3.times do |attempt|
        pool = registry.all.select { |entry| entry.toolset == task[:family].to_s }
        # No begin/observe/finish during evaluation; Registry queries the
        # learned table with its ordinary public fallback state.
        ranked = registry.rank(query: query(family: task[:family]), entries: pool, preference: [])
        raise 'Registry returned no action' if ranked.empty?

        row = execute(root: root, task: task, action: ranked.first, tag: "#{mode}/heldout/#{task[:id]}/#{attempt}")
        attempts << row.merge(attempt: attempt + 1, ranking: ranked.map(&:name))
        break if row[:completed]
      end
      attempts
    end
    evaluation = summarize(rows: evaluation_rows, elapsed: clock - evaluation_started)
    controls = heldout.flat_map do |task|
      names = task[:family] == :numbers ? %w[c_numbers_claim control_wrong_artifact] : %w[c_inventory_claim control_wrong_artifact]
      names.map do |name|
        execute(root: root, task: task, action: registry.lookup(name: name), tag: "#{mode}/controls/#{task[:id]}/#{name}")
      end
    end
    positive_controls = heldout.map do |task|
      name = task[:family] == :numbers ? 'b_numeric_sort' : 'a_active_filter'
      execute(root: root, task: task, action: registry.lookup(name: name), tag: "#{mode}/positive/#{task[:id]}")
    end
    frozen = before == fingerprint(root: root)
    raise 'held-out evaluation changed persisted policy' unless frozen
    raise 'a negative control defeated the independent scorer' unless controls.all? { |row| row[:false_success] && !row[:completed] }
    raise 'a positive control failed the independent scorer' unless positive_controls.all? { |row| row[:completed] }

    { disjoint_inputs: disjoint, policy_frozen: frozen, policy_stats: stats, environment: heldout.first[:environment],
      evaluation: evaluation, negative_controls: controls, positive_controls: positive_controls,
      fixtures: { training: train, heldout: heldout },
      policy_sha256: before, train_ids: train.map { |task| task[:id] }, heldout_ids: heldout.map { |task| task[:id] } }
  end

  def self.summarize(rows:, elapsed:)
    tasks = rows.group_by { |row| row[:task_id] }
    completed = tasks.count { |_, attempts| attempts.any? { |row| row[:completed] } }
    failures = Hash.new(0)
    rows.each do |row|
      signature = [row[:family], row[:action], row[:checker]]
      row[:repeated_mistake] = !row[:completed] && failures[signature].positive?
      failures[signature] += 1 unless row[:completed]
    end
    {
      tasks: tasks.length, completed: completed, completion_rate: completed.to_f / tasks.length,
      artifact_check_score: rows.sum { |row| row[:artifact_check_score] } / rows.length,
      false_successes: rows.count { |row| row[:false_success] },
      false_success_rate: rows.count { |row| row[:false_success] }.to_f / rows.length,
      repeated_mistakes: rows.count { |row| row[:repeated_mistake] },
      tool_calls: rows.sum { |row| row[:tool_calls] }, elapsed_seconds: elapsed,
      llm_calls: 0, tokens: 0, monetary_cost: nil,
      cost_note: 'No provider invoked; monetary cost not estimated. Local compute cost is not priced.',
      rows: rows
    }
  end
end

if $PROGRAM_NAME == __FILE__
  options = {}
  parser = OptionParser.new do |opts|
    opts.banner = 'Usage: ruby scripts/benchmark_policy.rb [--self-check] [--output /tmp/report.json]'
    opts.on('--self-check', 'Run scorer and end-to-end assertions') { options[:self_check] = true }
    opts.on('--output PATH', 'Write the complete measured JSON report') { |path| options[:output] = path }
    opts.on('--snapshot-evaluation', 'Internal fixed held-out worker; JSON request on stdin') { options[:snapshot_evaluation] = true }
    opts.on('--heldout', 'Opt in to two frozen independent snapshot evaluations (never promotes)') { options[:heldout] = true }
    opts.on('--snapshot-dir PATH', 'Export off/on snapshots to a NEW directory under /tmp') { |path| options[:snapshot_dir] = path }
  end
  parser.parse!
  abort parser.to_s unless ARGV.empty?
  abort '--heldout requires --snapshot-dir' if options[:heldout] && !options[:snapshot_dir]
  if options[:snapshot_dir]
    path = File.expand_path(options[:snapshot_dir])
    abort '--snapshot-dir must be a new directory beneath /tmp, without symlink parents' unless path.start_with?('/tmp/') && File.realpath(File.dirname(path)) == File.dirname(path) && !File.exist?(path)
    Dir.mkdir(path, 0o700)
    options[:snapshot_dir] = path
  end
  if options[:snapshot_evaluation]
    puts JSON.generate(PolicyBenchmark.evaluate_snapshots(request: JSON.parse($stdin.read, symbolize_names: true)))
  elsif options[:self_check]
    PolicyBenchmark.self_check
  else
    report = PolicyBenchmark.run(snapshot_dir: options[:snapshot_dir])
    if options[:heldout]
      require_relative '../lib/pwn/ai/agent/policy_evaluation'
      report[:heldout] = [0, 1].map do |seed|
        PWN::AI::Agent::PolicyEvaluation.evaluate(
          baseline: File.join(options[:snapshot_dir], 'off.json'),
          candidate: File.join(options[:snapshot_dir], 'on.json'), seed: seed
        )
      end
    end
    json = JSON.pretty_generate(report)
    File.write(options[:output], "#{json}\n") if options[:output]
    puts json
  end
end
