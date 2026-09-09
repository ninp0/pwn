# frozen_string_literal: true

require 'fileutils'

module PWN
  # This file, using the autoload directive loads Report modules
  # into memory only when they're needed. For more information, see:
  # http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html
  module Reports
    autoload :AIRedTeam, 'pwn/reports/ai_red_team'
    autoload :CSV, 'pwn/reports/csv'
    autoload :Engagement, 'pwn/reports/engagement'
    autoload :Fuzz, 'pwn/reports/fuzz'
    autoload :HTML, 'pwn/reports/html'
    autoload :HTMLFooter, 'pwn/reports/html_footer'
    autoload :HTMLHeader, 'pwn/reports/html_header'
    autoload :JSON, 'pwn/reports/json'
    autoload :Markdown, 'pwn/reports/markdown'
    autoload :PDF, 'pwn/reports/pdf'
    autoload :Phone, 'pwn/reports/phone'
    autoload :SAST, 'pwn/reports/sast'
    autoload :SARIF, 'pwn/reports/sarif'
    autoload :URIBuster, 'pwn/reports/uri_buster'
    autoload :XML, 'pwn/reports/xml'

    public_class_method def self.resolve_path(opts = {})
      path = opts[:path].to_s
      ext = opts[:ext].to_s.sub(/\A\./, '')
      unless path.empty?
        FileUtils.mkdir_p(File.dirname(path)) unless File.dirname(path).to_s.empty? || File.dirname(path) == '.'
        return path
      end

      dir = opts[:dir_path].to_s
      dir = '.' if dir.empty?
      FileUtils.mkdir_p(dir)
      name = opts[:report_name].to_s
      name = File.basename(Dir.pwd) if name.empty?
      File.join(dir, "#{name}.#{ext}")
    end

    public_class_method def self.report_payload(opts = {})
      raw = opts[:results_hash]
      raw = {} unless raw.is_a?(Hash)
      title = (
        opts[:title] ||
        raw[:title] || raw['title'] ||
        raw[:report_name] || raw['report_name'] ||
        'PWN Report'
      ).to_s
      summary = (
        opts[:executive_summary] ||
        raw[:executive_summary] || raw['executive_summary']
      ).to_s
      findings = raw[:findings] || raw['findings'] || raw[:data] || raw['data'] || []
      findings = [] unless findings.is_a?(Array)
      {
        title: title,
        executive_summary: summary,
        findings: findings.map { |row| stringify_keys(hash: row) },
        attack_chains: attack_chains(findings: findings),
        raw: raw
      }
    end

    # Connected explicit references only; references never imply a severity boost.
    public_class_method def self.attack_chains(opts = {})
      rows = Array(opts[:findings]).map { |row| stringify_keys(hash: row) }
      by_id = rows.to_h { |row| [row['id'].to_s, row] }
      adjacency = Hash.new { |hash, key| hash[key] = [] }
      rows.each do |row|
        id = row['id'].to_s
        refs = Array(row['attack_chain_refs'] || row['chain_refs'] || row['chain_parent_id'])
        refs.each do |ref|
          ref = ref.to_s
          next if id.empty? || ref == id || !by_id.key?(ref)
          next unless row['engagement_id'].to_s == by_id[ref]['engagement_id'].to_s

          adjacency[id] << ref
          adjacency[ref] << id
        end
      end
      seen = []
      adjacency.keys.sort.filter_map do |id|
        next if seen.include?(id)

        group = []
        pending = [id]
        until pending.empty?
          current = pending.shift
          next if group.include?(current)

          group << current
          pending.concat(adjacency[current])
        end
        seen.concat(group)
        ranks = %w[info low medium high critical]
        severity = group.map { |key| by_id[key]['severity'].to_s }.max_by { |value| ranks.index(value) || -1 }
        { finding_ids: group.sort, combined_severity: severity,
          rationale: 'Maximum recorded constituent severity. No automatic escalation; linking is not proof of combined exploitability.' }
      end
    end

    private_class_method def self.stringify_keys(opts = {})
      hash = opts[:hash]
      return { 'value' => hash.to_s } unless hash.is_a?(Hash)

      hash.each_with_object({}) do |(key, val), acc|
        acc[key.to_s] = val
      end
    end

    public_class_method def self.authors
      "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
    end

    public_class_method def self.help
      puts "USAGE:
        # Run resolve path and return its result
        #{self}.resolve_path(
          path: 'required - filesystem path to read or write',
          ext: 'optional - ext value consumed by #resolve_path',
          dir_path: 'optional - dir path value consumed by #resolve_path',
          report_name: 'optional - report name value consumed by #resolve_path'
        )

        # Compose explicit same-engagement references; never invent severity escalation.
        #{self}.attack_chains(findings: 'required - Array of finding hashes')

        # Run report payload and return its result
        #{self}.report_payload(
          results_hash: 'optional - results hash value consumed by #report_payload',
          title: 'optional - title value consumed by #report_payload',
          executive_summary: 'optional - executive summary value consumed by #report_payload'
        )

        # Print the AUTHOR(S) string for this module.
        #{self}.authors
      "
      constants.sort
    end
  end
end
