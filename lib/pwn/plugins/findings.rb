# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'securerandom'
require 'digest'

module PWN
  module Plugins
    # Persistent finding rows for pwn-ai (title, severity, host, evidence, PoC).
    module Findings
      FILE = File.join(Dir.home, '.pwn', 'findings.jsonl')

      public_class_method def self.required_bins
        []
      end

      public_class_method def self.record(opts = {})
        title = opts[:title].to_s
        raise 'ERROR: title is required' if title.empty?

        arts = Array(opts[:poc_artifacts]).map(&:to_s).reject(&:empty?)
        if opts[:poc].is_a?(Hash)
          arts << opts[:poc][:path].to_s unless opts[:poc][:path].to_s.empty?
        else
          arts << opts[:poc].to_s unless opts[:poc].to_s.empty?
        end
        raise 'ERROR: poc_artifacts are required' if arts.empty?

        ev = opts[:evidence]
        ev_list = Array(ev).map(&:to_s)
        ev_text = ev_list.join(' ')
        raise 'ERROR: evidence must be at least 40 characters citing the PoC' if ev_text.length < 40

        sha_ev = arts.filter_map do |p|
          next unless File.file?(p)

          Digest::SHA256.file(p).hexdigest
        end
        proven = sha_ev.any?
        row = {
          id: SecureRandom.hex(6),
          title: title,
          severity: proven ? (opts[:severity] || 'info').to_s : 'unproven',
          cvss_vector: (opts[:cvss_vector] || opts[:cvss]).to_s,
          affected_asset: (opts[:affected_asset] || opts[:host]).to_s,
          host: opts[:host].to_s,
          evidence: sha_ev.any? ? sha_ev : ev_list,
          poc: opts[:poc].is_a?(Hash) ? opts[:poc] : { type: 'file', path: arts.first, reproduction_steps: opts[:reproduction_steps].to_s },
          poc_artifacts: arts,
          chain_refs: Array(opts[:chain_refs] || opts[:chain_parent_id]).map(&:to_s).reject(&:empty?),
          cvss: opts[:cvss].to_s,
          status: proven ? (opts[:status] || 'open').to_s : 'unproven',
          engagement_id: opts[:engagement_id].to_s,
          chain_parent_id: opts[:chain_parent_id].to_s,
          session_id: opts[:session_id].to_s,
          at: Time.now.utc.iso8601
        }
        FileUtils.mkdir_p(File.dirname(FILE))
        File.open(FILE, 'a') { |f| f.puts(JSON.generate(row)) }
        evidence_anchor(row: row, arts: arts)
        row
      end

      public_class_method def self.evidence_verify(opts = {})
        eng = (opts[:engagement_id] || opts[:name] || 'default').to_s
        path = File.join(Dir.home, '.pwn', 'engagements', eng, 'evidence.jsonl')
        return { ok: true, rows: 0 } unless File.file?(path)

        mismatches = []
        n = 0
        File.readlines(path).each do |ln|
          row = JSON.parse(ln, symbolize_names: true)
          n += 1
          next unless File.file?(row[:path].to_s)

          sha = Digest::SHA256.file(row[:path]).hexdigest
          mismatches << row[:path] unless sha == row[:sha256].to_s
        end
        { ok: mismatches.empty?, rows: n, mismatches: mismatches }
      end

      public_class_method def self.report(opts = {})
        return [] unless File.file?(FILE)

        rows = File.readlines(FILE).filter_map do |ln|
          JSON.parse(ln, symbolize_names: true)
        rescue JSON::ParserError
          nil
        end
        host = opts[:host].to_s
        rows = rows.select { |r| r[:host].to_s == host } unless host.empty?
        rows
      end

      public_class_method def self.query(opts = {})
        report(opts)
      end

      public_class_method def self.chain(opts = {})
        parent_id = opts[:parent_id].to_s
        raise 'ERROR: parent_id is required' if parent_id.empty?

        child = record(
          opts.merge(
            chain_parent_id: parent_id,
            evidence: (opts[:evidence].to_s.length >= 40 ? opts[:evidence] : 'Chained finding reuses parent PoC evidence and raises composite impact.')
          )
        )
        ranks = { 'info' => 0, 'low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4 }
        parent = report.find { |r| r[:id].to_s == parent_id }
        sev = [parent&.[](:severity), child[:severity]].compact.max_by { |s| ranks[s.to_s] || 0 }
        child.merge(composite_severity: sev)
      end

      public_class_method def self.chain_score(opts = {})
        ids = Array(opts[:ids] || opts[:chain_refs]).map(&:to_s)
        rows = report.select { |r| ids.include?(r[:id].to_s) || ids.include?(r[:chain_parent_id].to_s) }
        rows = report if rows.empty? && ids.empty?
        ranks = { 'info' => 0, 'low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4, 'unproven' => 0 }
        peak = rows.map { |r| ranks[r[:severity].to_s] || 0 }.max || 0
        linked = rows.length >= 2
        sev = if linked && peak >= 2
                'critical'
              else
                %w[info low medium high critical][peak] || 'info'
              end
        { chain_refs: rows.map { |r| r[:id] }, score: sev, combined_severity: sev, n: rows.length }
      end

      public_class_method def self.render(opts = {})
        dir = opts[:dir_path].to_s
        dir = File.join(Dir.home, '.pwn', 'exports') if dir.empty?
        name = opts[:report_name].to_s
        name = 'findings' if name.empty?
        payload = { title: 'Findings', findings: report }
        {
          markdown: PWN::Reports::Markdown.generate(results_hash: payload, dir_path: dir, report_name: name),
          html: PWN::Reports::HTML.generate(results_hash: payload, dir_path: dir, report_name: name),
          json: PWN::Reports::JSON.generate(results_hash: payload, dir_path: dir, report_name: name),
          sarif: PWN::Reports::SARIF.generate(results_hash: payload, dir_path: dir, report_name: name)
        }
      end

      private_class_method def self.evidence_anchor(opts = {})
        row = opts[:row]
        arts = Array(opts[:arts])
        eng = (row[:engagement_id] || 'default').to_s
        dir = File.join(Dir.home, '.pwn', 'engagements', eng)
        FileUtils.mkdir_p(dir)
        path = File.join(dir, 'evidence.jsonl')
        arts.each do |art|
          next unless File.file?(art.to_s)

          rec = {
            ts: Time.now.utc.iso8601,
            finding_id: row[:id],
            path: art,
            sha256: Digest::SHA256.file(art).hexdigest,
            size: File.size(art)
          }
          File.open(path, 'a') { |f| f.puts(JSON.generate(rec)) }
        end
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Append a finding row to ~/.pwn/findings.jsonl.
          #{self}.record(
            title: 'required - short finding title',
            severity: 'optional - info|low|medium|high|critical (defaults to info)',
            host: 'optional - affected host or URL',
            evidence: 'optional - proof text or path',
            poc: 'optional - filesystem path of a PoC or Hash with type/path/reproduction_steps',
            poc_artifacts: 'required - Array of artifact paths proving the issue',
            cvss: 'optional - CVSS vector or score string',
            cvss_vector: 'optional - CVSS 3.1 vector string (defaults to cvss)',
            affected_asset: 'optional - host or URL the finding applies to (defaults to host)',
            reproduction_steps: 'optional - how to replay the PoC',
            chain_refs: 'optional - Array of related finding ids',
            status: 'optional - open|closed (defaults to open)',
            engagement_id: 'optional - engagement identifier',
            session_id: 'optional - pwn-ai session id',
            chain_parent_id: 'optional - id of a parent finding this issue chains from'
          )

          # Alias of report for querying stored findings.
          #{self}.query(
            host: 'optional - affected host or URL'
          )

          # Record a child finding chained to a parent and return composite severity.
          #{self}.chain(
            parent_id: 'required - id of the parent finding',
            title: 'required - short finding title',
            severity: 'optional - info|low|medium|high|critical (defaults to info)',
            poc_artifacts: 'required - Array of artifact paths proving the issue',
            host: 'optional - affected host or URL',
            session_id: 'optional - pwn-ai session id'
          )

          # List recorded findings, optionally filtered by host.
          #{self}.report(
            host: 'optional - only rows whose host matches this string'
          )

          # Render findings as markdown, html, json, and SARIF reports.
          #{self}.render(
            dir_path: 'optional - output directory (defaults to ~/.pwn/exports)',
            report_name: 'optional - basename without extension (defaults to findings)'
          )

          # Re-hash evidence files and report tampering.
          #{self}.evidence_verify(
            engagement_id: 'optional - engagement name (defaults to default)',
            name: 'optional - alias for engagement_id'
          )

          # Recompute combined severity for chained findings.
          #{self}.chain_score(
            ids: 'optional - Array of finding ids to score together',
            chain_refs: 'optional - alias for ids'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
