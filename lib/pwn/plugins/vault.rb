# frozen_string_literal: true

require 'base64'
require 'openssl'
require 'yaml'
require 'json'
require 'fileutils'

module PWN
  module Plugins
    # Used to encrypt/decrypt configuration files leveraging AES256
    module Vault
      CREDENTIAL_KDF_ITERATIONS = 600_000

      # Returns an authenticated envelope; the caller persists only this value.
      # keyring is an injected OS-keyring reader responding to call(key_id).
      public_class_method def self.seal_credentials(opts = {})
        envelope = { 'version' => 1, 'cipher' => 'aes-256-gcm',
                     'kdf' => opts[:keyring] ? 'keyring' : 'pbkdf2-sha256',
                     'key_id' => opts[:key_id] || 'pwn-ai-credentials',
                     'iterations' => CREDENTIAL_KDF_ITERATIONS,
                     'salt' => Base64.strict_encode64(OpenSSL::Random.random_bytes(16)) }
        cipher = OpenSSL::Cipher.new('aes-256-gcm')
        cipher.encrypt
        cipher.key = credential_key(opts.merge(envelope: envelope))
        envelope['iv'] = Base64.strict_encode64(cipher.random_iv)
        cipher.auth_data = credential_aad(envelope: envelope)
        plaintext = JSON.generate(opts.fetch(:credentials))
        envelope['ct'] = Base64.strict_encode64(cipher.update(plaintext) + cipher.final)
        envelope['tag'] = Base64.strict_encode64(cipher.auth_tag)
        envelope
      end

      # Decrypts in memory only. Does not modify or open any credential file.
      public_class_method def self.open_credentials(opts = {})
        envelope = opts.fetch(:envelope).transform_keys(&:to_s)
        raise ArgumentError, 'Unsupported credential envelope' unless envelope['version'] == 1 && envelope['cipher'] == 'aes-256-gcm'

        cipher = OpenSSL::Cipher.new('aes-256-gcm')
        cipher.decrypt
        cipher.key = credential_key(opts.merge(envelope: envelope))
        cipher.iv = Base64.strict_decode64(envelope.fetch('iv'))
        tag = Base64.strict_decode64(envelope.fetch('tag'))
        raise ArgumentError, 'Invalid credential authentication tag' unless tag.bytesize == 16

        cipher.auth_tag = tag
        cipher.auth_data = credential_aad(envelope: envelope)
        JSON.parse(cipher.update(Base64.strict_decode64(envelope.fetch('ct'))) + cipher.final)
      rescue OpenSSL::Cipher::CipherError, JSON::ParserError
        raise ArgumentError, 'Credential authentication failed'
      end

      private_class_method def self.credential_key(opts = {})
        envelope = opts.fetch(:envelope)
        if envelope['kdf'] == 'keyring'
          reader = opts[:keyring]
          raise ArgumentError, 'OS keyring reader required' unless reader.respond_to?(:call)

          key = reader.call(envelope.fetch('key_id'))
          raise ArgumentError, 'OS keyring must return a 32-byte key' unless key.is_a?(String) && key.bytesize == 32

          return key
        end
        raise ArgumentError, 'Unsupported credential KDF' unless envelope['kdf'] == 'pbkdf2-sha256'

        passphrase = opts[:passphrase].to_s
        raise ArgumentError, 'Credential passphrase required' if passphrase.empty?
        raise ArgumentError, 'Invalid credential KDF iterations' unless envelope['iterations'] == CREDENTIAL_KDF_ITERATIONS

        salt = Base64.strict_decode64(envelope.fetch('salt'))
        raise ArgumentError, 'Invalid credential salt' unless salt.bytesize == 16

        OpenSSL::PKCS5.pbkdf2_hmac(passphrase, salt, CREDENTIAL_KDF_ITERATIONS, 32, 'sha256')
      end

      private_class_method def self.credential_aad(opts = {})
        envelope = opts.fetch(:envelope)
        JSON.generate(envelope.except('ct', 'tag').sort.to_h)
      end

      # Supported Method Parameters::
      # PWN::Plugins::Vault.refresh_encryption_secrets(
      #   file: 'required - file to encrypt with new key and iv',
      #   key: 'required - key to decrypt',
      #   iv: 'required - iv to decrypt'
      # )

      public_class_method def self.refresh_encryption_secrets(opts = {})
        file = opts[:file].to_s.scrub if File.exist?(opts[:file].to_s.scrub)
        key = opts[:key]
        iv = opts[:iv]

        decrypt(
          file: file,
          key: key,
          iv: iv
        )

        create(
          file: file
        )
      rescue ArgumentError
        raise 'ERROR: Incorrect Key or IV.'
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Vault.create(
      #   file: 'required - encrypted file to create',
      #   decryptor_file: 'optional - file to save the key && iv values'
      # )

      public_class_method def self.create(opts = {})
        file = opts[:file].to_s.scrub if File.exist?(opts[:file].to_s.scrub)
        decryptor_file = opts[:decryptor_file]

        cipher = OpenSSL::Cipher.new('aes-256-cbc')
        key = Base64.strict_encode64(cipher.random_key)
        iv = Base64.strict_encode64(cipher.random_iv)

        if decryptor_file
          decryptor_hash = { key: key, iv: iv }
          yaml_decryptor = YAML.dump(decryptor_hash).gsub(/^(\s*):/, '\1')
          File.write(decryptor_file, yaml_decryptor)
          # Change permissions to 400
          File.chmod(0o400, decryptor_file)
        else
          puts 'Please store the Key && IV in a secure location as they are required for decryption.'
          puts "Key: #{key}"
          puts "IV: #{iv}"
        end

        encrypt(
          file: file,
          key: key,
          iv: iv
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Vault.decrypt(
      #   file: 'required - file to decrypt',
      #   key: 'required - key to decrypt',
      #   iv: 'required - iv to decrypt'
      # )

      public_class_method def self.decrypt(opts = {})
        file = opts[:file].to_s.scrub if File.exist?(opts[:file].to_s.scrub)
        key = opts[:key] ||= PWN::Plugins::AuthenticationHelper.mask_password(
          prompt: 'Key'
        )

        iv = opts[:iv] ||= PWN::Plugins::AuthenticationHelper.mask_password(
          prompt: 'IV'
        )

        is_encrypted = file_encrypted?(file: file)
        raise 'ERROR: File is not encrypted.' unless is_encrypted

        cipher = OpenSSL::Cipher.new('aes-256-cbc')
        cipher.decrypt
        cipher.key = Base64.strict_decode64(key)
        cipher.iv = Base64.strict_decode64(iv)

        b64_decoded_file_contents = Base64.strict_decode64(File.read(file).chomp)
        plain_text = cipher.update(b64_decoded_file_contents) + cipher.final

        File.write(file, plain_text)
      rescue ArgumentError
        raise 'ERROR: Incorrect Key or IV.'
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # vault = PWN::Plugins::Vault.dump(
      #   file: 'required - file to dump',
      #   key: 'required - key to decrypt',
      #   iv: 'required - iv to decrypt',
      #   yaml: 'optional - dump as parsed yaml hash (default: true)'
      # )

      public_class_method def self.dump(opts = {})
        file = opts[:file].to_s.scrub if File.exist?(opts[:file].to_s.scrub)
        key = opts[:key] ||= PWN::Plugins::AuthenticationHelper.mask_password(
          prompt: 'Key'
        )

        iv = opts[:iv] ||= PWN::Plugins::AuthenticationHelper.mask_password(
          prompt: 'IV'
        )

        cipher = OpenSSL::Cipher.new('aes-256-cbc')
        cipher.decrypt
        cipher.key = Base64.strict_decode64(key)
        cipher.iv = Base64.strict_decode64(iv)
        bytes = Base64.strict_decode64(File.read(file).chomp)
        plaintext = cipher.update(bytes) + cipher.final
        opts[:yaml] == false ? plaintext : YAML.safe_load(plaintext, permitted_classes: [Symbol], aliases: true, symbolize_names: true)
      rescue ArgumentError
        raise 'ERROR: Incorrect Key or IV.'
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Vault.edit(
      #   file: 'required - file to edit',
      #   key: 'required - key to decrypt',
      #   iv: 'required - iv to decrypt',
      #   editor: 'optional - editor to use (default: "/usr/bin/vim")'
      # )

      public_class_method def self.edit(opts = {})
        file = opts[:file].to_s.scrub if File.exist?(opts[:file].to_s.scrub)
        key = opts[:key] ||= PWN::Plugins::AuthenticationHelper.mask_password(
          prompt: 'Key'
        )

        iv = opts[:iv] ||= PWN::Plugins::AuthenticationHelper.mask_password(
          prompt: 'IV'
        )

        editor = opts[:editor] ||= '/usr/bin/vim'

        raise 'ERROR: Editor not found.' unless File.exist?(editor)

        decrypt(
          file: file,
          key: key,
          iv: iv
        )

        # Get realtive editor in case aliases are used
        relative_editor = File.basename(editor)
        system(relative_editor, file)

        # If the Pry object exists, set refresh_config to true
        Pry.config.refresh_pwn_env = true if defined?(Pry)

        encrypt(
          file: file,
          key: key,
          iv: iv
        )
      rescue ArgumentError
        raise 'ERROR: Incorrect Key or IV.'
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Vault.encrypt(
      #   file: 'required - file to encrypt',
      #   key: 'required - key to decrypt',
      #   iv: 'required - iv to decrypt'
      # )

      public_class_method def self.encrypt(opts = {})
        file = opts[:file].to_s.scrub if File.exist?(opts[:file].to_s.scrub)
        key = opts[:key] ||= PWN::Plugins::AuthenticationHelper.mask_password(
          prompt: 'Key'
        )

        iv = opts[:iv] ||= PWN::Plugins::AuthenticationHelper.mask_password(
          prompt: 'IV'
        )

        cipher = OpenSSL::Cipher.new('aes-256-cbc')
        cipher.encrypt
        cipher.key = Base64.strict_decode64(key)
        cipher.iv = Base64.strict_decode64(iv)

        data = File.read(file)
        encrypted = cipher.update(data) + cipher.final
        encrypted_string = Base64.strict_encode64(encrypted)

        File.write(file, "#{encrypted_string}\n")
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Vault.file_encrypted?(
      #   file: 'required - file to check if encrypted'
      # )
      public_class_method def self.file_encrypted?(opts = {})
        file = opts[:file].to_s.scrub if File.exist?(opts[:file].to_s.scrub)

        raise 'ERROR: File does not exist.' unless File.exist?(file)

        file_contents = File.read(file).chomp
        file_contents.is_a?(String) && Base64.strict_encode64(Base64.strict_decode64(file_contents)) == file_contents
      rescue ArgumentError
        false
      rescue StandardError => e
        raise e
      end

      public_class_method def self.store(opts = {})
        label = opts[:label].to_s
        secret = opts[:secret].to_s
        raise 'ERROR: label and secret are required' if label.empty? || secret.empty?

        box = load_box
        box[label] = encrypt_secret(secret: secret)
        save_box(box: box)
        { label: label, stored: true }
      end

      public_class_method def self.fetch(opts = {})
        label = opts[:label].to_s
        raise 'ERROR: label is required' if label.empty?

        row = load_box[label]
        return nil unless row

        decrypt_secret(row: row)
      end

      public_class_method def self.expand(opts = {})
        text = opts[:text].to_s
        text.gsub(/\{\{vault:([^}]+)\}\}/) { fetch(label: Regexp.last_match(1).to_s.strip).to_s }
      end

      public_class_method def self.redact(opts = {})
        text = opts[:text].to_s
        load_box.each do |label, row|
          val = decrypt_secret(row: row).to_s
          next if val.empty?

          text = text.gsub(val, "{{vault:#{label}}}")
        end
        text
      end

      private_class_method def self.key_path
        File.join(Dir.home, '.pwn-vault.key')
      end

      private_class_method def self.box_path
        File.join(Dir.home, '.pwn', 'vault-secrets.json')
      end

      private_class_method def self.master_key(opts = {})
        _n = opts[:n]
        path = key_path
        unless File.file?(path)
          File.binwrite(path, OpenSSL::Random.random_bytes(32))
          File.chmod(0o600, path)
        end
        File.binread(path)
      end

      private_class_method def self.encrypt_secret(opts = {})
        cipher = OpenSSL::Cipher.new('aes-256-gcm')
        cipher.encrypt
        cipher.key = master_key
        iv = cipher.random_iv
        cipher.auth_data = 'pwn-vault'
        ct = cipher.update(opts[:secret].to_s) + cipher.final
        { iv: Base64.strict_encode64(iv), ct: Base64.strict_encode64(ct), tag: Base64.strict_encode64(cipher.auth_tag) }
      end

      private_class_method def self.decrypt_secret(opts = {})
        row = opts[:row]
        return '' unless row.is_a?(Hash)

        cipher = OpenSSL::Cipher.new('aes-256-gcm')
        cipher.decrypt
        cipher.key = master_key
        cipher.iv = Base64.strict_decode64(row[:iv] || row['iv'].to_s)
        cipher.auth_tag = Base64.strict_decode64(row[:tag] || row['tag'].to_s)
        cipher.auth_data = 'pwn-vault'
        cipher.update(Base64.strict_decode64(row[:ct] || row['ct'].to_s)) + cipher.final
      end

      private_class_method def self.load_box(opts = {})
        return {} unless opts.is_a?(Hash)
        return {} unless File.file?(box_path)

        JSON.parse(File.read(box_path))
      rescue StandardError
        {}
      end

      private_class_method def self.save_box(opts = {})
        FileUtils.mkdir_p(File.dirname(box_path))
        File.write(box_path, JSON.pretty_generate(opts[:box] || {}))
        File.chmod(0o600, box_path)
      end

      # Author(s):: 0day Inc. <support@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <support@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          # Seal credentials in an authenticated AES256GCM envelope, without filesystem access.
          #{self}.seal_credentials(
            credentials: 'required - JSON-compatible credentials hash',
            passphrase: 'optional - required unless keyring is supplied',
            keyring: 'optional - callable OS keyring reader returning a raw 32-byte key',
            key_id: 'optional - keyring identifier, default pwn-ai-credentials'
          )
          # Open an authenticated envelope in memory; never writes plaintext.
          #{self}.open_credentials(
            envelope: 'required - sealed credentials hash',
            passphrase: 'optional - required for passphrase envelopes',
            keyring: 'optional - callable OS keyring reader for keyring envelopes'
          )
          # Run refresh encryption secrets and return its result
          #{self}.refresh_encryption_secrets(
            file: 'required - file to encrypt with new key and iv',
            key: 'required - key to decrypt',
            iv: 'required - iv to decrypt'
          )

          # Run create and return its result
          #{self}.create(
            file: 'required - encrypted file to create',
            decryptor_file: 'optional - file to save the key && iv values'
          )

          # Run decrypt and return its result
          #{self}.decrypt(
            file: 'required - file to decrypt',
            key: 'required - key to decrypt',
            iv: 'required - iv to decrypt'
          )

          # Run dump and return its result
          #{self}.dump(
            file: 'required - file to dump',
            key: 'required - key to decrypt',
            iv: 'required - iv to decrypt',
            yaml: 'optional - dump as parsed yaml hash (default: true)'
          )

          # Run edit and return its result
          #{self}.edit(
            file: 'required - file to edit',
            key: 'required - key to decrypt',
            iv: 'required - iv to decrypt',
            editor: 'optional - editor to use (default: /usr/bin/vim)'
          )

          # Run encrypt and return its result
          #{self}.encrypt(
            file: 'required - file to encrypt',
            key: 'required - key to decrypt',
            iv: 'required - iv to decrypt'
          )

          # Run file encrypted and return its result
          #{self}.file_encrypted?(
            file: 'required - file to check if encrypted'
          )

          # Store a secret outside the transcript (AES-GCM; key in ~/.pwn-vault.key).
          #{self}.store(
            label: 'required - vault label',
            secret: 'required - secret value'
          )

          # Fetch a stored secret by label.
          #{self}.fetch(
            label: 'required - vault label'
          )

          # Replace {{vault:label}} tokens with stored secrets.
          #{self}.expand(
            text: 'required - string possibly containing {{vault:label}} tokens'
          )

          # Replace stored secret values with {{vault:label}} placeholders.
          #{self}.redact(
            text: 'required - string that may contain stored secrets'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
