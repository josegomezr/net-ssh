module Net
  module SSH
    # A lightweight SSH Signature described in openssh/PROTOCOL.sshsig
    class SshSig
      BEGIN_ARMOR = '-----BEGIN SSH SIGNATURE-----'.freeze
      END_ARMOR = '-----END SSH SIGNATURE-----'.freeze
      MAGIC_PREAMBLE = 'SSHSIG'.freeze
      SIG_VERSION = 0x01 # defined in openssh/PROTOCOL.sshsig

      # ssh-keygen does not allow you to select the hashing algorithm
      #
      # ssh-keytype => [digester, signer]
      ALLOWED_SIGN_ALGOS = {
        "ssh-rsa" => ["sha512", "rsa-sha2-512"],
        "ssh-ed25519" => ["sha512", "ssh-ed25519"]
      }

      def initialize(key)
        signature_params = ALLOWED_SIGN_ALGOS[key.ssh_type]

        raise "Unknown signature algorithm for key-type #{key.ssh_type}" unless signature_params

        unless [
            OpenSSL::PKey::RSA,
            Authentication::ED25519::PrivKey
          ].include?(key.class)
          raise 'unsupported key type'
        end

        @key = key
        @hash_algo, @sign_algo = signature_params
      end

      def sign(namespace, data, as_armor: false)
        raise "Can't sign with a public key" unless @key.private?

        digest = digester_klass(@hash_algo).digest(data)

        signing_buffer = build_signing_buffer(namespace, @hash_algo, digest)

        signed_message = @key.ssh_do_sign(signing_buffer.to_s, @sign_algo)

        signature_buffer = Buffer.from(
          :string, @sign_algo,
          :string, signed_message
        )

        message_buffer = Buffer.from(
          :raw, MAGIC_PREAMBLE,
          :long, SIG_VERSION,
          :string, @key.public_key.to_blob,
          :string, namespace,
          :long, 0x0,
          :string, @hash_algo,
          :string, signature_buffer.to_s
        )

        return make_armor(message_buffer.to_s) if as_armor

        message_buffer.to_s
      end

      def verify(message, expected_namespace, data, from_armor: false, allowed_signers: [])
        if from_armor
          message = message.strip

          raise "Invalid armor signature format" unless message.start_with?(BEGIN_ARMOR)

          raise "Invalid armor signature format" unless message.end_with?(END_ARMOR)

          message = message[(BEGIN_ARMOR.size)..-(END_ARMOR.size + 1)]
          message = Base64.decode64(message)
        end

        public_key = @key.private? ? @key.public_key : @key
        message_buffer = Buffer.new(message)

        # verify preamble
        raise "Couldn't verify signature: invalid format" unless message_buffer.read(MAGIC_PREAMBLE.size) == MAGIC_PREAMBLE

        sig_version = message_buffer.read_long

        # verify signature version
        raise "Signature version #{sig_version} is larger than supported version #{SIG_VERSION}" unless sig_version <= SIG_VERSION

        got_publickey = message_buffer.read_string

        # verify public key
        allowed_signers << public_key.to_blob.to_s if allowed_signers.empty?

        raise "Signature key is not in the allowed signers" unless allowed_signers.include?(got_publickey)

        got_namespace = message_buffer.read_string
        # verify namespace
        raise "Couldn't verify signature: namespace does not match" unless expected_namespace == got_namespace

        message_buffer.read_long # reserved

        hash_algorithm = message_buffer.read_string
        # verify hash algorithm
        raise "Couldn't verify signature: hash algorithm mismatch" unless hash_algorithm == @hash_algo

        signature_blob = message_buffer.read_string
        # check for trailing data
        raise "Signature contains trailing data" unless message_buffer.eof?

        signature_buffer = Buffer.new(signature_blob)
        got_sign_algo = signature_buffer.read_string

        # check signing algorithm
        raise "Couldn't verify signature: unsupported signature algorithm #{got_sign_algo}" unless @sign_algo == got_sign_algo

        digest = digester_klass(hash_algorithm).digest(data)

        expected_signing_buffer = build_signing_buffer(expected_namespace, @hash_algo, digest).to_s

        got_signature = signature_buffer.read_string

        # check ssh signature
        sign_result = public_key.ssh_do_verify(got_signature, expected_signing_buffer.to_s, { host_key: got_sign_algo })

        unless sign_result
          raise "Signature verification failed: invalid signature"
        end

        return true
      end

      private

      def build_signing_buffer(namespace, hash_algo, digest)
        Buffer.from(
          :raw, MAGIC_PREAMBLE,
          :string, namespace,
          :long, 0x0, # reserved as per PROTOCOL.sshsig
          :string, hash_algo,
          :string, digest
        )
      end

      # SSHSig only allows sha256 & sha512 digests
      def digester_klass(hash_algo)
        case hash_algo
        when "sha512"
          OpenSSL::Digest::SHA512
        when "sha256"
          OpenSSL::Digest::SHA256
        else
          raise "Hashing algorithm '#{hash_algo}' not allowed"
        end
      end

      def make_armor(signature)
        # we wrap at 70 chars as ssh-keygen does although the
        # protocol says it SHOULD be 76 chars.
        result = Base64.strict_encode64(signature)
                       .chars.each_slice(70)
                       .map(&:join).join("\n")

        [BEGIN_ARMOR, result, END_ARMOR].join("\n")
      end
    end
  end
end
