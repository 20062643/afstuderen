require 'net/http'
require_relative '../polarssl'

entropy = PolarSSL::EntropyContext.new
entropy.gather

p entropy

ctr_drbg = PolarSSL::CtrDrbgContext.new(entropy)

p ctr_drbg

sock = TCPSocket.new("www.polarssl.org", 443)

ssl_context = PolarSSL::SSLContext.new
ssl_context.set_bio(sock)
ssl_context.random_number_generator = ctr_drbg
ssl_context.handshake

ssl_context.write("GET / HTTP/1.1\r\nHost: www.polarssl.org\r\n\r\n")

response = ""

ssl_context.read do |chunk|
  response << chunk
  puts chunk
  break if chunk.include?("0\r\n\r\n")
end

sock.close