require_relative '../polarssl'

entropy = PolarSSL::EntropyContext.new
entropy.gather

ctr_drbg = PolarSSL::CtrDrbgContext.new(entropy)

p ctr_drbg