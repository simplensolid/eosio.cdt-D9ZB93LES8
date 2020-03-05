/**
 *  @file
 *  @copyright defined in eos/LICENSE
 */
#include "core/eosio/crypto.hpp"
#include "core/eosio/datastream.hpp"

extern "C" {
   struct __attribute__((aligned (16))) capi_checksum160 { uint8_t hash[20]; };
   struct __attribute__((aligned (16))) capi_checksum256 { uint8_t hash[32]; };
   struct __attribute__((aligned (16))) capi_checksum512 { uint8_t hash[64]; };
   __attribute__((eosio_wasm_import))
   void assert_sha256( const char* data, uint32_t length, const capi_checksum256* hash );

   __attribute__((eosio_wasm_import))
   void assert_sha1( const char* data, uint32_t length, const capi_checksum160* hash );

   __attribute__((eosio_wasm_import))
   void assert_sha512( const char* data, uint32_t length, const capi_checksum512* hash );

   __attribute__((eosio_wasm_import))
   void assert_ripemd160( const char* data, uint32_t length, const capi_checksum160* hash );

   __attribute__((eosio_wasm_import))
   void sha256( const char* data, uint32_t length, capi_checksum256* hash );

   __attribute__((eosio_wasm_import))
   void sha1( const char* data, uint32_t length, capi_checksum160* hash );

   __attribute__((eosio_wasm_import))
   void sha512( const char* data, uint32_t length, capi_checksum512* hash );

   __attribute__((eosio_wasm_import))
   void ripemd160( const char* data, uint32_t length, capi_checksum160* hash );

   __attribute__((eosio_wasm_import))
   void evm_keccak256( const char* data, uint32_t length, capi_checksum256* hash );

   __attribute__((eosio_wasm_import))
   void evm_ecrecover( const capi_checksum256* digest, const char* sig, size_t siglen, char* pub, size_t publen );

   __attribute__((eosio_wasm_import))
   void evm_bigmodexp( const char* base, uint32_t baselen, const char* exp, uint32_t explen, const char* mod, uint32_t modlen, char *output, size_t outlen );

   __attribute__((eosio_wasm_import))
   void evm_bn256add( const capi_checksum512* point1, const capi_checksum512* point2, capi_checksum512* point3 );

   __attribute__((eosio_wasm_import))
   void evm_bn256scalarmul( const capi_checksum512* point1, const capi_checksum256* scalar, capi_checksum512* point2 );

   __attribute__((eosio_wasm_import))
   bool evm_bn256pairing( const eosio::checksum512* points, uint32_t count );

   __attribute__((eosio_wasm_import))
   void evm_blake2f( const char* data, uint32_t length, capi_checksum512* state, const char* offset, uint32_t offsetlen, uint32_t last, uint32_t rounds );

   __attribute__((eosio_wasm_import))
   int recover_key( const capi_checksum256* digest, const char* sig,
                    size_t siglen, char* pub, size_t publen );

   __attribute__((eosio_wasm_import))
   void assert_recover_key( const capi_checksum256* digest, const char* sig,
                            size_t siglen, const char* pub, size_t publen );

}

namespace eosio {

   void assert_sha256( const char* data, uint32_t length, const eosio::checksum256& hash ) {
      auto hash_data = hash.extract_as_byte_array();
      ::assert_sha256( data, length, reinterpret_cast<const ::capi_checksum256*>(hash_data.data()) );
   }

   void assert_sha1( const char* data, uint32_t length, const eosio::checksum160& hash ) {
      auto hash_data = hash.extract_as_byte_array();
      ::assert_sha1( data, length, reinterpret_cast<const ::capi_checksum160*>(hash_data.data()) );
   }

   void assert_sha512( const char* data, uint32_t length, const eosio::checksum512& hash ) {
      auto hash_data = hash.extract_as_byte_array();
      ::assert_sha512( data, length, reinterpret_cast<const ::capi_checksum512*>(hash_data.data()) );
   }

   void assert_ripemd160( const char* data, uint32_t length, const eosio::checksum160& hash ) {
      auto hash_data = hash.extract_as_byte_array();
      ::assert_ripemd160( data, length, reinterpret_cast<const ::capi_checksum160*>(hash_data.data()) );
   }

   eosio::checksum256 sha256( const char* data, uint32_t length ) {
      ::capi_checksum256 hash;
      ::sha256( data, length, &hash );
      return {hash.hash};
   }

   eosio::checksum160 sha1( const char* data, uint32_t length ) {
      ::capi_checksum160 hash;
      ::sha1( data, length, &hash );
      return {hash.hash};
   }

   eosio::checksum512 sha512( const char* data, uint32_t length ) {
      ::capi_checksum512 hash;
      ::sha512( data, length, &hash );
      return {hash.hash};
   }

   eosio::checksum160 ripemd160( const char* data, uint32_t length ) {
      ::capi_checksum160 hash;
      ::ripemd160( data, length, &hash );
      return {hash.hash};
   }

   eosio::checksum256 evm_keccak256( const char* data, uint32_t length ) {
      ::capi_checksum256 hash;
      ::evm_keccak256( data, length, &hash );
      return {hash.hash};
   }

   eosio::ecc_uncompressed_public_key evm_ecrecover( const eosio::checksum256& digest, const eosio::ecc_signature& sig ) {
      auto digest_data = digest.extract_as_byte_array();
      char pubkey_data[65];
      ::evm_ecrecover( reinterpret_cast<const capi_checksum256*>(digest_data.data()), sig.data(), sig.size(), pubkey_data, sizeof(pubkey_data) );
      eosio::ecc_uncompressed_public_key pubkey;
      eosio::datastream<const char*> pubkey_ds( pubkey_data, sizeof(pubkey_data) );
      pubkey_ds >> pubkey;
      return pubkey;
   }

   void evm_bigmodexp( const char* base, uint32_t baselen, const char* exp, uint32_t explen, const char* mod, uint32_t modlen, char *output, size_t outlen ) {
      ::evm_bigmodexp( base, baselen, exp, explen, mod, modlen, output, outlen );
   }

   eosio::checksum512 evm_bn256add( const eosio::checksum512& point1, const eosio::checksum512& point2 ) {
      auto point1_data = point1.extract_as_byte_array();
      auto point2_data = point2.extract_as_byte_array();
      ::capi_checksum512 point3;
      ::evm_bn256add( reinterpret_cast<const capi_checksum512*>(point1_data.data()), reinterpret_cast<const capi_checksum512*>(point2_data.data()), &point3 );
      return {point3.hash};
   }

   eosio::checksum512 evm_bn256scalarmul( const eosio::checksum512& point1, const eosio::checksum256& scalar ) {
      auto point1_data = point1.extract_as_byte_array();
      auto scalar_data = scalar.extract_as_byte_array();
      ::capi_checksum512 point2;
      ::evm_bn256scalarmul( reinterpret_cast<const capi_checksum512*>(point1_data.data()), reinterpret_cast<const capi_checksum256*>(scalar_data.data()), &point2 );
      return {point2.hash};
   }

   bool evm_bn256pairing( const eosio::checksum512* points, uint32_t count ) {
      return ::evm_bn256pairing( points, count );
   }

   void evm_blake2f( const char* data, uint32_t length, eosio::checksum512& state, const char* offset, uint32_t offsetlen, uint32_t last, uint32_t rounds ) {
      auto state_data = state.extract_as_byte_array();
      ::evm_blake2f( data, length, reinterpret_cast<capi_checksum512*>(state_data.data()), offset, offsetlen, last, rounds );
      state = checksum512(state_data);
   }

   eosio::public_key recover_key( const eosio::checksum256& digest, const eosio::signature& sig ) {
      auto digest_data = digest.extract_as_byte_array();

      auto sig_data = eosio::pack(sig);

      char optimistic_pubkey_data[256];
      size_t pubkey_size = ::recover_key( reinterpret_cast<const capi_checksum256*>(digest_data.data()),
                                          sig_data.data(), sig_data.size(),
                                          optimistic_pubkey_data, sizeof(optimistic_pubkey_data) );

      eosio::public_key pubkey;
      if ( pubkey_size <= sizeof(optimistic_pubkey_data) ) {
         eosio::datastream<const char*> pubkey_ds( optimistic_pubkey_data, pubkey_size );
         pubkey_ds >> pubkey;
      } else {
         constexpr static size_t max_stack_buffer_size = 512;
         void* pubkey_data = (max_stack_buffer_size < pubkey_size) ? malloc(pubkey_size) : alloca(pubkey_size);

         ::recover_key( reinterpret_cast<const capi_checksum256*>(digest_data.data()),
                        sig_data.data(), sig_data.size(),
                        reinterpret_cast<char*>(pubkey_data), pubkey_size );
         eosio::datastream<const char*> pubkey_ds( reinterpret_cast<const char*>(pubkey_data), pubkey_size );
         pubkey_ds >> pubkey;

         if( max_stack_buffer_size < pubkey_size ) {
            free(pubkey_data);
         }
      }
      return pubkey;
   }

   void assert_recover_key( const eosio::checksum256& digest, const eosio::signature& sig, const eosio::public_key& pubkey ) {
      auto digest_data = digest.extract_as_byte_array();

      auto sig_data = eosio::pack(sig);
      auto pubkey_data = eosio::pack(pubkey);

      ::assert_recover_key( reinterpret_cast<const capi_checksum256*>(digest_data.data()),
                            sig_data.data(), sig_data.size(),
                            pubkey_data.data(), pubkey_data.size() );
   }

}
