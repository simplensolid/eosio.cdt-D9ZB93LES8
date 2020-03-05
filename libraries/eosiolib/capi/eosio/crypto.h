/**
 *  @file
 *  @copyright defined in eos/LICENSE
 */
#pragma once
#include "types.h"
#ifdef __cplusplus
extern "C" {
#endif

/**
 *  @addtogroup crypto Crypto
 *  @brief Defines %C API for calculating and checking hash
 *  @{
 */

/**
 *  Tests if the sha256 hash generated from data matches the provided checksum.
 *
 *  @param data - Data you want to hash
 *  @param length - Data length
 *  @param hash - `capi_checksum256*` hash to compare to
 *
 *  @pre **assert256 hash** of `data` equals provided `hash` parameter.
 *  @post Executes next statement. If was not `true`, hard return.
 *
 *  @note This method is optimized to a NO-OP when in fast evaluation mode.
 *
 *  Example:
 *
 *  @code
 *  checksum hash;
 *  char data;
 *  uint32_t length;
 *  assert_sha256( data, length, hash )
 *  //If the sha256 hash generated from data does not equal provided hash, anything below will never fire.
 *  eosio::print("sha256 hash generated from data equals provided hash");
 *  @endcode
 */
__attribute__((eosio_wasm_import))
void assert_sha256( const char* data, uint32_t length, const capi_checksum256* hash );

/**
 *  Tests if the sha1 hash generated from data matches the provided checksum.
 *
 *  @note This method is optimized to a NO-OP when in fast evaluation mode.
 *  @param data - Data you want to hash
 *  @param length - Data length
 *  @param hash - `capi_checksum160*` hash to compare to
 *
 *  @pre **sha1 hash** of `data` equals provided `hash` parameter.
 *  @post Executes next statement. If was not `true`, hard return.
 *
 *  Example:
*
 *  @code
 *  checksum hash;
 *  char data;
 *  uint32_t length;
 *  assert_sha1( data, length, hash )
 *  //If the sha1 hash generated from data does not equal provided hash, anything below will never fire.
 *  eosio::print("sha1 hash generated from data equals provided hash");
 *  @endcode
 */
__attribute__((eosio_wasm_import))
void assert_sha1( const char* data, uint32_t length, const capi_checksum160* hash );

/**
 *  Tests if the sha512 hash generated from data matches the provided checksum.
 *
 *  @note This method is optimized to a NO-OP when in fast evaluation mode.
 *  @param data - Data you want to hash
 *  @param length - Data length
 *  @param hash - `capi_checksum512*` hash to compare to
 *
 *  @pre **assert512 hash** of `data` equals provided `hash` parameter.
 *  @post Executes next statement. If was not `true`, hard return.
 *
 *  Example:
*
 *  @code
 *  checksum hash;
 *  char data;
 *  uint32_t length;
 *  assert_sha512( data, length, hash )
 *  //If the sha512 hash generated from data does not equal provided hash, anything below will never fire.
 *  eosio::print("sha512 hash generated from data equals provided hash");
 *  @endcode
 */
__attribute__((eosio_wasm_import))
void assert_sha512( const char* data, uint32_t length, const capi_checksum512* hash );

/**
 *  Tests if the ripemod160 hash generated from data matches the provided checksum.
 *
 *  @param data - Data you want to hash
 *  @param length - Data length
 *  @param hash - `capi_checksum160*` hash to compare to
 *
 *  @pre **assert160 hash** of `data` equals provided `hash` parameter.
 *  @post Executes next statement. If was not `true`, hard return.
 *
 *  Example:
*
 *  @code
 *  checksum hash;
 *  char data;
 *  uint32_t length;
 *  assert_ripemod160( data, length, hash )
 *  //If the ripemod160 hash generated from data does not equal provided hash, anything below will never fire.
 *  eosio::print("ripemod160 hash generated from data equals provided hash");
 *  @endcode
 */
__attribute__((eosio_wasm_import))
void assert_ripemd160( const char* data, uint32_t length, const capi_checksum160* hash );

/**
 *  Hashes `data` using `sha256` and stores result in memory pointed to by hash.
 *
 *  @param data - Data you want to hash
 *  @param length - Data length
 *  @param hash - Hash pointer
 *
 *  Example:
*
 *  @code
 *  checksum calc_hash;
 *  sha256( data, length, &calc_hash );
 *  eos_assert( calc_hash == hash, "invalid hash" );
 *  @endcode
 */
__attribute__((eosio_wasm_import))
void sha256( const char* data, uint32_t length, capi_checksum256* hash );

/**
 *  Hashes `data` using `sha1` and stores result in memory pointed to by hash.
 *
 *  @param data - Data you want to hash
 *  @param length - Data length
 *  @param hash - Hash pointer
 *
 *  Example:
*
 *  @code
 *  checksum calc_hash;
 *  sha1( data, length, &calc_hash );
 *  eos_assert( calc_hash == hash, "invalid hash" );
 *  @endcode
 */
__attribute__((eosio_wasm_import))
void sha1( const char* data, uint32_t length, capi_checksum160* hash );

/**
 *  Hashes `data` using `sha512` and stores result in memory pointed to by hash.
 *
 *  @param data - Data you want to hash
 *  @param length - Data length
 *  @param hash - Hash pointer
 *
 *  Example:
*
 *  @code
 *  checksum calc_hash;
 *  sha512( data, length, &calc_hash );
 *  eos_assert( calc_hash == hash, "invalid hash" );
 *  @endcode
 */
__attribute__((eosio_wasm_import))
void sha512( const char* data, uint32_t length, capi_checksum512* hash );

/**
 *  Hashes `data` using `ripemod160` and stores result in memory pointed to by hash.
 *
 *  @param data - Data you want to hash
 *  @param length - Data length
 *  @param hash - Hash pointer
 *
 *  Example:
*
 *  @code
 *  checksum calc_hash;
 *  ripemod160( data, length, &calc_hash );
 *  eos_assert( calc_hash == hash, "invalid hash" );
 *  @endcode
 */
__attribute__((eosio_wasm_import))
void ripemd160( const char* data, uint32_t length, capi_checksum160* hash );

/**
 *  EVM Compatibility Layer - Hashes `data` using KECCAK256.
 *
 *  @ingroup crypto
 *  @param data - Data you want to hash
 *  @param length - Data length
 *  @param hash - Hash pointer
 *
 */
__attribute__((eosio_wasm_import))
void evm_keccak256( const char* data, uint32_t length, capi_checksum256* hash );

/**
 *  EVM Compatibility Layer - Calculates the uncompressed public key used for a given signature on a given digest.
 *
 *  @ingroup crypto
 *  @param digest - Digest of the message that was signed
 *  @param sig - Signature
 *  @param siglen - The signature buffer length
 *  @param pub - The recovered public key
 *  @param publen - The public key buffer length
 */
__attribute__((eosio_wasm_import))
void evm_ecrecover( const capi_checksum256* digest, const char* sig, size_t siglen, char* pub, size_t publen );

/**
 *  EVM Compatibility Layer - Perform modular exponentiation of unsigned numbers.
 *
 *  @ingroup crypto
 *  @param base - The base number
 *  @param baselen - The base length in bytes
 *  @param exp - The exponent number
 *  @param explen - The exponent length in bytes
 *  @param mod - The modulus number
 *  @param modlen - The modulus length in bytes
 *  @param output - The resulting number
 *  @param outlen - The resulting number length in bytes
 */
__attribute__((eosio_wasm_import))
void evm_bigmodexp( const char* base, uint32_t baselen, const char* exp, uint32_t explen, const char* mod, uint32_t modlen, char *output, size_t outlen );

/**
 *  EVM Compatibility Layer - Adds two BN256 curve points.
 *
 *  @ingroup crypto
 *  @param point1 - First point to add
 *  @param point2 - Second point to add
 *  @param point3 - The resulting point
 */
__attribute__((eosio_wasm_import))
void evm_bn256add( const capi_checksum512* point1, const capi_checksum512* point2, capi_checksum512* point3 );

/**
 *  EVM Compatibility Layer - Multiplies a BN256 curve point by a scalar.
 *
 *  @ingroup crypto
 *  @param point1 - Point to multiply
 *  @param scalar - Scalar multiplier
 *  @param point2 - The resulting point
 */
__attribute__((eosio_wasm_import))
void evm_bn256scalarmul( const capi_checksum512* point1, const capi_checksum256* scalar, capi_checksum512* point2 );

/**
 *  EVM Compatibility Layer - Check for a BN256 curve point/twist pairing.
 *
 *  @ingroup crypto
 *  @param point_twistx_twisty_list - A list of tuples consisting of bn256 point, bn256 twist x, and y coordinates
 *  @param count - The number of tuples
 *  @return bool - Whether or not there is a pairing
 */
__attribute__((eosio_wasm_import))
bool evm_bn256pairing( const capi_checksum512* point_twistx_twisty_list, uint32_t count );

/**
 *  EVM Compatibility Layer - Hashes `data` using BLAKE2F cipher.
 *
 *  @ingroup crypto
 *  @param data - Data you want to hash
 *  @param length - Data length (should always be 128)
 *  @param state - Cipher state (modified after call)
 *  @param offset - Offset into the data
 *  @param offsetlen - Length of the offset (should always be 16)
 *  @param last - Marks the end of data
 *  @param rounds - Number of cipher rounds to perform
 */
__attribute__((eosio_wasm_import))
void evm_blake2f( const char* data, uint32_t length, capi_checksum512* state, const char *offset, uint32_t offsetlen, uint32_t last, uint32_t rounds );

/**
 *  Calculates the public key used for a given signature and hash used to create a message.
 *
 *  @param digest - Hash used to create a message
 *  @param sig - Signature
 *  @param siglen - Signature length
 *  @param pub - Public key
 *  @param publen - Public key length
*   @return int - number of bytes written to pub
 *
 *  Example:
*
 *  @code
 *  @endcode
 */
__attribute__((eosio_wasm_import))
int recover_key( const capi_checksum256* digest, const char* sig, size_t siglen, char* pub, size_t publen );

/**
 *  Tests a given public key with the generated key from digest and the signature.
 *
 *  @param digest - What the key will be generated from
 *  @param sig - Signature
 *  @param siglen - Signature length
 *  @param pub - Public key
 *  @param publen - Public key length
 *
 *  @pre **assert recovery key** of `pub` equals the key generated from the `digest` parameter
 *  @post Executes next statement. If was not `true`, hard return.
 *
 *  Example:
*
 *  @code
 *  checksum digest;
 *  char sig;
 *  size_t siglen;
 *  char pub;
 *  size_t publen;
 *  assert_recover_key( digest, sig, siglen, pub, publen )
 *  // If the given public key does not match with the generated key from digest and the signature, anything below will never fire.
 *  eosio::print("pub key matches the pub key generated from digest");
 *  @endcode
 */
__attribute__((eosio_wasm_import))
void assert_recover_key( const capi_checksum256* digest, const char* sig, size_t siglen, const char* pub, size_t publen );

#ifdef __cplusplus
}
#endif
/// @}
