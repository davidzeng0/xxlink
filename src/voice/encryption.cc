#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <xe/error.h>
#include "encryption.h"

using namespace xxlink;

enum{
	XE_AES_AUTH_SIZE = 16
};

int xe_encryption::init(xe_encryption_mode mode_, byte key_[XE_ENCRYPT_KEY_SIZE]){
	int err;

	mode = mode_;

	if(mode == XE_AEAD_AES256_GCM || mode == XE_AEAD_AES256_GCM_RTPSIZE){
		err = wc_AesInit(&aes, null, INVALID_DEVID);

		if(err)
			goto err;
		err = wc_AesGcmInit(&aes, key_, XE_ENCRYPT_KEY_SIZE, null, 0);

		if(err)
			goto err;
	}else{
		wc_AesFree(&aes);
		xe_memcpy(key.data(), key_, XE_ENCRYPT_KEY_SIZE);
	}

	return 0;
err:
	return err = MEMORY_E ? XE_ENOMEM : XE_FATAL;
}

int xe_encryption::encrypt(byte* out, const byte* in, uint in_sz, uint header_size){
	xe_fla<byte, 24> iv;

	xe_zero(iv.data(), iv.size());

	if(mode == XE_AEAD_AES256_GCM || mode == XE_AEAD_AES256_GCM_RTPSIZE){
		constexpr uint nonce_size = 4, iv_size = 12;

		xe_memcpy(iv.data(), &nonce, nonce_size);

		if(wc_AesGcmEncrypt(&aes, out + header_size,
			in, in_sz,
			iv.data(), iv_size,
			out + header_size + in_sz, XE_AES_AUTH_SIZE,
			out, header_size))
			return XE_FATAL;
		*(uint*)(out + header_size + in_sz + XE_AES_AUTH_SIZE) = nonce;

		nonce++;

		return header_size + in_sz + XE_AES_AUTH_SIZE + nonce_size;
	}

	return XE_ENOSYS;
}

int xe_encryption::decrypt(byte* out, const byte* in, uint in_sz, uint header_size){
	const byte* ciphertext = in + header_size;
	xe_fla<byte, 24> iv;

	xe_zero(iv.data(), iv.size());

	if(in_sz < header_size)
		return XE_EAGAIN;
	in_sz -= header_size;

	if(mode == XE_AEAD_AES256_GCM || mode == XE_AEAD_AES256_GCM_RTPSIZE){
		constexpr uint nonce_size = 4, iv_size = 12;

		if(in_sz < nonce_size)
			return XE_EAGAIN;
		in_sz -= nonce_size;

		xe_memcpy(iv.data(), ciphertext + in_sz, nonce_size);

		if(in_sz < XE_AES_AUTH_SIZE)
			return XE_EAGAIN;
		in_sz -= XE_AES_AUTH_SIZE;

		return wc_AesGcmDecrypt(&aes, out,
			ciphertext, in_sz,
			iv.data(), iv_size,
			ciphertext + in_sz, XE_AES_AUTH_SIZE,
			in, header_size
		) ? XE_EAGAIN : in_sz;
	}

	return XE_EAGAIN;
}

xe_encryption::~xe_encryption(){
	if(mode == XE_AEAD_AES256_GCM ||
		mode == XE_AEAD_AES256_GCM_RTPSIZE)
		wc_AesFree(&aes);
}