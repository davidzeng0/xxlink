#pragma once

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <xstd/fla.h>

namespace xxlink{

enum{
	XE_ENCRYPT_KEY_SIZE = 32
};

enum xe_encryption_mode{
	XE_ENCRYPTION_NONE = 0x0,
	XE_AEAD_AES256_GCM_RTPSIZE = 0x1,
	XE_AEAD_AES256_GCM = 0x2,
	XE_XSALSA20_POLY1305_LITE_RTPSIZE = 0x4,
	XE_XSALSA20_POLY1305_LITE = 0x8,
	XE_XSALSA20_POLY1305_SUFFIX = 0x10,
	XE_XSALSA20_POLY1305 = 0x20,
};

static xe_cstr xe_encryption_mode_to_string(xe_encryption_mode mode){
	switch(mode){
		case XE_ENCRYPTION_NONE:
			return "none";
		case XE_AEAD_AES256_GCM_RTPSIZE:
			return "aead_aes256_gcm_rtpsize";
		case XE_AEAD_AES256_GCM:
			return "aead_aes256_gcm";
		case XE_XSALSA20_POLY1305_LITE_RTPSIZE:
			return "xsalsa20_poly1305_lite_rtpsize";
		case XE_XSALSA20_POLY1305_LITE:
			return "xsalsa20_poly1305_lite";
		case XE_XSALSA20_POLY1305_SUFFIX:
			return "xsalsa20_poly1305_suffix";
		case XE_XSALSA20_POLY1305:
			return "xsalsa20_poly1305";
	}

	return "unknown";
}

class xe_encryption{
private:
	xe_encryption_mode mode;
	xe_fla<byte, XE_ENCRYPT_KEY_SIZE> key;
	uint nonce;

	Aes aes;
public:
	xe_encryption(): mode(), nonce(){}

	int init(xe_encryption_mode mode, byte key[XE_ENCRYPT_KEY_SIZE]);
	int encrypt(byte* out, const byte* in, uint in_sz, uint header_size);
	int decrypt(byte* out, const byte* in, uint in_sz, uint header_size);

	~xe_encryption();
};

}