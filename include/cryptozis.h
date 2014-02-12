#ifndef _CRYPTOZIS_H_
#define _CRYPTOZIS_H_
/**
 * Create an 256 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 **/

int rsa_encrypt_init(EVP_CIPHER_CTX *rsa_en);
int rsa_decrypt_init(EVP_CIPHER_CTX *rsa_de);


int rsa_encrypt(const u_char *msg,
		size_t msgLen,
		u_char **encMsg,
		u_char **ek,
		size_t *ekl,
		u_char **iv,
		size_t *ivl,
		EVP_PKEY *key,
		EVP_CIPHER_CTX * rsaEncryptCtx);


int rsa_decrypt(u_char *encMsg,
		size_t encMsgLen,
		u_char *ek,
		size_t ekl,
		u_char *iv,
		size_t ivl,
		u_char **decMsg,
		EVP_PKEY *key,
		EVP_CIPHER_CTX * rsaDecryptCtx);

int aes_init(unsigned char *key_data, 
	     int key_data_len, unsigned char *salt, 
	     EVP_CIPHER_CTX *e_ctx, 
	     EVP_CIPHER_CTX *d_ctx);

int encrypt_digest(EVP_CIPHER_CTX *en,
		   u_char *frame,
		   u_char** sha_frame,
		   u_char **encr_frame,
		   int*encr_frame_len,
		   u_char* key,
		   int key_len);

int decrypt_digest(EVP_CIPHER_CTX *de,
		   u_char * pUncomp_cipher_frame, 
		   u_char** sha_frame,
		   u_char **decr_frame,
		   int* decr_frame_len,
		   u_char* key,
		   int key_len);

int compress_cipher_frame(u_char **pCmp_cipher_frame,
			  ulong *compressed_frame_len,	  
			  u_char * cipher_frame,
			  int cipher_frame_len);

int uncompress_cipher_frame(u_char** pUncomp_cipher_frame,
			    u_char* pCmp_cipher_frame,
			    ulong *uncompressed_frame_len,
			    ulong compressed_frame_len);

char* base64Encode(const u_char *buffer, 
		   const size_t length);
int base64Decode(const char *b64message, 
		 const size_t length,
		 u_char **buffer);
int printKey(FILE *fd,
	     int code, 
	     EVP_PKEY * key);
#endif /*_CRYPTOZIS_H_*/
