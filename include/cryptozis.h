/**
 * Create an 256 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 **/
int aes_init(unsigned char *key_data, 
	     int key_data_len, unsigned char *salt, 
	     EVP_CIPHER_CTX *e_ctx, 
	     EVP_CIPHER_CTX *d_ctx);

int enrypt_digest(EVP_CIPHER_CTX *en,
		  u_char *frame,
		  u_int32_t frame_len,
		  u_char** sha_frame,
		  u_char **encr_frame,
		  int*encr_frame_len,
		  u_char key[]);

int decrypt_digest(EVP_CIPHER_CTX *de,
		   u_char * pUncomp_cipher_frame, 
		   u_char** sha_frame,
		   u_char **decr_frame,
		   int* decr_frame_len,
		   u_char key[]);
int compress_cipher_frame(u_char **pCmp_cipher_frame,
		      ulong *compressed_frame_len,	  
		      u_char * cipher_frame,
		      int cipher_frame_len);
int uncompress_cipher_frame(u_char** pUncomp_cipher_frame,
			    u_char* pCmp_cipher_frame,
			    ulong *uncompressed_frame_len,
			    ulong compressed_frame_len,
			    int cipher_frame_len);