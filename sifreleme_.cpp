

#include <iostream>
#include "openssl/applink.c" 
#include <openssl/evp.h>


// Function to Decrypt Text provided
int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* plaintext, unsigned char* key) {

	// Initiate Length of texts
	int text_len = 0;
	int len = 0;

	//Create Cipher context struct
	EVP_CIPHER_CTX* dec_ctx = EVP_CIPHER_CTX_new();

	// Set up cipher context ctx for encryption with cipher type
	if (EVP_DecryptInit_ex(dec_ctx, EVP_aes_256_cbc(), NULL, key, NULL) <= 0) {
		std::cerr << "Decrypt Init Failed";
	}

	// Update cipher context ctx for encryption with cipher type
	if (!EVP_DecryptUpdate(dec_ctx, plaintext,&len, ciphertext, ciphertext_len)) {
		std::cerr << "Decrypt Upate Failed";;
	}
	
	text_len += len;

	// Finalize cipher context ctx for encryption with cipher type
	if (!EVP_DecryptFinal_ex(dec_ctx, plaintext + len, &len)) {
		std::cerr << "Decrypt Final Failed";
	}
	text_len += len;

	//Free Cipher Context Struct from Memory
	EVP_CIPHER_CTX_free(dec_ctx);

	return text_len;
}

int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* ciphertext, unsigned char* key) {
	int ciphertext_len = 0;
	int len = 0;

	//Create Cipher context struct
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	// Set up cipher context ctx for encryption with cipher type
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL) <= 0) {
		std::cerr << "Encrypt Init Failed";

	}

	// Sets Cipher Context key length to max value`
	if (EVP_CIPHER_CTX_set_key_length(ctx, EVP_MAX_KEY_LENGTH) <= 0) {
		std::cerr << "Key length Error";
	}

	// Update cipher context ctx for encryption with cipher type
	if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) <= 0) {
		std::cerr << "Encrypt Upate Failed";;
	}

	ciphertext_len += len;

	// Finalize cipher context ctx for encryption with cipher type
	if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) <= 0) {
		std::cerr << "Encrypt Final Failed";
	}

	ciphertext_len += len;

	//Free Cipher Context Struct from Memory
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int main(int argc, char** argv) {

	unsigned char* plaintext = (unsigned char*)"Example Secret Info";

	unsigned char* key = (unsigned char*)"Example Password";

	unsigned char ciphertext[256];

	int plaintext_len = strlen((const char*)plaintext);


	std::cout << "Encrypted Text: " << std::endl;

	int cipher_len = encrypt(plaintext, plaintext_len, ciphertext, key);

	for (int i = 0; i < cipher_len; i++) {
		printf("%02x ", ciphertext[i]);
	}

	std::cout << std::endl;

	std::cout << "Decrypted Text: " << std::endl;

	unsigned char decrypted[256];

	int dec_len = decrypt(ciphertext, cipher_len, decrypted, key);

	for (int i = 0; i < dec_len; i++) {
		printf("%c", (const char)decrypted[i]);
	}

	printf("\n");


}
