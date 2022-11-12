/*
 * rsa.c
 *
 *  Created on: Nov 5, 2022
 *      Author: seed
 */

/*
 * FEATURES THAT NEED TO BE ADDED:
 * TODO: Ask user to either Encrypt or Decrypt
 * 		-if encrypt then give the option to generate new keys or use existing keys
 * 		-if decrypt then ask them to add the relevant information
 * TODO: Implement main loop so the user can keep encrypting and decrypting
 *
 */

#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <iostream>
#include <stdlib.h>
#include <sstream>
#include <openssl/crypto.h>
 #include <openssl/err.h>
using namespace std;

BN_CTX *ctx = BN_CTX_new(); //this is for temp variables
BIGNUM *p,*q,*n, *phi, *e, *d;

void readInput(char* user_input, int key_size){

	cin.get(user_input,key_size + 1);
	 return;
}

void printBN(char *msg, BIGNUM * a){
	// Convert the BIGNUM to number string
	char * number_str = BN_bn2dec(a);
	// Print out the number string
	printf("%s %s\n", msg, number_str);
	// Free the dynamically allocated memory
	OPENSSL_free(number_str);
}

void setupRSA(){
	//choose two large primes p and q
	p = BN_new();
	q = BN_new();

	// Generate a random prime number of 128 bits
	//TODO: Allow for different bit sizes
	BN_generate_prime_ex(p, 128, 1, NULL, NULL, NULL);
	BN_generate_prime_ex(q, 128, 1, NULL, NULL, NULL);

	//compute n = p*q
	n = BN_new();
	BN_mul(n, p, q, ctx);

	//compute phi = (p-1)(q-1)
	BIGNUM *one = BN_new();
	BN_dec2bn(&one, "1");

	BIGNUM *p_minus1 = BN_new();
	BN_sub(p_minus1, p, one);

	BIGNUM *q_minus1 = BN_new();
	BN_sub(q_minus1, q, one);

	phi = BN_new();
	BN_mul(phi, p_minus1, q_minus1, ctx);

	//select e such that gcd(e,phi) == 1
	//any prime number will be coprime with phi so just generate random prime number
	e = BN_new();
	BN_generate_prime_ex(e, 128, 1, NULL, NULL, NULL);

	//compute private key d where d*e mod phi = 1
	d = BN_new();
	BN_mod_inverse(d, e, phi, ctx);

	return;
}

char* textToHex(char* text){
	int* text_dec = (int*) malloc(sizeof(int) * strlen(text));	//will hold the decimal value of the input string

	//turns text into decimal representation
	for(int i = 0; i < (int)strlen(text); i++){
		int current_char = text[i];
		text_dec[i] = current_char;
	}

	//build the hexadecimal string here
	char* text_hex = (char*) malloc((sizeof(int) * strlen(text))/2 + 1);
	int i, j;
	for( i = 0, j = 0; i < (int)strlen(text); i++, j+=2){
		sprintf((char*)text_hex + j,"%X",text_dec[i]);
	}
	text_hex[j] = '\0';

	free(text_dec);

	return text_hex;
}

char* hexToText(char* decryptedHex){
	//https://www.geeksforgeeks.org/convert-hexadecimal-value-string-ascii-value-string/
	char* decryptedPlaintext = (char*) malloc(BN_num_bytes(n));
	size_t i;
	int j;

	for (i = 0, j = 0; i < strlen(decryptedHex); i += 2, j++)
	    {
	        // extract two characters from hex string
	        char hex_digit[2];
	        hex_digit[0] = decryptedHex[i];
	        hex_digit[1] = decryptedHex[i+1];


	        // change it into base 16 and typecast as the character
	        char ch = stoul(hex_digit, nullptr, 16);

	        // add this char to final ASCII string
	        sprintf((char*)decryptedPlaintext + j,"%c",ch);
	    }

	decryptedPlaintext[j] = '\0';

	return decryptedPlaintext;

}

BIGNUM* encryptInput(char* plaintext){
	//takes ASCII input and converts it to a Hexadecimal string
	char* plaintextHex = textToHex(plaintext);
	printf(" Plaintext in hexadecimal format: %s\n",plaintextHex);

	//convert the hexadecimal input to a BIGNUM
	BIGNUM *plaintext_BN = NULL;
	BN_hex2bn(&plaintext_BN, plaintextHex);
	printBN(" Plaintext as a BIGNUM: ",plaintext_BN);

	//Encrypt the BIGNUM representation of the input string
	BIGNUM *ciphertext = BN_new();
	BN_mod_exp(ciphertext, plaintext_BN, e, n, ctx);

	char* bnHex = BN_bn2hex(ciphertext);
	printf(" Encrypted ciphertext in hexadecimal format: %s\n",bnHex);

	//Free memory
	OPENSSL_free(bnHex);
	BN_free(plaintext_BN);
	free(plaintextHex);


	return ciphertext;
}

char* decryptCipher(BIGNUM* ciphertext){
	BIGNUM *decrpytedtext = BN_new();
	BN_mod_exp(decrpytedtext, ciphertext, d, n, ctx);	//gets the BN representation of the decryption
	//printBN("Decryption as a BN: ",decrpytedtext);

	char* decryptedHex = BN_bn2hex(decrpytedtext);		//gets the HEX representation of the decryption
	printf("Decryption in HEX form: %s\n",decryptedHex);

	return hexToText(decryptedHex);
}

int main(){
	printf("RSA Encryption & Decryption\n");
	printf("---------------------------\n");
	printf("\n");


	setupRSA(); //setup the rsa algorithm (generate public(e,n) and private(d) keys)

	printf("Components\n");
	printBN("   p: ",p);
	printBN("   q: ",q);
	printBN(" phi: ",phi);

	printf("Public Keys\n");
	printBN("   n: ",n);
	printBN("   e: ",e);

	printf("Private Key\n");
	printBN("   d: ",d);

	printf("\n");

	//ENCRYPTION
	printf("Encryption\n");
	printf("----------\n");

	int key_size = BN_num_bytes(n);
	printf(" Number of bytes in n: %d\n", key_size);

	char *plaintext = (char*)malloc(key_size);		//this is because the string needs to be less than or equal to the size of n
	if (plaintext == NULL){
		printf("[ERROR] Something went wrong...\n");
		exit(1);
	}

	printf(" Enter the text you would like to encrypt (size = %d bytes): ",key_size);
	readInput(plaintext, key_size);
	printf(" You entered: %s \n",plaintext);

	BIGNUM* ciphertext = encryptInput(plaintext);	//encrypt the plaintext


	//DECRYPTION
	printf("\n");
	printf("Decryption\n");
	printf("----------\n");
	char* decryptedPlaintext = decryptCipher(ciphertext);
	printf("The decrypted message is: %s\n",decryptedPlaintext);


	return 1;
}





