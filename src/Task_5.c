#include <stdio.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM * a)
{
	/* Use BN_bn2hex(a) for hex string
	* Use BN_bn2dec(a) for decimal string */
	char * number_str = BN_bn2hex(a);
	printf("%s %s\n", msg, number_str);
	OPENSSL_free(number_str);
}

int main() 
{
	// Variables declaration
	BN_CTX *ctx = BN_CTX_new();
	
	BIGNUM *e = BN_new();
	BIGNUM *n = BN_new();
	BIGNUM *M = BN_new();
	BIGNUM *H = BN_new();
	BIGNUM *S = BN_new();

	// Initialize <e>, <n>, <M>, <S> values
	BN_hex2bn(&e, "010001");
	BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
	BN_hex2bn(&M, "4c61756e63682061206d6973736c652e"); // python -c 'print("Launch a missle.".encode("hex"))'

	BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
	//BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");

	// Calculate <H> = S^e mod n
	BN_mod_exp(H, S, e, n, ctx);

	// Print final information
	printBN("Hash (H)    =", H);
	printBN("Message (M) =", M);

	if(BN_cmp(H, M) == 0) 
		printf("Alice SENT the message\n");
	else 
		printf("Alice NOT SENT the message\n");
};