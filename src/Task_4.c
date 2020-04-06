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
	BIGNUM *d = BN_new();
	BIGNUM *n = BN_new();
	BIGNUM *M = BN_new();
	BIGNUM *S = BN_new();

	// Initialize <e>, <d>, <n>, values
	BN_hex2bn(&e, "010001");
	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");

	// Initialize <M1> and <M2> values
	BN_hex2bn(&M, "49206f776520796f752024323030302e"); // python -c 'print("I owe you $2000.".encode("hex"))'
	//BN_hex2bn(&M, "49206f776520796f752024333030302e"); // python -c 'print("I owe you $3000.".encode("hex"))'

	// Calculate <S> = M^d mod n
	BN_mod_exp(S, M, d, n, ctx);

	// Print final information
	printBN("Signature (S) =", S);
};