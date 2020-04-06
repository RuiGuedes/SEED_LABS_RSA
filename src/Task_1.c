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
	
	BIGNUM *p = BN_new();
	BIGNUM *q = BN_new();
	BIGNUM *n = BN_new();
	BIGNUM *e = BN_new();
	BIGNUM *d = BN_new();

	BIGNUM *one = BN_new();
	BIGNUM *p_minus_one = BN_new();
	BIGNUM *q_minus_one = BN_new();
	BIGNUM *tot_n = BN_new();

	// Initialize <p>, <q>, <e>, <one> values
	BN_dec2bn(&one, "1");
	BN_hex2bn(&e, "0D88C3");
	BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
	BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");

	// Calculate <n>
	BN_mul(n, p, q, ctx);

	// Calculate the tot_n = (p - 1)*(q - 1)
	BN_sub(p_minus_one, p, one);
	BN_sub(q_minus_one, q, one);
	BN_mul(tot_n, p_minus_one, q_minus_one, ctx);

	// Calculate private key: e*d mod totient(n) = 1
	BN_mod_inverse(d, e, tot_n, ctx);

	// Print final information
	printBN("Private Key =", d);
};