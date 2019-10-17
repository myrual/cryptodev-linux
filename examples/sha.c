/*
 * Demo on how to use /dev/crypto device for ciphering.
 *
 * Placed under public domain.
 *
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/ioctl.h>
#include <crypto/cryptodev.h>
#include "sha.h"

int sha_ctx_init(struct cryptodev_ctx* ctx, int cfd, const uint8_t *key, unsigned int key_size)
{

	memset(ctx, 0, sizeof(*ctx));
	ctx->cfd = cfd;

	if (key == NULL)
		ctx->sess.mac = CRYPTO_SHA2_256;
	else {
		ctx->sess.mac = CRYPTO_SHA1_HMAC;
		ctx->sess.mackeylen = key_size;
		ctx->sess.mackey = (void*)key;
	}
	if (ioctl(ctx->cfd, CIOCGSESSION, &ctx->sess)) {
		perror("ioctl(CIOCGSESSION)");
		return -1;
	}

	return 0;
}

void sha_ctx_deinit(struct cryptodev_ctx* ctx) 
{
	if (ioctl(ctx->cfd, CIOCFSESSION, &ctx->sess.ses)) {
		perror("ioctl(CIOCFSESSION)");
	}
}

int
sha_hash(struct cryptodev_ctx* ctx, const void* text, size_t size, void* digest)
{
	struct crypt_op cryp;
	void* p;
	
	/* check text and ciphertext alignment */
	if (ctx->alignmask) {
		p = (void*)(((unsigned long)text + ctx->alignmask) & ~ctx->alignmask);
		if (text != p) {
			fprintf(stderr, "text is not aligned\n");
			return -1;
		}
	}

	memset(&cryp, 0, sizeof(cryp));

	/* Encrypt data.in to data.encrypted */
	cryp.ses = ctx->sess.ses;
	cryp.len = size;
	cryp.src = (void*)text;
	cryp.mac = digest;
	if (ioctl(ctx->cfd, CIOCCRYPT, &cryp)) {
		perror("ioctl(CIOCCRYPT)");
		return -1;
	}

	return 0;
}

int
main()
{
	int cfd = -1, i;
	struct cryptodev_ctx ctx;
	uint8_t digest[32];
	uint8_t digest_final[32];
	char text[] = "The quick brown fox jumps over the lazy dogThe quick brown fox jumps over the lazy dogThe quick brown fox jumps over the lazy dog";
	uint8_t expected[] = "\x2f\xd4\xe1\xc6\x7a\x2d\x28\xfc\xed\x84\x9e\xe1\xbb\x76\xe7\x39\x1b\x93\xeb\x12";

	/* Open the crypto device */
	cfd = open("/dev/crypto", O_RDWR, 0);
	if (cfd < 0) {
		perror("open(/dev/crypto)");
		return 1;
	}

	/* Set close-on-exec (not really neede here) */
	if (fcntl(cfd, F_SETFD, 1) == -1) {
		perror("fcntl(F_SETFD)");
		return 1;
	}
  	time_t rawtime;
  	struct tm * timeinfo;
  	time ( &rawtime );
  	timeinfo = localtime ( &rawtime );
  	printf ( "Current local time and date: %s", asctime (timeinfo) );
		sha_ctx_init(&ctx, cfd, NULL, 0);
    for(int j = 0x00; j < 1000 * 1000; j++){

		sha_hash(&ctx, text, strlen(text), digest);
		sha_hash(&ctx, digest, 32, digest_final);

	}
		sha_ctx_deinit(&ctx);
  	time ( &rawtime );
  	timeinfo = localtime ( &rawtime );
  	printf ( "exit program: local time and date: %s", asctime (timeinfo) );
	printf("digest: ");
	for (i = 0; i < 32; i++) {
		printf("%02x:", digest[i]);
	}
	printf("\n");
	

	/* Close the original descriptor */
	if (close(cfd)) {
		perror("close(cfd)");
		return 1;
	}

	return 0;
}

