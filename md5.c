#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

main(int argc, char *argv[])
{
  EVP_MD_CTX mdctx;
  const EVP_MD *md;
  char input[] = "md5";
  unsigned char output[EVP_MAX_MD_SIZE];
  int output_len, i;

  /* Initialize digests table */
  OpenSSL_add_all_digests();

  /* You can pass the name of another algorithm supported by your version of OpenSSL here */
  /* For instance, MD2, MD4, SHA1, RIPEMD160 etc. Check the OpenSSL documentation for details */
  md = EVP_get_digestbyname("MD5");

  if(!md) {
         printf("Unable to init MD5 digest\n");
         exit(1);
  }

  EVP_MD_CTX_init(&mdctx);
  EVP_DigestInit_ex(&mdctx, md, NULL);
  EVP_DigestUpdate(&mdctx, input, strlen(input));
  /* to add more data to hash, place additional calls to EVP_DigestUpdate here */
  EVP_DigestFinal_ex(&mdctx, output, &output_len);
  EVP_MD_CTX_cleanup(&mdctx);

  /* Now output contains the hash value, output_len contains length of output, which is 128 bit or 16 byte in case of MD5 */

  printf("Digest is: ");
  for(i = 0; i < output_len; i++) printf("%02x", output[i]);
  printf("\n");
}
