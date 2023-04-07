/*
*    ZeroTrace: Oblivious Memory Primitives from Intel SGX 
*    Copyright (C) 2018  Sajin (sshsshy)
*
*    This program is free software: you can redistribute it and/or modify
*    it under the terms of the GNU General Public License as published by
*    the Free Software Foundation, version 3 of the License.
*
*    This program is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*    GNU General Public License for more details.
*
*    You should have received a copy of the GNU General Public License
*    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include "Sample_App.hpp"


struct node{
  uint32_t id;
  uint32_t data;
  struct node *left, *right;
};

int initializeZeroTrace() {
  // Variables for Enclave Public Key retrieval 
  uint32_t max_buff_size = PRIME256V1_KEY_SIZE;
  unsigned char bin_x[PRIME256V1_KEY_SIZE], bin_y[PRIME256V1_KEY_SIZE], signature_r[PRIME256V1_KEY_SIZE], signature_s[PRIME256V1_KEY_SIZE];
  
  ZT_Initialize(bin_x, bin_y, signature_r, signature_s, max_buff_size);
  
  EC_GROUP *curve;
  EC_KEY *enclave_verification_key = NULL;
  ECDSA_SIG *sig_enclave = ECDSA_SIG_new();	
  BIGNUM *x, *y, *xh, *yh, *sig_r, *sig_s;
  BN_CTX *bn_ctx = BN_CTX_new();
  int ret;

  if(NULL == (curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)))
	  printf("Setting EC_GROUP failed \n");

  EC_POINT *pub_point = EC_POINT_new(curve);
  //Verify the Enclave Public Key
  enclave_verification_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  xh = BN_bin2bn(hardcoded_verification_key_x, PRIME256V1_KEY_SIZE, NULL);
  yh = BN_bin2bn(hardcoded_verification_key_y, PRIME256V1_KEY_SIZE, NULL);
  EC_KEY_set_public_key_affine_coordinates(enclave_verification_key, xh, yh);
  unsigned char *serialized_public_key = (unsigned char*) malloc (PRIME256V1_KEY_SIZE*2);
  memcpy(serialized_public_key, bin_x, PRIME256V1_KEY_SIZE);
  memcpy(serialized_public_key + PRIME256V1_KEY_SIZE, bin_y, PRIME256V1_KEY_SIZE);

	
  // This syntax was for older versions of OpenSSL
  //sig_enclave->r = BN_bin2bn(signature_r, PRIME256V1_KEY_SIZE, NULL);
  //sig_enclave->s = BN_bin2bn(signature_s, PRIME256V1_KEY_SIZE, NULL);	
  // New syntax
  ECDSA_SIG_set0(sig_enclave, BN_bin2bn(signature_r, PRIME256V1_KEY_SIZE, NULL), BN_bin2bn(signature_s, PRIME256V1_KEY_SIZE, NULL));	
  
  ret = ECDSA_do_verify((const unsigned char*) serialized_public_key, PRIME256V1_KEY_SIZE*2, sig_enclave, enclave_verification_key);
  if(ret==1){
	  printf("GetEnclavePublishedKey : Verification Successful! \n");
  }
  else{
	  printf("GetEnclavePublishedKey : Verification FAILED! \n");
  }
  
  //Load the Enclave Public Key
  ENCLAVE_PUBLIC_KEY = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  
  x = BN_bin2bn(bin_x, PRIME256V1_KEY_SIZE, NULL);
  y = BN_bin2bn(bin_y, PRIME256V1_KEY_SIZE, NULL);
  if(EC_POINT_set_affine_coordinates_GFp(curve, pub_point, x, y, bn_ctx)==0)
	  printf("EC_POINT_set_affine_coordinates FAILED \n");

  if(EC_KEY_set_public_key(ENCLAVE_PUBLIC_KEY, pub_point)==0)
	  printf("EC_KEY_set_public_key FAILED \n");

  BN_CTX_free(bn_ctx);
  free(serialized_public_key);

}

int main(int argc, char *argv[]) {

  uint32_t MAX_BLOCKS = 1000; //Number of data blocks in the ORAM
  uint32_t DATA_SIZE = 4096; //Size of a block (Z blocks per bucket)
  uint32_t STASH_SIZE = 150; //Refer to PathORAM and CircuitORAM papers to understand stash size bounds.
  uint32_t OBLIVIOUS_FLAG = 1; //ZeroTrace is a Doubly-oblivious ORAM i.e. the ORAM controller logic is itself oblivious to provide side-channel security against an adversary that observer the memory trace of this controller. Setting this to 0 improves performance, at the cost of introducing side-channel vulnerabilities
  uint32_t RECURSION_DATA_SIZE = 64; //recursion_data_size can be used to tailor the data size of the recursive ORAM trees, since currently ZT uses ids of 4 bytes, recursion size of 64, gives us a compression factor of 16 with each level of recursion.
  uint32_t ORAM_TYPE = 0; // path is 0, circuit is 1
  uint32_t Z = 4; //Z is the number of blocks in a bucket of the ORAMTree, typically PathORAM uses Z=4. But Z can be adjusted to make trade-offs on the security VS performance bar. Read more about this in the original Circuit ORAM/ Path ORAM papers. 

  initializeZeroTrace();
 
  //create a new oram, referrable to its zerotrace_id (zt_id)
  //it's unclear if multiple orams is even supported though...
  uint32_t zt_id = ZT_New(MAX_BLOCKS, DATA_SIZE, STASH_SIZE, OBLIVIOUS_FLAG, RECURSION_DATA_SIZE, ORAM_TYPE, Z);

  uint32_t response_size = DATA_SIZE;
  //+1 for simplicity printing a null-terminated string
  unsigned char *oram_output = (unsigned char*) malloc (DATA_SIZE + 1);
  uint32_t enc_request_size = computeCiphertextSize(DATA_SIZE);
  unsigned char *enc_request = (unsigned char *) malloc (enc_request_size);				
  unsigned char *enc_response = (unsigned char *) malloc (response_size);

  unsigned char *in_data  = (unsigned char*) malloc (DATA_SIZE);
  unsigned char *in_tag = (unsigned char*) malloc (TAG_SIZE); //in_tag and out_tag are used for authenticated encryption
  unsigned char *out_data  = (unsigned char*) malloc (DATA_SIZE+1);
  unsigned char *out_tag = (unsigned char*) malloc (TAG_SIZE);
  strcpy((char*) in_data, "I am heatmap data or smth");
  //strcpy((char*) in_tag, "Arbitrary Tag"); // (this probably gets overridden)
  // encrypt the request before sending it to the enclave
  // use 'r' for read and 'w' for write. First arg is the index you're accessing
  encryptRequest(0, 'w', in_data, DATA_SIZE, enc_request, in_tag, enc_request_size);
  // ZT_Access handles both reads and writes
  ZT_Access(zt_id, ORAM_TYPE, enc_request, enc_response, in_tag, out_tag, enc_request_size, response_size, TAG_SIZE);
  // ignore enc_response for now

  // now let's write some other data that we don't care about
  // in_tag and out_tag only need to stay around for the duration of the access, so it's okay to overwrite these
  // (same with enc_request and enc_response)
  unsigned char *other_data  = (unsigned char*) malloc (DATA_SIZE);
  strcpy((char*) other_data, "I am some other data. Don't access me!");
  encryptRequest(1, 'w', other_data, DATA_SIZE, enc_request, in_tag, enc_request_size);
  ZT_Access(zt_id, ORAM_TYPE, enc_request, enc_response, in_tag, out_tag, enc_request_size, response_size, TAG_SIZE);

  
  // now create a request to fetch the data we just wrote
  unsigned char *enc_request2 = (unsigned char *) malloc (enc_request_size);
  encryptRequest(0, 'r', in_data, DATA_SIZE, enc_request2, in_tag, enc_request_size);
  ZT_Access(zt_id, ORAM_TYPE, enc_request2, enc_response, in_tag, out_tag, enc_request_size, response_size, TAG_SIZE);
  extractResponse(enc_response, out_tag, response_size, out_data);

  printf("Obtained data : %s\n", out_data);
  
  free(encrypted_request);
  free(encrypted_response);
  free(tag_in);
  free(tag_out);
  free(data_in);
  free(data_out);
  return 0;
}


