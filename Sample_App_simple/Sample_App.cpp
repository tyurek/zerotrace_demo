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


Oram* create_oram(uint32_t MAX_BLOCKS, uint32_t DATA_SIZE, uint32_t STASH_SIZE, uint32_t OBLIVIOUS_FLAG, uint32_t RECURSION_DATA_SIZE, uint32_t ORAM_TYPE, uint32_t Z){
  //create a new oram, referrable to its zerotrace_id (zt_id)
  //it's unclear if multiple orams is even supported though...
  uint32_t zt_id = ZT_New(MAX_BLOCKS, DATA_SIZE, STASH_SIZE, OBLIVIOUS_FLAG, RECURSION_DATA_SIZE, ORAM_TYPE, Z);
  
  uint32_t enc_request_size = computeCiphertextSize(DATA_SIZE);
  unsigned char *enc_request = (unsigned char *) malloc (enc_request_size);				
  unsigned char *enc_response = (unsigned char *) malloc (DATA_SIZE);
  //in_tag and out_tag are used for authenticated encryption
  unsigned char *in_tag = (unsigned char*) malloc (TAG_SIZE);
  unsigned char *out_tag = (unsigned char*) malloc (TAG_SIZE);
  //the encryption utility function appears to need pointers to in_data and out_data even when it doesn't make sense...
  unsigned char *dummy_in_data  = (unsigned char*) malloc (DATA_SIZE);
  unsigned char *dummy_out_data  = (unsigned char*) malloc (DATA_SIZE);

  Oram *oram = (Oram*)malloc(sizeof(Oram));
  oram-> enc_request = enc_request;
  oram-> enc_response = enc_response;
  oram -> dummy_in_data = dummy_in_data;
  oram -> dummy_out_data = dummy_out_data;
  oram -> in_tag = in_tag;
  oram -> out_tag = out_tag;
  oram -> DATA_SIZE = DATA_SIZE;
  oram -> ORAM_TYPE = ORAM_TYPE;
  oram -> zt_id = zt_id;
  oram -> enc_request_size = enc_request_size;
  return oram;
}

void free_oram(Oram *oram){
  free(oram -> enc_request);
  free(oram -> enc_response);
  free(oram -> dummy_in_data);
  free(oram -> dummy_out_data);
  free(oram -> in_tag);
  free(oram -> out_tag);
  free(oram);
}

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

void oram_read(Oram *oram, int index, unsigned char *out_data){
  encryptRequest(index, 'r', oram->dummy_in_data, oram->DATA_SIZE, oram->enc_request, oram->in_tag, oram->enc_request_size);
  ZT_Access(oram->zt_id, oram->ORAM_TYPE, oram->enc_request, oram->enc_response, oram->in_tag, oram->out_tag, oram->enc_request_size, oram->DATA_SIZE, TAG_SIZE);
  extractResponse(oram->enc_response, oram->out_tag, oram->DATA_SIZE, out_data);
}

void oram_write(Oram *oram, int index, unsigned char *in_data){
  encryptRequest(index, 'w', in_data, oram->DATA_SIZE, oram->enc_request, oram->in_tag, oram->enc_request_size);
  ZT_Access(oram->zt_id, oram->ORAM_TYPE, oram->enc_request, oram->enc_response, oram->in_tag, oram->out_tag, oram->enc_request_size, oram->DATA_SIZE, TAG_SIZE);
}

int main(int argc, char *argv[]) {

  // start by specifying all the parameters we'll need
  uint32_t MAX_BLOCKS = 1000; //Number of data blocks in the ORAM
  uint32_t DATA_SIZE = 4096; //Size of a block (Z blocks per bucket)
  uint32_t STASH_SIZE = 150; //Refer to PathORAM and CircuitORAM papers to understand stash size bounds.
  uint32_t OBLIVIOUS_FLAG = 1; //ZeroTrace is a Doubly-oblivious ORAM i.e. the ORAM controller logic is itself oblivious to provide side-channel security against an adversary that observer the memory trace of this controller. Setting this to 0 improves performance, at the cost of introducing side-channel vulnerabilities
  uint32_t RECURSION_DATA_SIZE = 64; //recursion_data_size can be used to tailor the data size of the recursive ORAM trees, since currently ZT uses ids of 4 bytes, recursion size of 64, gives us a compression factor of 16 with each level of recursion.
  uint32_t ORAM_TYPE = 0; // path is 0, circuit is 1
  uint32_t Z = 4; //Z is the number of blocks in a bucket of the ORAMTree, typically PathORAM uses Z=4. But Z can be adjusted to make trade-offs on the security VS performance bar. Read more about this in the original Circuit ORAM/ Path ORAM papers. 

  initializeZeroTrace();
  
  // creates a pointer for the struct you need to use the new oram interface. Don't lose it!
  Oram *oram = create_oram(MAX_BLOCKS, DATA_SIZE, STASH_SIZE, OBLIVIOUS_FLAG, RECURSION_DATA_SIZE, ORAM_TYPE, Z);

  // buffers for writing and reading data respectively
  unsigned char *in_data  = (unsigned char*) malloc (DATA_SIZE);
  unsigned char *out_data  = (unsigned char*) malloc (DATA_SIZE);

  // create some identifiable data to write to the oram
  strcpy((char*) in_data, "I am heatmap data or smth");
  oram_write(oram, 0, in_data);

  // it's okay to reuse this buffer, as the data is already in the oram
  strcpy((char*) in_data, "I am some other data");
  oram_write(oram, 999, in_data);

  oram_read(oram, 0, out_data);
  printf("Obtained data : %s\n", out_data);

  oram_read(oram, 999, out_data);
  printf("Obtained data : %s\n", out_data);

  // custom function to make sure all parts of the oram struct are freed
  free_oram(oram);

  return 0;
}


