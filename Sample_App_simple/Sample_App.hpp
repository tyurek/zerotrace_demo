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

#include "Globals.hpp"
#include "CONFIG.h"
#include "CONFIG_FLAGS.h"
#include "utils.hpp"
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string.h>
#include <cstdint>
#include <random>
#include "ZT.hpp"
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>


EC_KEY *ENCLAVE_PUBLIC_KEY = NULL;
unsigned char *enclave_public_key;

typedef struct Oram{
  unsigned char *enc_request;
  unsigned char *enc_response;
  unsigned char *dummy_in_data;
  unsigned char *dummy_out_data;
  unsigned char *in_tag;
  unsigned char *out_tag;
  uint32_t DATA_SIZE;
  uint32_t ORAM_TYPE;
  uint32_t zt_id;
  uint32_t enc_request_size;
} Oram;

void oram_read(Oram *oram, int index, unsigned char *out_data);
void oram_write(Oram *oram, int index, unsigned char *in_data);
Oram* create_oram(uint32_t MAX_BLOCKS, uint32_t DATA_SIZE, uint32_t STASH_SIZE, uint32_t OBLIVIOUS_FLAG, uint32_t RECURSION_DATA_SIZE, uint32_t ORAM_TYPE, uint32_t Z);
void free_oram(Oram *oram);
int initializeZeroTrace();