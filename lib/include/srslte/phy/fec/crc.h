/*
 * Copyright 2013-2019 Software Radio Systems Limited
 *
 * This file is part of srsLTE.
 *
 * srsLTE is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * srsLTE is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 *
 */

/**********************************************************************************************
 *  File:         convcoder.h
 *
 *  Description:  Cyclic Redundancy Check
 *                LTE requires CRC lengths 8, 16, 24A and 24B, each with it's own generator
 *                polynomial.
 *
 *  Reference:    3GPP TS 36.212 version 10.0.0 Release 10 Sec. 5.1.1
 *********************************************************************************************/

#ifndef SRSLTE_CRC_H
#define SRSLTE_CRC_H

#include "srslte/config.h"
#include <stdint.h>

typedef struct SRSLTE_API {
  uint64_t table[256];
  int polynom;
  int order;
  uint64_t crcinit; 
  uint64_t crcmask;
  uint64_t crchighbit;
  uint32_t srslte_crc_out;
} srslte_crc_t;

SRSLTE_API int srslte_crc_init(srslte_crc_t *h, 
                               uint32_t srslte_crc_poly, 
                               int srslte_crc_order);

SRSLTE_API int srslte_crc_set_init(srslte_crc_t *h, 
                                   uint64_t init_value);

SRSLTE_API uint32_t srslte_crc_attach(srslte_crc_t *h, 
                                      uint8_t *data, 
                                      int len);

SRSLTE_API uint32_t srslte_crc_attach_byte(srslte_crc_t *h, 
                                           uint8_t *data, 
                                           int len);

static inline void srslte_crc_checksum_put_byte(srslte_crc_t *h, uint8_t byte) {

  // Polynom order 8, 16, 24 or 32 only.
  int ord = h->order - 8;
  uint64_t crc = h->crcinit;

  crc = (crc << 8) ^ h->table[((crc >> (ord)) & 0xff) ^ byte];
  h->crcinit = crc;
}

static inline uint64_t srslte_crc_checksum_get(srslte_crc_t *h) {
  return (h->crcinit  & h->crcmask);
}

SRSLTE_API uint32_t srslte_crc_checksum_byte(srslte_crc_t *h, 
                                             uint8_t *data, 
                                             int len); 

SRSLTE_API uint32_t srslte_crc_checksum(srslte_crc_t *h, 
                                        uint8_t *data, 
                                        int len);

#endif // SRSLTE_CRC_H
