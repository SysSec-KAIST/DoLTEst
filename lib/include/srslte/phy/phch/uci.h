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

/******************************************************************************
 *  File:         uci.h
 *
 *  Description:  Uplink control information. Only 1-bit ACK for UCI on PUSCCH is supported
 *
 *  Reference:    3GPP TS 36.212 version 10.0.0 Release 10 Sec. 5.2.3, 5.2.4
 *****************************************************************************/

#ifndef SRSLTE_UCI_H
#define SRSLTE_UCI_H

#include "srslte/config.h"
#include "srslte/phy/common/phy_common.h"
#include "srslte/phy/fec/crc.h"
#include "srslte/phy/fec/viterbi.h"
#include "srslte/phy/phch/pusch_cfg.h"
#include "srslte/phy/phch/uci_cfg.h"

#define SRSLTE_UCI_MAX_CQI_LEN_PUSCH       512
#define SRSLTE_UCI_MAX_CQI_LEN_PUCCH       13
#define SRSLTE_UCI_CQI_CODED_PUCCH_B       20
#define SRSLTE_UCI_STR_MAX_CHAR 32

typedef struct SRSLTE_API {
  srslte_crc_t crc;
  srslte_viterbi_t viterbi; 
  uint8_t tmp_cqi[SRSLTE_UCI_MAX_CQI_LEN_PUSCH];
  uint8_t encoded_cqi[3*SRSLTE_UCI_MAX_CQI_LEN_PUSCH];
  int16_t encoded_cqi_s[3*SRSLTE_UCI_MAX_CQI_LEN_PUSCH];
  uint8_t *cqi_table[11];
  int16_t *cqi_table_s[11];
} srslte_uci_cqi_pusch_t;

typedef struct SRSLTE_API {
  uint8_t **cqi_table;
  int16_t **cqi_table_s;
} srslte_uci_cqi_pucch_t;

SRSLTE_API void srslte_uci_cqi_pucch_init(srslte_uci_cqi_pucch_t *q);

SRSLTE_API void srslte_uci_cqi_pucch_free(srslte_uci_cqi_pucch_t *q);

SRSLTE_API int srslte_uci_encode_cqi_pucch(uint8_t *cqi_data,
                                           uint32_t cqi_len, 
                                           uint8_t b_bits[SRSLTE_UCI_CQI_CODED_PUCCH_B]);

SRSLTE_API int srslte_uci_encode_cqi_pucch_from_table(srslte_uci_cqi_pucch_t *q,
                                                      uint8_t *cqi_data,
                                                      uint32_t cqi_len,
                                                      uint8_t b_bits[SRSLTE_UCI_CQI_CODED_PUCCH_B]);

SRSLTE_API int16_t srslte_uci_decode_cqi_pucch(srslte_uci_cqi_pucch_t* q,
                                               int16_t                 b_bits[SRSLTE_CQI_MAX_BITS], // aligned for simd
                                               uint8_t*                cqi_data,
                                               uint32_t                cqi_len);

SRSLTE_API void srslte_uci_encode_ack_sr_pucch3(uint8_t* data, uint32_t nof_bits, uint8_t output[32]);

SRSLTE_API int srslte_uci_cqi_init(srslte_uci_cqi_pusch_t* q);

SRSLTE_API void srslte_uci_cqi_free(srslte_uci_cqi_pusch_t *q);

SRSLTE_API int srslte_uci_encode_cqi_pusch(srslte_uci_cqi_pusch_t *q, 
                                           srslte_pusch_cfg_t *cfg,
                                           uint8_t *cqi_data, 
                                           uint32_t cqi_len, 
                                           float beta, 
                                           uint32_t Q_prime_ri, 
                                           uint8_t *q_bits);

SRSLTE_API int srslte_uci_decode_cqi_pusch(srslte_uci_cqi_pusch_t *q, 
                                           srslte_pusch_cfg_t *cfg,
                                           int16_t *q_bits, 
                                           float beta, 
                                           uint32_t Q_prime_ri, 
                                           uint32_t cqi_len, 
                                           uint8_t *cqi_data, 
                                           bool *cqi_ack);

SRSLTE_API int srslte_uci_encode_ack(srslte_pusch_cfg_t* cfg,
                                     uint8_t             acks[2],
                                     uint32_t            nof_acks,
                                     uint32_t            O_cqi,
                                     float               beta,
                                     uint32_t            H_prime_total,
                                     srslte_uci_bit_t*   ri_bits);

SRSLTE_API int srslte_uci_encode_ack_ri(srslte_pusch_cfg_t* cfg,
                                        uint8_t*            data,
                                        uint32_t            O_ack,
                                        uint32_t            O_cqi,
                                        float               beta,
                                        uint32_t            H_prime_total,
                                        bool                input_is_ri,
                                        uint32_t            N_bundle,
                                        srslte_uci_bit_t*   ri_bits);

SRSLTE_API int srslte_uci_decode_ack_ri(srslte_pusch_cfg_t* cfg,
                                        int16_t*            q_bits,
                                        uint8_t*            c_seq,
                                        float               beta,
                                        uint32_t            H_prime_total,
                                        uint32_t            O_cqi,
                                        srslte_uci_bit_t*   ack_ri_bits,
                                        uint8_t             data[2],
                                        uint32_t            nof_bits,
                                        bool                is_ri);

SRSLTE_API int srslte_uci_data_info(srslte_uci_cfg_t* uci_cfg,
                                    srslte_uci_value_t* uci_data,
                                    char* str,
                                    uint32_t maxlen);

#endif // SRSLTE_UCI_H
