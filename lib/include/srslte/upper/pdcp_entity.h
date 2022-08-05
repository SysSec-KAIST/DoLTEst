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

#ifndef SRSLTE_PDCP_ENTITY_H
#define SRSLTE_PDCP_ENTITY_H

#include "srslte/common/buffer_pool.h"
#include "srslte/common/log.h"
#include "srslte/common/common.h"
#include "srslte/interfaces/ue_interfaces.h"
#include "srslte/common/security.h"
#include "srslte/common/threads.h"
#include "pdcp_interface.h"


namespace srslte {

/****************************************************************************
 * Structs and Defines
 * Ref: 3GPP TS 36.323 v10.1.0
 ***************************************************************************/

#define PDCP_CONTROL_MAC_I 0x00000000

#define PDCP_PDU_TYPE_PDCP_STATUS_REPORT                0x0
#define PDCP_PDU_TYPE_INTERSPERSED_ROHC_FEEDBACK_PACKET 0x1

typedef enum{
    PDCP_D_C_CONTROL_PDU = 0,
    PDCP_D_C_DATA_PDU,
    PDCP_D_C_N_ITEMS,
}pdcp_d_c_t;
static const char pdcp_d_c_text[PDCP_D_C_N_ITEMS][20] = {"Control PDU",
                                                         "Data PDU"};

/****************************************************************************
 * PDCP Entity interface
 * Common interface for all PDCP entities
 ***************************************************************************/
class pdcp_entity : public pdcp_entity_interface
{
public:
  pdcp_entity();
  ~pdcp_entity();
  void init(srsue::rlc_interface_pdcp     *rlc_,
            srsue::rrc_interface_pdcp     *rrc_,
            srsue::gw_interface_pdcp      *gw_,
            srslte::log                   *log_,
            uint32_t                       lcid_,
            srslte_pdcp_config_t           cfg_);
  void reset();
  void reestablish();

  bool is_active();

  // RRC interface
  void     write_sdu(unique_byte_buffer_t sdu, bool blocking);
  void     write_sdu_doltest(unique_byte_buffer_t sdu, srslte::INTEGRITY_ALGORITHM_ID_ENUM integ_algo_doltest, srslte::CIPHERING_ALGORITHM_ID_ENUM cipher_algo_doltest, bool blocking);
  void config_security(uint8_t *k_rrc_enc_,
                       uint8_t *k_rrc_int_,
                       uint8_t *k_up_enc_,
                       CIPHERING_ALGORITHM_ID_ENUM cipher_algo_,
                       INTEGRITY_ALGORITHM_ID_ENUM integ_algo_);
  void enable_integrity();
  void enable_encryption();
  uint32_t get_dl_count();
  uint32_t get_ul_count();

  // RLC interface
  void write_pdu(unique_byte_buffer_t pdu);

private:
  byte_buffer_pool* pool = byte_buffer_pool::get_instance();
  srslte::log*      log  = nullptr;

  srsue::rlc_interface_pdcp* rlc = nullptr;
  srsue::rrc_interface_pdcp* rrc = nullptr;
  srsue::gw_interface_pdcp*  gw  = nullptr;

  bool                 active        = false;
  uint32_t             lcid          = 0;
  srslte_pdcp_config_t cfg           = {};
  uint8_t              sn_len_bytes  = 0;
  bool                 do_integrity  = false;
  bool                 do_encryption = false;

  uint32_t rx_count      = 0;
  uint32_t tx_count      = 0;
  uint8_t  k_rrc_enc[32] = {};
  uint8_t  k_rrc_int[32] = {};
  uint8_t  k_up_enc[32]  = {};

  uint32_t rx_hfn                    = 0;
  uint32_t next_pdcp_rx_sn           = 0;
  uint32_t reordering_window         = 0;
  uint32_t last_submitted_pdcp_rx_sn = 0;
  uint32_t maximum_pdcp_sn           = 0;

  CIPHERING_ALGORITHM_ID_ENUM cipher_algo = CIPHERING_ALGORITHM_ID_EEA0;
  INTEGRITY_ALGORITHM_ID_ENUM integ_algo  = INTEGRITY_ALGORITHM_ID_EIA0;

  pthread_mutex_t mutex;

  void handle_um_drb_pdu(const srslte::unique_byte_buffer_t& pdu);
  void handle_am_drb_pdu(const srslte::unique_byte_buffer_t& pdu);

  void integrity_generate(uint8_t* msg, uint32_t msg_len, uint8_t* mac);
  bool integrity_verify(uint8_t* msg, uint32_t count, uint32_t msg_len, uint8_t* mac);
  void cipher_encrypt(uint8_t* msg, uint32_t msg_len, uint8_t* ct);
  void cipher_decrypt(uint8_t* ct, uint32_t count, uint32_t ct_len, uint8_t* msg);

  void integrity_generate_doltest(uint8_t* msg, uint32_t msg_len, uint8_t* mac, srslte::INTEGRITY_ALGORITHM_ID_ENUM integ_algo_doltest);
  void cipher_encrypt_doltest(uint8_t* msg, uint32_t msg_len, uint8_t* ct, srslte::CIPHERING_ALGORITHM_ID_ENUM cipher_algo_doltest);

};

/****************************************************************************
 * Pack/Unpack helper functions
 * Ref: 3GPP TS 36.323 v10.1.0
 ***************************************************************************/

void pdcp_pack_control_pdu(uint32_t sn, byte_buffer_t *sdu);
void pdcp_unpack_control_pdu(byte_buffer_t *sdu, uint32_t *sn);

void pdcp_pack_data_pdu_short_sn(uint32_t sn, byte_buffer_t *sdu);
void pdcp_unpack_data_pdu_short_sn(byte_buffer_t *sdu, uint32_t *sn);
void pdcp_pack_data_pdu_long_sn(uint32_t sn, byte_buffer_t *sdu);
void pdcp_unpack_data_pdu_long_sn(byte_buffer_t *sdu, uint32_t *sn);

} // namespace srslte
#endif // SRSLTE_PDCP_ENTITY_H
