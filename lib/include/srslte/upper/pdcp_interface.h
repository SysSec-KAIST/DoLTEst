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

#ifndef SRSLTE_PDCP_INTERFACE_H
#define SRSLTE_PDCP_INTERFACE_H

#include "srslte/common/buffer_pool.h"
#include "srslte/common/log.h"
#include "srslte/common/common.h"
#include "srslte/interfaces/ue_interfaces.h"
#include "srslte/common/security.h"
#include "srslte/common/threads.h"


namespace srslte {

/****************************************************************************
 * Virtual PDCP interface common for all PDCP entities
 ***************************************************************************/
class pdcp_entity_interface
{
public:
  virtual ~pdcp_entity_interface() {};
  virtual void init(srsue::rlc_interface_pdcp     *rlc_,
                    srsue::rrc_interface_pdcp     *rrc_,
                    srsue::gw_interface_pdcp      *gw_,
                    srslte::log                   *log_,
                    uint32_t                       lcid_,
                    srslte_pdcp_config_t           cfg_) = 0;
  virtual void reset() = 0;
  virtual void reestablish() = 0;
  virtual bool is_active() = 0;

  // RRC interface
  virtual void     write_sdu(unique_byte_buffer_t sdu, bool blocking) = 0;
  virtual void     write_sdu_doltest(unique_byte_buffer_t sdu, srslte::INTEGRITY_ALGORITHM_ID_ENUM integ_algo_doltest, srslte::CIPHERING_ALGORITHM_ID_ENUM cipher_algo_doltest, bool blocking) = 0;
  virtual void config_security(uint8_t *k_rrc_enc_,
                       uint8_t *k_rrc_int_,
                       uint8_t *k_up_enc_,
                       CIPHERING_ALGORITHM_ID_ENUM cipher_algo_,
                       INTEGRITY_ALGORITHM_ID_ENUM integ_algo_) = 0;
  virtual void enable_integrity() = 0;
  virtual void enable_encryption() = 0;
  virtual uint32_t get_dl_count() = 0;
  virtual uint32_t get_ul_count() = 0;

  // RLC interface
  virtual void write_pdu(unique_byte_buffer_t pdu) = 0;
};

} // namespace srslte


#endif // SRSLTE_PDCP_INTERFACE_H
