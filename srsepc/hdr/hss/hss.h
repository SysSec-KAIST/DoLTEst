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
 * File:        hss.h
 * Description: Top-level HSS class. Creates and links all
 *              interfaces and helpers.
 *****************************************************************************/

#ifndef SRSEPC_HSS_H
#define SRSEPC_HSS_H

#include <cstddef>
#include "srslte/common/log.h"
#include "srslte/common/logger_file.h"
#include "srslte/common/log_filter.h"
#include "srslte/common/buffer_pool.h"
#include "srslte/interfaces/epc_interfaces.h"
#include <fstream>
#include <map>

#define LTE_FDD_ENB_IND_HE_N_BITS    5
#define LTE_FDD_ENB_IND_HE_MASK      0x1FUL
#define LTE_FDD_ENB_IND_HE_MAX_VALUE 31
#define LTE_FDD_ENB_SEQ_HE_MAX_VALUE 0x07FFFFFFFFFFUL

namespace srsepc {

typedef struct {
  std::string db_file;
  uint16_t    mcc;
  uint16_t    mnc;
} hss_args_t;

enum hss_auth_algo { HSS_ALGO_XOR, HSS_ALGO_MILENAGE };

typedef struct {
  std::string        name;
  uint64_t           imsi;
  enum hss_auth_algo algo;
  uint8_t            key[16];
  bool               op_configured;
  uint8_t            op[16];
  uint8_t            opc[16];
  uint8_t            amf[2];
  uint8_t            sqn[6];
  uint16_t           qci;
  uint8_t            last_rand[16];
  std::string        static_ip_addr;
} hss_ue_ctx_t;

class hss : public hss_interface_nas
{
public:
  static hss* get_instance(void);
  static void cleanup(void);
  int         init(hss_args_t* hss_args, srslte::log_filter* hss_log);
  void        stop(void);

  virtual bool gen_auth_info_answer(uint64_t imsi, uint8_t* k_asme, uint8_t* autn, uint8_t* rand, uint8_t* xres);
  virtual bool gen_update_loc_answer(uint64_t imsi, uint8_t* qci);

  virtual bool resync_sqn(uint64_t imsi, uint8_t* auts);

  std::map<std::string, uint64_t> get_ip_to_imsi() const;

private:
  hss();
  virtual ~hss();
  static hss* m_instance;

  std::map<uint64_t, hss_ue_ctx_t*> m_imsi_to_ue_ctx;

  void gen_rand(uint8_t rand_[16]);
  bool get_k_amf_opc_sqn(uint64_t imsi, uint8_t* k, uint8_t* amf, uint8_t* opc, uint8_t* sqn);

  bool gen_auth_info_answer_milenage(uint64_t imsi, uint8_t* k_asme, uint8_t* autn, uint8_t* rand, uint8_t* xres);
  bool gen_auth_info_answer_xor(uint64_t imsi, uint8_t* k_asme, uint8_t* autn, uint8_t* rand, uint8_t* xres);

  bool resync_sqn_milenage(uint64_t imsi, uint8_t* auts);
  bool resync_sqn_xor(uint64_t imsi, uint8_t* auts);

  std::vector<std::string> split_string(const std::string& str, char delimiter);
  void                     get_uint_vec_from_hex_str(const std::string& key_str, uint8_t* key, uint len);

  void increment_ue_sqn(uint64_t imsi);
  void increment_seq_after_resync(uint64_t imsi);
  void increment_sqn(uint8_t* sqn, uint8_t* next_sqn);
  void set_sqn(uint64_t imsi, uint8_t* sqn);

  void set_last_rand(uint64_t imsi, uint8_t* rand);
  void get_last_rand(uint64_t imsi, uint8_t* rand);

  bool set_auth_algo(std::string auth_algo);
  bool read_db_file(std::string db_file);
  bool write_db_file(std::string db_file);
  bool get_ue_ctx(uint64_t imsi, hss_ue_ctx_t** ue_ctx);

  std::string hex_string(uint8_t* hex, int size);

  std::string        db_file;

  /*Logs*/
  srslte::log_filter* m_hss_log;

  uint16_t mcc;
  uint16_t mnc;

  std::map<std::string, uint64_t> m_ip_to_imsi;
};

} // namespace srsepc
#endif // SRSEPC_HSS_H
