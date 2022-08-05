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

#ifndef SRSUE_PHY_H
#define SRSUE_PHY_H

#include "phy_common.h"
#include "phy_metrics.h"
#include "prach.h"
#include "scell/async_scell_recv.h"
#include "sf_worker.h"
#include "srslte/common/log_filter.h"
#include "srslte/common/trace.h"
#include "srslte/interfaces/common_interfaces.h"
#include "srslte/interfaces/ue_interfaces.h"
#include "srslte/radio/radio.h"
#include "srslte/srslte.h"
#include "srsue/hdr/phy/ue_lte_phy_base.h"
#include "sync.h"

namespace srsue {

typedef _Complex float cf_t;

class phy : public ue_lte_phy_base, public thread
{
public:
  phy(srslte::logger* logger_) : logger(logger_), workers_pool(MAX_WORKERS), common(MAX_WORKERS), thread("PHY"){};
  ~phy() { stop(); }

  // Init defined in base class
  int init(const phy_args_t& args_) final;

  // Init for LTE PHYs
  int init(const phy_args_t&            args_,
           stack_interface_phy_lte*     stack_,
           srslte::radio_interface_phy* radio_) final;

  void stop() final;

  void wait_initialize() final;
  bool is_initiated();

  void get_metrics(phy_metrics_t* m) final;
  void srslte_phy_logger(phy_logger_level_t log_level, char *str);

  void enable_pregen_signals(bool enable) final;

  void set_earfcn(std::vector<uint32_t> earfcns) final;

  void radio_overflow() final;
  void radio_failure() final;

  /********** RRC INTERFACE ********************/
  void              reset() final;
  cell_search_ret_t cell_search(phy_cell_t* cell) final;
  bool              cell_select(phy_cell_t* cell) final;

  void meas_reset() final;
  int  meas_start(uint32_t earfcn, int pci) final;
  int  meas_stop(uint32_t earfcn, int pci) final;

  // also MAC interface
  bool cell_is_camping() final;

  /********** MAC INTERFACE ********************/
  /* Sets a C-RNTI allowing the PHY to pregenerate signals if necessary */
  void set_crnti(uint16_t rnti) final;

  /* Instructs the PHY to configure using the parameters written by set_param() */
  void configure_prach_params() final;

  /* Transmits PRACH in the next opportunity */
  void         prach_send(uint32_t preamble_idx, int allowed_subframe, float target_power_dbm) final;
  prach_info_t prach_get_info() final;

  /* Indicates the transmission of a SR signal in the next opportunity */
  void sr_send() final;
  int  sr_last_tx_tti() final;

  // Time advance commands
  void set_timeadv_rar(uint32_t ta_cmd) final;
  void set_timeadv(uint32_t ta_cmd) final;

  /* Activate / Disactivate SCell*/
  void set_activation_deactivation_scell(uint32_t ta_cmd) final;

  /* Sets RAR dci payload */
  void set_rar_grant(uint8_t grant_payload[SRSLTE_RAR_GRANT_LEN], uint16_t rnti) final;

  /* Get/Set PHY parameters interface from RRC */
  void set_config(phy_cfg_t* phy_cfg) final;
  void set_config_scell(asn1::rrc::scell_to_add_mod_r10_s* scell_config) final;
  void set_config_tdd(asn1::rrc::tdd_cfg_s* tdd) final;
  void set_config_mbsfn_sib2(asn1::rrc::sib_type2_s* sib2) final;
  void set_config_mbsfn_sib13(asn1::rrc::sib_type13_r9_s* sib13) final;
  void set_config_mbsfn_mcch(asn1::rrc::mcch_msg_s* mcch) final;

  /*Set MAC->PHY MCH period  stopping point*/
  void set_mch_period_stop(uint32_t stop) final;

  float get_phr() final;
  float get_pathloss_db() final;

  uint32_t get_current_tti() final;

  void     get_current_cell(srslte_cell_t* cell, uint32_t* current_earfcn) final;
  uint32_t get_current_earfcn() final;
  uint32_t get_current_pci() final;

  void start_plot() final;

  const static int MAX_WORKERS     = 4;
  const static int DEFAULT_WORKERS = 4;

  std::string get_type() final { return "lte_soft"; }

private:
  void run_thread() final;

  bool     initiated   = false;
  uint32_t nof_workers = 0;

  const static int SF_RECV_THREAD_PRIO = 1;
  const static int WORKERS_THREAD_PRIO = 2;

  srslte::radio_interface_phy*                              radio = nullptr;
  std::vector<std::unique_ptr<srslte::log_filter> > log_vec;
  srslte::logger*                                   logger = nullptr;

  srslte::log*                    log_h         = nullptr;
  srslte::log*                    log_phy_lib_h = nullptr;
  srsue::stack_interface_phy_lte* stack         = nullptr;

  srslte::thread_pool      workers_pool;
  std::vector<std::unique_ptr<sf_worker> > workers;
  phy_common               common;
  sync                     sfsync;
  scell::async_recv_vector scell_sync;
  prach                   prach_buffer;

  srslte_prach_cfg_t  prach_cfg  = {};
  srslte_tdd_config_t tdd_config = {};

  phy_interface_rrc_lte::phy_cfg_t config = {};
  phy_args_t                       args   = {};

  /* Current time advance */
  uint32_t n_ta = 0;

  void set_default_args(phy_args_t *args);
  bool check_args(const phy_args_t& args);
};

} // namespace srsue

#endif // SRSUE_PHY_H
