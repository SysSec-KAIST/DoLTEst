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

#ifndef SRSUE_PROC_RA_H
#define SRSUE_PROC_RA_H

#include <mutex>
#include <stdint.h>

#include "srslte/common/log.h"
#include "srslte/common/timers.h"
#include "mux.h"
#include "demux.h"
#include "srslte/common/pdu.h"
#include "srslte/common/mac_pcap.h"

/* Random access procedure as specified in Section 5.1 of 36.321 */


namespace srsue {

class ra_proc : public srslte::timer_callback
{
public:
  ra_proc() : rar_pdu_msg(20) {
    bzero(&softbuffer_rar, sizeof(srslte_softbuffer_rx_t));
    pcap = NULL;
    backoff_interval_start    = 0;
    backoff_interval          = 0;
    received_target_power_dbm = 0;
    ra_rnti                   = 0;
    current_ta                = 0;
    state                     = IDLE;
    last_msg3_group           = RA_GROUP_A;
    phy_h                     = NULL;
    log_h                     = NULL;
    mux_unit                  = NULL;
    rrc                       = NULL;
    transmitted_contention_id = 0;
    transmitted_crnti         = 0;
    started_by_pdcch          = false;
    rar_grant_nbytes          = 0;

    noncontention_enabled     = false;
    next_preamble_idx         = 0;
    next_prach_mask           = 0;

    time_alignment_timer        = NULL;
    contention_resolution_timer = NULL;
  };

  ~ra_proc();

  void init(phy_interface_mac_lte*        phy_h,
            rrc_interface_mac*            rrc_,
            srslte::log*                  log_h,
            mac_interface_rrc::ue_rnti_t* rntis,
            srslte::timers::timer*        time_alignment_timer_,
            srslte::timers::timer*        contention_resolution_timer_,
            mux*                          mux_unit);

  void reset();

  void set_config(mac_interface_rrc::rach_cfg_t& rach_cfg);

  void start_pdcch_order();
  void start_mac_order(uint32_t msg_len_bits = 56, bool is_ho = false);
  void step(uint32_t tti);

  bool update_rar_window(int* rar_window_start, int* rar_window_length);
  bool is_contention_resolution();
  void harq_retx();
  void harq_max_retx();
  void pdcch_to_crnti(bool is_new_uplink_transmission);
  void timer_expired(uint32_t timer_id);
  void new_grant_dl(mac_interface_phy_lte::mac_grant_dl_t grant, mac_interface_phy_lte::tb_action_dl_t* action);
  void tb_decoded_ok();

  void start_noncont(uint32_t preamble_index, uint32_t prach_mask);
  bool contention_resolution_id_received(uint64_t uecri);
  void start_pcap(srslte::mac_pcap* pcap);

private:
  void state_pdcch_setup();
  void state_response_reception(uint32_t tti);
  void state_backoff_wait(uint32_t tti);
  void state_contention_resolution();
  void state_completition();

  void process_timeadv_cmd(uint32_t ta_cmd);
  void initialization();
  void resource_selection();
  void preamble_transmission();
  void response_error();
  void complete();

  //  Buffer to receive RAR PDU
  static const uint32_t MAX_RAR_PDU_LEN = 2048;
  uint8_t               rar_pdu_buffer[MAX_RAR_PDU_LEN];
  srslte::rar_pdu       rar_pdu_msg;

  // Random Access parameters provided by higher layers defined in 5.1.1
  mac_interface_rrc::rach_cfg_t rach_cfg, new_cfg;

  int      delta_preamble_db;
  uint32_t maskIndex;
  int      preambleIndex;
  uint32_t new_ra_msg_len;

  bool     noncontention_enabled;
  uint32_t next_preamble_idx;
  uint32_t next_prach_mask;

  // Internal variables
  uint32_t preambleTransmissionCounter;
  uint32_t backoff_param_ms;
  uint32_t sel_maskIndex;
  uint32_t sel_preamble;
  int      backoff_interval_start;
  uint32_t backoff_interval;
  int      received_target_power_dbm;
  uint32_t ra_rnti;
  uint32_t ra_tti;
  uint32_t current_ta;

  srslte_softbuffer_rx_t softbuffer_rar;

  enum { IDLE = 0, PDCCH_SETUP, RESPONSE_RECEPTION, BACKOFF_WAIT, CONTENTION_RESOLUTION, COMPLETITION } state;

  typedef enum { RA_GROUP_A, RA_GROUP_B } ra_group_t;

  ra_group_t last_msg3_group;

  uint32_t rar_window_st;

  void read_params();

  phy_interface_mac_lte* phy_h;
  srslte::log*       log_h;
  mux               *mux_unit;
  srslte::mac_pcap  *pcap;
  rrc_interface_mac *rrc;

  srslte::timers::timer  *time_alignment_timer;
  srslte::timers::timer  *contention_resolution_timer;

  mac_interface_rrc::ue_rnti_t *rntis;

  uint64_t    transmitted_contention_id;
  uint16_t    transmitted_crnti;

  std::mutex mutex;

  bool ra_is_ho;
  bool started_by_pdcch;
  uint32_t rar_grant_nbytes;
  bool rar_received;
};

} // namespace srsue

#endif // SRSUE_PROC_RA_H
