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

#ifndef SRSUE_PROC_BSR_H
#define SRSUE_PROC_BSR_H

#include <map>
#include <stdint.h>

#include "srslte/common/log.h"
#include "srslte/interfaces/ue_interfaces.h"
#include "srslte/common/timers.h"

/* Buffer status report procedure */

namespace srsue {

class bsr_proc : public srslte::timer_callback, public bsr_interface_mux
{
public:
  bsr_proc();
  void init(rlc_interface_mac* rlc, srslte::log* log_h, srslte::timers* timers_db);
  void step(uint32_t tti);  
  void reset();
  void set_config(mac_interface_rrc::bsr_cfg_t& bsr_cfg);

  void     setup_lcid(uint32_t lcid, uint32_t lcg, uint32_t priority);
  void timer_expired(uint32_t timer_id);
  uint32_t get_buffer_state();
  bool need_to_send_bsr_on_ul_grant(uint32_t grant_size, bsr_t *bsr); 
  bool generate_padding_bsr(uint32_t nof_padding_bytes, bsr_t *bsr);
  bool need_to_send_sr(uint32_t tti);
  bool     need_to_reset_sr();

private:
  const static int QUEUE_STATUS_PERIOD_MS = 1000;

  pthread_mutex_t mutex;

  bool              reset_sr;
  srslte::timers    *timers_db;
  srslte::log       *log_h;
  rlc_interface_mac *rlc;

  mac_interface_rrc::bsr_cfg_t bsr_cfg;

  bool              initiated;

  const static int NOF_LCG = 4;

  typedef struct {
    int      priority;
    uint32_t old_buffer;
    uint32_t new_buffer;
  } lcid_t;

  std::map<uint32_t, lcid_t> lcgs[NOF_LCG]; // groups LCID in LCG

  uint32_t find_max_priority_lcg();
  typedef enum {NONE, REGULAR, PADDING, PERIODIC} triggered_bsr_type_t;
  triggered_bsr_type_t triggered_bsr_type; 
  
  bool sr_is_sent;
  uint32_t last_print;
  uint32_t current_tti;
  uint32_t trigger_tti;

  void     set_trigger(triggered_bsr_type_t new_trigger);
  void     update_new_data();
  void     update_buffer_state();
  bool     check_highest_channel();
  bool     check_new_data();
  bool     check_any_channel();
  uint32_t get_buffer_state_lcg(uint32_t lcg);
  bool     generate_bsr(bsr_t* bsr, uint32_t nof_padding_bytes);
  char* bsr_type_tostring(triggered_bsr_type_t type); 
  char* bsr_format_tostring(bsr_format_t format);

  uint32_t timer_periodic_id;
  uint32_t timer_retx_id;
};

} // namespace srsue

#endif // SRSUE_PROC_BSR_H
