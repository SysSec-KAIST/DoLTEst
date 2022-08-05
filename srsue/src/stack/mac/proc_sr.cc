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

#define Error(fmt, ...)   log_h->error(fmt, ##__VA_ARGS__)
#define Warning(fmt, ...) log_h->warning(fmt, ##__VA_ARGS__)
#define Info(fmt, ...)    log_h->info(fmt, ##__VA_ARGS__)
#define Debug(fmt, ...)   log_h->debug(fmt, ##__VA_ARGS__)

#include "srsue/hdr/stack/mac/proc_sr.h"

namespace srsue {

sr_proc::sr_proc() {
  initiated = false;
}

void sr_proc::init(phy_interface_mac_lte* phy_h_, rrc_interface_mac* rrc_, srslte::log* log_h_)
{
  log_h     = log_h_;
  rrc       = rrc_; 
  phy_h     = phy_h_;
  initiated    = true;
  sr_counter   = 0;
  do_ra = false; 
}
  
void sr_proc::reset()
{
  is_pending_sr = false;
}

bool sr_proc::need_tx(uint32_t tti) 
{
  int last_tx_tti = phy_h->sr_last_tx_tti();
  Debug("SR:    need_tx(): last_tx_tti=%d, tti=%d\n", last_tx_tti, tti);
  if (last_tx_tti >= 0)  {
    if (tti > (uint32_t)last_tx_tti) {
      if (tti - last_tx_tti > 8) {
        return true; 
      }
    } else {
      uint32_t interval = 10240-last_tx_tti+tti;
      if (interval > 8 && tti < 8) {
        return true; 
      }
    }
  }
  return false; 
}

void sr_proc::set_config(srsue::mac_interface_rrc::sr_cfg_t& cfg)
{
  sr_cfg = cfg;
}

void sr_proc::step(uint32_t tti)
{
  if (initiated) {
    if (is_pending_sr) {
      if (sr_cfg.enabled) {
        if (sr_counter < sr_cfg.dsr_transmax) {
          if (sr_counter == 0 || need_tx(tti)) {
            sr_counter++;
            Info("SR:    Signalling PHY sr_counter=%d\n", sr_counter);
            phy_h->sr_send();
          }
        } else {
          if (need_tx(tti)) {
            Info("SR:    Releasing PUCCH/SRS resources, sr_counter=%d, dsr_transmax=%d\n",
                 sr_counter,
                 sr_cfg.dsr_transmax);
            log_h->console("Scheduling request failed: releasing RRC connection...\n");
            rrc->release_pucch_srs();
            do_ra = true; 
            is_pending_sr = false; 
          }
        }
      } else {
        Info("SR:    PUCCH not configured. Starting RA procedure\n");
        do_ra = true; 
        reset();
      }
    }
  }
}

bool sr_proc::need_random_access() {
  if (initiated) {
    if (do_ra) {
      do_ra = false; 
      return true; 
    } else {
      return false; 
    }
  }
  return false;
}

void sr_proc::start()
{
  if (initiated) {
    if (!is_pending_sr) {
      sr_counter = 0;
      is_pending_sr = true;
    }
    if (sr_cfg.enabled) {
      Info("SR:    Starting Procedure. dsrTransMax=%d\n", sr_cfg.dsr_transmax);
    }
  }
}

}

