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

#ifndef SRSUE_MAC_H
#define SRSUE_MAC_H

#include "demux.h"
#include "dl_harq.h"
#include "mac_metrics.h"
#include "mux.h"
#include "proc_bsr.h"
#include "proc_phr.h"
#include "proc_ra.h"
#include "proc_sr.h"
#include "srslte/common/log.h"
#include "srslte/common/mac_pcap.h"
#include "srslte/common/threads.h"
#include "srslte/common/timers.h"
#include "srslte/common/tti_sync_cv.h"
#include "srslte/interfaces/ue_interfaces.h"
#include "ul_harq.h"
#include <condition_variable>
#include <mutex>

namespace srsue {

class mac : public mac_interface_phy_lte,
            public mac_interface_rrc,
            public srslte::timer_callback,
            public srslte::mac_interface_timers,
            public mac_interface_demux
{
public:
  mac(srslte::log* log_);
  ~mac();
  bool init(phy_interface_mac_lte* phy, rlc_interface_mac* rlc, rrc_interface_mac* rrc);
  void stop();

  void get_metrics(mac_metrics_t m[SRSLTE_MAX_CARRIERS]);

  /******** Interface from PHY (PHY -> MAC) ****************/
  /* see mac_interface.h for comments */
  void     new_grant_ul(uint32_t cc_idx, mac_grant_ul_t grant, tb_action_ul_t* action);
  void     new_grant_dl(uint32_t cc_idx, mac_grant_dl_t grant, tb_action_dl_t* action);
  void     new_mch_dl(srslte_pdsch_grant_t phy_grant, tb_action_dl_t* action);
  void     tb_decoded(uint32_t cc_idx, mac_grant_dl_t grant, bool ack[SRSLTE_MAX_CODEWORDS]);
  void     bch_decoded_ok(uint8_t* payload, uint32_t len);
  uint16_t get_dl_sched_rnti(uint32_t tti);
  uint16_t get_ul_sched_rnti(uint32_t tti);

  void mch_decoded(uint32_t len, bool crc);
  void process_mch_pdu(uint32_t len);

  void set_mbsfn_config(uint32_t nof_mbsfn_services);

  void run_tti(const uint32_t tti);

  /******** Interface from RRC (RRC -> MAC) ****************/
  void bcch_start_rx(int si_window_start, int si_window_length);
  void bcch_stop_rx();
  void pcch_start_rx();
  void setup_lcid(uint32_t lcid, uint32_t lcg, uint32_t priority, int PBR_x_tti, uint32_t BSD);
  void setup_lcid(const logical_channel_config_t& config);
  void mch_start_rx(uint32_t lcid);
  void reconfiguration(const uint32_t& cc_idx, const bool& enable);
  void reset();
  void wait_uplink();

  /******** set/get MAC configuration  ****************/
  void set_config(mac_cfg_t& mac_cfg);
  void set_contention_id(uint64_t uecri);

  /******* interface from demux object ****************/
  void reset_harq(uint32_t cc_idx);
  bool contention_resolution_id_rcv(uint64_t id);

  void start_noncont_ho(uint32_t preamble_index, uint32_t prach_mask);
  void start_cont_ho();

  void get_rntis(ue_rnti_t *rntis);
  void set_ho_rnti(uint16_t crnti, uint16_t target_pci);

  void start_pcap(srslte::mac_pcap* pcap);

  // Timer callback interface
  void timer_expired(uint32_t timer_id); 

  uint32_t get_current_tti();

  // Interface for upper-layer timers
  srslte::timers::timer* timer_get(uint32_t timer_id);
  void                   timer_release_id(uint32_t timer_id);
  uint32_t               timer_get_unique_id();

private:
  void clear_rntis();

  bool is_in_window(uint32_t tti, int* start, int* len);

  static const int MAC_MAIN_THREAD_PRIO = -1; // Use default high-priority below UHD
  static const int MAC_PDU_THREAD_PRIO  = 5;

  // Interaction with PHY 
  phy_interface_mac_lte    *phy_h;
  rlc_interface_mac    *rlc_h; 
  rrc_interface_mac    *rrc_h; 
  srslte::log          *log_h;
  mac_interface_phy_lte::mac_phy_cfg_mbsfn_t phy_mbsfn_cfg;

  // RNTI search window scheduling
  int si_window_length, si_window_start;
  int ra_window_length, ra_window_start;
  int p_window_start;

  // UE-specific RNTIs
  ue_rnti_t uernti;

  /* Multiplexing/Demultiplexing Units */
  mux           mux_unit;
  demux         demux_unit;

  /* DL/UL HARQ */
  dl_harq_entity_vector dl_harq;
  ul_harq_entity_vector ul_harq;
  ul_harq_cfg_t         ul_harq_cfg;

  /* MAC Uplink-related Procedures */
  ra_proc       ra_procedure;
  sr_proc       sr_procedure; 
  bsr_proc      bsr_procedure; 
  phr_proc      phr_procedure; 
  
  /* Buffers for PCH reception (not included in DL HARQ) */
  const static uint32_t  pch_payload_buffer_sz = 8*1024;
  srslte_softbuffer_rx_t pch_softbuffer;
  uint8_t                pch_payload_buffer[pch_payload_buffer_sz];

  /* Buffers for MCH reception (not included in DL HARQ) */
  const static uint32_t  mch_payload_buffer_sz = SRSLTE_MAX_BUFFER_SIZE_BYTES;
  srslte_softbuffer_rx_t mch_softbuffer;
  uint8_t                mch_payload_buffer[mch_payload_buffer_sz];
  srslte::mch_pdu        mch_msg;

  /* Functions for MAC Timers */
  uint32_t        timer_alignment = 0;
  void            setup_timers(int time_alignment_timer);
  void            timer_alignment_expire();
  srslte::timers  timers;

  // pointer to MAC PCAP object
  srslte::mac_pcap* pcap              = nullptr;
  bool              is_first_ul_grant = false;

  mac_metrics_t metrics[SRSLTE_MAX_CARRIERS] = {};

  bool initialized = false;

  /* Class to process MAC PDUs from DEMUX unit */
  class pdu_process : public thread {
  public:
    explicit pdu_process(demux* demux_unit);
    ~pdu_process();
    void notify();
    void stop();
  private:
    void                    run_thread() final;
    bool                    running   = false;
    bool                    have_data = false;
    std::mutex              mutex;
    std::condition_variable cvar;
    demux*                  demux_unit = nullptr;
  };
  pdu_process pdu_process_thread;
};

} // namespace srsue

#endif // SRSUE_MAC_H
