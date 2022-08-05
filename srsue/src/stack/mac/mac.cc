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

#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <unistd.h>

#include "srslte/common/log.h"
#include "srslte/common/pcap.h"
#include "srsue/hdr/stack/mac/mac.h"

using namespace asn1::rrc;

namespace srsue {

mac::mac(srslte::log* log_) :
  timers(64),
  pdu_process_thread(&demux_unit),
  mch_msg(10, log_),
  mux_unit(log_),
  demux_unit(log_),
  pcap(nullptr),
  log_h(log_)
{
  // Create PCell HARQ entities
  auto ul = ul_harq_entity_ptr(new ul_harq_entity());
  auto dl = dl_harq_entity_ptr(new dl_harq_entity());

  ul_harq.clear();
  dl_harq.clear();

  ul_harq.push_back(std::move(ul));
  dl_harq.push_back(std::move(dl));

  srslte_softbuffer_rx_init(&pch_softbuffer, 100);
  srslte_softbuffer_rx_init(&mch_softbuffer, 100);

  // Keep initialising members
  bzero(&metrics, sizeof(mac_metrics_t));
  clear_rntis();
}

mac::~mac()
{
  stop();

  srslte_softbuffer_rx_free(&pch_softbuffer);
  srslte_softbuffer_rx_free(&mch_softbuffer);
}

bool mac::init(phy_interface_mac_lte* phy, rlc_interface_mac* rlc, rrc_interface_mac* rrc)
{
  phy_h = phy;
  rlc_h = rlc;
  rrc_h = rrc;

  timer_alignment                      = timers.get_unique_id();
  uint32_t contention_resolution_timer = timers.get_unique_id();

  bsr_procedure.init(rlc_h, log_h, &timers);
  phr_procedure.init(phy_h, log_h, &timers);
  mux_unit.init(rlc_h, &bsr_procedure, &phr_procedure);
  demux_unit.init(phy_h, rlc_h, this, timers.get(timer_alignment));
  ra_procedure.init(
      phy_h, rrc, log_h, &uernti, timers.get(timer_alignment), timers.get(contention_resolution_timer), &mux_unit);
  sr_procedure.init(phy_h, rrc, log_h);

  // Create UL/DL unique HARQ pointers
  ul_harq.at(0)->init(log_h, &uernti, &ra_procedure, &mux_unit);
  dl_harq.at(0)->init(log_h, &uernti, timers.get(timer_alignment), &demux_unit);

  reset();

  initialized = true;

  return true;
}

void mac::stop()
{
  if (initialized) {
    pdu_process_thread.stop();
    run_tti(0); // make sure it's not locked after last TTI
    initialized = false;
  }
}

void mac::start_pcap(srslte::mac_pcap* pcap_)
{
  pcap = pcap_;
  for (auto& r : dl_harq) {
    r->start_pcap(pcap);
  }
  for (auto& r : ul_harq) {
    r->start_pcap(pcap);
  }
  ra_procedure.start_pcap(pcap);
}

// FIXME: Change the function name and implement reconfiguration as in specs
// Implement Section 5.8
void mac::reconfiguration(const uint32_t& cc_idx, const bool& enable)
{
  if (cc_idx < SRSLTE_MAX_CARRIERS) {
    // Create as many HARQ entities as carriers required
    while (ul_harq.size() < cc_idx + 1) {
      auto ul = ul_harq_entity_ptr(new ul_harq_entity());
      ul->init(log_h, &uernti, &ra_procedure, &mux_unit);
      ul->set_config(ul_harq_cfg);
      ul_harq.push_back(std::move(ul));
    }
    while (dl_harq.size() < cc_idx + 1) {
      auto dl = dl_harq_entity_ptr(new dl_harq_entity());
      dl->init(log_h, &uernti, timers.get(timer_alignment), &demux_unit);

      if (pcap) {
        dl->start_pcap(pcap);
      }

      dl_harq.push_back(std::move(dl));
    }
  }
}

void mac::wait_uplink() {
  int cnt=0;
  Info("Waiting to uplink...\n");
  while(mux_unit.is_pending_any_sdu() && cnt<20) {
    usleep(1000);
    cnt++;
  }
}

// Implement Section 5.9
void mac::reset()
{
  bzero(&metrics, sizeof(mac_metrics_t));

  Info("Resetting MAC\n");

  timers.get(timer_alignment)->stop();

  timer_alignment_expire();

  for (auto& r : dl_harq) {
    r->reset();
  }
  for (auto& r : ul_harq) {
    r->reset();
  }

  mux_unit.msg3_flush();
  mux_unit.reset();

  ra_procedure.reset();
  sr_procedure.reset();
  bsr_procedure.reset();
  phr_procedure.reset();

  // Setup default LCID 0 with highest priority
  logical_channel_config_t config = {};
  config.lcid                     = 0;
  config.lcg                      = 0;
  config.PBR                      = -1;
  config.BSD                      = 50;
  config.priority                 = 0;
  setup_lcid(config);

  // and LCID 1 with lower priority
  config.lcid     = 1;
  config.priority = 1;
  setup_lcid(config);

  mux_unit.print_logical_channel_state("After MAC reset:");
  is_first_ul_grant = true;

  clear_rntis();
}

void mac::run_tti(const uint32_t tti)
{
  log_h->step(tti);

  /* Warning: Here order of invocation of procedures is important!! */

  // Step all procedures
  Debug("Running MAC tti=%d\n", tti);
  mux_unit.step(tti);
  bsr_procedure.step(tti);
  phr_procedure.step(tti);

  // Check if BSR procedure need to start SR
  if (bsr_procedure.need_to_send_sr(tti)) {
    Debug("Starting SR procedure by BSR request, PHY TTI=%d\n", tti);
    sr_procedure.start();
  }
  if (bsr_procedure.need_to_reset_sr()) {
    Debug("Resetting SR procedure by BSR request\n");
    sr_procedure.reset();
  }
  sr_procedure.step(tti);

  // Check SR if we need to start RA
  if (sr_procedure.need_random_access()) {
    ra_procedure.start_mac_order();
  }

  ra_procedure.step(tti);
  ra_window_start  = -1;
  ra_window_length = -1;
  ra_procedure.update_rar_window(&ra_window_start, &ra_window_length);
  timers.step_all();
}

void mac::bcch_start_rx(int si_window_start, int si_window_length)
{
  if (si_window_length >= 0 && si_window_start >= 0) {
    dl_harq.at(0)->set_si_window_start(si_window_start);
    this->si_window_length = si_window_length;
    this->si_window_start  = si_window_start;
  } else {
    this->si_window_length = 0;
    this->si_window_start  = 0;
  }
  Info("SCHED: Searching for DL dci for SI-RNTI window_st=%d, window_len=%d\n", si_window_start, si_window_length);
}

void mac::bcch_stop_rx()
{
  bcch_start_rx(-1, -1);
}

void mac::pcch_start_rx()
{
  this->p_window_start = 1;
}

void mac::clear_rntis()
{
  p_window_start  = 0;
  si_window_start = 0;
  ra_window_start  = -1;
  ra_window_length = -1;
  bzero(&uernti, sizeof(ue_rnti_t));
}

void mac::get_rntis(ue_rnti_t* rntis)
{
  if (rntis) {
    *rntis = uernti;
  }
}

void mac::set_ho_rnti(uint16_t crnti, uint16_t target_pci)
{
  uernti.crnti = crnti;
  if (pcap) {
    pcap->set_ue_id(target_pci);
  }
}

uint16_t mac::get_ul_sched_rnti(uint32_t tti)
{
  if (uernti.temp_rnti && !uernti.crnti) {
    return uernti.temp_rnti;
  }
  if (uernti.crnti) {
    return uernti.crnti;
  }
  return 0;
}

bool mac::is_in_window(uint32_t tti, int* start, int* len)
{
  uint32_t st = (uint32_t)*start;
  uint32_t l  = (uint32_t)*len;

  if (srslte_tti_interval(tti, st) < l + 5) {
    if (tti > st) {
      if (tti <= st + l) {
        return true;
      } else {
        *start = 0;
        *len   = 0;
        return false;
      }
    } else {
      if (tti <= (st + l) % 10240) {
        return true;
      } else {
        *start = 0;
        *len   = 0;
        return false;
      }
    }
  }
  return false;
}

uint16_t mac::get_dl_sched_rnti(uint32_t tti)
{
  // Priority: SI-RNTI, P-RNTI, RA-RNTI, Temp-RNTI, CRNTI
  if (si_window_start > 0) {
    if (is_in_window(tti, &si_window_start, &si_window_length)) {
      // FIXME: This scheduling decision belongs to RRC
      if (si_window_length > 1) {                     // This is not a SIB1
        if ((tti / 10) % 2 == 0 && (tti % 10) == 5) { // Skip subframe #5 for which SFN mod 2 = 0
          return 0;
        }
      }
      Debug("SCHED: Searching SI-RNTI, tti=%d, window start=%d, length=%d\n", tti, si_window_start, si_window_length);
      return SRSLTE_SIRNTI;
    }
  }
  if (ra_window_start > 0 && ra_window_length > 0 && is_in_window(tti, &ra_window_start, &ra_window_length)) {
    Debug("SCHED: Searching RAR-RNTI=0x%x, tti=%d\n", uernti.rar_rnti, tti);
    return uernti.rar_rnti;
  }
  if (uernti.temp_rnti && !uernti.crnti) {
    Debug("SCHED: Searching Temp-RNTI=0x%x\n", uernti.temp_rnti);
    return uernti.temp_rnti;
  }
  if (uernti.crnti) {
    Debug("SCHED: Searching C-RNTI=0x%x\n", uernti.crnti);
    return uernti.crnti;
  }
  if (p_window_start > 0) {
    Debug("SCHED: Searching P-RNTI\n");
    return SRSLTE_PRNTI;
  }
  return 0;
}

void mac::bch_decoded_ok(uint8_t* payload, uint32_t len)
{
  // Send MIB to RLC
  rlc_h->write_pdu_bcch_bch(payload, len);

  if (pcap) {
    pcap->write_dl_bch(payload, len, true, phy_h->get_current_tti());
  }
}

void mac::mch_decoded(uint32_t len, bool crc)
{
  // Parse MAC header
  if (crc) {
    mch_msg.init_rx(len);
    mch_msg.parse_packet(mch_payload_buffer);
    while (mch_msg.next()) {
      for (uint32_t i = 0; i < phy_mbsfn_cfg.nof_mbsfn_services; i++) {
        if (srslte::sch_subh::MCH_SCHED_INFO == mch_msg.get()->ce_type()) {
          uint16_t stop;
          uint8_t  lcid;
          if (mch_msg.get()->get_next_mch_sched_info(&lcid, &stop)) {
            phy_h->set_mch_period_stop(stop);
            Info("MCH Sched Info: LCID: %d, Stop: %d, tti is %d \n", lcid, stop, phy_h->get_current_tti());
          }
        }
      }
    }

    demux_unit.push_pdu_mch(mch_payload_buffer, len);
    pdu_process_thread.notify();
    if (pcap) {
      pcap->write_dl_mch(mch_payload_buffer, len, true, phy_h->get_current_tti());
    }
    metrics[0].rx_brate += len * 8;
  } else {
    metrics[0].rx_errors++;
  }
  metrics[0].rx_pkts++;
}

void mac::tb_decoded(uint32_t cc_idx, mac_grant_dl_t grant, bool ack[SRSLTE_MAX_CODEWORDS])
{
  if (SRSLTE_RNTI_ISRAR(grant.rnti)) {
    if (ack[0]) {
      ra_procedure.tb_decoded_ok();
    }
  } else if (grant.rnti == SRSLTE_PRNTI) {
    // Send PCH payload to RLC
    rlc_h->write_pdu_pcch(pch_payload_buffer, grant.tb[0].tbs);

    if (pcap) {
      pcap->write_dl_pch(pch_payload_buffer, grant.tb[0].tbs, true, phy_h->get_current_tti());
    }
  } else {

    dl_harq.at(cc_idx)->tb_decoded(grant, ack);
    pdu_process_thread.notify();

    for (uint32_t tb = 0; tb < SRSLTE_MAX_CODEWORDS; tb++) {
      if (grant.tb[tb].tbs) {
        if (ack[tb]) {
          metrics[cc_idx].rx_brate += grant.tb[tb].tbs * 8;
        } else {
          metrics[cc_idx].rx_errors++;
        }
        metrics[cc_idx].rx_pkts++;
      }
    }
  }
}

void mac::new_grant_dl(uint32_t                               cc_idx,
                       mac_interface_phy_lte::mac_grant_dl_t  grant,
                       mac_interface_phy_lte::tb_action_dl_t* action)
{
  if (SRSLTE_RNTI_ISRAR(grant.rnti)) {
    ra_procedure.new_grant_dl(grant, action);
  } else if (grant.rnti == SRSLTE_PRNTI) {

    bzero(action, sizeof(mac_interface_phy_lte::tb_action_dl_t));
    if (grant.tb[0].tbs > pch_payload_buffer_sz) {
      Error("Received dci for PCH (%d bytes) exceeds buffer (%d bytes)\n", grant.tb[0].tbs, pch_payload_buffer_sz);
      action->tb[0].enabled = false;
    } else {
      action->tb[0].enabled       = true;
      action->tb[0].payload       = pch_payload_buffer;
      action->tb[0].softbuffer.rx = &pch_softbuffer;
      action->tb[0].rv            = grant.tb[0].rv;
      srslte_softbuffer_rx_reset_cb(&pch_softbuffer, 1);
    }
  } else if (!(grant.rnti == SRSLTE_SIRNTI && cc_idx != 0)) {
    // If PDCCH for C-RNTI and RA procedure in Contention Resolution, notify it
    if (grant.rnti == uernti.crnti && ra_procedure.is_contention_resolution()) {
      ra_procedure.pdcch_to_crnti(false);
    }
    dl_harq.at(cc_idx)->new_grant_dl(grant, action);
  } else {
    /* Discard */
    Info("Discarding dci in CC %d, RNTI=0x%x\n", cc_idx, grant.rnti);
  }
}

uint32_t mac::get_current_tti()
{
  return phy_h->get_current_tti();
}

void mac::reset_harq(uint32_t cc_idx)
{
  if (cc_idx < dl_harq.size()) {
    dl_harq.at(cc_idx)->reset();
    ul_harq.at(cc_idx)->reset();
  }
}

bool mac::contention_resolution_id_rcv(uint64_t id)
{
  return ra_procedure.contention_resolution_id_received(id);
}

void mac::new_grant_ul(uint32_t                               cc_idx,
                       mac_interface_phy_lte::mac_grant_ul_t  grant,
                       mac_interface_phy_lte::tb_action_ul_t* action)
{
  /* Start PHR Periodic timer on first UL dci */
  if (is_first_ul_grant) {
    is_first_ul_grant = false;
    phr_procedure.start_timer();
  }
  ul_harq.at(cc_idx)->new_grant_ul(grant, action);
  metrics[cc_idx].tx_pkts++;

  if (grant.phich_available) {
    if (!grant.hi_value) {
      metrics[cc_idx].tx_errors++;
    } else {
      metrics[cc_idx].tx_brate += ul_harq.at(cc_idx)->get_current_tbs(grant.pid) * 8;
    }
  }
}

void mac::new_mch_dl(srslte_pdsch_grant_t phy_grant, tb_action_dl_t* action)
{
  action->generate_ack        = false;
  action->tb[0].enabled       = true;
  action->tb[0].payload       = mch_payload_buffer;
  action->tb[0].softbuffer.rx = &mch_softbuffer;
  srslte_softbuffer_rx_reset_cb(&mch_softbuffer, 1);
}

void mac::setup_timers(int time_alignment_timer)
{
  // stop currently running time alignment timer
  if (timers.get(timer_alignment)->is_running()) {
    timers.get(timer_alignment)->stop();
  }

  if (time_alignment_timer > 0) {
    timers.get(timer_alignment)->set(this, time_alignment_timer);
  }
}

void mac::timer_expired(uint32_t timer_id)
{
  if(timer_id == timer_alignment) {
    timer_alignment_expire();
  } else {
    Warning("Received callback from unknown timer_id=%d\n", timer_id);
  }
}

/* Function called on expiry of TimeAlignmentTimer */
void mac::timer_alignment_expire()
{
  rrc_h->release_pucch_srs();
  for (auto& r : dl_harq) {
    r->reset();
  }
  for (auto& r : ul_harq) {
    r->reset();
  }
}

void mac::set_contention_id(uint64_t uecri)
{
  uernti.contention_id = uecri;
}

void mac::start_noncont_ho(uint32_t preamble_index, uint32_t prach_mask)
{
  ra_procedure.start_noncont(preamble_index, prach_mask);
}

void mac::start_cont_ho()
{
  ra_procedure.start_mac_order(56, true);
}

void mac::set_mbsfn_config(uint32_t nof_mbsfn_services)
{
  // ul_cfg->nof_mbsfn_services = config.mbsfn.mcch.pmch_infolist_r9[0].mbms_sessioninfolist_r9_size;
  phy_mbsfn_cfg.nof_mbsfn_services = nof_mbsfn_services;
}

void mac::set_config(mac_cfg_t& mac_cfg)
{
  // Set configuration for each module in MAC
  bsr_procedure.set_config(mac_cfg.get_bsr_cfg());
  phr_procedure.set_config(mac_cfg.get_phr_cfg());
  sr_procedure.set_config(mac_cfg.get_sr_cfg());
  ra_procedure.set_config(mac_cfg.get_rach_cfg());
  ul_harq_cfg = mac_cfg.get_harq_cfg();
  for (auto& i : ul_harq) {
    if (i != nullptr) {
      i->set_config(ul_harq_cfg);
    }
  }
  setup_timers(mac_cfg.get_time_alignment_timer());
}

void mac::setup_lcid(uint32_t lcid, uint32_t lcg, uint32_t priority, int PBR_x_tti, uint32_t BSD)
{
  logical_channel_config_t config = {};
  config.lcid                     = lcid;
  config.lcg                      = lcg;
  config.priority                 = priority;
  config.PBR                      = PBR_x_tti;
  config.BSD                      = BSD;
  config.bucket_size              = config.PBR * config.BSD;
  setup_lcid(config);
}

void mac::setup_lcid(const logical_channel_config_t& config)
{
  Info("Logical Channel Setup: LCID=%d, LCG=%d, priority=%d, PBR=%d, BSD=%dms, bucket_size=%d\n",
       config.lcid,
       config.lcg,
       config.priority,
       config.PBR,
       config.BSD,
       config.bucket_size);
  mux_unit.setup_lcid(config);
  bsr_procedure.setup_lcid(config.lcid, config.lcg, config.priority);
}

void mac::mch_start_rx(uint32_t lcid)
{
  demux_unit.mch_start_rx(lcid);
}

void mac::get_metrics(mac_metrics_t m[SRSLTE_MAX_CARRIERS])
{
  int   tx_pkts          = 0;
  int   tx_errors        = 0;
  int   tx_brate         = 0;
  int   rx_pkts          = 0;
  int   rx_errors        = 0;
  int   rx_brate         = 0;
  int   ul_buffer        = 0;
  float dl_avg_ret       = 0;
  float ul_avg_ret       = 0;
  int   dl_avg_ret_count = 0;
  int   ul_avg_ret_count = 0;

  for (uint32_t r = 0; r < dl_harq.size(); r++) {
    tx_pkts += metrics[r].tx_pkts;
    tx_errors += metrics[r].tx_errors;
    tx_brate += metrics[r].tx_brate;
    rx_pkts += metrics[r].rx_pkts;
    rx_errors += metrics[r].rx_errors;
    rx_brate += metrics[r].rx_brate;
    ul_buffer += metrics[r].ul_buffer;

    if (metrics[r].rx_pkts) {
      dl_avg_ret += dl_harq.at(r)->get_average_retx();
      dl_avg_ret_count++;
    }
  }

  if (dl_avg_ret_count) {
    dl_avg_ret /= dl_avg_ret_count;
  }

  Info("DL retx: %.2f \%%, perpkt: %.2f, UL retx: %.2f \%% perpkt: %.2f\n",
       rx_pkts ? ((float)100 * rx_errors / rx_pkts) : 0.0f,
       dl_avg_ret,
       tx_pkts ? ((float)100 * tx_errors / tx_pkts) : 0.0f,
       ul_harq.at(0)->get_average_retx());

  metrics[0].ul_buffer = (int)bsr_procedure.get_buffer_state();
  memcpy(m, metrics, sizeof(mac_metrics_t) * SRSLTE_MAX_CARRIERS);
  m = metrics;
  bzero(&metrics, sizeof(mac_metrics_t) * SRSLTE_MAX_CARRIERS);
}




/********************************************************
 *
 * Interface for timers used by upper layers
 *
 *******************************************************/
srslte::timers::timer* mac::timer_get(uint32_t timer_id)
{
  return timers.get(timer_id);
}

void mac::timer_release_id(uint32_t timer_id)
{
  timers.release_id(timer_id);
}

uint32_t mac::timer_get_unique_id()
{
  return timers.get_unique_id();
}


/********************************************************
 *
 * Class that runs a thread to process DL MAC PDUs from
 * DEMUX unit
 *
 *******************************************************/
mac::pdu_process::pdu_process(demux* demux_unit_) : thread("MAC_PDU_PROCESS"), demux_unit(demux_unit_)
{
  running = true;
  start(MAC_PDU_THREAD_PRIO);
}

mac::pdu_process::~pdu_process()
{
  if (running) {
    stop();
  }
}

void mac::pdu_process::stop()
{
  if (running) {
    {
      std::lock_guard<std::mutex> ul(mutex);
      running = false;
      cvar.notify_all();
    }
    wait_thread_finish();
  }
}

void mac::pdu_process::notify()
{
  std::unique_lock<std::mutex> ul(mutex);
  have_data = true;
  cvar.notify_all();
}

void mac::pdu_process::run_thread()
{
  while(running) {
    have_data = demux_unit->process_pdus();
    if (!have_data) {
      std::unique_lock<std::mutex> ul(mutex);
      while(!have_data && running) {
        cvar.wait(ul);
      }
    }
  }
}

}



