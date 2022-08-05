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

#include "srslte/srslte.h"
#include "srsue/hdr/phy/sf_worker.h"
#include "srslte/interfaces/ue_interfaces.h"
#include <string.h>
#include <unistd.h>

#define Error(fmt, ...)                                                                                                \
  if (SRSLTE_DEBUG_ENABLED)                                                                                            \
  log_h->error(fmt, ##__VA_ARGS__)
#define Warning(fmt, ...)                                                                                              \
  if (SRSLTE_DEBUG_ENABLED)                                                                                            \
  log_h->warning(fmt, ##__VA_ARGS__)
#define Info(fmt, ...)                                                                                                 \
  if (SRSLTE_DEBUG_ENABLED)                                                                                            \
  log_h->info(fmt, ##__VA_ARGS__)
#define Debug(fmt, ...)                                                                                                \
  if (SRSLTE_DEBUG_ENABLED)                                                                                            \
  log_h->debug(fmt, ##__VA_ARGS__)

/* This is to visualize the channel response */
#ifdef ENABLE_GUI
#include "srsgui/srsgui.h"
#include <semaphore.h>

void       init_plots(srsue::sf_worker* worker);
pthread_t  plot_thread;
sem_t      plot_sem;
static int plot_worker_id = -1;
#else
#pragma message "Compiling without srsGUI support"
#endif
/*********************************************/

namespace srsue {

sf_worker::sf_worker(uint32_t            max_prb,
                     phy_common*         phy_,
                     srslte::log*        log_h_,
                     srslte::log*        log_phy_lib_h_,
                     chest_feedback_itf* chest_loop_)
{
  cell_initiated      = false;
  phy                 = phy_;
  log_h               = log_h_;
  log_phy_lib_h       = log_phy_lib_h_;
  chest_loop          = chest_loop_;

  bzero(&tdd_config, sizeof(srslte_tdd_config_t));

  // ue_sync in phy.cc requires a buffer for 3 subframes
  for (uint32_t r = 0; r < phy->args->nof_carriers; r++) {
    cc_workers.push_back(new cc_worker(r, max_prb, phy, log_h));
  }

  pthread_mutex_init(&mutex, NULL);
  reset_();
}

sf_worker::~sf_worker()
{
  for (uint32_t r = 0; r < phy->args->nof_carriers; r++) {
    delete cc_workers[r];
  }
  pthread_mutex_destroy(&mutex);
}

void sf_worker::reset()
{
  pthread_mutex_lock(&mutex);
  reset_();
  pthread_mutex_unlock(&mutex);
}

void sf_worker::reset_()
{
  rssi_read_cnt = 0;
  for (uint32_t i = 0; i < cc_workers.size(); i++) {
    cc_workers[i]->reset();
  }
}

bool sf_worker::set_cell(uint32_t cc_idx, srslte_cell_t cell)
{
  bool ret = false;
  pthread_mutex_lock(&mutex);

  if (cc_idx < cc_workers.size()) {
    if (!cc_workers[cc_idx]->set_cell(cell)) {
      Error("Setting cell for cc=%d\n", cc_idx);
      goto unlock;
    }
  } else {
    Error("Setting cell for cc=%d; Not enough CC workers (%ld);\n", cc_idx, cc_workers.size());
  }

  if (cc_idx == 0) {
    this->cell     = cell;
    cell_initiated = true;
  }
  ret = true;

unlock:
  pthread_mutex_unlock(&mutex);
  return ret;
}

cf_t* sf_worker::get_buffer(uint32_t carrier_idx, uint32_t antenna_idx)
{
  return cc_workers[carrier_idx]->get_rx_buffer(antenna_idx);
}

void sf_worker::set_tti(uint32_t tti, uint32_t tx_worker_cnt)
{
  for (uint32_t cc_idx = 0; cc_idx < cc_workers.size(); cc_idx++) {
    cc_workers[cc_idx]->set_tti(tti);
  }

  this->tti = tti;

  tx_sem_id = tx_worker_cnt;
  log_h->step(tti);

  if (log_phy_lib_h) {
    log_phy_lib_h->step(tti);
  }
}

void sf_worker::set_tx_time(uint32_t radio_idx, srslte_timestamp_t tx_time, int next_offset)
{
  this->next_offset[radio_idx] = next_offset;
  this->tx_time[radio_idx]     = tx_time;
}

void sf_worker::set_prach(cf_t* prach_ptr, float prach_power)
{
  this->prach_ptr   = prach_ptr;
  this->prach_power = prach_power;
}

void sf_worker::set_cfo(const uint32_t& cc_idx, float cfo)
{
  cc_workers[cc_idx]->set_cfo(cfo);
}

void sf_worker::set_crnti(uint16_t rnti)
{
  for (uint32_t cc_idx = 0; cc_idx < cc_workers.size(); cc_idx++) {
    cc_workers[cc_idx]->set_crnti(rnti);
  }
}

void sf_worker::set_tdd_config(srslte_tdd_config_t config)
{
  for (uint32_t cc_idx = 0; cc_idx < cc_workers.size(); cc_idx++) {
    cc_workers[cc_idx]->set_tdd_config(config);
  }
  tdd_config = config;
}

void sf_worker::enable_pregen_signals(bool enabled)
{
  for (uint32_t cc_idx = 0; cc_idx < cc_workers.size(); cc_idx++) {
    cc_workers[cc_idx]->enable_pregen_signals(enabled);
  }
}

void sf_worker::set_pcell_config(srsue::phy_interface_rrc_lte::phy_cfg_t* phy_cfg)
{
  pthread_mutex_lock(&mutex);
  Info("Setting PCell configuration for cc_worker=%d, cc=%d\n", get_id(), 0);
  cc_workers[0]->set_pcell_config(phy_cfg);
  pthread_mutex_unlock(&mutex);
}

void sf_worker::set_scell_config(uint32_t cc_idx, asn1::rrc::scell_to_add_mod_r10_s* scell_config)
{
  pthread_mutex_lock(&mutex);
  if (cc_idx < cc_workers.size()) {
    Info("Setting SCell configuration for cc_worker=%d, cc=%d\n", get_id(), cc_idx);
    cc_workers[cc_idx]->set_scell_config(scell_config);
  } else {
    Error("Setting scell config for cc=%d; Not enough CC workers;\n", cc_idx);
  }
  pthread_mutex_unlock(&mutex);
}

void sf_worker::work_imp()
{
  if (!cell_initiated) {
    return;
  }

  pthread_mutex_lock(&mutex);

  /***** Downlink Processing *******/

  bool rx_signal_ok = false;

  // Loop through all carriers. carrier_idx=0 is PCell
  for (uint32_t carrier_idx = 0; carrier_idx < cc_workers.size(); carrier_idx++) {

    // Process all DL and special subframes
    if (srslte_sfidx_tdd_type(tdd_config, tti % 10) != SRSLTE_TDD_SF_U || cell.frame_type == SRSLTE_FDD) {
      srslte_mbsfn_cfg_t mbsfn_cfg;
      ZERO_OBJECT(mbsfn_cfg);

      if (carrier_idx == 0 && phy->is_mbsfn_sf(&mbsfn_cfg, tti)) {
        cc_workers[0]->work_dl_mbsfn(mbsfn_cfg); // Don't do chest_ok in mbsfn since it trigger measurements
      } else {
        if ((carrier_idx == 0) || phy->scell_cfg[carrier_idx].enabled) {
          rx_signal_ok = cc_workers[carrier_idx]->work_dl_regular();
        }
      }
    }
  }

  /***** Uplink Generation + Transmission *******/

  bool  tx_signal_ready                                    = false;
  cf_t* tx_signal_ptr[SRSLTE_MAX_RADIOS][SRSLTE_MAX_PORTS] = {};

  /* If TTI+4 is an uplink subframe (TODO: Support short PRACH and SRS in UpPts special subframes) */
  if ((srslte_sfidx_tdd_type(tdd_config, TTI_TX(tti) % 10) == SRSLTE_TDD_SF_U) || cell.frame_type == SRSLTE_FDD) {
    // Generate Uplink signal if no PRACH pending
    if (!prach_ptr) {

      // Common UCI data object for all carriers
      srslte_uci_data_t uci_data;
      reset_uci(&uci_data);

      // Loop through all carriers. Do in reverse order since control information from SCells is transmitted in PCell
      for (int carrier_idx = phy->args->nof_carriers - 1; carrier_idx >= 0; carrier_idx--) {
        tx_signal_ready = cc_workers[carrier_idx]->work_ul(&uci_data);

        // Get carrier mapping
        carrier_map_t* m = &phy->args->carrier_map[carrier_idx];

        // Set signal pointer based on offset
        cf_t* b = cc_workers[carrier_idx]->get_tx_buffer(0);
        if (next_offset[m->radio_idx] > 0) {
          tx_signal_ptr[m->radio_idx][m->channel_idx] = b;
        } else {
          tx_signal_ptr[m->radio_idx][m->channel_idx] = &b[-next_offset[m->radio_idx]];
        }
      }
    }
  }

  // Set PRACH buffer signal pointer
  if (prach_ptr) {
    tx_signal_ready     = true;
    tx_signal_ptr[0][0] = prach_ptr;
    prach_ptr           = NULL;
  }

  uint32_t nof_samples[SRSLTE_MAX_RADIOS];
  for (uint32_t i = 0; i < phy->args->nof_radios; i++) {
    nof_samples[i] = SRSLTE_SF_LEN_PRB(cell.nof_prb) + next_offset[i];
  }

  // Call worker_end to transmit the signal
  phy->worker_end(tx_sem_id, tx_signal_ready, tx_signal_ptr, nof_samples, tx_time);

  if (rx_signal_ok) {
    update_measurements();
  }

  pthread_mutex_unlock(&mutex);

  // Call feedback loop for chest
  if (chest_loop && ((1 << (tti % 10)) & phy->args->cfo_ref_mask)) {
    chest_loop->set_cfo(cc_workers[0]->get_ref_cfo());
  }

  /* Tell the plotting thread to draw the plots */
#ifdef ENABLE_GUI
  if ((int)get_id() == plot_worker_id) {
    sem_post(&plot_sem);
  }
#endif
}

/********************* Uplink common control functions ****************************/

void sf_worker::reset_uci(srslte_uci_data_t* uci_data)
{
  bzero(uci_data, sizeof(srslte_uci_data_t));

  /* Set all ACKs to DTX */
  memset(uci_data->value.ack.ack_value, 2, SRSLTE_UCI_MAX_ACK_BITS);
}

/**************************** Measurements **************************/

void sf_worker::update_measurements()
{
  /* Only worker 0 reads the RSSI sensor every ~1-nof_cores s */
  if (get_id() == 0) {

    // Average RSSI over all symbols in antenna port 0 (make sure SF length is non-zero)
    float rssi_dbm =
        SRSLTE_SF_LEN_PRB(cell.nof_prb) > 0
            ? (10 * log10(srslte_vec_avg_power_cf(cc_workers[0]->get_rx_buffer(0), SRSLTE_SF_LEN_PRB(cell.nof_prb))) +
               30)
            : 0;
    if (std::isnormal(rssi_dbm)) {
      phy->avg_rssi_dbm = SRSLTE_VEC_EMA(rssi_dbm, phy->avg_rssi_dbm, phy->args->snr_ema_coeff);
    }

    if (!rssi_read_cnt) {
      phy->rx_gain_offset = phy->get_radio()->get_rx_gain(0) + phy->args->rx_gain_offset;
    }
    rssi_read_cnt++;
    if (rssi_read_cnt == 1000) {
      rssi_read_cnt = 0;
    }
  }

  // Run measurements in all carriers
  for (uint32_t cc_idx = 0; cc_idx < cc_workers.size(); cc_idx++) {
    // Update measurement of the Component Carrier
    cc_workers[cc_idx]->update_measurements();

    // Send measurements
    if ((tti % phy->pcell_report_period) == phy->pcell_report_period - 1) {
      if (cc_idx == 0) {
        // Send report for PCell
        phy->stack->new_phy_meas(phy->avg_rsrp_dbm[0], phy->avg_rsrq_db, tti);
      } else {
        // Send report for SCell (if enabled)
        if (phy->scell_cfg[cc_idx].enabled) {
          phy->stack->new_phy_meas(phy->avg_rsrp_dbm[cc_idx],
                                   phy->avg_rsrq_db,
                                   tti,
                                   phy->scell_cfg[cc_idx].earfcn,
                                   phy->scell_cfg[cc_idx].pci);
        }
      }
    }
  }

  // Check in-sync / out-sync conditions
  if (phy->avg_rsrp_dbm[0] > -130.0 && phy->avg_snr_db_cqi[0] > -6.0) {
    log_h->debug("SNR=%.1f dB, RSRP=%.1f dBm sync=in-sync from channel estimator\n",
                 phy->avg_snr_db_cqi[0],
                 phy->avg_rsrp_dbm[0]);
    chest_loop->in_sync();
  } else {
    log_h->warning("SNR=%.1f dB RSRP=%.1f dBm, sync=out-of-sync from channel estimator\n",
                   phy->avg_snr_db_cqi[0],
                   phy->avg_rsrp_dbm[0]);
    chest_loop->out_of_sync();
  }
}

/***********************************************************
 *
 * Interface for Plot visualization
 *
 ***********************************************************/

void sf_worker::start_plot()
{
#ifdef ENABLE_GUI
  if (plot_worker_id == -1) {
    plot_worker_id = get_id();
    log_h->console("Starting plot for worker_id=%d\n", plot_worker_id);
    init_plots(this);
  } else {
    log_h->console("Trying to start a plot but already started by worker_id=%d\n", plot_worker_id);
  }
#else
  log_h->console("Trying to start a plot but plots are disabled (ENABLE_GUI constant in sf_worker.cc)\n");
#endif
}

int sf_worker::read_ce_abs(float* ce_abs, uint32_t tx_antenna, uint32_t rx_antenna)
{
  return cc_workers[0]->read_ce_abs(ce_abs, tx_antenna, rx_antenna);
}

int sf_worker::read_pdsch_d(cf_t* pdsch_d)
{
  return cc_workers[0]->read_pdsch_d(pdsch_d);
}
float sf_worker::get_sync_error()
{
  dl_metrics_t dl_metrics[SRSLTE_MAX_CARRIERS] = {};
  phy->get_dl_metrics(dl_metrics);
  return dl_metrics->sync_err;
}

float sf_worker::get_cfo()
{
  sync_metrics_t sync_metrics[SRSLTE_MAX_CARRIERS] = {};
  phy->get_sync_metrics(sync_metrics);
  return sync_metrics[0].cfo;
}
} // namespace srsue

/***********************************************************
 *
 * PLOT TO VISUALIZE THE CHANNEL RESPONSEE
 *
 ***********************************************************/

#ifdef ENABLE_GUI
plot_real_t    pce[SRSLTE_MAX_PORTS][SRSLTE_MAX_PORTS];
plot_scatter_t pconst;
#define SCATTER_PDSCH_BUFFER_LEN (20 * 6 * SRSLTE_SF_LEN_RE(SRSLTE_MAX_PRB, SRSLTE_CP_NORM))
#define SCATTER_PDSCH_PLOT_LEN 4000
float tmp_plot[SCATTER_PDSCH_BUFFER_LEN];
cf_t  tmp_plot2[SRSLTE_SF_LEN_RE(SRSLTE_MAX_PRB, SRSLTE_CP_NORM)];

#define CFO_PLOT_LEN 0 /* Set to non zero for enabling CFO plot */
#if CFO_PLOT_LEN > 0
static plot_real_t pcfo;
static uint32_t    icfo = 0;
static float       cfo_buffer[CFO_PLOT_LEN];
#endif /* CFO_PLOT_LEN > 0 */

#define SYNC_PLOT_LEN 0 /* Set to non zero for enabling Sync error plot */
#if SYNC_PLOT_LEN > 0
static plot_real_t psync;
static uint32_t    isync = 0;
static float       sync_buffer[SYNC_PLOT_LEN];
#endif /* SYNC_PLOT_LEN > 0 */

void* plot_thread_run(void* arg)
{
  srsue::sf_worker* worker = (srsue::sf_worker*)arg;
  uint32_t          row_count = 0;

  sdrgui_init();
  for (uint32_t tx = 0; tx < worker->get_cell_nof_ports(); tx++) {
    for (uint32_t rx = 0; rx < worker->get_rx_nof_antennas(); rx++) {
      char str_buf[64];
      snprintf(str_buf, 64, "|H%d%d|", rx, tx);
      plot_real_init(&pce[tx][rx]);
      plot_real_setTitle(&pce[tx][rx], str_buf);
      plot_real_setLabels(&pce[tx][rx], (char*)"Index", (char*)"dB");
      plot_real_setYAxisScale(&pce[tx][rx], -40, 40);

      plot_real_addToWindowGrid(&pce[tx][rx], (char*)"srsue", tx, rx);
    }
  }
  row_count = worker->get_rx_nof_antennas();

  plot_scatter_init(&pconst);
  plot_scatter_setTitle(&pconst, (char*)"PDSCH - Equalized Symbols");
  plot_scatter_setXAxisScale(&pconst, -4, 4);
  plot_scatter_setYAxisScale(&pconst, -4, 4);

  plot_scatter_addToWindowGrid(&pconst, (char*)"srsue", 0, row_count);

#if CFO_PLOT_LEN > 0
  plot_real_init(&pcfo);
  plot_real_setTitle(&pcfo, (char*)"CFO (Hz)");
  plot_real_setLabels(&pcfo, (char*)"Time", (char*)"Hz");
  plot_real_setYAxisScale(&pcfo, -4000, 4000);

  plot_scatter_addToWindowGrid(&pcfo, (char*)"srsue", 1, row_count++);
#endif /* CFO_PLOT_LEN > 0 */

#if SYNC_PLOT_LEN > 0
  plot_real_init(&psync);
  plot_real_setTitle(&psync, (char*)"Sync error (in samples)");
  plot_real_setLabels(&psync, (char*)"Time", (char*)"Error");
  plot_real_setYAxisScale(&psync, -2, +2);

  plot_scatter_addToWindowGrid(&psync, (char*)"srsue", 1, row_count++);
#endif /* SYNC_PLOT_LEN > 0 */

  int n;
  int readed_pdsch_re = 0;
  while (1) {
    sem_wait(&plot_sem);

    if (readed_pdsch_re < SCATTER_PDSCH_PLOT_LEN) {
      n = worker->read_pdsch_d(&tmp_plot2[readed_pdsch_re]);
      readed_pdsch_re += n;
    } else {
      for (uint32_t tx = 0; tx < worker->get_cell_nof_ports(); tx++) {
        for (uint32_t rx = 0; rx < worker->get_rx_nof_antennas(); rx++) {
          n = worker->read_ce_abs(tmp_plot, tx, rx);
          if (n > 0) {
            plot_real_setNewData(&pce[tx][rx], tmp_plot, n);
          }
        }
      }
      if (readed_pdsch_re > 0) {
        plot_scatter_setNewData(&pconst, tmp_plot2, readed_pdsch_re);
      }
      readed_pdsch_re = 0;
    }

#if CFO_PLOT_LEN > 0
    cfo_buffer[icfo] = worker->get_cfo() * 15000.0f;
    icfo             = (icfo + 1) % CFO_PLOT_LEN;
    plot_real_setNewData(&pcfo, cfo_buffer, CFO_PLOT_LEN);
#endif /* CFO_PLOT_LEN > 0 */
  }
  return NULL;
}

void init_plots(srsue::sf_worker* worker)
{

  if (sem_init(&plot_sem, 0, 0)) {
    perror("sem_init");
    exit(-1);
  }

  pthread_attr_t     attr;
  struct sched_param param;
  param.sched_priority = 0;
  pthread_attr_init(&attr);
  pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
  pthread_attr_setschedpolicy(&attr, SCHED_OTHER);
  pthread_attr_setschedparam(&attr, &param);
  if (pthread_create(&plot_thread, &attr, plot_thread_run, worker)) {
    perror("pthread_create");
    exit(-1);
  }
}
#endif
