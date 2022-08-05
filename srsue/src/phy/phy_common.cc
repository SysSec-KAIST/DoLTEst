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

#include <sstream>
#include <string.h>

#include "srslte/srslte.h"
#include "srsue/hdr/phy/phy_common.h"

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

using namespace asn1::rrc;

namespace srsue {

static cf_t  zeros[50000];
static cf_t* zeros_multi[SRSLTE_MAX_PORTS];

phy_common::phy_common(uint32_t max_workers) : tx_sem(max_workers)
{
  args              = NULL;
  log_h             = NULL;
  radio_h           = NULL;
  stack             = NULL;
  this->max_workers = max_workers;
  rx_gain_offset    = 0;
  // have_mtch_stop = false;

  pthread_mutex_init(&pending_ul_ack_mutex, NULL);
  pthread_mutex_init(&pending_dl_ack_mutex, NULL);
  pthread_mutex_init(&pending_ul_grant_mutex, NULL);
  pthread_mutex_init(&received_ul_ack_mutex, NULL);
  pthread_mutex_init(&mtch_mutex, NULL);
  pthread_cond_init(&mtch_cvar, NULL);

  bzero(&dl_metrics, sizeof(dl_metrics_t) * SRSLTE_MAX_CARRIERS);
  dl_metrics_read  = true;
  dl_metrics_count = 0;
  bzero(&ul_metrics, sizeof(ul_metrics_t) * SRSLTE_MAX_CARRIERS);
  ul_metrics_read  = true;
  ul_metrics_count = 0;
  ZERO_OBJECT(sync_metrics);
  sync_metrics_read  = true;
  sync_metrics_count = 0;

  rar_grant_tti = -1;

  bzero(zeros, 50000 * sizeof(cf_t));
  for (int p = 0; p < SRSLTE_MAX_PORTS; p++) {
    zeros_multi[p] = zeros;
  }

  for (int i = 0; i < TTIMOD_SZ; i++) {
    for (int j = 0; j < SRSLTE_MAX_CARRIERS; j++) {
      bzero(&received_ul_ack[i][j], sizeof(received_ul_ack_t));
    }
  }

  for (uint32_t i = 0; i < max_workers; i++) {
    sem_init(&tx_sem[i], 0, 0); // All semaphores start blocked
  }

  reset();

  sib13_configured = false;
  mcch_configured  = false;
}

phy_common::~phy_common()
{
  pthread_mutex_destroy(&pending_ul_ack_mutex);
  pthread_mutex_destroy(&pending_dl_ack_mutex);
  pthread_mutex_destroy(&pending_ul_grant_mutex);
  pthread_mutex_destroy(&received_ul_ack_mutex);
  for (uint32_t i = 0; i < max_workers; i++) {
    sem_post(&tx_sem[i]);
  }
  for (uint32_t i = 0; i < max_workers; i++) {
    sem_destroy(&tx_sem[i]);
  }
}

void phy_common::set_nof_workers(uint32_t nof_workers)
{
  this->nof_workers = nof_workers;
}

void phy_common::init(phy_args_t*                  _args,
                      srslte::log*                 _log,
                      srslte::radio_interface_phy* _radio,
                      stack_interface_phy_lte*     _stack)
{
  log_h          = _log;
  radio_h        = _radio;
  stack          = _stack;
  args           = _args;
  is_first_tx    = true;
  sr_last_tx_tti = -1;

  // Instantiate UL channel emulator
  if (args->ul_channel_args.enable) {
    ul_channel =
        srslte::channel_ptr(new srslte::channel(args->ul_channel_args, args->nof_rf_channels * args->nof_rx_ant));
  }
}

void phy_common::set_ue_dl_cfg(srslte_ue_dl_cfg_t* ue_dl_cfg)
{
  ue_dl_cfg->snr_to_cqi_offset = args->snr_to_cqi_offset;

  srslte_chest_dl_cfg_t* chest_cfg = &ue_dl_cfg->chest_cfg;

  // Setup estimator filter
  bzero(chest_cfg, sizeof(srslte_chest_dl_cfg_t));

  if (args->estimator_fil_auto) {
    chest_cfg->filter_coef[0] = 0;
  } else {
    chest_cfg->filter_coef[0] = args->estimator_fil_order;
    chest_cfg->filter_coef[1] = args->estimator_fil_stddev;
  }
  chest_cfg->filter_type = SRSLTE_CHEST_FILTER_GAUSS;

  if (!args->snr_estim_alg.compare("refs")) {
    chest_cfg->noise_alg = SRSLTE_NOISE_ALG_REFS;
  } else if (!args->snr_estim_alg.compare("empty")) {
    chest_cfg->noise_alg = SRSLTE_NOISE_ALG_EMPTY;
  } else {
    chest_cfg->noise_alg = SRSLTE_NOISE_ALG_PSS;
  }

  chest_cfg->rsrp_neighbour       = false;
  chest_cfg->sync_error_enable    = false;
  chest_cfg->interpolate_subframe = args->interpolate_subframe_enabled;
  chest_cfg->cfo_estimate_enable  = args->cfo_ref_mask != 0;
  chest_cfg->cfo_estimate_sf_mask = args->cfo_ref_mask;
}

void phy_common::set_pdsch_cfg(srslte_pdsch_cfg_t* pdsch_cfg)
{
  bzero(pdsch_cfg, sizeof(srslte_pdsch_cfg_t));
  pdsch_cfg->csi_enable         = args->pdsch_csi_enabled;
  pdsch_cfg->max_nof_iterations = args->pdsch_max_its;
  pdsch_cfg->decoder_type = !args->equalizer_mode.compare("zf") ? SRSLTE_MIMO_DECODER_ZF : SRSLTE_MIMO_DECODER_MMSE;
}

void phy_common::set_ue_ul_cfg(srslte_ue_ul_cfg_t* ue_ul_cfg)
{
  // Setup uplink configuration
  bzero(ue_ul_cfg, sizeof(srslte_ue_ul_cfg_t));
  ue_ul_cfg->cfo_en                              = true;
  if (args->force_ul_amplitude > 0.0f) {
    ue_ul_cfg->force_peak_amplitude = args->force_ul_amplitude;
    ue_ul_cfg->normalize_mode       = SRSLTE_UE_UL_NORMALIZE_MODE_FORCE_AMPLITUDE;
  } else {
    ue_ul_cfg->normalize_mode = SRSLTE_UE_UL_NORMALIZE_MODE_AUTO;
  }
  ue_ul_cfg->ul_cfg.pucch.ack_nack_feedback_mode = SRSLTE_PUCCH_ACK_NACK_FEEDBACK_MODE_NORMAL;
}

srslte::radio_interface_phy* phy_common::get_radio()
{
  return radio_h;
}

// Unpack RAR dci as defined in Section 6.2 of 36.213
void phy_common::set_rar_grant(uint8_t             grant_payload[SRSLTE_RAR_GRANT_LEN],
                               uint16_t            rnti,
                               srslte_tdd_config_t tdd_config)
{

  if (MSG3_DELAY_MS < 0) {
    ERROR("Error MSG3_DELAY_MS can't be negative\n");
  }

  if (rar_grant_tti < 0) {
    Error("Must call set_rar_grant_tti before set_rar_grant\n");
  }

  srslte_dci_ul_t        dci_ul;
  srslte_dci_rar_grant_t rar_grant;
  srslte_dci_rar_unpack(grant_payload, &rar_grant);

  if (srslte_dci_rar_to_ul_dci(&cell, &rar_grant, &dci_ul)) {
    Error("Converting RAR message to UL dci\n");
    return;
  }
  dci_ul.rnti = rnti;

  uint32_t msg3_tx_tti;
  if (rar_grant.ul_delay) {
    msg3_tx_tti = (TTI_TX(rar_grant_tti) + MSG3_DELAY_MS + 1) % 10240;
  } else {
    msg3_tx_tti = (TTI_TX(rar_grant_tti) + MSG3_DELAY_MS) % 10240;
  }

  if (cell.frame_type == SRSLTE_TDD) {
    while (srslte_sfidx_tdd_type(tdd_config, msg3_tx_tti % 10) != SRSLTE_TDD_SF_U) {
      msg3_tx_tti++;
    }
  }

  // Save Msg3 UL dci
  pthread_mutex_lock(&pending_ul_grant_mutex);
  if (!pending_ul_grant[TTIMOD(msg3_tx_tti)][0].enable) {
    Debug("RAR grant rar_grant=%d, msg3_tti=%d, stored in index=%d\n", rar_grant_tti, msg3_tx_tti, TTIMOD(msg3_tx_tti));
    pending_ul_grant[TTIMOD(msg3_tx_tti)][0].pid    = ul_pidof(msg3_tx_tti, &tdd_config);
    pending_ul_grant[TTIMOD(msg3_tx_tti)][0].dci    = dci_ul;
    pending_ul_grant[TTIMOD(msg3_tx_tti)][0].enable = true;
  } else {
    Warning("set_rar_grant: sf->tti=%d, cc=%d already in use\n", msg3_tx_tti, 0);
  }
  pthread_mutex_unlock(&pending_ul_grant_mutex);

  rar_grant_tti = -1;
}

// Table 8-2
const static uint32_t k_pusch[7][10] = {
    {4, 6, 0, 0, 0, 4, 6, 0, 0, 0},
    {0, 6, 0, 0, 4, 0, 6, 0, 0, 4},
    {0, 0, 0, 4, 0, 0, 0, 0, 4, 0},
    {4, 0, 0, 0, 0, 0, 0, 0, 4, 4},
    {0, 0, 0, 0, 0, 0, 0, 0, 4, 4},
    {0, 0, 0, 0, 0, 0, 0, 0, 4, 0},
    {7, 7, 0, 0, 0, 7, 7, 0, 0, 5},
};

const static uint32_t k_phich[7][10] = {{0, 0, 4, 7, 6, 0, 0, 4, 7, 6},
                                        {0, 0, 4, 6, 0, 0, 0, 4, 6, 0},
                                        {0, 0, 6, 0, 0, 0, 0, 6, 0, 0},
                                        {0, 0, 6, 6, 6, 0, 0, 0, 0, 0},
                                        {0, 0, 6, 6, 0, 0, 0, 0, 0, 0},
                                        {0, 0, 6, 0, 0, 0, 0, 0, 0, 0},
                                        {0, 0, 4, 6, 6, 0, 0, 4, 7, 0}};

uint32_t phy_common::ul_pidof(uint32_t tti, srslte_tdd_config_t* tdd_config)
{

  if (tdd_config->configured) {
    /* In TDD modes 1-5, each PID is associated with a unique subframe and the number of harq processes equals the
     * number of UL subframes Modes 0 and 6 have more processes than UL subframes and PID depends on sfn
     */
    uint32_t sf_idx = tti % 10;
    uint32_t sfn    = tti / 10;
    uint32_t cycle_idx;
    switch (tdd_config->sf_config) {
      case 0:
        cycle_idx = 7 - sfn % 7;
        if (sf_idx < 5) {
          return (cycle_idx + sf_idx - 2) % 7;
        } else {
          return (cycle_idx + sf_idx - 4) % 7;
        }
      case 1:
        if (sf_idx < 5) {
          return sf_idx - 2;
        } else {
          return sf_idx - 5;
        }
      case 2:
        if (sf_idx < 5) {
          return 0;
        } else {
          return 1;
        }
      case 3:
      case 4:
      case 5:
        return sf_idx - 2;
      case 6:
        cycle_idx = 6 - sfn % 6;
        if (sf_idx < 5) {
          return (cycle_idx + sf_idx - 2) % 6;
        } else {
          return (cycle_idx + sf_idx - 4) % 6;
        }
      default:
        Error("Invalid SF configuration %d\n", tdd_config->sf_config);
    }
  } else {
    return tti % SRSLTE_FDD_NOF_HARQ;
  }
  return 0;
}

// Computes SF->TTI at which PHICH will be received according to 9.1.2 of 36.213
#define tti_phich(sf)                                                                                                  \
  (sf->tti + (cell.frame_type == SRSLTE_FDD ? FDD_HARQ_DELAY_MS : k_phich[sf->tdd_config.sf_config][sf->tti % 10]))

// Here SF->TTI is when PUSCH is transmitted
void phy_common::set_ul_pending_ack(srslte_ul_sf_cfg_t*  sf,
                                    uint32_t             cc_idx,
                                    srslte_phich_grant_t phich_grant,
                                    srslte_dci_ul_t*     dci_ul)
{
  // Use a lock here because subframe 4 and 9 of TDD config 0 accept multiple PHICH from multiple frames
  pthread_mutex_lock(&pending_ul_ack_mutex);

  if (!pending_ul_ack[TTIMOD(tti_phich(sf))][cc_idx][phich_grant.I_phich].enable) {
    pending_ul_ack[TTIMOD(tti_phich(sf))][cc_idx][phich_grant.I_phich].dci_ul      = *dci_ul;
    pending_ul_ack[TTIMOD(tti_phich(sf))][cc_idx][phich_grant.I_phich].phich_grant = phich_grant;
    pending_ul_ack[TTIMOD(tti_phich(sf))][cc_idx][phich_grant.I_phich].enable      = true;
    Debug("Set pending ACK for sf->tti=%d n_dmrs=%d, I_phich=%d, cc_idx=%d\n",
          sf->tti,
          phich_grant.n_dmrs,
          phich_grant.I_phich,
          cc_idx);
  } else {
    Warning("set_ul_pending_ack: sf->tti=%d, cc=%d already in use\n", sf->tti, cc_idx);
  }
  pthread_mutex_unlock(&pending_ul_ack_mutex);
}

// Here SF->TTI is when PHICH is being transmitted so that's DL subframe
bool phy_common::get_ul_pending_ack(srslte_dl_sf_cfg_t*   sf,
                                    uint32_t              cc_idx,
                                    srslte_phich_grant_t* phich_grant,
                                    srslte_dci_ul_t*      dci_ul)
{
  pthread_mutex_lock(&pending_ul_ack_mutex);
  bool ret = false;
  if (pending_ul_ack[TTIMOD(sf->tti)][cc_idx][phich_grant->I_phich].enable) {
    *phich_grant = pending_ul_ack[TTIMOD(sf->tti)][cc_idx][phich_grant->I_phich].phich_grant;
    *dci_ul      = pending_ul_ack[TTIMOD(sf->tti)][cc_idx][phich_grant->I_phich].dci_ul;
    ret          = true;
    pending_ul_ack[TTIMOD(sf->tti)][cc_idx][phich_grant->I_phich].enable = false;
    Debug("Get pending ACK for sf->tti=%d n_dmrs=%d, I_phich=%d\n", sf->tti, phich_grant->n_dmrs, phich_grant->I_phich);
  }
  pthread_mutex_unlock(&pending_ul_ack_mutex);
  return ret;
}

bool phy_common::is_any_ul_pending_ack()
{
  pthread_mutex_lock(&pending_ul_ack_mutex);
  bool ret = false;
  for (int i = 0; i < TTIMOD_SZ; i++) {
    for (int n = 0; n < SRSLTE_MAX_CARRIERS; n++) {
      for (int j = 0; j < 2; j++) {
        if (pending_ul_ack[i][n][j].enable) {
          ret = true;
          goto unlock_exit;
        }
      }
    }
  }
unlock_exit:
  pthread_mutex_unlock(&pending_ul_ack_mutex);
  return ret;
}

// Computes SF->TTI at which PUSCH will be transmitted according to Section 8 of 36.213
#define tti_pusch_hi(sf)                                                                                               \
  (sf->tti +                                                                                                           \
   (cell.frame_type == SRSLTE_FDD ? FDD_HARQ_DELAY_MS                                                                  \
                                  : I_phich ? 7 : k_pusch[sf->tdd_config.sf_config][sf->tti % 10]) +                   \
   (TX_DELAY - FDD_HARQ_DELAY_MS))
#define tti_pusch_gr(sf)                                                                                               \
  (sf->tti +                                                                                                           \
   (cell.frame_type == SRSLTE_FDD ? FDD_HARQ_DELAY_MS                                                                  \
                                  : dci->ul_idx == 1 ? 7 : k_pusch[sf->tdd_config.sf_config][sf->tti % 10]) +          \
   (TX_DELAY - FDD_HARQ_DELAY_MS))

// SF->TTI is at which Format0 dci is received
void phy_common::set_ul_pending_grant(srslte_dl_sf_cfg_t* sf, uint32_t cc_idx, srslte_dci_ul_t* dci)
{

  pthread_mutex_lock(&pending_ul_grant_mutex);

  // Calculate PID for this SF->TTI
  uint32_t pid = ul_pidof(tti_pusch_gr(sf), &sf->tdd_config);

  if (!pending_ul_grant[TTIMOD(tti_pusch_gr(sf))][cc_idx].enable) {
    pending_ul_grant[TTIMOD(tti_pusch_gr(sf))][cc_idx].pid    = pid;
    pending_ul_grant[TTIMOD(tti_pusch_gr(sf))][cc_idx].dci    = *dci;
    pending_ul_grant[TTIMOD(tti_pusch_gr(sf))][cc_idx].enable = true;
    Debug("Set ul pending grant for sf->tti=%d current_tti=%d, pid=%d\n", tti_pusch_gr(sf), sf->tti, pid);
  } else {
    Warning("set_ul_pending_grant: sf->tti=%d, cc=%d already in use\n", sf->tti, cc_idx);
  }
  pthread_mutex_unlock(&pending_ul_grant_mutex);
}

// SF->TTI at which PUSCH should be transmitted
bool phy_common::get_ul_pending_grant(srslte_ul_sf_cfg_t* sf, uint32_t cc_idx, uint32_t* pid, srslte_dci_ul_t* dci)
{
  pthread_mutex_lock(&pending_ul_grant_mutex);
  bool ret = false;
  if (pending_ul_grant[TTIMOD(sf->tti)][cc_idx].enable) {
    Debug("Reading grant sf->tti=%d idx=%d\n", sf->tti, TTIMOD(sf->tti));
    if (pid) {
      *pid = pending_ul_grant[TTIMOD(sf->tti)][cc_idx].pid;
    }
    if (dci) {
      *dci = pending_ul_grant[TTIMOD(sf->tti)][cc_idx].dci;
    }
    pending_ul_grant[TTIMOD(sf->tti)][cc_idx].enable = false;
    ret                                              = true;
  }
  pthread_mutex_unlock(&pending_ul_grant_mutex);
  return ret;
}

// SF->TTI at which PHICH is received
void phy_common::set_ul_received_ack(
    srslte_dl_sf_cfg_t* sf, uint32_t cc_idx, bool ack_value, uint32_t I_phich, srslte_dci_ul_t* dci_ul)
{
  pthread_mutex_lock(&received_ul_ack_mutex);
  received_ul_ack[TTIMOD(tti_pusch_hi(sf))][cc_idx].hi_present = true;
  received_ul_ack[TTIMOD(tti_pusch_hi(sf))][cc_idx].hi_value   = ack_value;
  received_ul_ack[TTIMOD(tti_pusch_hi(sf))][cc_idx].dci_ul     = *dci_ul;
  Debug("Set ul received ack for sf->tti=%d, current_tti=%d\n", tti_pusch_hi(sf), sf->tti);
  pthread_mutex_unlock(&received_ul_ack_mutex);
}

// SF->TTI at which PUSCH will be transmitted
bool phy_common::get_ul_received_ack(srslte_ul_sf_cfg_t* sf, uint32_t cc_idx, bool* ack_value, srslte_dci_ul_t* dci_ul)
{
  pthread_mutex_lock(&received_ul_ack_mutex);
  bool ret = false;
  if (received_ul_ack[TTIMOD(sf->tti)][cc_idx].hi_present) {
    if (ack_value) {
      *ack_value = received_ul_ack[TTIMOD(sf->tti)][cc_idx].hi_value;
    }
    if (dci_ul) {
      *dci_ul = received_ul_ack[TTIMOD(sf->tti)][cc_idx].dci_ul;
    }
    Debug("Get ul received ack for current_tti=%d\n", sf->tti);
    received_ul_ack[TTIMOD(sf->tti)][cc_idx].hi_present = false;
    ret                                                 = true;
  }
  pthread_mutex_unlock(&received_ul_ack_mutex);
  return ret;
}

// SF->TTI at which PDSCH is decoded and ACK generated
void phy_common::set_dl_pending_ack(srslte_dl_sf_cfg_t*         sf,
                                    uint32_t                    cc_idx,
                                    uint8_t                     value[SRSLTE_MAX_CODEWORDS],
                                    srslte_pdsch_ack_resource_t resource)
{
  pthread_mutex_lock(&pending_dl_ack_mutex);
  if (!pending_dl_ack[TTIMOD(sf->tti)][cc_idx].enable) {
    pending_dl_ack[TTIMOD(sf->tti)][cc_idx].enable   = true;
    pending_dl_ack[TTIMOD(sf->tti)][cc_idx].resource = resource;
    memcpy(pending_dl_ack[TTIMOD(sf->tti)][cc_idx].value, value, SRSLTE_MAX_CODEWORDS * sizeof(uint8_t));
    Debug("Set dl pending ack for sf->tti=%d, value=%d, ncce=%d\n", sf->tti, value[0], resource.n_cce);
  } else {
    Warning("pending_dl_ack: sf->tti=%d, cc=%d already in use\n", sf->tti, cc_idx);
  }
  pthread_mutex_unlock(&pending_dl_ack_mutex);
}

void phy_common::set_rar_grant_tti(uint32_t tti)
{
  rar_grant_tti = tti;
}

typedef struct {
  uint32_t M;
  uint32_t K[9];
} das_index_t;

// Downlink association set index, Table 10.1-1 36.213
das_index_t das_table[7][10] = {
    {{0, {}}, {0, {}}, {1, {6}}, {0, {}}, {1, {4}}, {0, {}}, {0, {}}, {1, {6}}, {0, {}}, {1, {4}}},
    {{0, {}}, {0, {}}, {2, {7, 6}}, {1, {4}}, {0, {}}, {0, {}}, {0, {}}, {2, {7, 6}}, {1, {4}}, {0, {}}},
    {{0, {}}, {0, {}}, {4, {8, 7, 4, 6}}, {0, {}}, {0, {}}, {0, {}}, {0, {}}, {4, {8, 7, 4, 6}}, {0, {}}, {0, {}}},
    {{0, {}}, {0, {}}, {3, {7, 6, 11}}, {2, {6, 5}}, {2, {5, 4}}, {0, {}}, {0, {}}, {0, {}}, {0, {}}, {0, {}}},
    {{0, {}}, {0, {}}, {4, {12, 8, 7, 11}}, {4, {6, 5, 4, 7}}, {0, {}}, {0, {}}, {0, {}}, {0, {}}, {0, {}}, {0, {}}},
    {{0, {}},
     {0, {}},
     {9, {13, 12, 9, 8, 7, 5, 4, 11, 6}},
     {0, {}},
     {0, {}},
     {0, {}},
     {0, {}},
     {0, {}},
     {0, {}},
     {0, {}}},
    {{0, {}}, {0, {}}, {1, {7}}, {1, {7}}, {1, {5}}, {0, {}}, {0, {}}, {1, {7}}, {1, {7}}, {0, {}}}};

// SF->TTI at which ACK/NACK would be transmitted
bool phy_common::get_dl_pending_ack(srslte_ul_sf_cfg_t* sf, uint32_t cc_idx, srslte_pdsch_ack_cc_t* ack)
{
  pthread_mutex_lock(&pending_dl_ack_mutex);
  bool     ret = false;
  uint32_t M;
  if (cell.frame_type == SRSLTE_FDD) {
    M = 1;
  } else {
    M = das_table[sf->tdd_config.sf_config][sf->tti % 10].M;
  }
  for (uint32_t i = 0; i < M; i++) {

    uint32_t k =
        (cell.frame_type == SRSLTE_FDD) ? FDD_HARQ_DELAY_MS : das_table[sf->tdd_config.sf_config][sf->tti % 10].K[i];
    uint32_t pdsch_tti = TTI_SUB(sf->tti, k + (TX_DELAY - FDD_HARQ_DELAY_MS));
    if (pending_dl_ack[TTIMOD(pdsch_tti)][cc_idx].enable) {
      ack->m[i].present  = true;
      ack->m[i].k        = k;
      ack->m[i].resource = pending_dl_ack[TTIMOD(pdsch_tti)][cc_idx].resource;
      memcpy(ack->m[i].value, pending_dl_ack[TTIMOD(pdsch_tti)][cc_idx].value, SRSLTE_MAX_CODEWORDS * sizeof(uint8_t));
      Debug("Get dl pending ack for sf->tti=%d, i=%d, k=%d, pdsch_tti=%d, value=%d, ncce=%d, v_dai=%d\n",
            sf->tti,
            i,
            k,
            pdsch_tti,
            ack->m[i].value[0],
            ack->m[i].resource.n_cce,
            ack->m[i].resource.v_dai_dl);
      ret = true;
    }
    bzero(&pending_dl_ack[TTIMOD(pdsch_tti)][cc_idx], sizeof(received_ack_t));
  }
  ack->M = ret ? M : 0;
  pthread_mutex_unlock(&pending_dl_ack_mutex);
  return ret;
}

/* The transmission of UL subframes must be in sequence. The correct sequence is guaranteed by a chain of N semaphores,
 * one per SF->TTI%max_workers. Each threads waits for the semaphore for the current thread and after transmission
 * allows next SF->TTI to be transmitted
 *
 * Each worker uses this function to indicate that all processing is done and data is ready for transmission or
 * there is no transmission at all (tx_enable). In that case, the end of burst message will be sent to the radio
 */
void phy_common::worker_end(uint32_t           tti,
                            bool               tx_enable,
                            cf_t*              buffer[SRSLTE_MAX_RADIOS][SRSLTE_MAX_PORTS],
                            uint32_t           nof_samples[SRSLTE_MAX_RADIOS],
                            srslte_timestamp_t tx_time[SRSLTE_MAX_RADIOS])
{

  // This variable is not protected but it is very unlikely that 2 threads arrive here simultaneously since at the
  // beginning there is no workload and threads are separated by 1 ms
  if (is_first_tx) {
    is_first_tx = false;
    // Allow my own transmission if I'm the first to transmit
    sem_post(&tx_sem[tti % nof_workers]);
  }

  // Wait for the green light to transmit in the current TTI
  sem_wait(&tx_sem[tti % nof_workers]);

  // For each radio, transmit
  for (uint32_t i = 0; i < args->nof_radios; i++) {
    if (tx_enable && !srslte_timestamp_iszero(&tx_time[i])) {

      if (ul_channel) {
        ul_channel->run(buffer[i], buffer[i], nof_samples[i], tx_time[i]);
      }

      radio_h->tx(i, buffer[i], nof_samples[i], tx_time[i]);
      is_first_of_burst[i] = false;
    } else {
      if (radio_h->is_continuous_tx()) {
        if (!is_first_of_burst[i]) {

          if (ul_channel && !srslte_timestamp_iszero(&tx_time[i])) {
            bzero(zeros_multi[0], sizeof(cf_t) * nof_samples[i]);
            ul_channel->run(zeros_multi, zeros_multi, nof_samples[i], tx_time[i]);
          }

          radio_h->tx(i, zeros_multi, nof_samples[i], tx_time[i]);
        }
      } else {
        if (!is_first_of_burst[i]) {
          radio_h->tx_end();
          is_first_of_burst[i] = true;
        }
      }
    }
  }

  // Allow next TTI to transmit
  sem_post(&tx_sem[(tti + 1) % nof_workers]);
}

void phy_common::set_cell(const srslte_cell_t& c)
{
  cell = c;

  if (ul_channel) {
    ul_channel->set_srate((uint32_t)srslte_sampling_freq_hz(cell.nof_prb));
  }
}

uint32_t phy_common::get_nof_prb()
{
  return cell.nof_prb;
}

void phy_common::set_dl_metrics(const dl_metrics_t m, uint32_t cc_idx)
{
  if (dl_metrics_read) {
    bzero(dl_metrics, sizeof(dl_metrics_t) * SRSLTE_MAX_CARRIERS);
    dl_metrics_count = 0;
    dl_metrics_read  = false;
  }
  dl_metrics_count++;
  dl_metrics[cc_idx].mcs  = dl_metrics[cc_idx].mcs + (m.mcs - dl_metrics[cc_idx].mcs) / dl_metrics_count;
  dl_metrics[cc_idx].n    = dl_metrics[cc_idx].n + (m.n - dl_metrics[cc_idx].n) / dl_metrics_count;
  dl_metrics[cc_idx].rsrq = dl_metrics[cc_idx].rsrq + (m.rsrq - dl_metrics[cc_idx].rsrq) / dl_metrics_count;
  dl_metrics[cc_idx].rssi = dl_metrics[cc_idx].rssi + (m.rssi - dl_metrics[cc_idx].rssi) / dl_metrics_count;
  dl_metrics[cc_idx].rsrp = dl_metrics[cc_idx].rsrp + (m.rsrp - dl_metrics[cc_idx].rsrp) / dl_metrics_count;
  dl_metrics[cc_idx].sinr = dl_metrics[cc_idx].sinr + (m.sinr - dl_metrics[cc_idx].sinr) / dl_metrics_count;
  dl_metrics[cc_idx].sync_err =
      dl_metrics[cc_idx].sync_err + (m.sync_err - dl_metrics[cc_idx].sync_err) / dl_metrics_count;
  dl_metrics[cc_idx].pathloss =
      dl_metrics[cc_idx].pathloss + (m.pathloss - dl_metrics[cc_idx].pathloss) / dl_metrics_count;
  dl_metrics[cc_idx].turbo_iters =
      dl_metrics[cc_idx].turbo_iters + (m.turbo_iters - dl_metrics[cc_idx].turbo_iters) / dl_metrics_count;
}

void phy_common::get_dl_metrics(dl_metrics_t m[SRSLTE_MAX_CARRIERS])
{
  memcpy(m, dl_metrics, sizeof(dl_metrics_t) * SRSLTE_MAX_CARRIERS);
  dl_metrics_read = true;
}

void phy_common::set_ul_metrics(const ul_metrics_t m, uint32_t cc_idx)
{
  if (ul_metrics_read) {
    bzero(ul_metrics, sizeof(ul_metrics_t) * SRSLTE_MAX_CARRIERS);
    ul_metrics_count = 0;
    ul_metrics_read  = false;
  }
  ul_metrics_count++;
  for (uint32_t r = 0; r < args->nof_carriers; r++) {
    ul_metrics[cc_idx].mcs   = ul_metrics[cc_idx].mcs + (m.mcs - ul_metrics[cc_idx].mcs) / ul_metrics_count;
    ul_metrics[cc_idx].power = ul_metrics[cc_idx].power + (m.power - ul_metrics[cc_idx].power) / ul_metrics_count;
  }
}

void phy_common::get_ul_metrics(ul_metrics_t m[SRSLTE_MAX_RADIOS])
{
  memcpy(m, ul_metrics, sizeof(ul_metrics_t) * SRSLTE_MAX_RADIOS);
  ul_metrics_read = true;
}

void phy_common::set_sync_metrics(const uint32_t& cc_idx, const sync_metrics_t& m)
{
  if (sync_metrics_read) {
    sync_metrics[cc_idx] = m;
    sync_metrics_count = 1;
    if (cc_idx == 0)
      sync_metrics_read = false;
  } else {
    if (cc_idx == 0)
      sync_metrics_count++;
    sync_metrics[cc_idx].cfo = sync_metrics[cc_idx].cfo + (m.cfo - sync_metrics[cc_idx].cfo) / sync_metrics_count;
    sync_metrics[cc_idx].sfo = sync_metrics[cc_idx].sfo + (m.sfo - sync_metrics[cc_idx].sfo) / sync_metrics_count;
  }
}

void phy_common::get_sync_metrics(sync_metrics_t m[SRSLTE_MAX_CARRIERS])
{
  for (uint32_t i = 0; i < args->nof_carriers; i++) {
    m[i] = sync_metrics[i];
  }
  sync_metrics_read = true;
}

void phy_common::reset()
{
  sr_enabled      = false;
  is_first_tx     = true;
  cur_pathloss    = 0;
  cur_pusch_power = 0;
  p0_preamble     = 0;
  cur_radio_power = 0;
  sr_last_tx_tti  = -1;
  cur_pusch_power = 0;
  ZERO_OBJECT(pathloss);
  ZERO_OBJECT(avg_snr_db_cqi);
  ZERO_OBJECT(avg_rsrp);
  ZERO_OBJECT(avg_rsrp_dbm);
  ZERO_OBJECT(scell_cfg);
  avg_rsrq_db = 0;

  pcell_report_period = 20;

  for (int i = 0; i < SRSLTE_MAX_RADIOS; i++) {
    is_first_of_burst[i] = true;
  }

  multiple_csi_request_enabled = false;
  cif_enabled                  = false;
  srs_request_enabled          = false;
  ZERO_OBJECT(pending_dl_ack);
  ZERO_OBJECT(pending_dl_dai);
  ZERO_OBJECT(pending_ul_ack);
  ZERO_OBJECT(pending_ul_grant);
}

/*  Convert 6-bit maps to 10-element subframe tables
    bitmap         = |0|0|0|0|0|0|
    subframe index = |1|2|3|6|7|8|
*/
void phy_common::build_mch_table()
{
  // First reset tables
  bzero(&mch_table[0], sizeof(uint8_t) * 40);

  // 40 element table represents 4 frames (40 subframes)
  if (mbsfn_config.mbsfn_subfr_cnfg.sf_alloc.type() == asn1::rrc::mbsfn_sf_cfg_s::sf_alloc_c_::types::one_frame) {
    generate_mch_table(&mch_table[0], (uint32_t)mbsfn_config.mbsfn_subfr_cnfg.sf_alloc.one_frame().to_number(), 1u);
  } else if (mbsfn_config.mbsfn_subfr_cnfg.sf_alloc.type() ==
             asn1::rrc::mbsfn_sf_cfg_s::sf_alloc_c_::types::four_frames) {
    generate_mch_table(&mch_table[0], (uint32_t)mbsfn_config.mbsfn_subfr_cnfg.sf_alloc.four_frames().to_number(), 4u);
  } else {
    log_h->error("The subframe config has not been set for MBSFN\n");
  }
  // Debug

  std::stringstream ss;
  ss << "|";
  for (uint32_t j = 0; j < 40; j++) {
    ss << (int)mch_table[j] << "|";
  }
  Info("MCH table: %s\n", ss.str().c_str());
}

void phy_common::build_mcch_table()
{
  // First reset tables
  bzero(&mcch_table[0], sizeof(uint8_t) * 10);
  generate_mcch_table(&mcch_table[0], (uint32_t)mbsfn_config.mbsfn_area_info.mcch_cfg_r9.sf_alloc_info_r9.to_number());
  // Debug
  std::stringstream ss;
  ss << "|";
  for (uint32_t j = 0; j < 10; j++) {
    ss << (int)mcch_table[j] << "|";
  }
  Info("MCCH table: %s\n", ss.str().c_str());
  sib13_configured = true;
}

void phy_common::set_mcch()
{
  mcch_configured = true;
}

void phy_common::set_mch_period_stop(uint32_t stop)
{
  pthread_mutex_lock(&mtch_mutex);
  have_mtch_stop  = true;
  mch_period_stop = stop;
  pthread_cond_signal(&mtch_cvar);
  pthread_mutex_unlock(&mtch_mutex);
}

bool phy_common::is_mch_subframe(srslte_mbsfn_cfg_t* cfg, uint32_t phy_tti)
{
  uint32_t sfn; // System Frame Number
  uint8_t  sf;  // Subframe
  uint8_t  offset;
  uint8_t  period;

  sfn = phy_tti / 10;
  sf  = phy_tti % 10;

  // Set some defaults
  cfg->mbsfn_area_id           = 0;
  cfg->non_mbsfn_region_length = 1;
  cfg->mbsfn_mcs               = 2;
  cfg->enable                  = false;
  cfg->is_mcch                 = false;

  // Check for MCCH
  if (is_mcch_subframe(cfg, phy_tti)) {
    cfg->is_mcch = true;
    return true;
  }

  // Not MCCH, check for MCH
  if (sib13_configured) {
    mbsfn_sf_cfg_s*                  subfr_cnfg = &mbsfn_config.mbsfn_subfr_cnfg;
    asn1::rrc::mbsfn_area_info_r9_s* area_info  = &mbsfn_config.mbsfn_area_info;
    offset                                      = subfr_cnfg->radioframe_alloc_offset;
    period                                      = subfr_cnfg->radioframe_alloc_period.to_number();

    if (subfr_cnfg->sf_alloc.type() == mbsfn_sf_cfg_s::sf_alloc_c_::types::one_frame) {
      if ((sfn % period == offset) && (mch_table[sf] > 0)) {
        cfg->mbsfn_area_id           = area_info->mbsfn_area_id_r9;
        cfg->non_mbsfn_region_length = area_info->non_mbsfn_region_len.to_number();
        if (mcch_configured) {
          // Iterate through PMCH configs to see which one applies in the current frame
          mbsfn_area_cfg_r9_s* mcch            = &mbsfn_config.mcch.msg.c1().mbsfn_area_cfg_r9();
          uint32_t             mbsfn_per_frame = mcch->pmch_info_list_r9[0].pmch_cfg_r9.sf_alloc_end_r9 /
                                     mcch->pmch_info_list_r9[0].pmch_cfg_r9.mch_sched_period_r9.to_number();
          uint32_t frame_alloc_idx = sfn % mcch->common_sf_alloc_period_r9.to_number();
          uint32_t sf_alloc_idx    = frame_alloc_idx * mbsfn_per_frame + ((sf < 4) ? sf - 1 : sf - 3);
          pthread_mutex_lock(&mtch_mutex);
          while (!have_mtch_stop) {
            pthread_cond_wait(&mtch_cvar, &mtch_mutex);
          }
          pthread_mutex_unlock(&mtch_mutex);

          for (uint32_t i = 0; i < mcch->pmch_info_list_r9.size(); i++) {
            if (sf_alloc_idx <= mch_period_stop) {
              // trigger conditional variable, has ot be untriggered by mtch stop location
              cfg->mbsfn_mcs = mcch->pmch_info_list_r9[i].pmch_cfg_r9.data_mcs_r9;
              cfg->enable    = true;
            } else {
              // have_mtch_stop = false;
            }
          }
          Debug("MCH subframe TTI:%d\n", phy_tti);
        }
        return true;
      }
    } else if (subfr_cnfg->sf_alloc.type() == mbsfn_sf_cfg_s::sf_alloc_c_::types::four_frames) {
      uint8_t idx = sfn % period;
      if ((idx >= offset) && (idx < offset + 4)) {
        if (mch_table[(idx * 10) + sf] > 0) {
          cfg->mbsfn_area_id           = area_info->mbsfn_area_id_r9;
          cfg->non_mbsfn_region_length = area_info->non_mbsfn_region_len.to_number();
          // TODO: check for MCCH configuration, set MCS and decode
          return true;
        }
      }
    } else {
      log_h->error("The subframe allocation type is not yet configured\n");
    }
  }

  return false;
}

bool phy_common::is_mcch_subframe(srslte_mbsfn_cfg_t* cfg, uint32_t phy_tti)
{
  uint32_t sfn; // System Frame Number
  uint8_t  sf;  // Subframe
  uint8_t  offset;
  uint16_t period;

  sfn = phy_tti / 10;
  sf  = (uint8_t)(phy_tti % 10);

  if (sib13_configured) {
    mbsfn_area_info_r9_s* area_info = &mbsfn_config.mbsfn_area_info;

    offset = area_info->mcch_cfg_r9.mcch_offset_r9;
    period = area_info->mcch_cfg_r9.mcch_repeat_period_r9.to_number();

    if ((sfn % period == offset) && mcch_table[sf] > 0) {
      cfg->mbsfn_area_id           = area_info->mbsfn_area_id_r9;
      cfg->non_mbsfn_region_length = area_info->non_mbsfn_region_len.to_number();
      cfg->mbsfn_mcs               = area_info->mcch_cfg_r9.sig_mcs_r9.to_number();
      cfg->enable                  = true;
      have_mtch_stop               = false;
      Debug("MCCH subframe TTI:%d\n", phy_tti);
      return true;
    }
  }
  return false;
}

bool phy_common::is_mbsfn_sf(srslte_mbsfn_cfg_t* cfg, uint32_t phy_tti)
{
  return is_mch_subframe(cfg, phy_tti);
}

void phy_common::enable_scell(uint32_t cc_idx, bool enable)
{
  if (cc_idx < SRSLTE_MAX_CARRIERS) {
    scell_cfg[cc_idx].enabled = enable;
  }
}

} // namespace srsue
