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

#include "srslte/asn1/liblte_s1ap.h"
#include "srslte/asn1/rrc_asn1.h"
#include "srslte/common/common.h"
#include "srslte/common/interfaces_common.h"
#include "srslte/common/security.h"
#include "srslte/interfaces/rrc_interface_types.h"
#include "srslte/interfaces/sched_interface.h"

#include <vector>

#ifndef SRSLTE_ENB_INTERFACES_H
#define SRSLTE_ENB_INTERFACES_H

namespace srsenb {

/* Interface PHY -> MAC */
class mac_interface_phy_lte
{
public:
  const static int MAX_GRANTS = 64;

  typedef struct {
    srslte_dci_dl_t         dci;
    srslte_dci_cfg_t        dci_cfg;
    uint8_t*                data[SRSLTE_MAX_TB];
    srslte_softbuffer_tx_t* softbuffer_tx[SRSLTE_MAX_TB];
  } dl_sched_grant_t;

  typedef struct {
    dl_sched_grant_t pdsch[MAX_GRANTS];
    uint32_t         nof_grants;
    uint32_t         cfi;
  } dl_sched_t;

  typedef struct {
    uint16_t rnti;
    bool     ack;
  } ul_sched_ack_t;

  typedef struct {
    srslte_dci_ul_t         dci;
    srslte_dci_cfg_t        dci_cfg;
    uint32_t                current_tx_nb;
    uint8_t*                data;
    bool                    needs_pdcch;
    srslte_softbuffer_rx_t* softbuffer_rx;
  } ul_sched_grant_t;

  typedef struct {
    ul_sched_grant_t pusch[MAX_GRANTS];
    ul_sched_ack_t   phich[MAX_GRANTS];
    uint32_t         nof_grants;
    uint32_t nof_phich; 
  } ul_sched_t; 

  virtual int sr_detected(uint32_t tti, uint16_t rnti) = 0; 
  virtual int rach_detected(uint32_t tti, uint32_t preamble_idx, uint32_t time_adv) = 0; 
  
  virtual int ri_info(uint32_t tti, uint16_t rnti, uint32_t ri_value) = 0;
  virtual int pmi_info(uint32_t tti, uint16_t rnti, uint32_t pmi_value) = 0;
  virtual int cqi_info(uint32_t tti, uint16_t rnti, uint32_t cqi_value) = 0; 
  virtual int snr_info(uint32_t tti, uint16_t rnti, float snr_db) = 0; 
  virtual int ack_info(uint32_t tti, uint16_t rnti, uint32_t tb_idx, bool ack) = 0;
  virtual int crc_info(uint32_t tti, uint16_t rnti, uint32_t nof_bytes, bool crc_res) = 0; 
  
  virtual int get_dl_sched(uint32_t tti, dl_sched_t *dl_sched_res) = 0;
  virtual int get_mch_sched(uint32_t tti, bool is_mcch, dl_sched_t* dl_sched_res) = 0;
  virtual int get_ul_sched(uint32_t tti, ul_sched_t *ul_sched_res) = 0;
  virtual void set_sched_dl_tti_mask(uint8_t* tti_mask, uint32_t nof_sfs)          = 0;

  // Radio-Link status 
  virtual void rl_failure(uint16_t rnti) = 0;
  virtual void rl_ok(uint16_t rnti) = 0;

  virtual void tti_clock() = 0; 
};

/* Interface MAC -> PHY */
class phy_interface_mac_lte
{
public:
  
  /* MAC adds/removes an RNTI to the list of active RNTIs */
  virtual int  add_rnti(uint16_t rnti, bool is_temporal = false) = 0;
  virtual void rem_rnti(uint16_t rnti)                           = 0;
  virtual void set_mch_period_stop(uint32_t stop)                = 0;
};

/* Interface RRC -> PHY */
class phy_interface_rrc_lte
{
public:
  struct phy_cfg_mbsfn_t {
    asn1::rrc::mbsfn_sf_cfg_s       mbsfn_subfr_cnfg;
    asn1::rrc::mbms_notif_cfg_r9_s  mbsfn_notification_cnfg;
    asn1::rrc::mbsfn_area_info_r9_s mbsfn_area_info;
    asn1::rrc::mcch_msg_s           mcch;
  };

  typedef struct {
    phy_cfg_mbsfn_t  mbsfn;
  } phy_rrc_cfg_t;

  virtual void configure_mbsfn(asn1::rrc::sib_type2_s* sib2, asn1::rrc::sib_type13_r9_s* sib13,
                               asn1::rrc::mcch_msg_s mcch)                               = 0;
  virtual void set_config_dedicated(uint16_t rnti, asn1::rrc::phys_cfg_ded_s* dedicated) = 0;
};

class mac_interface_rrc
{
public: 
  /* Provides cell configuration including SIB periodicity, etc. */
  virtual int cell_cfg(sched_interface::cell_cfg_t *cell_cfg) = 0; 
  virtual void reset() = 0;

  /* Manages UE configuration context */
  virtual int ue_cfg(uint16_t rnti, sched_interface::ue_cfg_t *cfg) = 0; 
  virtual int ue_rem(uint16_t rnti) = 0;

  /* Manages UE bearers and associated configuration */
  virtual int bearer_ue_cfg(uint16_t rnti, uint32_t lc_id, sched_interface::ue_bearer_cfg_t *cfg) = 0; 
  virtual int bearer_ue_rem(uint16_t rnti, uint32_t lc_id) = 0;
  virtual int  set_dl_ant_info(uint16_t rnti, asn1::rrc::phys_cfg_ded_s::ant_info_c_* dl_ant_info) = 0;
  virtual void phy_config_enabled(uint16_t rnti, bool enabled) = 0;
  virtual void write_mcch(asn1::rrc::sib_type2_s* sib2, asn1::rrc::sib_type13_r9_s* sib13,
                          asn1::rrc::mcch_msg_s* mcch)                                             = 0;
};

class mac_interface_rlc 
{
public:   
  virtual int rlc_buffer_state(uint16_t rnti, uint32_t lc_id, uint32_t tx_queue, uint32_t retx_queue) = 0;  
};

//RLC interface for MAC
class rlc_interface_mac
{
public:

  /* MAC calls RLC to get RLC segment of nof_bytes length.
   * Segmentation happens in this function. RLC PDU is stored in payload. */
  virtual int  read_pdu(uint16_t rnti, uint32_t lcid, uint8_t *payload, uint32_t nof_bytes) = 0;

  virtual void read_pdu_bcch_dlsch(uint32_t sib_index, uint8_t *payload) = 0;
  virtual void read_pdu_pcch(uint8_t* payload, uint32_t buffer_size) = 0; 
  
  /* MAC calls RLC to push an RLC PDU. This function is called from an independent MAC thread.
   * PDU gets placed into the buffer and higher layer thread gets notified. */
  virtual void write_pdu(uint16_t rnti, uint32_t lcid, uint8_t *payload, uint32_t nof_bytes) = 0;
  
};


// RLC interface for PDCP
class rlc_interface_pdcp
{
public:
  /* PDCP calls RLC to push an RLC SDU. SDU gets placed into the RLC buffer and MAC pulls
   * RLC PDUs according to TB size. */
  virtual void write_sdu(uint16_t rnti, uint32_t lcid, srslte::unique_byte_buffer_t sdu) = 0;
  virtual bool rb_is_um(uint16_t rnti, uint32_t lcid) = 0;
};

// RLC interface for RRC
class rlc_interface_rrc
{
public:
  virtual void clear_buffer(uint16_t rnti) = 0;
  virtual void add_user(uint16_t rnti) = 0; 
  virtual void rem_user(uint16_t rnti) = 0;
  virtual void add_bearer(uint16_t rnti, uint32_t lcid, srslte::rlc_config_t cnfg)        = 0;
  virtual void add_bearer_mrb(uint16_t rnti, uint32_t lcid) = 0;
  virtual void write_sdu(uint16_t rnti, uint32_t lcid, srslte::unique_byte_buffer_t sdu)  = 0;
};

// PDCP interface for GTPU
class pdcp_interface_gtpu
{
public:
  virtual void write_sdu(uint16_t rnti, uint32_t lcid, srslte::unique_byte_buffer_t sdu) = 0;
};

// PDCP interface for RRC
class pdcp_interface_rrc
{
public:
  virtual void reset(uint16_t rnti) = 0;
  virtual void add_user(uint16_t rnti) = 0; 
  virtual void rem_user(uint16_t rnti) = 0;
  virtual void write_sdu(uint16_t rnti, uint32_t lcid, srslte::unique_byte_buffer_t sdu)   = 0;
  virtual void write_sdu_doltest(uint16_t rnti, uint32_t lcid, srslte::unique_byte_buffer_t sdu, srslte::INTEGRITY_ALGORITHM_ID_ENUM integ_algo_doltest, srslte::CIPHERING_ALGORITHM_ID_ENUM cipher_algo_doltest)  =  0;
  virtual void add_bearer(uint16_t rnti, uint32_t lcid, srslte::srslte_pdcp_config_t cnfg) = 0;
  virtual void config_security(uint16_t rnti, 
                               uint32_t lcid,
                               uint8_t *k_rrc_enc_,
                               uint8_t *k_rrc_int_,
                               uint8_t *k_up_enc_,
                               srslte::CIPHERING_ALGORITHM_ID_ENUM cipher_algo_,
                               srslte::INTEGRITY_ALGORITHM_ID_ENUM integ_algo_) = 0;
  virtual void enable_integrity(uint16_t rnti, uint32_t lcid) = 0;
  virtual void enable_encryption(uint16_t rnti, uint32_t lcid) = 0;
};

// PDCP interface for RLC
class pdcp_interface_rlc
{
public:
  /* RLC calls PDCP to push a PDCP PDU. */
  virtual void write_pdu(uint16_t rnti, uint32_t lcid, srslte::unique_byte_buffer_t sdu) = 0;
};

// RRC interface for RLC
class rrc_interface_rlc
{
public:
  virtual void read_pdu_bcch_dlsch(uint32_t sib_index, uint8_t *payload) = 0;
  virtual void read_pdu_pcch(uint8_t *payload, uint32_t payload_size) = 0; 
  virtual void max_retx_attempted(uint16_t rnti) = 0;
  virtual void write_pdu(uint16_t rnti, uint32_t lcid, srslte::unique_byte_buffer_t sdu) = 0;
};

// RRC interface for MAC
class rrc_interface_mac
{
public:
  /* Radio Link failure */ 
  virtual void rl_failure(uint16_t rnti) = 0; 
  virtual void add_user(uint16_t rnti) = 0;
  virtual void upd_user(uint16_t new_rnti, uint16_t old_rnti) = 0;
  virtual void set_activity_user(uint16_t rnti) = 0; 
  virtual bool is_paging_opportunity(uint32_t tti, uint32_t *payload_len) = 0; 
};

// RRC interface for PDCP
class rrc_interface_pdcp
{
public:
  virtual void write_pdu(uint16_t rnti, uint32_t lcid, srslte::unique_byte_buffer_t pdu) = 0;
};

// RRC interface for S1AP
class rrc_interface_s1ap
{
public:
  virtual void write_dl_info(uint16_t rnti, srslte::unique_byte_buffer_t sdu)                           = 0;
  virtual void release_complete(uint16_t rnti) = 0;
  virtual bool setup_ue_ctxt(uint16_t rnti, LIBLTE_S1AP_MESSAGE_INITIALCONTEXTSETUPREQUEST_STRUCT *msg) = 0;
  virtual bool modify_ue_ctxt(uint16_t rnti, LIBLTE_S1AP_MESSAGE_UECONTEXTMODIFICATIONREQUEST_STRUCT *msg) = 0;
  virtual bool setup_ue_erabs(uint16_t rnti, LIBLTE_S1AP_MESSAGE_E_RABSETUPREQUEST_STRUCT *msg) = 0;
  virtual bool release_erabs(uint32_t rnti) = 0;
  virtual void add_paging_id(uint32_t ueid, LIBLTE_S1AP_UEPAGINGID_STRUCT UEPagingID) = 0; 
};

// GTPU interface for PDCP
class gtpu_interface_pdcp
{
public:
  virtual void write_pdu(uint16_t rnti, uint32_t lcid, srslte::unique_byte_buffer_t pdu) = 0;
};

// GTPU interface for RRC
class gtpu_interface_rrc
{
public:
  virtual void add_bearer(uint16_t rnti, uint32_t lcid, uint32_t addr, uint32_t teid_out, uint32_t *teid_in) = 0;
  virtual void rem_bearer(uint16_t rnti, uint32_t lcid) = 0;
  virtual void rem_user(uint16_t rnti) = 0;
};

// S1AP interface for RRC
class s1ap_interface_rrc
{
public:
  virtual void
               initial_ue(uint16_t rnti, LIBLTE_S1AP_RRC_ESTABLISHMENT_CAUSE_ENUM cause, srslte::unique_byte_buffer_t pdu) = 0;
  virtual void initial_ue(uint16_t                                 rnti,
                          LIBLTE_S1AP_RRC_ESTABLISHMENT_CAUSE_ENUM cause,
                          srslte::unique_byte_buffer_t             pdu,
                          uint32_t                                 m_tmsi,
                          uint8_t                                  mmec)                                                                           = 0;
  virtual void write_pdu(uint16_t rnti, srslte::unique_byte_buffer_t pdu)                                         = 0;
  virtual bool user_exists(uint16_t rnti) = 0; 
  virtual bool user_release(uint16_t rnti, LIBLTE_S1AP_CAUSERADIONETWORK_ENUM cause_radio) = 0;
  virtual void ue_ctxt_setup_complete(uint16_t rnti, LIBLTE_S1AP_MESSAGE_INITIALCONTEXTSETUPRESPONSE_STRUCT *res) = 0;
  virtual void ue_erab_setup_complete(uint16_t rnti, LIBLTE_S1AP_MESSAGE_E_RABSETUPRESPONSE_STRUCT *res) = 0;
  virtual bool is_mme_connected() = 0;
  virtual bool send_identity_request_for_testing(uint16_t rnti) = 0;
};

// Combined interface for PHY to access stack (MAC and RRC)
class stack_interface_phy_lte : public mac_interface_phy_lte
{
};

// Combined interface for stack (MAC and RRC) to access PHY
class phy_interface_stack_lte : public phy_interface_mac_lte, public phy_interface_rrc_lte
{
};

typedef struct {
  uint32_t    enb_id;  // 20-bit id (lsb bits)
  uint8_t     cell_id; // 8-bit cell id
  uint16_t    tac;     // 16-bit tac
  uint16_t    mcc;     // BCD-coded with 0xF filler
  uint16_t    mnc;     // BCD-coded with 0xF filler
  std::string mme_addr;
  std::string gtp_bind_addr;
  std::string s1c_bind_addr;
  std::string enb_name;
} s1ap_args_t;

typedef struct {
  sched_interface::sched_args_t sched;
  int                           link_failure_nof_err;
} mac_args_t;
}

#endif // SRSLTE_ENB_INTERFACES_H
