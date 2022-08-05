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

#ifndef SRSENB_S1AP_H
#define SRSENB_S1AP_H

#include <map>

#include "srslte/common/buffer_pool.h"
#include "srslte/common/log.h"
#include "srslte/common/common.h"
#include "srslte/common/threads.h"
#include "srslte/interfaces/enb_interfaces.h"
#include "common_enb.h"

#include "srslte/asn1/liblte_s1ap.h"
#include "s1ap_metrics.h"

namespace srsenb {

typedef struct {
  uint32_t  rnti;
  uint32_t  eNB_UE_S1AP_ID;
  uint32_t  MME_UE_S1AP_ID;
  bool      release_requested;
  uint16_t  stream_id;
}ue_ctxt_t;

class s1ap
    :public s1ap_interface_rrc
    ,public thread
{
public:
  s1ap();
  ~s1ap();
  bool init(s1ap_args_t args_, rrc_interface_s1ap *rrc_, srslte::log *s1ap_log_);
  void stop();
  void get_metrics(s1ap_metrics_t &m);

  void run_thread();

  // RRC interface
  void initial_ue(uint16_t rnti, LIBLTE_S1AP_RRC_ESTABLISHMENT_CAUSE_ENUM cause, srslte::unique_byte_buffer_t pdu);
  void initial_ue(uint16_t                                 rnti,
                  LIBLTE_S1AP_RRC_ESTABLISHMENT_CAUSE_ENUM cause,
                  srslte::unique_byte_buffer_t             pdu,
                  uint32_t                                 m_tmsi,
                  uint8_t                                  mmec);
  void write_pdu(uint16_t rnti, srslte::unique_byte_buffer_t pdu);
  bool user_exists(uint16_t rnti); 
  bool user_release(uint16_t rnti, LIBLTE_S1AP_CAUSERADIONETWORK_ENUM cause_radio);
  void ue_ctxt_setup_complete(uint16_t rnti, LIBLTE_S1AP_MESSAGE_INITIALCONTEXTSETUPRESPONSE_STRUCT *res);
  void ue_erab_setup_complete(uint16_t rnti, LIBLTE_S1AP_MESSAGE_E_RABSETUPRESPONSE_STRUCT *res);
  bool is_mme_connected();
  //void ue_capabilities(uint16_t rnti, LIBLTE_RRC_UE_EUTRA_CAPABILITY_STRUCT *caps);
  bool send_identity_request_for_testing(uint16_t rnti);

private:
  static const int S1AP_THREAD_PRIO = 65;
  static const int MME_PORT         = 36412;
  static const int ADDR_FAMILY      = AF_INET;
  static const int SOCK_TYPE        = SOCK_STREAM;
  static const int PROTO            = IPPROTO_SCTP;
  static const int PPID             = 18;
  static const int NONUE_STREAM_ID  = 0;

  rrc_interface_s1ap    *rrc;
  s1ap_args_t            args;
  srslte::log           *s1ap_log;
  srslte::byte_buffer_pool   *pool;

  bool      mme_connected;
  bool      running;
  int       socket_fd;              // SCTP socket file descriptor
  struct    sockaddr_in mme_addr;   // MME address
  uint32_t  next_eNB_UE_S1AP_ID;    // Next ENB-side UE identifier
  uint16_t  next_ue_stream_id;      // Next UE SCTP stream identifier

  // Protocol IEs sent with every UL S1AP message
  LIBLTE_S1AP_TAI_STRUCT        tai;
  LIBLTE_S1AP_EUTRAN_CGI_STRUCT eutran_cgi;

  LIBLTE_S1AP_MESSAGE_S1SETUPRESPONSE_STRUCT s1setupresponse;

  std::map<uint16_t, ue_ctxt_t> ue_ctxt_map;
  std::map<uint32_t, uint16_t>  enbid_to_rnti_map;

  void build_tai_cgi();
  bool connect_mme();
  bool setup_s1();

  bool handle_s1ap_rx_pdu(srslte::byte_buffer_t* pdu);
  bool handle_initiatingmessage(LIBLTE_S1AP_INITIATINGMESSAGE_STRUCT *msg);
  bool handle_successfuloutcome(LIBLTE_S1AP_SUCCESSFULOUTCOME_STRUCT *msg);
  bool handle_unsuccessfuloutcome(LIBLTE_S1AP_UNSUCCESSFULOUTCOME_STRUCT *msg);
  bool handle_paging(LIBLTE_S1AP_MESSAGE_PAGING_STRUCT *msg);

  bool handle_s1setupresponse(LIBLTE_S1AP_MESSAGE_S1SETUPRESPONSE_STRUCT *msg);
  bool handle_dlnastransport(LIBLTE_S1AP_MESSAGE_DOWNLINKNASTRANSPORT_STRUCT *msg);
  bool handle_initialctxtsetuprequest(LIBLTE_S1AP_MESSAGE_INITIALCONTEXTSETUPREQUEST_STRUCT *msg);
  bool handle_uectxtreleasecommand(LIBLTE_S1AP_MESSAGE_UECONTEXTRELEASECOMMAND_STRUCT *msg);
  bool handle_s1setupfailure(LIBLTE_S1AP_MESSAGE_S1SETUPFAILURE_STRUCT *msg);
  bool handle_erabsetuprequest(LIBLTE_S1AP_MESSAGE_E_RABSETUPREQUEST_STRUCT *msg);
  bool handle_uecontextmodifyrequest(LIBLTE_S1AP_MESSAGE_UECONTEXTMODIFICATIONREQUEST_STRUCT *msg);

  bool send_initialuemessage(uint16_t                                 rnti,
                             LIBLTE_S1AP_RRC_ESTABLISHMENT_CAUSE_ENUM cause,
                             srslte::unique_byte_buffer_t             pdu,
                             bool                                     has_tmsi,
                             uint32_t                                 m_tmsi = 0,
                             uint8_t                                  mmec   = 0);
  bool send_ulnastransport(uint16_t rnti, srslte::unique_byte_buffer_t pdu);
  bool send_uectxtreleaserequest(uint16_t rnti, LIBLTE_S1AP_CAUSE_STRUCT *cause);
  bool send_uectxtreleasecomplete(uint16_t rnti, uint32_t mme_ue_id, uint32_t enb_ue_id);
  bool send_initial_ctxt_setup_response(uint16_t rnti, LIBLTE_S1AP_MESSAGE_INITIALCONTEXTSETUPRESPONSE_STRUCT *res_);
  bool send_initial_ctxt_setup_failure(uint16_t rnti);
  bool send_erab_setup_response(uint16_t rnti, LIBLTE_S1AP_MESSAGE_E_RABSETUPRESPONSE_STRUCT *res_);
  //bool send_ue_capabilities(uint16_t rnti, LIBLTE_RRC_UE_EUTRA_CAPABILITY_STRUCT *caps)
  bool send_uectxmodifyresp(uint16_t rnti);
  bool send_uectxmodifyfailure(uint16_t rnti, LIBLTE_S1AP_CAUSE_STRUCT *cause);

  bool        find_mme_ue_id(uint32_t mme_ue_id, uint16_t *rnti, uint32_t *enb_ue_id);
  std::string get_cause(LIBLTE_S1AP_CAUSE_STRUCT *c);

};

} // namespace srsenb


#endif // SRSENB_S1AP_H
