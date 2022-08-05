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

#include <string.h>
#include <map>

#include "srslte/common/buffer_pool.h"
#include "srslte/common/log.h"
#include "common_enb.h"
#include "srslte/common/threads.h"
#include "srslte/srslte.h"
#include "srslte/interfaces/enb_interfaces.h"

#ifndef SRSENB_GTPU_H
#define SRSENB_GTPU_H


namespace srsenb {

class gtpu
    :public gtpu_interface_rrc
    ,public gtpu_interface_pdcp
    ,public thread
{
public:

  gtpu();

  bool init(std::string gtp_bind_addr_, std::string mme_addr_, std::string m1u_multiaddr_, std::string m1u_if_addr_, pdcp_interface_gtpu *pdcp_, srslte::log *gtpu_log_, bool enable_mbsfn = false);
  void stop();

  // gtpu_interface_rrc
  void add_bearer(uint16_t rnti, uint32_t lcid, uint32_t addr, uint32_t teid_out, uint32_t *teid_in);
  void rem_bearer(uint16_t rnti, uint32_t lcid);
  void rem_user(uint16_t rnti);

  // gtpu_interface_pdcp
  void write_pdu(uint16_t rnti, uint32_t lcid, srslte::unique_byte_buffer_t pdu);

private:
  static const int THREAD_PRIO = 65;
  static const int GTPU_PORT   = 2152;
  srslte::byte_buffer_pool     *pool;
  bool                         running;
  bool                         run_enable;

  bool                         enable_mbsfn;
  std::string                  gtp_bind_addr;
  std::string                  mme_addr;
  srsenb::pdcp_interface_gtpu *pdcp;
  srslte::log                 *gtpu_log;

  // Class to create
  class mch_thread : public thread {
  public:
    mch_thread() : initiated(false), running(false), run_enable(false), pool(NULL), lcid_counter(0), thread("MCH") {}
    bool init(std::string m1u_multiaddr_, std::string m1u_if_addr_, pdcp_interface_gtpu *pdcp_, srslte::log *gtpu_log_);
    void stop();
  private:
    void run_thread();

    bool initiated;
    bool running;
    bool run_enable;

    static const int MCH_THREAD_PRIO = 65;

    pdcp_interface_gtpu *pdcp;
    srslte::log         *gtpu_log;
    int m1u_sd;
    int lcid_counter;
    std::string                  m1u_multiaddr;
    std::string                  m1u_if_addr;

    srslte::byte_buffer_pool *pool;
  };

  // MCH thread insteance
  mch_thread  mchthread;

  typedef struct{
    uint32_t teids_in[SRSENB_N_RADIO_BEARERS];
    uint32_t teids_out[SRSENB_N_RADIO_BEARERS];
    uint32_t spgw_addrs[SRSENB_N_RADIO_BEARERS];
  }bearer_map;
  std::map<uint16_t, bearer_map> rnti_bearers;

  // Socket file descriptor
  int fd;

  void run_thread();
  void echo_response(in_addr_t addr, in_port_t port, uint16_t seq);

  pthread_mutex_t mutex;

  /****************************************************************************
   * TEID to RNIT/LCID helper functions
   ***************************************************************************/
  void teidin_to_rntilcid(uint32_t teidin, uint16_t *rnti, uint16_t *lcid);
  void rntilcid_to_teidin(uint16_t rnti, uint16_t lcid, uint32_t *teidin);
};


} // namespace srsenb

#endif // SRSENB_GTPU_H
