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

#include "srsue/hdr/stack/ue_stack_lte.h"
#include "srslte/srslte.h"

using namespace srslte;

namespace srsue {

ue_stack_lte::ue_stack_lte() :
  running(false),
  args(),
  logger(nullptr),
  usim(nullptr),
  phy(nullptr),
  rlc(&rlc_log),
  mac(&mac_log),
  rrc(&rrc_log),
  pdcp(&pdcp_log),
  nas(&nas_log),
  thread("STACK")
{
}

ue_stack_lte::~ue_stack_lte()
{
  stop();
}

std::string ue_stack_lte::get_type()
{
  return "lte";
}

int ue_stack_lte::init(const stack_args_t&      args_,
                       srslte::logger*          logger_,
                       phy_interface_stack_lte* phy_,
                       gw_interface_stack*      gw_)
{
  phy = phy_;
  gw  = gw_;

  if (init(args_, logger_)) {
    return SRSLTE_ERROR;
  }

  return SRSLTE_SUCCESS;
}

int ue_stack_lte::init(const stack_args_t& args_, srslte::logger* logger_)
{
  args   = args_;
  logger = logger_;

  // setup logging for each layer
  mac_log.init("MAC ", logger, true);
  rlc_log.init("RLC ", logger);
  pdcp_log.init("PDCP", logger);
  rrc_log.init("RRC ", logger);
  nas_log.init("NAS ", logger);
  usim_log.init("USIM", logger);

  pool_log.init("POOL", logger);
  pool_log.set_level(srslte::LOG_LEVEL_ERROR);
  byte_buffer_pool::get_instance()->set_log(&pool_log);

  mac_log.set_level(args.log.mac_level);
  rlc_log.set_level(args.log.rlc_level);
  pdcp_log.set_level(args.log.pdcp_level);
  rrc_log.set_level(args.log.rrc_level);
  nas_log.set_level(args.log.nas_level);
  usim_log.set_level(args.log.usim_level);

  mac_log.set_hex_limit(args.log.mac_hex_limit);
  rlc_log.set_hex_limit(args.log.rlc_hex_limit);
  pdcp_log.set_hex_limit(args.log.pdcp_hex_limit);
  rrc_log.set_hex_limit(args.log.rrc_hex_limit);
  nas_log.set_hex_limit(args.log.nas_hex_limit);
  usim_log.set_hex_limit(args.log.usim_hex_limit);

  // Set up pcap
  if (args.pcap.enable) {
    mac_pcap.open(args.pcap.filename.c_str());
    mac.start_pcap(&mac_pcap);
  }
  if (args.pcap.nas_enable) {
    nas_pcap.open(args.pcap.nas_filename.c_str());
    nas.start_pcap(&nas_pcap);
  }

  // Init USIM first to allow early exit in case reader couldn't be found
  usim = usim_base::get_instance(&args.usim, &usim_log);
  if (usim->init(&args.usim)) {
    usim_log.console("Failed to initialize USIM.\n");
    return SRSLTE_ERROR;
  }

  mac.init(phy, &rlc, &rrc);
  rlc.init(&pdcp, &rrc, &mac, 0 /* RB_ID_SRB0 */);
  pdcp.init(&rlc, &rrc, gw);
  nas.init(usim.get(), &rrc, gw, args.nas);
  rrc.init(phy, &mac, &rlc, &pdcp, &nas, usim.get(), gw, &mac, args.rrc);

  running = true;
  start(STACK_MAIN_THREAD_PRIO);

  return SRSLTE_SUCCESS;
}

void ue_stack_lte::stop()
{
  if (running) {
    pending_tasks.push([this]() { stop_impl(); });
    wait_thread_finish();
  }
}

void ue_stack_lte::stop_impl()
{
  running = false;

  usim->stop();
  nas.stop();
  rrc.stop();

  rlc.stop();
  pdcp.stop();
  mac.stop();

  if (args.pcap.enable) {
    mac_pcap.close();
  }
  if (args.pcap.nas_enable) {
    nas_pcap.close();
  }
}

bool ue_stack_lte::switch_on()
{
  if (running) {
    return nas.attach_request();
  }

  return false;
}

bool ue_stack_lte::switch_off()
{
  // generate detach request
  nas.detach_request();

  // wait for max. 5s for it to be sent (according to TS 24.301 Sec 25.5.2.2)
  const uint32_t RB_ID_SRB1 = 1;
  int            cnt = 0, timeout = 5000;

  while (rlc.has_data(RB_ID_SRB1) && ++cnt <= timeout) {
    usleep(1000);
  }
  bool detach_sent = true;
  if (rlc.has_data(RB_ID_SRB1)) {
    nas_log.warning("Detach couldn't be sent after %ds.\n", timeout);
    detach_sent = false;
  }

  return detach_sent;
}

bool ue_stack_lte::get_metrics(stack_metrics_t* metrics)
{
  mac.get_metrics(metrics->mac);
  rlc.get_metrics(metrics->rlc);
  nas.get_metrics(&metrics->nas);
  rrc.get_metrics(metrics->rrc);
  return (metrics->nas.state == EMM_STATE_REGISTERED && metrics->rrc.state == RRC_STATE_CONNECTED);
}

void ue_stack_lte::run_thread()
{
  while (running) {
    // FIXME: For now it is a single queue
    std::function<void()> func = pending_tasks.wait_pop();
    func();
  }
}

void ue_stack_lte::in_sync()
{
  pending_tasks.push([this]() { rrc.in_sync(); });
}

void ue_stack_lte::out_of_sync()
{
  pending_tasks.push([this]() { rrc.out_of_sync(); });
}

void ue_stack_lte::run_tti(uint32_t tti)
{
  pending_tasks.push([this, tti]() { run_tti_impl(tti); });
}

void ue_stack_lte::run_tti_impl(uint32_t tti)
{
  mac.run_tti(tti);
  rrc.run_tti(tti);
}

} // namespace srsue
