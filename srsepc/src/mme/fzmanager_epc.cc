#include "srsepc/hdr/mme/s1ap.h"
#include "srsepc/hdr/mme/s1ap_nas_transport.h"
#include <cmath>
#include <inttypes.h>
#include <iostream>
#include <stdbool.h>

#include "srsepc/hdr/mme/fzmanager_epc.h"

// from nas.h
#include "srslte/asn1/gtpc_ies.h"
#include "srslte/asn1/liblte_mme.h"
#include "srslte/asn1/liblte_s1ap.h"
#include "srslte/common/buffer_pool.h"
#include "srslte/common/liblte_security.h"
#include "srslte/common/security.h"
#include "srslte/interfaces/epc_interfaces.h"

#include <iomanip>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include <fstream>

using namespace std;

namespace srsepc {

fzmanager_epc*  fzmanager_epc::m_instance    = NULL;
pthread_mutex_t fzmanager_epc_instance_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool     wait_for_response            = false;

// init
fzmanager_epc::fzmanager_epc()
{
  return;
}

fzmanager_epc::~fzmanager_epc()
{
  return;
}

fzmanager_epc* fzmanager_epc::get_instance(void)
{
  pthread_mutex_lock(&fzmanager_epc_instance_mutex);
  if (NULL == m_instance) {
    m_instance = new fzmanager_epc();
  }
  pthread_mutex_unlock(&fzmanager_epc_instance_mutex);
  return (m_instance);
}

void fzmanager_epc::cleanup(void)
{
  pthread_mutex_lock(&fzmanager_epc_instance_mutex);
  if (NULL != m_instance) {
    delete m_instance;
    m_instance = NULL;
  }
  pthread_mutex_unlock(&fzmanager_epc_instance_mutex);
}

/********************
  Testcase File IO 
********************/

bool fzmanager_epc::read_nas_test_config()
{
  prev_progress.open(NAS_CONFIG_FILE_NAME, std::ios_base::in);

  start_emm_cause_idx = 22; // means EMM cause #25
  sec_hdr_type_idx    = 0;

  if (prev_progress.is_open()) {
    if (!readvar(prev_progress, TEST_STATE_STR, &dt_nas_test_state)) {
      return false;
    }
    if (!readvar(prev_progress, TEST_PROTOCOL_STR, &dt_nas_test_protocol)) {
      return false;
    }
    if (!readvar(prev_progress, TEST_MESSAGE_STR, &dt_test_message)) {
      return false;
    }
    if (!readvar(prev_progress, EMM_CAUSE_IDX_STR, &start_emm_cause_idx)) {
      return false;
    }
    if (!readvar(prev_progress, SEC_HDR_TYPE_IDX_STR, &sec_hdr_type_idx)) {
      return false;
    }
    if (!readvar(prev_progress, ID_TYPE_IDX_STR, &id_type_idx)) {
      return false;
    }
    if (!readvar(prev_progress, MAC_TYPE_IDX_STR, &mac_type_idx)) {
      return false;
    }
    if (!readvar(prev_progress, START_DAY_STR, &start_day)) {
      return false;
    }
    if (!readvar(prev_progress, START_HOUR_STR, &start_hour)) {
      return false;
    }
    if (!readvar(prev_progress, CIPHER_ALGO_STR, &cipher_algo)) {
      return false;
    }
    if (!readvar(prev_progress, INTEG_ALGO_STR, &integ_algo)) {
      return false;
    }
    // printf("[DoLTEst] Reading configuration file.. (%s)\n", NAS_CONFIG_FILE_NAME);
    // printf("---------------------------------------\n");

    prev_progress.close();
    return true;
  } else {
      return false;
  }
}

bool fzmanager_epc::write_nas_test_config()
{
  out_progress.open(NAS_CONFIG_FILE_NAME);

  if (out_progress.is_open()) {

    out_progress << TEST_STATE_STR << (int)dt_nas_test_state << endl;
    out_progress << TEST_PROTOCOL_STR << (int)dt_nas_test_protocol << endl;
    out_progress << TEST_MESSAGE_STR << (int)dt_test_message << endl;
    out_progress << EMM_CAUSE_IDX_STR << start_emm_cause_idx << endl;
    out_progress << SEC_HDR_TYPE_IDX_STR << sec_hdr_type_idx << endl;
    out_progress << ID_TYPE_IDX_STR << id_type_idx << endl;
    out_progress << MAC_TYPE_IDX_STR << mac_type_idx << endl;
    out_progress << START_DAY_STR << (int)start_day << endl;
    out_progress << START_HOUR_STR << (int)start_hour << endl;
    out_progress << CIPHER_ALGO_STR << (int)cipher_algo << endl;
    out_progress << INTEG_ALGO_STR << (int)integ_algo << endl;

    out_progress.close();
    return true;
  } else {
      return false;
  }
}

void fzmanager_epc::set_path(int dt_nas_test_state)
{

  uint8_t msg_type_hex;
  int     temp_hex;

  // change str to hex value
  std::stringstream convert;
  convert << get_msg_type_hex(doltest_nas_test_msg_list[dt_test_message]);
  convert >> std::hex >> temp_hex;
  fz_target_msg = (uint8_t)temp_hex;

  int path_msg_n = path_msg_n_for_state[dt_nas_test_state];
  // clear path
  fz_target_path.clear();

    // set target path (NAS messages to move the UE's state)
  for (int i = 0; i < path_msg_n; i++) {

    std::stringstream convert;
    convert << get_msg_type_hex(path_list_str[i]);
    convert >> std::hex >> temp_hex;
    msg_type_hex = (uint8_t)temp_hex;
    fz_target_path.push_back(fz_nas_msg(msg_type_hex));
  }
}


void fzmanager_epc::init()
{
  m_pool = srslte::byte_buffer_pool::get_instance();

  is_finish          = false;
  need_to_wait       = false;
  msg_sent_cnt       = 0;
  epc_fuzz_state     = fzmanager_epc::EPC_SEC_STATE_NONE;
  is_path_traversing = true;

  if (path.empty()) {
    path.clear();
    
    start_day   = 1;
    start_hour  = 1;
    sms_msg_val = 0x40;

    dt_nas_test_protocol = 1;
    dt_nas_test_state = 0;
    dt_test_message = 0;

    // Default setting
    id_type_idx      = 0;
    sec_hdr_type_idx = LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS;

    if (!fzmanager_epc::read_nas_test_config()) {
      printf("*** %s does not exist. Creating new one ***\n", NAS_CONFIG_FILE_NAME);
      if (write_nas_test_config()) {
        printf("*** Updated test case configuration file (%s) ***\n", NAS_CONFIG_FILE_NAME);
      } else {
        printf("!!! Can not generate configuration file! Error! !!!\n");
        exit(-1);
      }
    } 
    fzmanager_epc::set_path(dt_nas_test_state);

    if (dt_test_message == LIBLTE_MME_MSG_TYPE_ATTACH_REJECT || dt_test_message == LIBLTE_MME_MSG_TYPE_SERVICE_REJECT) {
      is_reject_case      = true;
      start_emm_cause_idx = 0;
    } 
    next_msg = fz_target_path.begin();

  } else {
    if (!fzmanager_epc::read_nas_test_config()) {
      printf("*** %s does not exist. Creating new one ***\n", NAS_CONFIG_FILE_NAME);
      if (write_nas_test_config()) {
        printf("*** Updated test case configuration file (%s) ***\n", NAS_CONFIG_FILE_NAME);
      } else {
        printf("!!! Can not generate configuration file! Error! !!!\n");
        exit(-1);
      }
    } 
    fzmanager_epc::set_path(dt_nas_test_state);

    next_msg = fz_target_path.begin();
    sms_msg_val = 0x40;
  }

  if (dt_test_message == LIBLTE_MME_MSG_TYPE_ATTACH_REJECT || dt_test_message == LIBLTE_MME_MSG_TYPE_SERVICE_REJECT) {
    is_reject_case = true;
  }
}

// Signal handler for detecting no response
void fzmanager_epc::AlrmHandler(int signum)
{
  wait_for_response = true;

  if (signum == SIGALRM)
    printf("==== [DoLTEst] No response from UE ====\n");

  if (m_instance->is_finish && m_instance->is_reject_case) {
    // measure the elapsed time
    m_instance->end = time(NULL);
    double elapsed_time;
    elapsed_time = (double)(m_instance->end - m_instance->start);

    // EXIT code varies over its test case
    if (m_instance->start_emm_cause_idx < EMM_CAUSE_N) {
      printf("Need to test next test case after reboot\n");
      exit(TEST_INCOMPLETE_CODE);
    } else {
      printf("Test cases are done.\n");
      exit(TEST_FINISH_CODE);
    }
  }

  // Try to send next message
  srslte::byte_buffer_t* nas_tx;
  nas_tx       = m_instance->m_pool->allocate();
  nas* nas_ctx = m_instance->prev_nas_ctx;

  // If testing NAS message
  if (m_instance->dt_nas_test_protocol) {
    bool ret_val;
    ret_val = m_instance->fzmanager_ready_to_send(nas_ctx, nas_tx);
    if (ret_val)
      nas_ctx->m_s1ap->send_downlink_nas_transport(
          nas_ctx->m_ecm_ctx.enb_ue_s1ap_id, nas_ctx->m_ecm_ctx.mme_ue_s1ap_id, nas_tx, nas_ctx->m_ecm_ctx.enb_sri);
  }

  m_instance->m_pool->deallocate(nas_tx);
}

void fzmanager_epc::signal_setting()
{
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGALRM);
  sigprocmask(SIG_UNBLOCK, &set, NULL);
  if (signal(SIGALRM, AlrmHandler) == SIG_ERR) {
    fprintf(stderr, "signal() error\n");
    exit(-1);
  }
  alarm(RESPONSE_WAIT_TIME);
}

void fzmanager_epc::disable_alarm()
{
  alarm(0);
}

bool fzmanager_epc::add_to_path(uint8_t msg_type)
{
  if (is_path_traversing) {
    fz_nas_msg msg;
    msg.msg_type = msg_type;
    path.push_back(msg);

    // move to next
    if (next_msg != fz_target_path.end())
      next_msg++;

    if (next_msg == fz_target_path.end()) {
      // printf("[DoLTEst] Finish to traverse, UE is in target testing state\n");
      is_path_traversing = false;
    }
  } else {
    // ignore
    // printf("No need to add to path\n");
  }
  return true;
}

// For debug
void fzmanager_epc::print_path()
{
  list<fz_nas_msg>::iterator path_idx;
  printf("[Fuzz] Current NAS msg Path: ");
  for (path_idx = path.begin(); path_idx != path.end(); path_idx++)
    printf("(%u) ", path_idx->msg_type);
  printf("\n");
  printf("[Fuzz] Given target NAS msg Path: ");
  for (path_idx = fz_target_path.begin(); path_idx != fz_target_path.end(); path_idx++)
    printf("(%u) ", path_idx->msg_type);
  printf("\n");
}

void fzmanager_epc::reset_fuzzing_timing()
{
  this->init();
}

// Check whether the UE reaches to the target path. If not
bool fzmanager_epc::check_fuzzing_timing()
{

  if (is_finish && is_reject_case) {
    printf("Restarted Attach\n");

    // measure the elapsed time
    end = time(NULL);
    double elapsed_time;
    elapsed_time = (double)(end - start);
    printf("Restarted time: %f\n", elapsed_time);

    if (start_emm_cause_idx < EMM_CAUSE_N) {
      printf("Need to test next test case after reboot\n");
      exit(TEST_INCOMPLETE_CODE);
    } else {
      printf("Test cases are done.\n");
      exit(TEST_FINISH_CODE);
    }
  }

  if (is_path_traversing) {
    return false;
  }
  return true;
}

// send next msg to traverse (to reach target state of test case)
// *these are normal messages, not test messages 
void fzmanager_epc::traverse(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer)
{
  uint8_t cur_msg_type;
  cur_msg_type = next_msg->msg_type;

  /* pack original msg in NAS.cc */
  switch (cur_msg_type) {
    case LIBLTE_MME_MSG_TYPE_IDENTITY_REQUEST:
      // Send a Identity Request Message
      nas_ctx->pack_identity_request(nas_buffer);
      // nas_ctx->m_nas_log->console("[Traverse] Sending Identity Request.\n");
      nas_ctx->m_nas_log->console("---> NAS Identity Request --->\n");
      nas_ctx->m_nas_log->info("[Traverse] Sending Identity Request.\n");
      break;

    case LIBLTE_MME_MSG_TYPE_AUTHENTICATION_REQUEST:
      // Send a Authentication Request Message
      nas_ctx->pack_authentication_request(nas_buffer);
      // nas_ctx->m_nas_log->console("[Traverse] Sending Authentication Request.\n");
      nas_ctx->m_nas_log->console("---> NAS Authentication Request --->\n");
      nas_ctx->m_nas_log->info("[Traverse] Sending Authentication Request.\n");
      break;

    case LIBLTE_MME_MSG_TYPE_SECURITY_MODE_COMMAND:
      // Send a Security Mode Command Message
      nas_ctx->m_sec_ctx.ul_nas_count = 0; // Reset the NAS uplink counter for the right key k_enb derivation
      nas_ctx->pack_security_mode_command(nas_buffer);
      // nas_ctx->m_nas_log->console("[Traverse] Sending NAS Security Mode Command.\n");
      nas_ctx->m_nas_log->console("---> NAS Security Mode Command --->\n");
      nas_ctx->m_nas_log->info("[Traverse] Sending NAS Security Mode Command.\n");
      break;

    case LIBLTE_MME_MSG_TYPE_ESM_INFORMATION_REQUEST:
      // Send a ESM Information Request Message
      nas_ctx->pack_esm_information_request(nas_buffer);
      // nas_ctx->m_nas_log->console("[Traverse] Sending ESM Information Request\n");
      nas_ctx->m_nas_log->console("---> NAS ESM Information Request --->\n");
      nas_ctx->m_nas_log->info("[Traverse] Sending ESM Information Request\n");
      break;

    case LIBLTE_MME_MSG_TYPE_ATTACH_ACCEPT:
      // Send a Attach Accept Message
      nas_ctx->pack_attach_accept(nas_buffer);
      // nas_ctx->m_nas_log->console("[Traverse] Sending Attach accept\n");
      nas_ctx->m_nas_log->console("---> NAS Attach Accept --->\n");
      nas_ctx->m_nas_log->info("[Traverse] Sending Attach accept\n");
      break;

    case LIBLTE_MME_MSG_TYPE_EMM_INFORMATION:
      // Send a EMM Information Message
      nas_ctx->pack_emm_information(nas_buffer);
      // nas_ctx->m_nas_log->console("[Traverse] Sending EMM Information\n");
      nas_ctx->m_nas_log->console("---> NAS EMM Information --->\n");
      nas_ctx->m_nas_log->info("[Traverse] Sending EMM Information\n");
      break;

    default:
      break;
  }

  /* transmit the msg */
  if (cur_msg_type != LIBLTE_MME_MSG_TYPE_ATTACH_ACCEPT){
  nas_ctx->m_s1ap->send_downlink_nas_transport(
      nas_ctx->m_ecm_ctx.enb_ue_s1ap_id, nas_ctx->m_ecm_ctx.mme_ue_s1ap_id, nas_buffer, nas_ctx->m_ecm_ctx.enb_sri);
  }
  fzmanager_epc::add_to_path(cur_msg_type);  
}

// Control to send Next NAS msg
bool fzmanager_epc::fzmanager_ready_to_send(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer)
{
  if (is_finish) {
    if (is_reject_case) {
      printf("For the reject cases, wait for the response or measure the next attach\n");
      return false;
    } else {
      nas_ctx->m_nas_log->info("Test cases are done\n");
      printf("Test cases are done.\n");
      exit(TEST_FINISH_CODE);
    }
  }
  if (need_to_wait) {
    printf("...Waiting for next Attach Request...\n");
    nas_ctx->m_nas_log->info("...Waiting for next attach request...\n");
    return false;
  }

  path.clear();

  printf("\n------- [DoLTEst] Preparing next test message.. -------\n");
  printf("Test message # sent on this connection: %d \n", (msg_sent_cnt+1));

  // store the previous nas_ctx
  prev_nas_ctx    = nas_ctx;
  prev_nas_buffer = nas_buffer;

  fzmanager_epc::disable_alarm();

  if (!(dt_nas_test_state >= 2))
    fzmanager_epc::signal_setting();

  fzmanager_epc::pack_test_message(nas_ctx, nas_buffer);

  // printf("======= Test msg is prepared to be sent =======\n");

  return true;
}


// Control to send Next NAS msg
bool fzmanager_epc::fzmanager_ready_to_send_2(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer)
{
  if (is_finish) {
    if (is_reject_case) {
      printf("For the reject cases, wait for the response or measure the next attach\n");
      return false;
    } else {
      nas_ctx->m_nas_log->info("Test cases are done\n");
      printf("Test cases are done.\n");
      exit(TEST_FINISH_CODE);
    }
  }
  if (need_to_wait) {
    // printf("Wait for next attach request\n");
    // nas_ctx->m_nas_log->info("Wait for next attach request\n");
    return false;
  }
  prev_nas_ctx    = nas_ctx;
  prev_nas_buffer = nas_buffer;

  fzmanager_epc::disable_alarm();
  fzmanager_epc::signal_setting();

  return true;
}

// Handle unhandled messages
bool fzmanager_epc::fzmanager_receive_unhandled_msg(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer, uint8_t msg_type)
{
  std::stringstream sstream;
  sstream << "0x" << std::setfill('0') << std::setw(2) << std::hex << (int)msg_type;
  nas_ctx->m_nas_log->console("Received Msg(s): %s\n", sstream.str().c_str());
  nas_ctx->m_nas_log->console("Received Msg: %s\n", get_msg_type_name(sstream.str().c_str()));

  if (is_finish) {
    // exit(2);
    if (is_reject_case)
      return false;
    else {
      printf("Test cases are done.\n");
      exit(TEST_FINISH_CODE);
    }
  }
  // disalbe the alarm
  // fzmanager_epc::disable_alarm();

  // Send next msgs
  prev_nas_ctx = nas_ctx;
  // fzmanager_epc::AlrmHandler((int)msg_type);

  return true;
}

/*
  Main DoLTEst test message generation function

TS 24.301 4.4.4.2
Except the messages listed below, no NAS signalling messages shall be processed by the receiving EMM entity in the UE or
forwarded to the ESM entity, unless the network has established secure exchange of NAS messages for the NAS signalling
connection: -	EMM messages: -	IDENTITY REQUEST (if requested identification parameter is IMSI); -	AUTHENTICATION
REQUEST; -	AUTHENTICATION REJECT; -	ATTACH REJECT (if the EMM cause is not #25); -	DETACH ACCEPT (for non
switch off); -	TRACKING AREA UPDATE REJECT (if the EMM cause is not #25); -	SERVICE REJECT (if the EMM cause is not
#25).

0x42	66	to UE	Attach accept	8.2.1
0x44	68	to UE	Attach reject	8.2.3
0x45	69	to UE	Detach request (UE terminated detach)	8.2.11.2
0x46	70	to UE	Detach accept (UE originating detach)	8.2.10.1
0x49	73	to UE	Tracking area update accept	8.2.26
0x4b	75	to UE	Tracking area update reject	8.2.28
0x4d	77	to UE	Service reject	8.2.24
0x50	80	to UE	GUTI reallocation command	8.2.16
0x52	82	to UE	Authentication request	8.2.7
0x54	84	to UE	Authentication reject	8.2.6
0x55	85	to UE	Identity request	8.2.18
0x5d	93	to UE	Security mode command	8.2.20
0x62	98	to UE	Downlink NAS transport	8.2.12
0x64	100	to UE	CS Service notification	8.2.9
0x68	104	to UE	Downlink generic NAS transport	8.2.31

*/

bool fzmanager_epc::pack_test_message(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer)
{
  switch (fz_target_msg) {
    case LIBLTE_MME_MSG_TYPE_IDENTITY_REQUEST:
      // do identity request
      fzmanager_epc::pack_identity_request(nas_ctx, nas_buffer);
      break;

    case LIBLTE_MME_MSG_TYPE_GUTI_REALLOCATION_COMMAND:
      fzmanager_epc::pack_guti_reallocation(nas_ctx, nas_buffer);
      break;

    case LIBLTE_MME_MSG_TYPE_SECURITY_MODE_COMMAND:
      // nas_ctx->pack_security_mode_command(nas_buffer);
      fzmanager_epc::pack_security_mode_command(nas_ctx, nas_buffer);
      break;

    case LIBLTE_MME_MSG_TYPE_EMM_INFORMATION:
      fzmanager_epc::pack_emm_information(nas_ctx, nas_buffer);
      break;

    case LIBLTE_MME_MSG_TYPE_DOWNLINK_NAS_TRANSPORT:
      fzmanager_epc::pack_downlink_nas_transport(nas_ctx, nas_buffer);
      break;

    case LIBLTE_MME_MSG_TYPE_ATTACH_ACCEPT:
      fzmanager_epc::pack_attach_accept(nas_ctx, nas_buffer);
      // on nas.cc +1526
      break;
    case LIBLTE_MME_MSG_TYPE_DETACH_REQUEST:
      fzmanager_epc::pack_detach_request(nas_ctx, nas_buffer);
      break;
    case LIBLTE_MME_MSG_TYPE_DETACH_ACCEPT:
      fzmanager_epc::pack_detach_accept(nas_ctx, nas_buffer);
      // liblte_mme_pack_detach_accept_msg exists
      break;
    case LIBLTE_MME_MSG_TYPE_TRACKING_AREA_UPDATE_ACCEPT:
      fzmanager_epc::pack_tracking_area_update_accept(nas_ctx, nas_buffer);
      // liblte_mme_pack_tracking_area_update_accept_msg
      break;
    case LIBLTE_MME_MSG_TYPE_EMM_STATUS:
      fzmanager_epc::pack_emm_status(nas_ctx, nas_buffer);
      // liblte_mme_pack_emm_status_msg
      break;
    case LIBLTE_MME_MSG_TYPE_CS_SERVICE_NOTIFICATION:
      // fzmanager_epc::pack_cs_service_notification(nas_ctx,nas_buffer);
      break;
    case LIBLTE_MME_MSG_TYPE_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST:
      fzmanager_epc::pack_activate_default_eps_bearer_context_request(nas_ctx, nas_buffer);
      // liblte_mme_pack_activate_default_eps_bearer_context_request_msg
      break;
    case LIBLTE_MME_MSG_TYPE_ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REQUEST:
      // fzmanager_epc::pack_activate_dedicated_eps_bearer_context_request(nas_ctx,nas_buffer);
      // liblte_mme_pack_activate_dedicated_eps_bearer_context_request_msg
      break;
    case LIBLTE_MME_MSG_TYPE_MODIFY_EPS_BEARER_CONTEXT_REQUEST:
      fzmanager_epc::pack_modify_eps_bearer_context_request(nas_ctx, nas_buffer);
      // liblte_mme_pack_modify_eps_bearer_context_request_msg
      break;
    case LIBLTE_MME_MSG_TYPE_DEACTIVATE_EPS_BEARER_CONTEXT_REQUEST:
      fzmanager_epc::pack_deactivate_eps_bearer_context_request(nas_ctx, nas_buffer);
      // liblte_mme_pack_deactivate_eps_bearer_context_request_msg
      break;
    case LIBLTE_MME_MSG_TYPE_PDN_DISCONNECT_REJECT:
      fzmanager_epc::pack_pdn_disconnect_reject(nas_ctx, nas_buffer);
      // liblte_mme_pack_pdn_disconnect_reject_msg
      break;
    case LIBLTE_MME_MSG_TYPE_BEARER_RESOURCE_ALLOCATION_REJECT:
      fzmanager_epc::pack_bearer_resource_allocation_reject(nas_ctx, nas_buffer);
      // liblte_mme_pack_bearer_resource_allocation_reject_msg
      break;
    case LIBLTE_MME_MSG_TYPE_BEARER_RESOURCE_MODIFICATION_REJECT:
      fzmanager_epc::pack_bearer_resource_modification_reject(nas_ctx, nas_buffer);
      // liblte_mme_pack_bearer_resource_reject_msg
      break;
    case LIBLTE_MME_MSG_TYPE_ESM_INFORMATION_REQUEST:
      fzmanager_epc::pack_esm_information_request(nas_ctx, nas_buffer);
      // liblte_mme_esm_information_request_msg
      break;
    case LIBLTE_MME_MSG_TYPE_NOTIFICATION:
      fzmanager_epc::pack_notification(nas_ctx, nas_buffer);
      // liblte_mme_pack_notification_msg
      break;
    case LIBLTE_MME_MSG_TYPE_ESM_STATUS:
      fzmanager_epc::pack_esm_status(nas_ctx, nas_buffer);
      // liblte_mme_pack_esm_status_msg
      break;
      // reject cases

    case LIBLTE_MME_MSG_TYPE_ATTACH_REJECT:
      fzmanager_epc::pack_attach_reject(nas_ctx, nas_buffer);
      break;

    case LIBLTE_MME_MSG_TYPE_SERVICE_REJECT:
      fzmanager_epc::pack_service_reject(nas_ctx, nas_buffer);
      break;

    case LIBLTE_MME_MSG_TYPE_TRACKING_AREA_UPDATE_REJECT:
      fzmanager_epc::pack_tracking_area_update_reject(nas_ctx, nas_buffer);
      break;

    case LIBLTE_MME_MSG_TYPE_PDN_CONNECTIVITY_REJECT:
      fzmanager_epc::pack_pdn_connectivity_reject(nas_ctx, nas_buffer);
      is_reject_case = true;

      break;

    default:
      nas_ctx->m_nas_log->console("No such target msgs in this state\n");
      break;
  }

  msg_sent_cnt = msg_sent_cnt + 1;
  if (msg_sent_cnt >= TEST_LIMIT) {
    need_to_wait = true;
    path.clear();
  }

  return true;
}

bool fzmanager_epc::pack_identity_request(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer)
{

  sec_ctx_t* m_sec_ctx = &nas_ctx->m_sec_ctx;

  LIBLTE_MME_ID_REQUEST_MSG_STRUCT id_req;
  uint8_t                          sec_hdr_type;

  uint8 identity_request_type_value[16];
  uint8 temp_tv = 0;
  for (int tv = 0; tv < 16; tv++) {
    identity_request_type_value[tv] = temp_tv;
    temp_tv++;
  }
  id_req.id_type = nas_ctx->m_long_test_mode? identity_request_type_value[identity_type2_variation_long[id_type_idx]]: identity_request_type_value[identity_type2_variation[id_type_idx]];
  sec_hdr_type   = sec_hdr_type_variation[sec_hdr_type_idx];

  nas_ctx->m_nas_log->console("---> Packing next test message --->\n");
  nas_ctx->m_nas_log->console("---> Target State        : %s --->\n", doltest_state_names[dt_nas_test_state]);
  nas_ctx->m_nas_log->console("---> Target Msg          : %s --->\n", doltest_nas_test_msg_type_names[0]);
  nas_ctx->m_nas_log->console("---> Target Sec.hdr.type : %s --->\n", sec_hdr_type_str[sec_hdr_type]);
  nas_ctx->m_nas_log->console("---> Target MAC          : %s --->\n", mac_type_str[mac_type_idx]);
  nas_ctx->m_nas_log->console("---> Identity type value : %s --->\n", identity_type_str[id_req.id_type]);


  m_sec_ctx->dl_nas_count++;
  LIBLTE_ERROR_ENUM err = liblte_mme_pack_identity_request_msg_sec(
      &id_req, sec_hdr_type, m_sec_ctx->dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);
  if (err != LIBLTE_SUCCESS) {
    nas_ctx->m_nas_log->error("Error packing Identity Request\n");
    nas_ctx->m_nas_log->console("Error packing Identity REquest\n");
    return false;
  }

  if (sec_hdr_type != LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS) {
    uint8_t mac[4];
    integrity_generate(nas_ctx, nas_buffer, mac);
    memcpy(&nas_buffer->msg[1], mac, 4);
  }

  // Move to next IDRequest
  // This is for testing IE: ID type for value 0~15 (4bit)
  /*
      id_type_idx = id_type_idx + 1;
      if (id_type_idx == IDENTITY_REQUEST_TYPE_TESTN) {
              id_type_idx = 0;

              sec_hdr_type_idx = sec_hdr_type_idx + 1;
              if (sec_hdr_type_idx == SEC_HDR_TYPE_TESTN) {
                      sec_hdr_type_idx = 0;

                      mac_type_idx = mac_type_idx + 1;
          // For mac_type_idx 1 (invalid MAC), skip security header type 0, because it does not have MAC field.
                      sec_hdr_type_idx = sec_hdr_type_idx +1;

                      if (mac_type_idx == MAC_TYPE_TESTN){
                              mac_type_idx = 0;
                              nas_ctx->m_nas_log->console("Finish to test Identity Request\n\n\n\n\n\n");
                              is_finish = true;
                      }
              }
   }
   */
  identity_request_test_value_range = nas_ctx->m_long_test_mode? IDENTITY_TYPE2_LONG_TESTN : IDENTITY_TYPE2_TESTN;

  id_type_idx = id_type_idx + 1;
  if (id_type_idx == identity_request_test_value_range) {
    id_type_idx = 0;

    sec_hdr_type_idx = sec_hdr_type_idx + 1;
    if (sec_hdr_type_idx == SEC_HDR_TYPE_TESTN) {
      sec_hdr_type_idx = 0;

      mac_type_idx = mac_type_idx + 1;

      // For mac_type_idx 1 (invalid MAC), skip security header type 0, because it does not have MAC field.
      sec_hdr_type_idx = sec_hdr_type_idx + 1;

      if (mac_type_idx == MAC_TYPE_TESTN) {
        mac_type_idx     = 0;
        sec_hdr_type_idx = 0;
        nas_ctx->m_nas_log->console("\n[DoLTEst] <NAS Identity Request> testing finished\n\n\n\n\n\n");
        // is_finish = true;
        disable_alarm();
        dt_test_message++;
      }
    }
  }

  // write_prev_progress_file();
  write_nas_test_config();
  return true;
}

bool fzmanager_epc::pack_authentication_request(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer)
{
  nas_ctx->m_nas_log->console("Packing Authentication Request\n");

  sec_ctx_t* m_sec_ctx = &nas_ctx->m_sec_ctx;

  // Pack NAS msg
  LIBLTE_MME_AUTHENTICATION_REQUEST_MSG_STRUCT auth_req;
  memcpy(auth_req.autn, m_sec_ctx->autn, 16);
  memcpy(auth_req.rand, m_sec_ctx->rand, 16);
  auth_req.nas_ksi.tsc_flag = LIBLTE_MME_TYPE_OF_SECURITY_CONTEXT_FLAG_NATIVE;
  auth_req.nas_ksi.nas_ksi  = m_sec_ctx->eksi;

  LIBLTE_ERROR_ENUM err = liblte_mme_pack_authentication_request_msg(&auth_req, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);
  if (err != LIBLTE_SUCCESS) {
    nas_ctx->m_nas_log->error("Error packing Authentication Request\n");
    nas_ctx->m_nas_log->console("Error packing Authentication Request\n");
    return false;
  }
  return true;
}

bool fzmanager_epc::pack_authentication_reject(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer)
{
  nas_ctx->m_nas_log->console("Packing Authentication Reject\n");

  LIBLTE_MME_AUTHENTICATION_REJECT_MSG_STRUCT auth_rej;
  LIBLTE_ERROR_ENUM err = liblte_mme_pack_authentication_reject_msg(&auth_rej, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);
  if (err != LIBLTE_SUCCESS) {
    nas_ctx->m_nas_log->error("Error packing Authentication Reject\n");
    nas_ctx->m_nas_log->console("Error packing Authentication Reject\n");
    return false;
  }
  return true;
}

void fzmanager_epc::next_security_mode_command()
{
  // cipher_algo = cipher_algo + 1;

  // Longer version (For changing EEA)
  /*

  if(integ_algo == srslte::INTEGRITY_ALGORITHM_ID_ENUM::INTEGRITY_ALGORITHM_ID_EIA0)
    integ_algo = 4;
  else if(integ_algo == 4 || integ_algo == 5 ||integ_algo == 6 ||integ_algo == 7){
    integ_algo = integ_algo + 1;
  }else {
      integ_algo = 4;
  }


      if (integ_algo == 8) {
    integ_algo = 0;
    //

    if(cipher_algo == 0 || cipher_algo == 4 || cipher_algo == 5 || cipher_algo == 6 || cipher_algo == 7){
        cipher_algo = cipher_algo + 1;
    } else {
        cipher_algo = 4;
    }

    if (cipher_algo == 8){
      cipher_algo = 0;

      sec_hdr_type_idx = sec_hdr_type_idx + 1;
      if	(sec_hdr_type_idx == SEC_HDR_TYPE_TESTN) {
          sec_hdr_type_idx = 0;

          mac_type_idx = mac_type_idx + 1;
          if (mac_type_idx == MAC_TYPE_TESTN) {
              m_instance->prev_nas_ctx->m_nas_log->console("\n[DoLTEst] <NAS Security Mode Command> testing
  finished\n\n\n\n\n\n"); is_finish = true;
          }
      }
        }
      }
  */

  if (integ_algo == srslte::INTEGRITY_ALGORITHM_ID_ENUM::INTEGRITY_ALGORITHM_ID_EIA0)
    integ_algo = 4;
  else if (integ_algo == 4 || integ_algo == 5 || integ_algo == 6 || integ_algo == 7) {
    integ_algo = integ_algo + 1;
  }

  if (integ_algo == 8) {
    integ_algo       = 0;
    sec_hdr_type_idx = sec_hdr_type_idx + 1;

    if (sec_hdr_type_idx == SEC_HDR_TYPE_TESTN) {
      integ_algo       = 0;
      sec_hdr_type_idx = 1;

      mac_type_idx = mac_type_idx + 1;
      if (mac_type_idx == MAC_TYPE_TESTN) {
        mac_type_idx = 0;
        sec_hdr_type_idx = 0;
        m_instance->prev_nas_ctx->m_nas_log->console(
            "\n[DoLTEst] <NAS Security Mode Command> testing finished\n\n\n\n\n\n");
        // is_finish = true;
        disable_alarm();
        dt_test_message++;
      }
    }
  }

  // write_prev_progress_file();
  write_nas_test_config();
}

bool fzmanager_epc::pack_security_mode_command(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer)
{
  sec_ctx_t* m_sec_ctx = &nas_ctx->m_sec_ctx;

  // Reset the NAS uplink counter for the right key k_enb derivation
  m_sec_ctx->ul_nas_count = 0;

  // Pack NAS PDU
  LIBLTE_MME_SECURITY_MODE_COMMAND_MSG_STRUCT sm_cmd;

  m_sec_ctx->cipher_algo = (srslte::CIPHERING_ALGORITHM_ID_ENUM)cipher_algo;
  m_sec_ctx->integ_algo  = (srslte::INTEGRITY_ALGORITHM_ID_ENUM)integ_algo;

  sm_cmd.selected_nas_sec_algs.type_of_eea = (LIBLTE_MME_TYPE_OF_CIPHERING_ALGORITHM_ENUM)m_sec_ctx->cipher_algo;
  sm_cmd.selected_nas_sec_algs.type_of_eia = (LIBLTE_MME_TYPE_OF_INTEGRITY_ALGORITHM_ENUM)m_sec_ctx->integ_algo;

  sm_cmd.nas_ksi.tsc_flag = LIBLTE_MME_TYPE_OF_SECURITY_CONTEXT_FLAG_NATIVE;
  sm_cmd.nas_ksi.nas_ksi  = m_sec_ctx->eksi;

  // Replay UE security cap
  memcpy(sm_cmd.ue_security_cap.eea, m_sec_ctx->ue_network_cap.eea, 8 * sizeof(bool));
  memcpy(sm_cmd.ue_security_cap.eia, m_sec_ctx->ue_network_cap.eia, 8 * sizeof(bool));

  sm_cmd.ue_security_cap.uea_present = m_sec_ctx->ue_network_cap.uea_present;
  memcpy(sm_cmd.ue_security_cap.uea, m_sec_ctx->ue_network_cap.uea, 8 * sizeof(bool));

  sm_cmd.ue_security_cap.uia_present = m_sec_ctx->ue_network_cap.uia_present;
  memcpy(sm_cmd.ue_security_cap.uia, m_sec_ctx->ue_network_cap.uia, 8 * sizeof(bool));

  sm_cmd.ue_security_cap.gea_present = m_sec_ctx->ms_network_cap_present;
  memcpy(sm_cmd.ue_security_cap.gea, m_sec_ctx->ms_network_cap.gea, 8 * sizeof(bool));

  sm_cmd.imeisv_req_present = false;
  sm_cmd.nonce_ue_present   = false;
  sm_cmd.nonce_mme_present  = false;

  // Fuzz sec_hdr_type
  uint8_t sec_hdr_type;
  sec_hdr_type = sec_hdr_type_variation[sec_hdr_type_idx];
  // m_sec_ctx->dl_nas_count = 1;

  LIBLTE_ERROR_ENUM err = liblte_mme_pack_security_mode_command_msg(
      &sm_cmd, sec_hdr_type, m_sec_ctx->dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);
  if (err != LIBLTE_SUCCESS) {
    nas_ctx->m_nas_log->console("Error packing Authentication Request\n");
    return false;
  }

  // Generate EPS security context
  srslte::security_generate_k_nas(
      m_sec_ctx->k_asme, m_sec_ctx->cipher_algo, m_sec_ctx->integ_algo, m_sec_ctx->k_nas_enc, m_sec_ctx->k_nas_int);

  nas_ctx->m_nas_log->info_hex(m_sec_ctx->k_nas_enc, 32, "Key NAS Encryption (k_nas_enc)\n");
  nas_ctx->m_nas_log->info_hex(m_sec_ctx->k_nas_int, 32, "Key NAS Integrity (k_nas_int)\n");

  uint8_t key_enb[32];
  srslte::security_generate_k_enb(m_sec_ctx->k_asme, m_sec_ctx->ul_nas_count, m_sec_ctx->k_enb);
  // nas_ctx->m_nas_log->info("Generating KeNB with UL NAS COUNT: %d\n", m_sec_ctx->ul_nas_count);
  // nas_ctx->m_nas_log->console("Generating KeNB with UL NAS COUNT: %d\n", m_sec_ctx->ul_nas_count);
  // nas_ctx->m_nas_log->info_hex(m_sec_ctx->k_enb, 32, "Key eNodeB (k_enb)\n");

  // Generate MAC for integrity protection
  uint8_t mac[4];
  integrity_generate(nas_ctx, nas_buffer, mac);

  if (sec_hdr_type != LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS)
    memcpy(&nas_buffer->msg[1], mac, 4);

  nas_ctx->m_nas_log->console("---> Packing next test message --->\n");
  nas_ctx->m_nas_log->console("---> Target State        : %s --->\n", doltest_state_names[dt_nas_test_state]);
  nas_ctx->m_nas_log->console("---> Target Msg          : %s --->\n", doltest_nas_test_msg_type_names[1]);
  nas_ctx->m_nas_log->console("---> Target Sec.hdr.type : %s --->\n", sec_hdr_type_str[sec_hdr_type]);
  nas_ctx->m_nas_log->console("---> Target MAC          : %s --->\n", mac_type_str[mac_type_idx]);
  nas_ctx->m_nas_log->console("---> Integrity algorithm : %s --->\n", srslte::integrity_algorithm_id_text[sm_cmd.selected_nas_sec_algs.type_of_eia]);
                              

  // Increase Next mutation
  fzmanager_epc::next_security_mode_command();

  return true;
}

bool fzmanager_epc::pack_esm_information_request(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer)
{
  nas_ctx->m_nas_log->info("Packing ESM Information request\n");

  sec_ctx_t* m_sec_ctx = &nas_ctx->m_sec_ctx;
  emm_ctx_t* m_emm_ctx = &nas_ctx->m_emm_ctx;

  LIBLTE_MME_ESM_INFORMATION_REQUEST_MSG_STRUCT esm_info_req;
  esm_info_req.eps_bearer_id       = 0;
  esm_info_req.proc_transaction_id = m_emm_ctx->procedure_transaction_id;

  uint8_t sec_hdr_type = LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED;

  m_sec_ctx->dl_nas_count++;
  LIBLTE_ERROR_ENUM err = srslte_mme_pack_esm_information_request_msg(
      &esm_info_req, sec_hdr_type, m_sec_ctx->dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);
  if (err != LIBLTE_SUCCESS) {
    nas_ctx->m_nas_log->error("Error packing ESM information request\n");
    nas_ctx->m_nas_log->console("Error packing ESM information request\n");
    return false;
  }

  cipher_encrypt(nas_ctx, nas_buffer);
  uint8_t mac[4];
  integrity_generate(nas_ctx, nas_buffer, mac);
  memcpy(&nas_buffer->msg[1], mac, 4);

  return true;
}

void fzmanager_epc::next_emm_information()
{
  start_day        = start_day + 1;
  start_hour       = start_hour + 1;
  sec_hdr_type_idx = sec_hdr_type_idx + 1;
  if (sec_hdr_type_idx == SEC_HDR_TYPE_TESTN) {
    sec_hdr_type_idx = 1;
    mac_type_idx     = mac_type_idx + 1;
    if (mac_type_idx == MAC_TYPE_TESTN) {
      sec_hdr_type_idx = 0;
      mac_type_idx     = 0;
      m_instance->prev_nas_ctx->m_nas_log->console("\n[DoLTEst] <NAS EMM Information> testing finished\n\n\n\n\n\n");
      // is_finish = true;
      disable_alarm();
      dt_test_message++;
    }
  }
  // write_prev_progress_file();
  write_nas_test_config();
}

bool fzmanager_epc::pack_emm_information(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer)
{
  sec_ctx_t* m_sec_ctx = &nas_ctx->m_sec_ctx;
  emm_ctx_t* m_emm_ctx = &nas_ctx->m_emm_ctx;

  // nas_ctx->m_nas_log->console("Packing EMM Information\n");

  LIBLTE_MME_EMM_INFORMATION_MSG_STRUCT emm_info;
  emm_info.full_net_name_present = true;
  strncpy(emm_info.full_net_name.name, "Syssec_TEST", LIBLTE_STRING_LEN);
  emm_info.full_net_name.add_ci   = LIBLTE_MME_ADD_CI_DONT_ADD;
  emm_info.short_net_name_present = true;
  strncpy(emm_info.short_net_name.name, "Syssec", LIBLTE_STRING_LEN);
  emm_info.short_net_name.add_ci = LIBLTE_MME_ADD_CI_DONT_ADD;

  emm_info.local_time_zone_present         = false;
  emm_info.local_time_zone                 = 0x12;
  emm_info.utc_and_local_time_zone_present = true;
  emm_info.net_dst_present                 = false;

  LIBLTE_MME_TIME_ZONE_AND_TIME_STRUCT fake_time;
  emm_info.utc_and_local_time_zone.day    = start_day;
  emm_info.utc_and_local_time_zone.year   = 0x7e3;
  emm_info.utc_and_local_time_zone.month  = 0x5;
  emm_info.utc_and_local_time_zone.hour   = 0x1;
  emm_info.utc_and_local_time_zone.minute = 0;

  uint8_t sec_hdr_type = LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED;
  sec_hdr_type         = sec_hdr_type_variation[sec_hdr_type_idx];

  m_sec_ctx->dl_nas_count++;
  LIBLTE_ERROR_ENUM err = liblte_mme_pack_emm_information_msg(
      &emm_info, sec_hdr_type, m_sec_ctx->dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);
  if (err != LIBLTE_SUCCESS) {
    nas_ctx->m_nas_log->error("Error packing EMM Information\n");
    nas_ctx->m_nas_log->console("Error packing EMM Information\n");
    return false;
  }

  // Encrypt NAS message
  // cipher_encrypt(nas_ctx, nas_buffer);

  if (sec_hdr_type != LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS) {
    uint8_t mac[4];
    integrity_generate(nas_ctx, nas_buffer, mac);
    memcpy(&nas_buffer->msg[1], mac, 4);
    //  memcpy(&nas_buffer->msg[1], mac, 4);
    // Integrity protect NAS message
  }

  nas_ctx->m_nas_log->console("---> Packing next test message --->\n");
  nas_ctx->m_nas_log->console("---> Target State        : %s --->\n", doltest_state_names[dt_nas_test_state]);
  nas_ctx->m_nas_log->console("---> Target Msg          : %s --->\n", doltest_nas_test_msg_type_names[3]);
  nas_ctx->m_nas_log->console("---> Target Sec.hdr.type : %s --->\n", sec_hdr_type_str[sec_hdr_type]);
  nas_ctx->m_nas_log->console("---> Target MAC          : %s --->\n", mac_type_str[mac_type_idx]);

  fzmanager_epc::next_emm_information();



  nas_ctx->m_nas_log->info("Packed UE EMM information\n");
  return true;
}

void fzmanager_epc::next_guti_reallocation()
{
  sec_hdr_type_idx = sec_hdr_type_idx + 1;
  if (sec_hdr_type_idx == SEC_HDR_TYPE_TESTN) {
    sec_hdr_type_idx = 1;
    mac_type_idx     = mac_type_idx + 1;
    if (mac_type_idx == MAC_TYPE_TESTN) {
      sec_hdr_type_idx = 0;
      mac_type_idx     = 0;
      m_instance->prev_nas_ctx->m_nas_log->console(
          "\n[DoLTEst] <NAS GUTI Reallocation Command> testing finished\n\n\n\n\n\n");
      // is_finish = true;
      disable_alarm();
      dt_test_message++;
    }
  }
  // write_prev_progress_file();
  write_nas_test_config();
}

void fzmanager_epc::pack_guti_reallocation(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer)
{
  LIBLTE_MME_GUTI_REALLOCATION_COMMAND_MSG_STRUCT guti_realloc;
  LIBLTE_MME_EPS_MOBILE_ID_GUTI_STRUCT            new_guti;
  LIBLTE_MME_EPS_MOBILE_ID_STRUCT                 new_id;

  sec_ctx_t* sec_ctx = &nas_ctx->m_sec_ctx;
  emm_ctx_t* emm_ctx = &nas_ctx->m_emm_ctx;

  // Critical Field
  new_guti.m_tmsi       = 1;
  new_guti.mcc          = 901;
  new_guti.mnc          = 55;
  new_guti.mme_group_id = 1;
  new_guti.mme_code     = 1;

  new_id.type_of_id = 6;
  new_id.guti       = new_guti;

  guti_realloc.guti             = new_id;
  guti_realloc.tai_list_present = false;

  LIBLTE_ERROR_ENUM err;
  uint8_t           sec_hdr_type = LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED;
  sec_hdr_type                   = sec_hdr_type_variation[sec_hdr_type_idx];

  sec_ctx->dl_nas_count++;
  err = liblte_mme_pack_guti_reallocation_command_msg(
      &guti_realloc, sec_hdr_type, sec_ctx->dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);

  // Generate MAC for integrity protection
  uint8_t mac[4];
  integrity_generate(nas_ctx, nas_buffer, mac);

  if (sec_hdr_type != LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS)
    memcpy(&nas_buffer->msg[1], mac, 4);

  // nas_ctx->m_nas_log->console("Packing %s (SEC_HDR_TYPE= %s, MAC_type=%s)\n",
  //                           doltest_nas_test_msg_type_names[2],
  //                           sec_hdr_type_str[sec_hdr_type],
  //                           mac_type_str[mac_type_idx]);

  nas_ctx->m_nas_log->console("---> Packing next test message --->\n");
  nas_ctx->m_nas_log->console("---> Target State        : %s --->\n", doltest_state_names[dt_nas_test_state]);
  nas_ctx->m_nas_log->console("---> Target Msg          : %s --->\n", doltest_nas_test_msg_type_names[2]);
  nas_ctx->m_nas_log->console("---> Target Sec.hdr.type : %s --->\n", sec_hdr_type_str[sec_hdr_type]);
  nas_ctx->m_nas_log->console("---> Target MAC          : %s --->\n", mac_type_str[mac_type_idx]);

  // Increase Next mutation
  fzmanager_epc::next_guti_reallocation();
}

void fzmanager_epc::next_downlink_nas_transport()
{
  sms_msg_val++;
  start_day++;
  if (is_finish)
    return;

  sec_hdr_type_idx = sec_hdr_type_idx + 1;
  if (sec_hdr_type_idx == SEC_HDR_TYPE_TESTN) {
    sec_hdr_type_idx = 1;
    mac_type_idx     = mac_type_idx + 1;
    if (mac_type_idx == MAC_TYPE_TESTN) {
      sec_hdr_type_idx = 0;
      mac_type_idx     = 0;
      m_instance->prev_nas_ctx->m_nas_log->console(
          "\n[DoLTEst] <NAS Downlink NAS Transport> testing finished\n\n\n\n\n\n");
      // is_finish = true;
      disable_alarm();
      dt_test_message++;
    }
  }
  // write_prev_progress_file();
  write_nas_test_config();
}

bool fzmanager_epc::pack_downlink_nas_transport(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer)
{
  sec_ctx_t* sec_ctx = &nas_ctx->m_sec_ctx;
  emm_ctx_t* emm_ctx = &nas_ctx->m_emm_ctx;

  // sms_msg_val = 0x41;
  // sms_msg_val = 0x31;

  uint8_t sms_day = start_day << 4;

  LIBLTE_MME_DOWNLINK_NAS_TRANSPORT_MSG_STRUCT dl_nas_transport;
  uint8 sms_msg[]                  = {0x09, 0x01, 0x20, 0x01, 0x01,    0x07, 0x91, 0x41, 0x50, 0x74, 0x02,       0x50,
                     0xF6, 0x00, 0x14, 0x04, 0x0B,    0x91, 0x10, 0x10, 0x32, 0x54, 0x76,       0xF8,
                     0x00, 0x00, 0x81, 0x11, sms_day, 0x32, 0x35, 0x95, 0x0A, 0x01, sms_msg_val};
  dl_nas_transport.nas_msg.N_bytes = 35;
  memcpy(dl_nas_transport.nas_msg.msg, sms_msg, 35);
  sec_ctx->dl_nas_count++;

  // hardcoded for debugging
  LIBLTE_ERROR_ENUM err;

  err = liblte_mme_pack_downlink_nas_transport_msg(
      &dl_nas_transport, sec_hdr_type_idx, sec_ctx->dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);

  uint8_t sec_hdr_type = LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED;
  sec_hdr_type         = sec_hdr_type_variation[sec_hdr_type_idx];

  if (sec_hdr_type == LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED)
    cipher_encrypt(nas_ctx, nas_buffer);

  uint8_t mac[4];
  integrity_generate(nas_ctx, nas_buffer, mac);

  if (sec_hdr_type != LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS)
    memcpy(&nas_buffer->msg[1], mac, 4);

  // nas_ctx->m_nas_log->console("Packing %s (SEC_HDR_TYPE= %s, MAC_type=%s, SMS contents: %u)\n",
  //                           doltest_nas_test_msg_type_names[4],
  //                           sec_hdr_type_str[sec_hdr_type],
  //                           mac_type_str[mac_type_idx],
  //                           sms_msg_val);

  nas_ctx->m_nas_log->console("---> Packing next test message --->\n");
  nas_ctx->m_nas_log->console("---> Target State        : %s --->\n", doltest_state_names[dt_nas_test_state]);
  nas_ctx->m_nas_log->console("---> Target Msg          : %s --->\n", doltest_nas_test_msg_type_names[4]);
  nas_ctx->m_nas_log->console("---> Target Sec.hdr.type : %s --->\n", sec_hdr_type_str[sec_hdr_type]);
  nas_ctx->m_nas_log->console("---> Target MAC          : %s --->\n", mac_type_str[mac_type_idx]);
  //nas_ctx->m_nas_log->console("---> SMS val             : %u --->\n", sms_msg_val);

  fzmanager_epc::next_downlink_nas_transport();
  // is_finish = true;
  return true;
}

void fzmanager_epc::next_attach_reject()
{
  sec_hdr_type_idx = sec_hdr_type_idx + 1;
  if (sec_hdr_type_idx == SEC_HDR_TYPE_TESTN) {
    sec_hdr_type_idx = 1;
    mac_type_idx     = mac_type_idx + 1;
    if (mac_type_idx == MAC_TYPE_TESTN) {
      sec_hdr_type_idx = 0;
      mac_type_idx     = 0;
      m_instance->prev_nas_ctx->m_nas_log->console("\n[DoLTEst] <NAS Attach Reject> testing finished\n\n\n\n\n\n");
      // is_finish = true;
      disable_alarm();
      dt_test_message++;
    }
  }

  // Write Progress stat
  // write_prev_progress_file();
  write_nas_test_config();
}

bool fzmanager_epc::pack_attach_reject(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer)
{
  LIBLTE_MME_ATTACH_REJECT_MSG_STRUCT attach_rej;
  uint8_t                             emm_cause_hex;
  int                                 temp_hex;
  uint8_t                             sec_hdr_type = sec_hdr_type_variation[sec_hdr_type_idx];
  sec_ctx_t*                          m_sec_ctx = &nas_ctx->m_sec_ctx;

  attach_rej.esm_msg_present = false;

  // Critical Field
  attach_rej.t3446_value_present = true;
  attach_rej.t3446_value         = 33;

  // Assign Reject cause
  std::stringstream convert;
  convert << emm_cause_str[start_emm_cause_idx][1];
  // std::cout << convert.str() << endl;
  convert >> std::hex >> temp_hex;
  emm_cause_hex        = (uint8_t)temp_hex;
  attach_rej.emm_cause = emm_cause_hex;

  // Print logs
  nas_ctx->m_nas_log->console("---> Packing next test message --->\n");
  nas_ctx->m_nas_log->console("---> Target State        : %s --->\n", doltest_state_names[dt_nas_test_state]);
  nas_ctx->m_nas_log->console("---> Target Msg          : %s --->\n", doltest_nas_test_msg_type_names[5]);
  nas_ctx->m_nas_log->console("---> Target Sec.hdr.type : %s --->\n", sec_hdr_type_str[sec_hdr_type]);
  nas_ctx->m_nas_log->console("---> Target MAC          : %s --->\n", mac_type_str[mac_type_idx]);
  nas_ctx->m_nas_log->console("---> Target EMM cause    : %s (%s) --->\n", emm_cause_str[start_emm_cause_idx][1], emm_cause_str[start_emm_cause_idx][0]);

  LIBLTE_ERROR_ENUM err = liblte_mme_pack_attach_reject_msg_sec(
      &attach_rej, sec_hdr_type, m_sec_ctx->dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);
  /*
      // time measurement start
      m_instance->start = time(NULL);
      printf("start: %ld\n", m_instance->start);

      // set new alarm for reject messages
      alarm(REJECT_WAIT_TIME);

  */

  // generate MAC
  if (sec_hdr_type != LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS) {
    uint8_t mac[4];
    integrity_generate(nas_ctx, nas_buffer, mac);
    memcpy(&nas_buffer->msg[1], mac, 4);
  }

  fzmanager_epc::next_attach_reject();

  return true;
}

void fzmanager_epc::next_service_reject()
{
  start_emm_cause_idx++;
  is_finish = true;

  // write_prev_progress_file();
  write_nas_test_config();
}

bool fzmanager_epc::pack_service_reject(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer)
{
  LIBLTE_MME_SERVICE_REJECT_MSG_STRUCT service_rej;
  uint8_t                              emm_cause_hex;
  int                                  temp_hex;

  // Critical Field
  service_rej.t3446_present = true;
  service_rej.t3442_present = true;
  // attach_rej.emm_cause = LIBLTE_MME_EMM_CAUSE_CONGESTION;

  start_emm_cause_idx = 25;

  std::stringstream convert;
  convert << emm_cause_str[start_emm_cause_idx][1];
  std::cout << convert.str() << endl;
  convert >> std::hex >> temp_hex;
  emm_cause_hex = (uint8_t)temp_hex;
  emm_cause_hex = (uint8_t)0x19;

  printf("EMM CAUSE: %u, %s\n", emm_cause_hex, emm_cause_str[start_emm_cause_idx][1]);

  service_rej.emm_cause = emm_cause_hex;
  // attach_rej.t3446_value = 33;

  LIBLTE_ERROR_ENUM err = liblte_mme_pack_service_reject_msg(
      &service_rej, LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS, 0, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);

  // time measurement start
  m_instance->start = time(NULL);
  printf("start: %ld\n", m_instance->start);

  // set new alarm for reject messages
  alarm(REJECT_WAIT_TIME);

  ////fzmanager_epc::next_attach_reject();
  return true;
}

void fzmanager_epc::next_tracking_area_update_reject()
{
  start_emm_cause_idx++;
  is_finish = true;

  // write_prev_progress_file();
  write_nas_test_config();
}

bool fzmanager_epc::pack_tracking_area_update_reject(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer)
{
  LIBLTE_MME_TRACKING_AREA_UPDATE_REJECT_MSG_STRUCT tau_rej;
  uint8_t                                           emm_cause_hex;
  int                                               temp_hex;

  // Critical Field
  tau_rej.t3446_present = true;
  start_emm_cause_idx = 22;

  std::stringstream convert;
  convert << emm_cause_str[start_emm_cause_idx][1];
  std::cout << convert.str() << endl;
  convert >> std::hex >> temp_hex;
  emm_cause_hex = (uint8_t)temp_hex;
  emm_cause_hex = (uint8_t)0x19;

  printf("EMM CAUSE: %u, %s\n", emm_cause_hex, emm_cause_str[start_emm_cause_idx][1]);

  tau_rej.emm_cause = emm_cause_hex;
  // attach_rej.t3446_value = 33;

  LIBLTE_ERROR_ENUM err = liblte_mme_pack_tracking_area_update_reject_msg(
      &tau_rej, LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS, 0, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);

  // time measurement start
  m_instance->start = time(NULL);
  printf("start: %ld\n", m_instance->start);

  // set new alarm for reject messages
  alarm(REJECT_WAIT_TIME);

  return true;
}

bool fzmanager_epc::pack_pdn_connectivity_reject(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer)
{
  LIBLTE_MME_PDN_CONNECTIVITY_REJECT_MSG_STRUCT pdn_rej;
  sec_ctx_t*                                    m_sec_ctx = &nas_ctx->m_sec_ctx;
  uint8_t                                       emm_cause_hex;
  int                                           temp_hex;
  uint8_t                                       sec_hdr_type = 0;
  uint8_t                                       mac[4];

  pdn_rej.protocol_cnfg_opts_present = false;
  pdn_rej.t3496_present              = false;

  pdn_rej.eps_bearer_id       = 0; // @TODO Zero for now
  pdn_rej.proc_transaction_id = nas_ctx->m_emm_ctx.procedure_transaction_id;
  pdn_rej.esm_cause           = 0x20; // @TODO hardcoded now

  sec_hdr_type = sec_hdr_type_variation[sec_hdr_type_idx];
  if (sec_hdr_type != LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS)
    m_sec_ctx->dl_nas_count++;
  LIBLTE_ERROR_ENUM err = liblte_mme_pack_pdn_connectivity_reject_msg_sec(
      &pdn_rej, sec_hdr_type, m_sec_ctx->dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);
  if (err)
    nas_ctx->m_nas_log->console("Something wrong during preparing PDN Connectivity reject\n");

  if (sec_hdr_type == LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED)
    cipher_encrypt(nas_ctx, nas_buffer);

  if (sec_hdr_type != LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS) {
    uint8_t mac[4];
    integrity_generate(nas_ctx, nas_buffer, mac);
    memcpy(&nas_buffer->msg[1], mac, 4);
  }

  nas_ctx->m_nas_log->console(
      "Send PDN_Connectivity_Reject\n\t(SEC_HDR_TYPE= %s)\n\t(MAC_TYPE=%s)\n\t(MSG content: %u\n",
      sec_hdr_type_str[sec_hdr_type_idx],
      mac_type_str[mac_type_idx],
      sms_msg_val);

  nas_ctx->m_nas_log->console("Send PDN Connectivity reject\n");

  return true;
}

void fzmanager_epc::next_msg_security_property()
{
  sec_hdr_type_idx = sec_hdr_type_idx + 1;
  if (sec_hdr_type_idx == SEC_HDR_TYPE_TESTN) {
    sec_hdr_type_idx = 1;
    mac_type_idx     = mac_type_idx + 1;
    if (mac_type_idx == MAC_TYPE_TESTN) {
      sec_hdr_type_idx = 0;
      mac_type_idx     = 0;
      m_instance->prev_nas_ctx->m_nas_log->console("\n[DoLTEst] <NAS ** message> testing finished\n\n\n\n\n\n");
      is_finish = true;
      disable_alarm();
    }
  }
  // write_prev_progress_file();
  write_nas_test_config();
}

void fzmanager_epc::next_attach_accept()
{
  sec_hdr_type_idx = sec_hdr_type_idx + 1;
  if (sec_hdr_type_idx == SEC_HDR_TYPE_TESTN) {
    sec_hdr_type_idx = 1;
    mac_type_idx     = mac_type_idx + 1;
    if (mac_type_idx == MAC_TYPE_TESTN) {
      sec_hdr_type_idx = 0;
      mac_type_idx     = 0;
      m_instance->prev_nas_ctx->m_nas_log->console("\n[DoLTEst] <NAS Attach Accept> testing finished\n\n\n\n\n\n");
      // is_finish = true;
      disable_alarm();
      dt_test_message = 0;

      //new 
      dt_nas_test_protocol = 0;

      read_rrc_test_config(&doltest_stat_rrc);
      doltest_stat_rrc.test_protocol = 0;
      write_rrc_test_config(doltest_stat_rrc);
    }
  }

  // Write Progress stat
  // write_prev_progress_file();
  write_nas_test_config();
}

bool fzmanager_epc::pack_attach_accept(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer)
{
  LIBLTE_MME_ATTACH_ACCEPT_MSG_STRUCT attach_accept;
  // bring from nas.cc
  LIBLTE_MME_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST_MSG_STRUCT act_def_eps_bearer_context_req;

  sec_ctx_t* sec_ctx   = &nas_ctx->m_sec_ctx;
  emm_ctx_t* m_emm_ctx = &nas_ctx->m_emm_ctx; 

  // Get decimal MCC and MNC
  uint32_t mcc   = 0;
  uint32_t m_mcc = 0x901; // [DoLTEst] Set PLMN 
  uint32_t m_mnc = 0x55;  // 

  mcc += 0x000F & m_mcc;
  mcc += 10 * ((0x00F0 & m_mcc) >> 4);
  mcc += 100 * ((0x0F00 & m_mcc) >> 8);

  uint32_t mnc = 0;
  if (0xFF00 == (m_mnc & 0xFF00)) {
    // Two digit MNC
    mnc += 0x000F & m_mnc;
    mnc += 10 * ((0x00F0 & m_mnc) >> 4);
  } else {
    // Three digit MNC
    mnc += 0x000F & m_mnc;
    mnc += 10 * ((0x00F0 & m_mnc) >> 4);
    mnc += 100 * ((0x0F00 & m_mnc) >> 8);
  }

  // Attach accept
  attach_accept.eps_attach_result = 2; 

  // FIXME: Set t3412 from config
  attach_accept.t3412.unit  = LIBLTE_MME_GPRS_TIMER_UNIT_1_MINUTE; // GPRS 1 minute unit
  attach_accept.t3412.value = 30;                                  // 30 minute periodic timer

  attach_accept.tai_list.N_tais     = 1;
  attach_accept.tai_list.tai[0].mcc = mcc;
  attach_accept.tai_list.tai[0].mnc = mnc;
  attach_accept.tai_list.tai[0].tac = 8; // m_tac;

  nas_ctx->m_nas_log->info("Attach Accept -- MCC 0x%x, MNC 0x%x\n", m_mcc, m_mnc);

  // Allocate a GUTI ot the UE
  attach_accept.guti_present    = true;
  attach_accept.guti.type_of_id = 6; //
  attach_accept.guti.guti.mcc   = mcc;
  attach_accept.guti.guti.mnc   = mnc;
  attach_accept.guti.guti.mme_group_id = 1;    // m_mme_group;
  attach_accept.guti.guti.mme_code     = 26;   // m_mme_code;
  attach_accept.guti.guti.m_tmsi = 0x3caca691; // m_s1ap->allocate_m_tmsi(m_emm_ctx.imsi);
  nas_ctx->m_nas_log->debug("Allocated GUTI: MCC %d, MNC %d, MME Group Id %d, MME Code 0x%x, M-TMSI 0x%x\n",
                            attach_accept.guti.guti.mcc,
                            attach_accept.guti.guti.mnc,
                            attach_accept.guti.guti.mme_group_id,
                            attach_accept.guti.guti.mme_code,
                            attach_accept.guti.guti.m_tmsi);

  /// memcpy(&m_sec_ctx.guti, &attach_accept.guti, sizeof(LIBLTE_MME_EPS_MOBILE_ID_GUTI_STRUCT));///problematic
  memcpy(&(sec_ctx)->guti, &attach_accept.guti, sizeof(LIBLTE_MME_EPS_MOBILE_ID_GUTI_STRUCT)); /// problematic MAYBE??

  // Set up LAI for combined EPS/IMSI attach
  attach_accept.lai_present = true;
  attach_accept.lai.mcc     = mcc;
  attach_accept.lai.mnc     = mnc;
  attach_accept.lai.lac     = 001;

  attach_accept.ms_id_present    = true;
  attach_accept.ms_id.type_of_id = LIBLTE_MME_MOBILE_ID_TYPE_TMSI;
  attach_accept.ms_id.tmsi       = attach_accept.guti.guti.m_tmsi;

  // Make sure all unused options are set to false
  attach_accept.emm_cause_present                   = false;
  attach_accept.t3402_present                       = false;
  attach_accept.t3423_present                       = false;
  attach_accept.equivalent_plmns_present            = false;
  attach_accept.emerg_num_list_present              = false;
  attach_accept.eps_network_feature_support_present = false;
  attach_accept.additional_update_result_present    = false;
  attach_accept.t3412_ext_present                   = false;

  // Set activate default eps bearer (esm_ms)
  // Set pdn_addr
  act_def_eps_bearer_context_req.pdn_addr.pdn_type = LIBLTE_MME_PDN_TYPE_IPV4;
  memcpy(act_def_eps_bearer_context_req.pdn_addr.addr, &m_emm_ctx->ue_ip.s_addr, 4); 
  // Set eps bearer id
  act_def_eps_bearer_context_req.eps_bearer_id          = 5;
  act_def_eps_bearer_context_req.transaction_id_present = false;
  // set eps_qos
  act_def_eps_bearer_context_req.eps_qos.qci = 7; // m_esm_ctx[5].qci;//7 ??? And this part
  act_def_eps_bearer_context_req.eps_qos.br_present     = false;
  act_def_eps_bearer_context_req.eps_qos.br_ext_present = false;

  // set apn
  std::string m_apn = "srsapn";
  strncpy(act_def_eps_bearer_context_req.apn.apn, m_apn.c_str(), LIBLTE_STRING_LEN - 1); 
  /// act_def_eps_bearer_context_req.proc_transaction_id = m_emm_ctx.procedure_transaction_id; // FIXME
  act_def_eps_bearer_context_req.proc_transaction_id = m_emm_ctx->procedure_transaction_id; // FIXME

  // Set DNS server
  act_def_eps_bearer_context_req.protocol_cnfg_opts_present    = true;
  act_def_eps_bearer_context_req.protocol_cnfg_opts.N_opts     = 1;
  act_def_eps_bearer_context_req.protocol_cnfg_opts.opt[0].id  = 0x0d;
  act_def_eps_bearer_context_req.protocol_cnfg_opts.opt[0].len = 4;

  struct sockaddr_in dns_addr;
  
  std::string m_dns = "8.8.8.8";
  inet_pton(AF_INET, m_dns.c_str(), &(dns_addr.sin_addr)); 
  memcpy(act_def_eps_bearer_context_req.protocol_cnfg_opts.opt[0].contents, &dns_addr.sin_addr.s_addr, 4);

  // Make sure all unused options are set to false
  act_def_eps_bearer_context_req.negotiated_qos_present    = false;
  act_def_eps_bearer_context_req.llc_sapi_present          = false;
  act_def_eps_bearer_context_req.radio_prio_present        = false;
  act_def_eps_bearer_context_req.packet_flow_id_present    = false;
  act_def_eps_bearer_context_req.apn_ambr_present          = false;
  act_def_eps_bearer_context_req.esm_cause_present         = false;
  act_def_eps_bearer_context_req.connectivity_type_present = false;

  LIBLTE_ERROR_ENUM err;
  LIBLTE_ERROR_ENUM err2;

  uint8_t sec_hdr_type = LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED;
  sec_hdr_type         = sec_hdr_type_variation[sec_hdr_type_idx];

  sec_ctx->dl_nas_count++;

  err = liblte_mme_pack_activate_default_eps_bearer_context_request_msg(&act_def_eps_bearer_context_req,
                                                                        &attach_accept.esm_msg);
  // err2 = liblte_mme_pack_attach_accept_msg(&attach_accept, sec_hdr_type, m_sec_ctx.dl_nas_count,///m_sec_ctx is
  // problematic
  //                                  (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);

  err2 = liblte_mme_pack_attach_accept_msg(&attach_accept,
                                           sec_hdr_type,
                                           sec_ctx->dl_nas_count, /// m_sec_ctx is problematic
                                           (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);

  // Generate MAC for integrity protection

  if (sec_hdr_type != LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS) {
    uint8_t mac[4];
    integrity_generate(nas_ctx, nas_buffer, mac);
    memcpy(&nas_buffer->msg[1], mac, 4);
  }

  // nas_ctx->m_nas_log->console("Send ATTACH_ACCEPT\n\t(SEC_HDR_TYPE= %s)\n\t(MAC_TYPE=%s)\n\t(Start DAY=%u)\n",
  //                             sec_hdr_type_str[sec_hdr_type_idx],
  //                             mac_type_str[mac_type_idx],
  //                             start_day);

  // nas_ctx->m_nas_log->console("Packing %s (SEC_HDR_TYPE= %s, MAC_type=%s)\n",
  //                       doltest_nas_test_msg_type_names[6],
  //                       sec_hdr_type_str[sec_hdr_type], 
  //                       mac_type_str[mac_type_idx]);

  nas_ctx->m_nas_log->console("---> Packing next test message --->\n");
  nas_ctx->m_nas_log->console("---> Target State        : %s --->\n", doltest_state_names[dt_nas_test_state]);
  nas_ctx->m_nas_log->console("---> Target Msg          : %s --->\n", doltest_nas_test_msg_type_names[6]);
  nas_ctx->m_nas_log->console("---> Target Sec.hdr.type : %s --->\n", sec_hdr_type_str[sec_hdr_type]);
  nas_ctx->m_nas_log->console("---> Target MAC          : %s --->\n", mac_type_str[mac_type_idx]);

  // Increase Next mutation
  fzmanager_epc::next_attach_accept();

  return true;
}
bool fzmanager_epc::pack_detach_accept(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer)
{
  LIBLTE_MME_DETACH_ACCEPT_MSG_STRUCT detach_accept;

  sec_ctx_t* sec_ctx = &nas_ctx->m_sec_ctx;
  emm_ctx_t* emm_ctx = &nas_ctx->m_emm_ctx;

  uint8_t sec_hdr_type = LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS;
  sec_hdr_type         = sec_hdr_type_variation[sec_hdr_type_idx];

  /// Counter Add
  sec_ctx->dl_nas_count++;
  printf("Current NAS count is %d\n", sec_ctx->dl_nas_count);

  LIBLTE_ERROR_ENUM err = liblte_mme_pack_detach_accept_msg(
      &detach_accept, sec_hdr_type, sec_ctx->dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);

  if (err != LIBLTE_SUCCESS) {
    nas_ctx->m_nas_log->error("Error packing DETACH ACCEPT\n");
    nas_ctx->m_nas_log->console("Error packing DETACH ACCEPT\n");
    return false;
  }

  // Generate MAC for integrity protection
  if (sec_hdr_type != LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS) {
    uint8_t mac[4];
    integrity_generate(nas_ctx, nas_buffer, mac);
    memcpy(&nas_buffer->msg[1], mac, 4);
  }

  // nas_ctx->m_nas_log->console("Send DETACH_ACCEPT\n\t(SEC_HDR_TYPE= %s)\n\t(MAC_TYPE=%s)\n\t(MSG CONTENTS=uu)\n",
  //                             sec_hdr_type_str[sec_hdr_type_idx],
  //                             mac_type_str[mac_type_idx]);

  // nas_ctx->m_nas_log->console("Packing %s (SEC_HDR_TYPE= %s, MAC_type=%s)\n",
  //                     "(NAS)Detach Accept",
  //                     sec_hdr_type_str[sec_hdr_type], 
  //                     mac_type_str[mac_type_idx]);

  // Increase Next mutation
  fzmanager_epc::next_msg_security_property();

  return true;
}

bool fzmanager_epc::pack_detach_request(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer)
{
  LIBLTE_MME_DETACH_REQUEST_NET_MSG_STRUCT detach_request;

  nas_ctx->m_nas_log->info("Packing Detach Request\n");
  nas_ctx->m_nas_log->console("Packing Detach Request\n");

  sec_ctx_t* sec_ctx = &nas_ctx->m_sec_ctx;
  emm_ctx_t* emm_ctx = &nas_ctx->m_emm_ctx;

  uint8_t sec_hdr_type = LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS;
  sec_hdr_type         = sec_hdr_type_variation[sec_hdr_type_idx];

  /// Counter Add
  sec_ctx->dl_nas_count++;
  printf("Current NAS count is %d\n", sec_ctx->dl_nas_count);

  detach_request.detach_type.type_of_detach = 1;

  LIBLTE_ERROR_ENUM err = liblte_mme_pack_detach_request_net_msg(
      &detach_request, sec_hdr_type, sec_ctx->dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);

  if (err != LIBLTE_SUCCESS) {
    nas_ctx->m_nas_log->error("Error packing DETACH ACCEPT\n");
    nas_ctx->m_nas_log->console("Error packing DETACH ACCEPT\n");
    return false;
  }

  // Generate MAC for integrity protection
  if (sec_hdr_type != LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS) {
    uint8_t mac[4];
    integrity_generate(nas_ctx, nas_buffer, mac);
    memcpy(&nas_buffer->msg[1], mac, 4);
  }

  nas_ctx->m_nas_log->console("Send DETACH_ACCEPT\n\t(SEC_HDR_TYPE= %s)\n\t(MAC_TYPE=%s)\n\t(MSG CONTENTS=uu)\n",
                              sec_hdr_type_str[sec_hdr_type_idx],
                              mac_type_str[mac_type_idx]);

  // Increase Next mutation
  fzmanager_epc::next_msg_security_property();

  return true;
}

bool fzmanager_epc::pack_tracking_area_update_accept(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer)
{
  LIBLTE_MME_TRACKING_AREA_UPDATE_ACCEPT_MSG_STRUCT tau_accept;

  nas_ctx->m_nas_log->info("Packing [Tracking Area Update Accept]\n");
  nas_ctx->m_nas_log->console("Packing [Tracking Area Update Accept]\n");

  sec_ctx_t* sec_ctx = &nas_ctx->m_sec_ctx;
  emm_ctx_t* emm_ctx = &nas_ctx->m_emm_ctx;

  tau_accept.t3412_present                       = false;
  tau_accept.guti_present                        = false;
  tau_accept.tai_list_present                    = false;
  tau_accept.eps_bearer_context_status_present   = false;
  tau_accept.lai_present                         = false;
  tau_accept.ms_id_present                       = false;
  tau_accept.emm_cause_present                   = false;
  tau_accept.t3402_present                       = false;
  tau_accept.t3423_present                       = false;
  tau_accept.equivalent_plmns_present            = false;
  tau_accept.emerg_num_list_present              = false;
  tau_accept.eps_network_feature_support_present = false;
  tau_accept.additional_update_result_present    = false;
  tau_accept.t3412_ext_present                   = false;

  tau_accept.eps_update_result = 1;

  uint8_t sec_hdr_type = LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED;
  sec_hdr_type         = sec_hdr_type_variation[sec_hdr_type_idx];

  /// Counter Add
  sec_ctx->dl_nas_count++;
  printf("Current NAS count is %d\n", sec_ctx->dl_nas_count);

  LIBLTE_ERROR_ENUM err = liblte_mme_pack_tracking_area_update_accept_msg(
      &tau_accept, sec_hdr_type, sec_ctx->dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);

  if (err != LIBLTE_SUCCESS) {
    nas_ctx->m_nas_log->error("Error packing [TAU ACCEPT]\n");
    nas_ctx->m_nas_log->console("Error packing [TAU ACCEPT]\n");
    return false;
  }

  // Generate MAC for integrity protection
  if (sec_hdr_type != LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS) {
    uint8_t mac[4];
    integrity_generate(nas_ctx, nas_buffer, mac);
    memcpy(&nas_buffer->msg[1], mac, 4);
  }

  nas_ctx->m_nas_log->console("Send [TAU_ACCEPT]\n\t(SEC_HDR_TYPE= %s)\n\t(MAC_TYPE=%s)\n\t(MSG CONTENTS=uu)\n",
                              sec_hdr_type_str[sec_hdr_type_idx],
                              mac_type_str[mac_type_idx]);

  // Increase Next mutation
  fzmanager_epc::next_msg_security_property();

  return true;
}
bool fzmanager_epc::pack_emm_status(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer)
{
  LIBLTE_MME_EMM_STATUS_MSG_STRUCT emm_status;

  nas_ctx->m_nas_log->info("Packing [EMM STATUS]\n");
  nas_ctx->m_nas_log->console("Packing [EMM STATUS]\n");

  sec_ctx_t* sec_ctx = &nas_ctx->m_sec_ctx;
  emm_ctx_t* emm_ctx = &nas_ctx->m_emm_ctx;

  uint8_t sec_hdr_type = LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED;
  sec_hdr_type         = sec_hdr_type_variation[sec_hdr_type_idx];

  /// Counter Add
  sec_ctx->dl_nas_count++;
  printf("Current NAS count is %d\n", sec_ctx->dl_nas_count);

  emm_status.emm_cause = 25;
  // IMPLEMENT DEPENDENT

  LIBLTE_ERROR_ENUM err = liblte_mme_pack_emm_status_msg(
      &emm_status, sec_hdr_type, sec_ctx->dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);

  if (err != LIBLTE_SUCCESS) {
    nas_ctx->m_nas_log->error("Error packing [EMM STATUS]\n");
    nas_ctx->m_nas_log->console("Error packing [EMM STATUS]\n");
    return false;
  }

  // Generate MAC for integrity protection
  if (sec_hdr_type != LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS) {
    uint8_t mac[4];
    integrity_generate(nas_ctx, nas_buffer, mac);
    memcpy(&nas_buffer->msg[1], mac, 4);
  }

  nas_ctx->m_nas_log->console("Send [EMM STATUS]\n\t(SEC_HDR_TYPE= %s)\n\t(MAC_TYPE=%s)\n\t(MSG CONTENTS=uu)\n",
                              sec_hdr_type_str[sec_hdr_type_idx],
                              mac_type_str[mac_type_idx]);

  // Increase Next mutation
  fzmanager_epc::next_msg_security_property();

  return true;
}

bool fzmanager_epc::pack_activate_default_eps_bearer_context_request(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer)
{

  LIBLTE_MME_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST_MSG_STRUCT
      activate_default_eps_bearer_context_request; // UNTIL NOW

  nas_ctx->m_nas_log->info("Packing [DEFAULT EPS BEARER CONTEXT REQUEST]\n");
  nas_ctx->m_nas_log->console("Packing [DEFAULT EPS BEARER CONTEXT REQUEST]\n");

  sec_ctx_t* sec_ctx = &nas_ctx->m_sec_ctx;
  emm_ctx_t* emm_ctx = &nas_ctx->m_emm_ctx;

  uint8_t sec_hdr_type = LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED;
  sec_hdr_type         = sec_hdr_type_variation[sec_hdr_type_idx];

  sec_ctx->dl_nas_count++;
  printf("Current NAS count is %d\n", sec_ctx->dl_nas_count);

  activate_default_eps_bearer_context_request.transaction_id_present     = false;
  activate_default_eps_bearer_context_request.negotiated_qos_present     = false;
  activate_default_eps_bearer_context_request.llc_sapi_present           = false;
  activate_default_eps_bearer_context_request.radio_prio_present         = false;
  activate_default_eps_bearer_context_request.packet_flow_id_present     = false;
  activate_default_eps_bearer_context_request.apn_ambr_present           = false;
  activate_default_eps_bearer_context_request.esm_cause_present          = false;
  activate_default_eps_bearer_context_request.protocol_cnfg_opts_present = true;

  activate_default_eps_bearer_context_request.protocol_cnfg_opts.N_opts     = 1;
  activate_default_eps_bearer_context_request.protocol_cnfg_opts.opt[0].id  = 0x0d;
  activate_default_eps_bearer_context_request.protocol_cnfg_opts.opt[0].len = 4;

  struct sockaddr_in dns_addr;
  std::string m_dns = "8.8.8.8";
  inet_pton(AF_INET, m_dns.c_str(), &(dns_addr.sin_addr)); 
  memcpy(activate_default_eps_bearer_context_request.protocol_cnfg_opts.opt[0].contents, &dns_addr.sin_addr.s_addr, 4);

  activate_default_eps_bearer_context_request.connectivity_type_present = false;

  activate_default_eps_bearer_context_request.eps_qos.br_present     = false;
  activate_default_eps_bearer_context_request.eps_qos.br_ext_present = false;
  activate_default_eps_bearer_context_request.eps_qos.qci            = 7;

  std::string m_apn = "srsapn";
  strncpy(activate_default_eps_bearer_context_request.apn.apn, m_apn.c_str(), LIBLTE_STRING_LEN - 1); 

  activate_default_eps_bearer_context_request.pdn_addr.pdn_type = LIBLTE_MME_PDN_TYPE_IPV4;
  memcpy(activate_default_eps_bearer_context_request.pdn_addr.addr, &emm_ctx->ue_ip.s_addr, 4);
  activate_default_eps_bearer_context_request.eps_bearer_id       = 5;
  activate_default_eps_bearer_context_request.proc_transaction_id = emm_ctx->procedure_transaction_id;

  LIBLTE_ERROR_ENUM err =
      liblte_mme_pack_activate_default_eps_bearer_context_request_msg_sec(&activate_default_eps_bearer_context_request,
                                                                          sec_hdr_type,
                                                                          sec_ctx->dl_nas_count,
                                                                          (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);

  if (err != LIBLTE_SUCCESS) {
    nas_ctx->m_nas_log->error("Error packing [activate_default_eps_bearer_context_request]\n");
    nas_ctx->m_nas_log->console("Error packing [activate_default_eps_bearer_context_request]\n");
    return false;
  }

  // Generate MAC for integrity protection
  if (sec_hdr_type != LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS) {
    uint8_t mac[4];
    integrity_generate(nas_ctx, nas_buffer, mac);
    memcpy(&nas_buffer->msg[1], mac, 4);
  }

  nas_ctx->m_nas_log->console("Send [activate_default_eps_bearer_context_request]\n\t(SEC_HDR_TYPE= "
                              "%s)\n\t(MAC_TYPE=%s)\n\t(MSG CONTENTS=uu)\n",
                              sec_hdr_type_str[sec_hdr_type_idx],
                              mac_type_str[mac_type_idx]);

  // Increase Next mutation
  fzmanager_epc::next_msg_security_property();
  return true;
}

bool fzmanager_epc::pack_modify_eps_bearer_context_request(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer)
{
  LIBLTE_MME_MODIFY_EPS_BEARER_CONTEXT_REQUEST_MSG_STRUCT modify_eps_bearer_context_request;

  nas_ctx->m_nas_log->info("Packing [modify_eps_bearer_context_request]\n");
  nas_ctx->m_nas_log->console("Packing [modify_eps_bearer_context_request]\n");

  sec_ctx_t* sec_ctx = &nas_ctx->m_sec_ctx;
  emm_ctx_t* emm_ctx = &nas_ctx->m_emm_ctx;

  uint8_t sec_hdr_type = LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED;
  sec_hdr_type         = sec_hdr_type_variation[sec_hdr_type_idx];

  sec_ctx->dl_nas_count++;
  printf("Current NAS count is %d\n", sec_ctx->dl_nas_count);

  modify_eps_bearer_context_request.new_eps_qos_present         = false;
  modify_eps_bearer_context_request.tft_present                 = false;
  modify_eps_bearer_context_request.new_qos_present             = false;
  modify_eps_bearer_context_request.apn_ambr_present            = false;
  modify_eps_bearer_context_request.protocol_cnfg_opts_present  = false;
  modify_eps_bearer_context_request.eps_bearer_id               = 5;
  modify_eps_bearer_context_request.proc_transaction_id         = emm_ctx->procedure_transaction_id;
  modify_eps_bearer_context_request.negotiated_llc_sapi_present = false;
  modify_eps_bearer_context_request.radio_prio_present          = false;
  modify_eps_bearer_context_request.packet_flow_id_present      = false;

  LIBLTE_ERROR_ENUM err = liblte_mme_pack_modify_eps_bearer_context_request_msg_sec(
      &modify_eps_bearer_context_request, sec_hdr_type, sec_ctx->dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);

  if (err != LIBLTE_SUCCESS) {
    nas_ctx->m_nas_log->error("Error packing [modify_eps_bearer_context_request]\n");
    nas_ctx->m_nas_log->console("Error packing [modify_eps_bearer_context_request]\n");
    return false;
  }

  // Generate MAC for integrity protection
  if (sec_hdr_type != LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS) {
    uint8_t mac[4];
    integrity_generate(nas_ctx, nas_buffer, mac);
    memcpy(&nas_buffer->msg[1], mac, 4);
  }

  nas_ctx->m_nas_log->console(
      "Send [modify_eps_bearer_context_request]\n\t(SEC_HDR_TYPE= %s)\n\t(MAC_TYPE=%s)\n\t(MSG CONTENTS=uu)\n",
      sec_hdr_type_str[sec_hdr_type_idx],
      mac_type_str[mac_type_idx]);

  // Increase Next mutation
  fzmanager_epc::next_msg_security_property();

  return true;
}

bool fzmanager_epc::pack_deactivate_eps_bearer_context_request(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer)
{
  LIBLTE_MME_DEACTIVATE_EPS_BEARER_CONTEXT_REQUEST_MSG_STRUCT deactivate_eps_bearer_context_request;

  nas_ctx->m_nas_log->info("Packing [deactivate_eps_bearer_context_request]\n");
  nas_ctx->m_nas_log->console("Packing [deactivate_eps_bearer_context_request]\n");

  sec_ctx_t* sec_ctx = &nas_ctx->m_sec_ctx;
  emm_ctx_t* emm_ctx = &nas_ctx->m_emm_ctx;

  uint8_t sec_hdr_type = LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED;
  sec_hdr_type         = sec_hdr_type_variation[sec_hdr_type_idx];

  sec_ctx->dl_nas_count++;
  printf("Current NAS count is %d\n", sec_ctx->dl_nas_count);

  deactivate_eps_bearer_context_request.protocol_cnfg_opts_present = false;
  deactivate_eps_bearer_context_request.eps_bearer_id              = 5;
  deactivate_eps_bearer_context_request.proc_transaction_id        = emm_ctx->procedure_transaction_id;
  deactivate_eps_bearer_context_request.esm_cause                  = 1;

  LIBLTE_ERROR_ENUM err = liblte_mme_pack_deactivate_eps_bearer_context_request_msg_sec(
      &deactivate_eps_bearer_context_request, sec_hdr_type, sec_ctx->dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);

  if (err != LIBLTE_SUCCESS) {
    nas_ctx->m_nas_log->error("Error packing [deactivate_eps_bearer_context_request]\n");
    nas_ctx->m_nas_log->console("Error packing [deactivate_eps_bearer_context_request]\n");
    return false;
  }

  // Generate MAC for integrity protection
  if (sec_hdr_type != LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS) {
    uint8_t mac[4];
    integrity_generate(nas_ctx, nas_buffer, mac);
    memcpy(&nas_buffer->msg[1], mac, 4);
  }

  nas_ctx->m_nas_log->console(
      "Send [deactivate_eps_bearer_context_request]\n\t(SEC_HDR_TYPE= %s)\n\t(MAC_TYPE=%s)\n\t(MSG CONTENTS=uu)\n",
      sec_hdr_type_str[sec_hdr_type_idx],
      mac_type_str[mac_type_idx]);

  // Increase Next mutation
  fzmanager_epc::next_msg_security_property();

  return true;
}

bool fzmanager_epc::pack_pdn_disconnect_reject(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer)
{
  LIBLTE_MME_PDN_DISCONNECT_REJECT_MSG_STRUCT pdn_disconnect_reject;

  nas_ctx->m_nas_log->info("Packing [pdn_disconnect_reject]\n");
  nas_ctx->m_nas_log->console("Packing [pdn_disconnect_reject]\n");

  sec_ctx_t* sec_ctx = &nas_ctx->m_sec_ctx;
  emm_ctx_t* emm_ctx = &nas_ctx->m_emm_ctx;

  uint8_t sec_hdr_type = LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED;
  sec_hdr_type         = sec_hdr_type_variation[sec_hdr_type_idx];

  sec_ctx->dl_nas_count++;
  printf("Current NAS count is %d\n", sec_ctx->dl_nas_count);

  pdn_disconnect_reject.protocol_cnfg_opts_present = false;
  pdn_disconnect_reject.eps_bearer_id              = 5;
  pdn_disconnect_reject.proc_transaction_id        = emm_ctx->procedure_transaction_id;
  pdn_disconnect_reject.esm_cause                  = 1;

  LIBLTE_ERROR_ENUM err = liblte_mme_pack_pdn_disconnect_reject_msg_sec(
      &pdn_disconnect_reject, sec_hdr_type, sec_ctx->dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);

  if (err != LIBLTE_SUCCESS) {
    nas_ctx->m_nas_log->error("Error packing [pdn_disconnect_reject]\n");
    nas_ctx->m_nas_log->console("Error packing [pdn_disconnect_reject]\n");
    return false;
  }

  // Generate MAC for integrity protection
  if (sec_hdr_type != LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS) {
    uint8_t mac[4];
    integrity_generate(nas_ctx, nas_buffer, mac);
    memcpy(&nas_buffer->msg[1], mac, 4);
  }

  nas_ctx->m_nas_log->console(
      "Send [pdn_disconnect_reject]\n\t(SEC_HDR_TYPE= %s)\n\t(MAC_TYPE=%s)\n\t(MSG CONTENTS=uu)\n",
      sec_hdr_type_str[sec_hdr_type_idx],
      mac_type_str[mac_type_idx]);

  // Increase Next mutation
  fzmanager_epc::next_msg_security_property();

  return true;
}

bool fzmanager_epc::pack_bearer_resource_allocation_reject(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer)
{
  LIBLTE_MME_BEARER_RESOURCE_ALLOCATION_REJECT_MSG_STRUCT bearer_resource_allocation_reject;

  nas_ctx->m_nas_log->info("Packing [bearer_resource_allocation_reject]\n");
  nas_ctx->m_nas_log->console("Packing [bearer_resource_allocation_reject]\n");

  sec_ctx_t* sec_ctx = &nas_ctx->m_sec_ctx;
  emm_ctx_t* emm_ctx = &nas_ctx->m_emm_ctx;

  uint8_t sec_hdr_type = LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED;
  sec_hdr_type         = sec_hdr_type_variation[sec_hdr_type_idx];

  sec_ctx->dl_nas_count++;
  printf("Current NAS count is %d\n", sec_ctx->dl_nas_count);

  bearer_resource_allocation_reject.protocol_cnfg_opts_present = false;
  bearer_resource_allocation_reject.t3496_present              = false;
  bearer_resource_allocation_reject.eps_bearer_id              = 5;
  bearer_resource_allocation_reject.proc_transaction_id        = emm_ctx->procedure_transaction_id;
  bearer_resource_allocation_reject.esm_cause                  = 1;

  LIBLTE_ERROR_ENUM err = liblte_mme_pack_bearer_resource_allocation_reject_msg_sec(
      &bearer_resource_allocation_reject, sec_hdr_type, sec_ctx->dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);

  if (err != LIBLTE_SUCCESS) {
    nas_ctx->m_nas_log->error("Error packing [bearer_resource_allocation_reject]\n");
    nas_ctx->m_nas_log->console("Error packing [bearer_resource_allocation_reject]\n");
    return false;
  }

  // Generate MAC for integrity protection
  if (sec_hdr_type != LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS) {
    uint8_t mac[4];
    integrity_generate(nas_ctx, nas_buffer, mac);
    memcpy(&nas_buffer->msg[1], mac, 4);
  }

  nas_ctx->m_nas_log->console(
      "Send [bearer_resource_allocation_reject]\n\t(SEC_HDR_TYPE= %s)\n\t(MAC_TYPE=%s)\n\t(MSG CONTENTS=uu)\n",
      sec_hdr_type_str[sec_hdr_type_idx],
      mac_type_str[mac_type_idx]);

  // Increase Next mutation
  fzmanager_epc::next_msg_security_property();

  return true;
}

bool fzmanager_epc::pack_bearer_resource_modification_reject(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer)
{
  LIBLTE_MME_BEARER_RESOURCE_MODIFICATION_REJECT_MSG_STRUCT bearer_resource_modification_reject;

  nas_ctx->m_nas_log->info("Packing [bearer_resource_modification_reject]\n");
  nas_ctx->m_nas_log->console("Packing [bearer_resource_modification_reject]\n");

  sec_ctx_t* sec_ctx = &nas_ctx->m_sec_ctx;
  emm_ctx_t* emm_ctx = &nas_ctx->m_emm_ctx;

  uint8_t sec_hdr_type = LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED;
  sec_hdr_type         = sec_hdr_type_variation[sec_hdr_type_idx];

  sec_ctx->dl_nas_count++;
  printf("Current NAS count is %d\n", sec_ctx->dl_nas_count);

  bearer_resource_modification_reject.protocol_cnfg_opts_present = false;
  bearer_resource_modification_reject.t3496_present              = false;
  bearer_resource_modification_reject.eps_bearer_id              = 5;
  bearer_resource_modification_reject.proc_transaction_id        = emm_ctx->procedure_transaction_id;
  bearer_resource_modification_reject.esm_cause                  = 1;

  LIBLTE_ERROR_ENUM err = liblte_mme_pack_bearer_resource_modification_reject_msg_sec(
      &bearer_resource_modification_reject, sec_hdr_type, sec_ctx->dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);

  if (err != LIBLTE_SUCCESS) {
    nas_ctx->m_nas_log->error("Error packing [bearer_resource_modification_reject]\n");
    nas_ctx->m_nas_log->console("Error packing [bearer_resource_modification_reject]\n");
    return false;
  }

  // Generate MAC for integrity protection
  if (sec_hdr_type != LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS) {
    uint8_t mac[4];
    integrity_generate(nas_ctx, nas_buffer, mac);
    memcpy(&nas_buffer->msg[1], mac, 4);
  }

  nas_ctx->m_nas_log->console(
      "Send [bearer_resource_modification_reject]\n\t(SEC_HDR_TYPE= %s)\n\t(MAC_TYPE=%s)\n\t(MSG CONTENTS=uu)\n",
      sec_hdr_type_str[sec_hdr_type_idx],
      mac_type_str[mac_type_idx]);

  // Increase Next mutation
  fzmanager_epc::next_msg_security_property();

  return true;
}

bool fzmanager_epc::pack_notification(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer)
{
  LIBLTE_MME_NOTIFICATION_MSG_STRUCT notification;

  nas_ctx->m_nas_log->info("Packing [notification]\n");
  nas_ctx->m_nas_log->console("Packing [notification]\n");

  sec_ctx_t* sec_ctx = &nas_ctx->m_sec_ctx;
  emm_ctx_t* emm_ctx = &nas_ctx->m_emm_ctx;

  uint8_t sec_hdr_type = LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED;
  sec_hdr_type         = sec_hdr_type_variation[sec_hdr_type_idx];

  sec_ctx->dl_nas_count++;
  printf("Current NAS count is %d\n", sec_ctx->dl_nas_count);

  notification.eps_bearer_id       = 5;
  notification.proc_transaction_id = emm_ctx->procedure_transaction_id;
  notification.notification_ind    = 1;

  LIBLTE_ERROR_ENUM err = liblte_mme_pack_notification_msg_sec(
      &notification, sec_hdr_type, sec_ctx->dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);

  if (err != LIBLTE_SUCCESS) {
    nas_ctx->m_nas_log->error("Error packing [notification]\n");
    nas_ctx->m_nas_log->console("Error packing [notification]\n");
    return false;
  }

  // Generate MAC for integrity protection
  if (sec_hdr_type != LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS) {
    uint8_t mac[4];
    integrity_generate(nas_ctx, nas_buffer, mac);
    memcpy(&nas_buffer->msg[1], mac, 4);
  }

  nas_ctx->m_nas_log->console("Send [notification]\n\t(SEC_HDR_TYPE= %s)\n\t(MAC_TYPE=%s)\n\t(MSG CONTENTS=uu)\n",
                              sec_hdr_type_str[sec_hdr_type_idx],
                              mac_type_str[mac_type_idx]);

  // Increase Next mutation
  fzmanager_epc::next_msg_security_property();

  return true;
}

bool fzmanager_epc::pack_esm_status(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer)
{
  LIBLTE_MME_ESM_STATUS_MSG_STRUCT esm_status;

  nas_ctx->m_nas_log->info("Packing [esm_status]\n");
  nas_ctx->m_nas_log->console("Packing [esm_status]\n");

  sec_ctx_t* sec_ctx = &nas_ctx->m_sec_ctx;
  emm_ctx_t* emm_ctx = &nas_ctx->m_emm_ctx;

  uint8_t sec_hdr_type = LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED;
  sec_hdr_type         = sec_hdr_type_variation[sec_hdr_type_idx];

  sec_ctx->dl_nas_count++;
  printf("Current NAS count is %d\n", sec_ctx->dl_nas_count);

  esm_status.eps_bearer_id       = 5;
  esm_status.proc_transaction_id = emm_ctx->procedure_transaction_id;
  esm_status.esm_cause           = 25;

  LIBLTE_ERROR_ENUM err = liblte_mme_pack_esm_status_msg_sec(
      &esm_status, sec_hdr_type, sec_ctx->dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);

  if (err != LIBLTE_SUCCESS) {
    nas_ctx->m_nas_log->error("Error packing [esm_status]\n");
    nas_ctx->m_nas_log->console("Error packing [esm_status]\n");
    return false;
  }

  // Generate MAC for integrity protection
  if (sec_hdr_type != LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS) {
    uint8_t mac[4];
    integrity_generate(nas_ctx, nas_buffer, mac);
    memcpy(&nas_buffer->msg[1], mac, 4);
  }

  nas_ctx->m_nas_log->console("Send [esm_status]\n\t(SEC_HDR_TYPE= %s)\n\t(MAC_TYPE=%s)\n\t(MSG CONTENTS=uu)\n",
                              sec_hdr_type_str[sec_hdr_type_idx],
                              mac_type_str[mac_type_idx]);

  // Increase Next mutation
  fzmanager_epc::next_msg_security_property();

  return true;
}

// <REATTACH>
/*
bool fzmanager_epc::pack_detach_request_for_reattach_required(nas *nas_ctx, srslte::byte_buffer_t* nas_buffer){
  LIBLTE_MME_DETACH_REQUEST_NET_MSG_STRUCT detach_request;

  nas_ctx->m_nas_log->info("Packing Detach Request for Re-attach\n");
  nas_ctx->m_nas_log->console("Packing Detach Request for Re-attach\n");

  sec_ctx_t* sec_ctx = &nas_ctx->m_sec_ctx;
  emm_ctx_t* emm_ctx = &nas_ctx->m_emm_ctx;

  uint8_t sec_hdr_type = LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS;
  sec_hdr_type = sec_hdr_type_variation[sec_hdr_type_idx];

  ///Counter Add
  sec_ctx->dl_nas_count++;
  printf("Current NAS count is %d\n", sec_ctx->dl_nas_count);

  detach_request.detach_type.type_of_detach = 1;

  //bit 4 is spare
  detach_request.detach_type.switch_off = 0;

  LIBLTE_ERROR_ENUM err = liblte_mme_pack_detach_request_net_msg(&detach_request, sec_hdr_type, sec_ctx->dl_nas_count,
(LIBLTE_BYTE_MSG_STRUCT *) nas_buffer);

  if (err != LIBLTE_SUCCESS){
    nas_ctx->m_nas_log->error("Error packing DETACH ACCEPT\n");
    nas_ctx->m_nas_log->console("Error packing DETACH ACCEPT\n");
    return false;
  }

  // Generate MAC for integrity protection
  if (sec_hdr_type != LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS){
      uint8_t mac[4];
      integrity_generate(nas_ctx, nas_buffer, mac);
      memcpy(&nas_buffer->msg[1], mac, 4);
  }



  nas_ctx->m_nas_log->console("Send DETACH_ACCEPT\n\t(SEC_HDR_TYPE= %s)\n\t(MAC_TYPE=%s)\n\t(MSG CONTENTS=uu)\n",
sec_hdr_type_str[sec_hdr_type_idx], mac_type_str[mac_type_idx]);

  // Increase Next mutation
  fzmanager_epc::next_msg_security_property();


  return true;
}

*/

//
// S1AP -> NAS function
//
//

bool fzmanager_epc::pack_identity_request_for_dl_info_transfer(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer)
{
  // nas_ctx->m_nas_log->info("Packing Identity Request\n");
  // nas_ctx->m_nas_log->console("Packing Identity Request\n");

  sec_ctx_t* m_sec_ctx  = &nas_ctx->m_sec_ctx;
  sec_ctx_t  no_sec_ctx = {};

  // Two value variation points
  LIBLTE_MME_ID_REQUEST_MSG_STRUCT id_req;
  uint8_t                          sec_hdr_type;

  uint8 identity_request_type_value[16];
  uint8 temp_tv = 0;
  for (int tv = 0; tv < 16; tv++) {
    identity_request_type_value[tv] = temp_tv;
    temp_tv++;
  }

  id_req.id_type = identity_request_type_value[identity_type2_variation_long[1]];

  sec_hdr_type_idx = m_sec_ctx ? 2 : 0;
  sec_hdr_type     = sec_hdr_type_variation[sec_hdr_type_idx];
  mac_type_idx     = 2;
  // Debug
  // nas_ctx->m_nas_log->console("DL count is : %d", m_sec_ctx->dl_nas_count);

  // nas_ctx->m_nas_log->console("Send Identity Request (ID_TYPE= %d, SEC_HDR_TYPE= %d, MAC_type=%d)\n",
  //                             id_req.id_type,
  //                             sec_hdr_type,
  //                             mac_type_idx);
  nas_ctx->m_nas_log->info("Send Identity Request (ID_TYPE= %d, SEC_HDR_TYPE= %d, MAC_type=%d)\n",
                           id_req.id_type,
                           sec_hdr_type,
                           mac_type_idx);

  if (sec_hdr_type != LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS)
    m_sec_ctx->dl_nas_count++;

  // Debug
  // nas_ctx->m_nas_log->console("DL count is : %d", m_sec_ctx->dl_nas_count);

  LIBLTE_ERROR_ENUM err = liblte_mme_pack_identity_request_msg_sec(
      &id_req, sec_hdr_type, m_sec_ctx->dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);

  if (err != LIBLTE_SUCCESS) {
    nas_ctx->m_nas_log->error("Error packing Identity Request\n");
    nas_ctx->m_nas_log->console("Error packing Identity REquest\n");
    return false;
  }

  // Debug
  // nas_ctx->m_nas_log->console("Integ algo is : %d", m_sec_ctx->integ_algo);
  // nas_ctx->m_nas_log->console("eKSI is : %d", m_sec_ctx->eksi);

  if (sec_hdr_type != LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS) {
    uint8_t mac[4];
    integrity_generate(nas_ctx, nas_buffer, mac);
    memcpy(&nas_buffer->msg[1], mac, 4);
  }

  return true;
}

//============================================================================
// Helper functions for security
//============================================================================
void fzmanager_epc::integrity_generate(nas* nas_ctx, srslte::byte_buffer_t* pdu, uint8_t* mac)
{
  emm_ctx_t* m_emm_ctx = &nas_ctx->m_emm_ctx;
  ecm_ctx_t* m_ecm_ctx = &nas_ctx->m_ecm_ctx;
  sec_ctx_t* m_sec_ctx = &nas_ctx->m_sec_ctx;

  switch (m_sec_ctx->integ_algo) {
    case srslte::INTEGRITY_ALGORITHM_ID_EIA0:
      break;
    case srslte::INTEGRITY_ALGORITHM_ID_128_EIA1:
      srslte::security_128_eia1(&m_sec_ctx->k_nas_int[16],
                                m_sec_ctx->dl_nas_count,
                                0, // Bearer always 0 for NAS
                                SECURITY_DIRECTION_DOWNLINK,
                                &pdu->msg[5],
                                pdu->N_bytes - 5,
                                mac);
      break;
    case srslte::INTEGRITY_ALGORITHM_ID_128_EIA2:
      srslte::security_128_eia2(&m_sec_ctx->k_nas_int[16],
                                m_sec_ctx->dl_nas_count,
                                0, // Bearer always 0 for NAS
                                SECURITY_DIRECTION_DOWNLINK,
                                &pdu->msg[5],
                                pdu->N_bytes - 5,
                                mac);
      break;
    default:
      break;
  }
  // nas_ctx->m_nas_log->debug("Generating MAC with inputs: Algorithm %s, DL COUNT %d\n",
  //                           srslte::integrity_algorithm_id_text[m_sec_ctx->integ_algo],
  //                           m_sec_ctx->dl_nas_count);
  // nas_ctx->m_nas_log->console("[fuzz]Generating MAC with inputs: Algorithm %s, DL COUNT %d\n",
  //                             srslte::integrity_algorithm_id_text[m_sec_ctx->integ_algo],
  //                             m_sec_ctx->dl_nas_count);

  if (mac_type_idx == INV_MAC) {
    mac[0] = 255;
    mac[2] = 255;
  } else if (mac_type_idx == ZERO_MAC) {
    mac[0] = 0;
    mac[1] = 0;
    mac[2] = 0;
    mac[3] = 0;
  } else {
    return;
  }
}

void fzmanager_epc::cipher_encrypt(nas* nas_ctx, srslte::byte_buffer_t* pdu)
{
  emm_ctx_t* m_emm_ctx = &nas_ctx->m_emm_ctx;
  ecm_ctx_t* m_ecm_ctx = &nas_ctx->m_ecm_ctx;
  sec_ctx_t* m_sec_ctx = &nas_ctx->m_sec_ctx;

  srslte::byte_buffer_t pdu_tmp;
  switch (m_sec_ctx->cipher_algo) {
    case srslte::CIPHERING_ALGORITHM_ID_EEA0:
      break;
    case srslte::CIPHERING_ALGORITHM_ID_128_EEA1:
      srslte::security_128_eea1(&m_sec_ctx->k_nas_enc[16],
                                pdu->msg[5],
                                0, // Bearer always 0 for NAS
                                SECURITY_DIRECTION_DOWNLINK,
                                &pdu->msg[6],
                                pdu->N_bytes - 6,
                                &pdu_tmp.msg[6]);
      memcpy(&pdu->msg[6], &pdu_tmp.msg[6], pdu->N_bytes - 6);
      nas_ctx->m_nas_log->debug_hex(pdu_tmp.msg, pdu->N_bytes, "Encrypted");
      break;
    case srslte::CIPHERING_ALGORITHM_ID_128_EEA2:
      srslte::security_128_eea2(&m_sec_ctx->k_nas_enc[16],
                                pdu->msg[5],
                                0, // Bearer always 0 for NAS
                                SECURITY_DIRECTION_DOWNLINK,
                                &pdu->msg[6],
                                pdu->N_bytes - 6,
                                &pdu_tmp.msg[6]);
      memcpy(&pdu->msg[6], &pdu_tmp.msg[6], pdu->N_bytes - 6);
      nas_ctx->m_nas_log->debug_hex(pdu_tmp.msg, pdu->N_bytes, "Encrypted");
      break;
    default:
      nas_ctx->m_nas_log->error("Ciphering algorithm not known\n");
      break;
  }
}

//============================================================================
// Helper functions
//============================================================================
char* fzmanager_epc::get_msg_type_name(const char* hex_str)
{
  for (int i = 0; i < MSG_TYPE_N; i++) {
    if (strncmp(hex_str, msg_type_hex_to_name_str[i][0], strlen(hex_str)) == 0) {
      return msg_type_hex_to_name_str[i][1];
    }
  }
  return NULL;
}

char* fzmanager_epc::get_msg_type_hex(const char* name)
{
  for (int i = 0; i < MSG_TYPE_N; i++) {
    if (strncmp(name, msg_type_hex_to_name_str[i][1], strlen(name)) == 0) {
      return msg_type_hex_to_name_str[i][0];
    }
  }
  return NULL;
}

char* fzmanager_epc::get_msg_type_str_from_uint(const uint8_t cur_msg_type)
{
  std::stringstream sstream;
  sstream << "0x" << std::setfill('0') << std::setw(2) << std::hex << (int)cur_msg_type;
  return get_msg_type_name(sstream.str().c_str());
}

// Update config file for test case management
bool fzmanager_epc::write_rrc_test_config(rrc_test_stat doltest_stat_rrc)
{
  // if (!doltest_stat){
  //  return false;
  //}

  std::ofstream file;
  file.open("../../../conf/doltest_stat_rrc", std::ios::out | std::ios::trunc);
  if (file.is_open()) {

    file << "state=" << (int)doltest_stat_rrc.state_fz << std::endl;              // state
    file << "test_protocol=" << (int)doltest_stat_rrc.test_protocol << std::endl; // USE ENUM
    file << "test_case=" << (int)doltest_stat_rrc.test_num_fz << std::endl;       // testnum
    file << "current_EIA=" << (int)doltest_stat_rrc.EIA_fz << std::endl;
    file << "current_EEA=" << (int)doltest_stat_rrc.EEA_fz << std::endl;
    // for RRC Connection Release
    file << "release_cause=" << (int)doltest_stat_rrc.release_cause_fz << std::endl;
    file << "extended_wait_time=" << (int)doltest_stat_rrc.extended_wait_time_fz << std::endl;
    file << "redirected_carrier_info_earfcn=" << (int)doltest_stat_rrc.redirected_carrier_info_earfcn_fz << std::endl;
    file << "set_to_arfcn=" << (int)doltest_stat_rrc.set_to_arfcn_fz << std::endl;
    // for RRC SecurityModeCommand
    file << "smc_eia_num=" << (int)doltest_stat_rrc.eia_num_fz << std::endl;
    file << "smc_eea_num=" << (int)doltest_stat_rrc.eea_num_fz << std::endl;
    // for RRC Attach Reject
    // file << "rrc_conn_reject_wait_time=" << (int)doltest_stat_rrc.reject_wait_time_fz << std::endl;
    // for rrc conn recfg
    file << "set_srb2=" << (int)doltest_stat_rrc.set_srb2 << std::endl;
    file << "set_drb=" << (int)doltest_stat_rrc.set_drb << std::endl;
    file << "req_meas_report=" << (int)doltest_stat_rrc.req_meas_report << std::endl;
    file << "do_ho=" << (int)doltest_stat_rrc.do_ho << std::endl;
    file << "reconf_comb=" << (int)doltest_stat_rrc.reconf_comb << std::endl;
    file << "idle_mode_mob_ctrl=" << (int)doltest_stat_rrc.idle_mode_mob_ctrl << std::endl;
    file << "counter_check_r15_true=" << (int)doltest_stat_rrc.counter_check_r15_true << std::endl;
    file << "info_request_r9_true=" << (int)doltest_stat_rrc.info_request_r9_true << std::endl;
    file << "info_request_r10_true=" << (int)doltest_stat_rrc.info_request_r10_true << std::endl;
    file << "info_request_r11_true=" << (int)doltest_stat_rrc.info_request_r11_true << std::endl;
    file << "info_request_r12_true=" << (int)doltest_stat_rrc.info_request_r12_true << std::endl;
    file << "info_request_r15_true=" << (int)doltest_stat_rrc.info_request_r15_true << std::endl;

    file.close();
    return true;
  } else {
    return false;
  }
}

bool fzmanager_epc::read_rrc_test_config(rrc_test_stat* doltest_stat_rrc)
{
  std::ifstream file;

  if (!doltest_stat_rrc) {
    printf("Error occured here\n");
    return false;
  }

  file.open("../../../conf/doltest_stat_rrc", std::ios::in);

  if (file.is_open()) {
    if (!readvar(file, "state=", &doltest_stat_rrc->state_fz)) {
      return false;
    }
    if (!readvar(file, "test_protocol=", &doltest_stat_rrc->test_protocol)) {
      return false;
    }
    if (!readvar(file, "test_case=", &doltest_stat_rrc->test_num_fz)) {
      return false;
    }
    if (!readvar(file, "current_EIA=", &doltest_stat_rrc->EIA_fz)) {
      return false;
    }
    if (!readvar(file, "current_EEA=", &doltest_stat_rrc->EEA_fz)) {
      return false;
    }
    if (!readvar(file, "release_cause=", &doltest_stat_rrc->release_cause_fz)) {
      return false;
    }
    if (!readvar(file, "extended_wait_time=", &doltest_stat_rrc->extended_wait_time_fz)) {
      return false;
    }
    if (!readvar(file, "redirected_carrier_info_earfcn=", &doltest_stat_rrc->redirected_carrier_info_earfcn_fz)) {
      return false;
    }
    if (!readvar(file, "set_to_arfcn=", &doltest_stat_rrc->set_to_arfcn_fz)) {
      return false;
    }
    if (!readvar(file, "smc_eia_num=", &doltest_stat_rrc->eia_num_fz)) {
      return false;
    }
    if (!readvar(file, "smc_eea_num=", &doltest_stat_rrc->eea_num_fz)) {
      return false;
    }
    // if (!readvar(file, "rrc_conn_reject_wait_time=", &doltest_stat_rrc->reject_wait_time_fz)) {
    //   return false;
    // }
    if (!readvar(file, "set_srb2=", &doltest_stat_rrc->set_srb2)) {
      return false;
    }
    if (!readvar(file, "set_drb=", &doltest_stat_rrc->set_drb)) {
      return false;
    }
    if (!readvar(file, "req_meas_report=", &doltest_stat_rrc->req_meas_report)) {
      return false;
    }
    if (!readvar(file, "do_ho=", &doltest_stat_rrc->do_ho)) {
      return false;
    }
    if (!readvar(file, "reconf_comb=", &doltest_stat_rrc->reconf_comb)) {
      return false;
    }
    if (!readvar(file, "idle_mode_mob_ctrl=", &doltest_stat_rrc->idle_mode_mob_ctrl)) {
      return false;
    }
    if (!readvar(file, "counter_check_r15_true=", &doltest_stat_rrc->counter_check_r15_true)) {
      return false;
    }
    if (!readvar(file, "info_request_r9_true=", &doltest_stat_rrc->info_request_r9_true)) {
      return false;
    }
    if (!readvar(file, "info_request_r10_true=", &doltest_stat_rrc->info_request_r10_true)) {
      return false;
    }
    if (!readvar(file, "info_request_r11_true=", &doltest_stat_rrc->info_request_r11_true)) {
      return false;
    }
    if (!readvar(file, "info_request_r12_true=", &doltest_stat_rrc->info_request_r12_true)) {
      return false;
    }
    if (!readvar(file, "info_request_r15_true=", &doltest_stat_rrc->info_request_r15_true)) {
      return false;
    }

    // rrc_log->console("\n**************************************** \n");
    printf("[DoLTEst] Reading configuration file.. (doltest_stat_rrc)\n");
    // rrc_log->console("**************************************** \n");
    printf("---------------------------------------\n");

    file.close();
    return true;
  } else {
    return false;
  }
}

} // namespace srsepc