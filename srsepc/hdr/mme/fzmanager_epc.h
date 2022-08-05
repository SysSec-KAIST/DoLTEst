#ifndef FZMANAGER_EPC_H
#define FZMANAGER_EPC_H

#include <stdbool.h>
#include <unistd.h>

#include "s1ap_common.h"
#include "srslte/asn1/liblte_s1ap.h"
#include "srslte/common/buffer_pool.h"
#include "srslte/interfaces/epc_interfaces.h"

#include <fstream>
#include <list>
#include <time.h>

using namespace std;

namespace srsepc {

#define TEST_FINISH_CODE 3
#define TEST_INCOMPLETE_CODE 4

class fz_nas_msg
{

public:
  fz_nas_msg() {}
  fz_nas_msg(uint8_t given_msg_type) : msg_type(given_msg_type) {}

  uint8_t msg_type;
  int     id_type_idx;
  int     sec_hdr_type_idx;
};

class fzmanager_epc
{

public:
  static fzmanager_epc* m_instance;
  static fzmanager_epc* get_instance(void);
  static void           cleanup(void);
  void                  init();

  // fuzzing func
  // msg handler
  bool fzmanager_ready_to_send(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer);
  bool fzmanager_ready_to_send_2(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer);
  bool fzmanager_receive_unhandled_msg(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer, uint8_t msg_type);

  bool pack_test_message(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer);
  bool check_fuzzing_timing();
  void reset_fuzzing_timing();

  typedef enum {
    EPC_SEC_STATE_NONE = 0,
    EPC_SEC_STATE_NAS,
    EPC_SEC_STATE_NAS_RRC,
    EPC_SEC_STATE_N,
  } epc_sec_state_t;
  epc_sec_state_t epc_fuzz_state, target_epc_sec_state;
  uint8_t         sec_hdr_type_variation[20] = {
      LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS,
      LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY,
      LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED,
      LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_WITH_NEW_EPS_SECURITY_CONTEXT,
      LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED_WITH_NEW_EPS_SECURITY_CONTEXT,
      0x5,
      0x6,
      0x7,
      0x8,
      0x9,
      0xa,
      0xb,
      LIBLTE_MME_SECURITY_HDR_TYPE_SERVICE_REQUEST,
      0xd,
      0xe,
      0xf};
  char sec_hdr_type_str[16][100] = {"0x0 (Plain NAS message, not security protected)",
                                    "0x1 (Integrity protected)",
                                    "0x2 (Integrity protected and ciphered)",
                                    "0x3 (Integrity protected with new EPS security context)",
                                    "0x4 (Integrity protected and ciphered with new EPS security context)",
                                    "0x5 (Integrity protected and partially ciphered NAS message)",
                                    "0x6 (Reserved)",
                                    "0x7 (Reserved)",
                                    "0x8 (Reserved)",
                                    "0x9 (Reserved)",
                                    "0xa (Reserved)",
                                    "0xb (Reserved)",
                                    "0xc (Security header for the SERVICE REQUEST message)",
                                    "0xd (Reserved)",
                                    "0xe (Reserved)",
                                    "0xf (Reserved)" };

  char doltest_nas_test_msg_type_names[7][100] = {"(NAS)Identity Request",
                                                  "(NAS)Security Mode Command",
                                                  "(NAS)GUTI Reallocation Command",
                                                  "(NAS)EMM Information",
                                                  "(NAS)Downlink NAS Transport",
                                                  "(NAS)Attach Reject",
                                                  "(NAS)Attach Accept"};

  char doltest_nas_pairing_response_names[7][100] = {"(NAS)Identity Response",
                                                     "(NAS)Security Mode Complete",
                                                     "(NAS)GUTI Reallocation Complete",
                                                     "-",
                                                     "(NAS)Uplink NAS Transport",
                                                     "-",
                                                     "(NAS)Attach Complete"};

  char doltest_nas_test_msg_list[7][100] =  {"LIBLTE_MME_MSG_TYPE_IDENTITY_REQUEST",
                                             "LIBLTE_MME_MSG_TYPE_SECURITY_MODE_COMMAND",
                                             "LIBLTE_MME_MSG_TYPE_GUTI_REALLOCATION_COMMAND",
                                             "LIBLTE_MME_MSG_TYPE_EMM_INFORMATION",
                                             "LIBLTE_MME_MSG_TYPE_DOWNLINK_NAS_TRANSPORT",
                                             "LIBLTE_MME_MSG_TYPE_ATTACH_REJECT",
                                             "LIBLTE_MME_MSG_TYPE_ATTACH_ACCEPT"};

#define SEC_HDR_TYPE_TESTN 16

  uint8_t identity_type2_variation[4]       = {0x0, 0x2, 0x3, 0x4};
  uint8_t identity_type2_variation_long[16] = {
      0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};

  char identity_type_str[16][100] = {"reserved value (0x0)",
                                     "IMSI (0x1)",
                                     "IMEI (0x2)",
                                     "IMEISV (0x3)",
                                     "TMSI (0x4)",
                                     "reserved value (0x5)",
                                     "reserved value (0x6)",
                                     "reserved value (0x7)",
                                     "reserved value (0x8)",
                                     "reserved value (0x9)",
                                     "reserved value (0xa)",
                                     "reserved value (0xb)",
                                     "reserved value (0xc)",
                                     "reserved value (0xd)",
                                     "reserved value (0xe)",
                                     "reserved value (0xf)"};

#define IDENTITY_TYPE2_TESTN 4
#define IDENTITY_TYPE2_LONG_TESTN 16
  uint8_t identity_request_test_value_range = IDENTITY_TYPE2_TESTN;

  char epc_sec_state_txt[EPC_SEC_STATE_N][40] = {"NONE: NAS/RRC security is not activated",
                                                 "NAS: NAS security is activated",
                                                 "NAS/RRC: NAS/AS security is activated"};

  char doltest_state_names[4][20] = {"No-SC", "N-SC", "NR-SC", "REGI"};
  // #define LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS 0x0
  // #define LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY 0x1
  // #define LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED 0x2
  // #define LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_WITH_NEW_EPS_SECURITY_CONTEXT 0x3
  // #define LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED_WITH_NEW_EPS_SECURITY_CONTEXT 0x4
  // #define LIBLTE_MME_SECURITY_HDR_TYPE_SERVICE_REQUEST 0xC

  typedef enum {
    DOLTEST_STATE_NO_SC = 0,
    DOLTEST_STATE_N_SC,
    DOLTEST_STATE_NR_SC,
    DOLTEST_STATE_REGI,
    DOLTEST_STATE_N
  } doltest_state_t;

  uint8_t          fz_target_msg; // Test Message
  list<fz_nas_msg> fz_target_path;

  int              fz_target_state; // Test State
  int              fz_target_epc_sec_state_idx;
  int              fz_target_protocol; // Test Protocol

  int              dt_nas_test_state;     // Test state
  int              dt_nas_test_protocol;  // Test protocol
  uint8_t          dt_test_message;       // Test message 

  typedef enum { RRC = 0, NAS, ESM, MAC } protocol_type_e_;

  char protocol_type_e_names[5][10] = {"RRC", "NAS", "ESM", "MAC"};

  // value mutation
  bool m_value_fuzzing;
  int  sec_hdr_type_idx;

  int     id_type_idx;         // Identity request
  uint8_t start_day;           // emm information msg
  uint8_t start_hour;          // emm information msg
  uint8_t sms_msg_val;         // dl_nas_transport
  int     start_emm_cause_idx; // reject msgs
  int     cipher_algo;
  int     integ_algo;

  typedef enum {
    ZERO_MAC = 0,
    INV_MAC,
    //	VALID_MAC,     // We skip valid MAC
    MAC_TYPE_TESTN,
  } fz_mac_type_t;
  int  mac_type_idx;
  char mac_type_str[3][40] = {
      "Zero MAC (no integrity)",
      "Invalid MAC (broken integrity)",
      "Valid MAC",
  };

#define IDENTITY_REQUEST_TYPE_TESTN 16

  /* Downlink NAS messages packing */
  bool pack_authentication_request(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer);
  bool pack_authentication_reject(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer);
  void next_security_mode_command();
  bool pack_security_mode_command(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer);
  bool pack_esm_information_request(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer);
  bool pack_identity_request(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer);
  bool pack_identity_request_for_dl_info_transfer(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer);

  void next_emm_information();
  bool pack_emm_information(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer);

  bool pack_service_reject(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer, uint8_t emm_cause);

  void next_guti_reallocation();
  void pack_guti_reallocation(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer);

  void next_downlink_nas_transport();
  bool pack_downlink_nas_transport(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer);

  void next_attach_reject();
  bool pack_attach_reject(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer);

  void next_service_reject();
  bool pack_service_reject(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer);

  void next_tracking_area_update_reject();
  bool pack_tracking_area_update_reject(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer);

  bool pack_pdn_connectivity_reject(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer);

  void next_msg_security_property();
  void next_attach_accept();

  bool pack_attach_accept(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer);
  bool pack_detach_accept(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer);
  bool pack_detach_request(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer);
  bool pack_tracking_area_update_accept(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer);
  bool pack_emm_status(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer);
  bool pack_cs_service_notification(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer);
  bool pack_activate_default_eps_bearer_context_request(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer);
  bool pack_activate_dedicated_eps_bearer_context_request(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer);
  bool pack_modify_eps_bearer_context_request(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer);
  bool pack_deactivate_eps_bearer_context_request(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer);
  bool pack_pdn_disconnect_reject(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer);
  bool pack_bearer_resource_allocation_reject(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer);
  bool pack_bearer_resource_modification_reject(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer);
  // bool pack_esm_information_request(nas *nas_ctx, srslte::byte_buffer_t* nas_buffer);
  bool pack_notification(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer);
  bool pack_esm_status(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer);

  void integrity_generate(nas* nas_ctx, srslte::byte_buffer_t* pdu, uint8_t* mac);
  void cipher_encrypt(nas* nas_ctx, srslte::byte_buffer_t* pdu);

  /* signal handler */
  static void AlrmHandler(int signum);
  void        signal_setting();
  void        disable_alarm();
#define RESPONSE_WAIT_TIME 2   // second
#define DISABLE_ALARM_TIME 200 // second
#define REJECT_WAIT_TIME 70    // second////
///> <SERVICE REJECT>
////

  bool   is_finish;
  bool   need_to_wait;
  bool   is_reject_case;
  bool   is_msg_sent;
  time_t start, end;
  int    msg_sent_cnt;

  /* Path information */
  list<fz_nas_msg>           path;
  list<fz_nas_msg>::iterator next_msg;
  bool                       add_to_path(uint8_t msg_type);
  void                       print_path();
  bool                       is_path_traversing;
  void                       traverse(nas* nas_ctx, srslte::byte_buffer_t* nas_buffer);
  int                        path_msg_n_for_state[4]       = {1, 7, 7, 11};
  void                       set_path(int dt_nas_test_state);

  char  path_list_str[11][100] = {
        "LIBLTE_MME_MSG_TYPE_ATTACH_REQUEST",
        "LIBLTE_MME_MSG_TYPE_IDENTITY_REQUEST",
        "LIBLTE_MME_MSG_TYPE_IDENTITY_RESPONSE",
        "LIBLTE_MME_MSG_TYPE_AUTHENTICATION_REQUEST",
        "LIBLTE_MME_MSG_TYPE_AUTHENTICATION_RESPONSE",
        "LIBLTE_MME_MSG_TYPE_SECURITY_MODE_COMMAND",
        "LIBLTE_MME_MSG_TYPE_SECURITY_MODE_COMPLETE",
        "LIBLTE_MME_MSG_TYPE_ESM_INFORMATION_REQUEST",
        "LIBLTE_MME_MSG_TYPE_ESM_INFORMATION_RESPONSE",
        "LIBLTE_MME_MSG_TYPE_ATTACH_ACCEPT",
        "LIBLTE_MME_MSG_TYPE_ATTACH_COMPLETE"
  };


  /* read testcase file */
  std::ifstream test_file;
  // void          read_test_file();

/* prev_progress */
#define PROGRESS_FILE_NAME "prev_progress.txt"
  std::ifstream prev_progress;
  // void          read_prev_progress_file();
  // void          write_prev_progress_file();

#define NAS_CONFIG_FILE_NAME "../../../conf/doltest_stat_nas"
  bool          read_nas_test_config();
  bool          write_nas_test_config();

  std::ofstream out_progress;

  /* results */
  std::ofstream outfile;

// test message management
  struct rrc_test_stat {
    uint8_t  state_fz;
    uint8_t  test_protocol = protocol_type_e_::NAS;
    uint8_t  test_num_fz;
    uint8_t  EIA_fz; // global EIA algorithm for PDCP
    uint8_t  EEA_fz; // global EEA algorithm for PDCP
    uint8_t  release_cause_fz;
    uint32_t extended_wait_time_fz;
    uint32_t redirected_carrier_info_earfcn_fz;
    uint8_t  set_to_arfcn_fz;
    uint8_t  eia_num_fz; // content in SMC message
    uint8_t  eea_num_fz; // content in SMC message
    uint32_t reject_wait_time_fz;
    uint8_t  set_srb2;
    uint8_t  set_drb;
    uint8_t  req_meas_report;
    uint8_t  do_ho;
    uint8_t  reconf_comb;
    uint8_t  idle_mode_mob_ctrl;
    uint8_t  counter_check_r15_true;
    uint8_t  info_request_r9_true;
    uint8_t  info_request_r10_true;
    uint8_t  info_request_r11_true;
    uint8_t  info_request_r12_true;
    uint8_t  info_request_r15_true;
  };

  rrc_test_stat doltest_stat_rrc = {};
  bool write_rrc_test_config(rrc_test_stat doltest_stat_rrc);
  bool read_rrc_test_config(rrc_test_stat* doltest_stat_rrc);

private:
  fzmanager_epc();
  virtual ~fzmanager_epc();

  srslte::byte_buffer_pool* m_pool;
  nas*                      prev_nas_ctx;
  srslte::byte_buffer_t*    prev_nas_buffer;

  bool path_comparison();

  /* helper functions */
  template <class T>
  bool readvar(std::istream& file, const char* key, T* var)
  {
    std::string line;
    size_t      len = strlen(key);
    std::getline(file, line);
    if (line.substr(0, len).compare(key)) {
      return false;
    }
    *var = (T)atoi(line.substr(len).c_str());
    return true;
  }


#define MSG_TYPE_N 61
  char* get_msg_type_name(const char* hex_str);
  char* get_msg_type_hex(const char* name);
  char* get_msg_type_str_from_uint(const uint8_t cur_msg_type);
  char  msg_type_name_to_hex_str[61][2][100] = {
      {"LIBLTE_MME_PD_EPS_SESSION_MANAGEMENT", "0x2"},
      {"LIBLTE_MME_PD_EPS_MOBILITY_MANAGEMENT", "0x7"},
      {"LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS", "0x0"},
      {"LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY", "0x1"},
      {"LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED", "0x2"},
      {"LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_WITH_NEW_EPS_SECURITY_CONTEXT", "0x3"},
      {"LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED_WITH_NEW_EPS_SECURITY_CONTEXT", "0x4"},
      {"LIBLTE_MME_SECURITY_HDR_TYPE_SERVICE_REQUEST", "0xC"},
      {"LIBLTE_MME_MSG_TYPE_ATTACH_REQUEST", "0x41"},
      {"LIBLTE_MME_MSG_TYPE_ATTACH_ACCEPT", "0x42"},
      {"LIBLTE_MME_MSG_TYPE_ATTACH_COMPLETE", "0x43"},
      {"LIBLTE_MME_MSG_TYPE_ATTACH_REJECT", "0x44"},
      {"LIBLTE_MME_MSG_TYPE_DETACH_REQUEST", "0x45"},
      {"LIBLTE_MME_MSG_TYPE_DETACH_ACCEPT", "0x46"},
      {"LIBLTE_MME_MSG_TYPE_TRACKING_AREA_UPDATE_REQUEST", "0x48"},
      {"LIBLTE_MME_MSG_TYPE_TRACKING_AREA_UPDATE_ACCEPT", "0x49"},
      {"LIBLTE_MME_MSG_TYPE_TRACKING_AREA_UPDATE_COMPLETE", "0x4A"},
      {"LIBLTE_MME_MSG_TYPE_TRACKING_AREA_UPDATE_REJECT", "0x4B"},
      {"LIBLTE_MME_MSG_TYPE_EXTENDED_SERVICE_REQUEST", "0x4C"},
      {"LIBLTE_MME_MSG_TYPE_SERVICE_REJECT", "0x4E"},
      {"LIBLTE_MME_MSG_TYPE_GUTI_REALLOCATION_COMMAND", "0x50"},
      {"LIBLTE_MME_MSG_TYPE_GUTI_REALLOCATION_COMPLETE", "0x51"},
      {"LIBLTE_MME_MSG_TYPE_AUTHENTICATION_REQUEST", "0x52"},
      {"LIBLTE_MME_MSG_TYPE_AUTHENTICATION_RESPONSE", "0x53"},
      {"LIBLTE_MME_MSG_TYPE_AUTHENTICATION_REJECT", "0x54"},
      {"LIBLTE_MME_MSG_TYPE_AUTHENTICATION_FAILURE", "0x5C"},
      {"LIBLTE_MME_MSG_TYPE_IDENTITY_REQUEST", "0x55"},
      {"LIBLTE_MME_MSG_TYPE_IDENTITY_RESPONSE", "0x56"},
      {"LIBLTE_MME_MSG_TYPE_SECURITY_MODE_COMMAND", "0x5D"},
      {"LIBLTE_MME_MSG_TYPE_SECURITY_MODE_COMPLETE", "0x5E"},
      {"LIBLTE_MME_MSG_TYPE_SECURITY_MODE_REJECT", "0x5F"},
      {"LIBLTE_MME_MSG_TYPE_EMM_STATUS", "0x60"},
      {"LIBLTE_MME_MSG_TYPE_EMM_INFORMATION", "0x61"},
      {"LIBLTE_MME_MSG_TYPE_DOWNLINK_NAS_TRANSPORT", "0x62"},
      {"LIBLTE_MME_MSG_TYPE_UPLINK_NAS_TRANSPORT", "0x63"},
      {"LIBLTE_MME_MSG_TYPE_CS_SERVICE_NOTIFICATION", "0x64"},
      {"LIBLTE_MME_MSG_TYPE_DOWNLINK_GENERIC_NAS_TRANSPORT", "0x68"},
      {"LIBLTE_MME_MSG_TYPE_UPLINK_GENERIC_NAS_TRANSPORT", "0x69"},
      {"LIBLTE_MME_MSG_TYPE_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST", "0xC1"},
      {"LIBLTE_MME_MSG_TYPE_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_ACCEPT", "0xC2"},
      {"LIBLTE_MME_MSG_TYPE_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REJECT", "0xC3"},
      {"LIBLTE_MME_MSG_TYPE_ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REQUEST", "0xC5"},
      {"LIBLTE_MME_MSG_TYPE_ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_ACCEPT", "0xC6"},
      {"LIBLTE_MME_MSG_TYPE_ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REJECT", "0xC7"},
      {"LIBLTE_MME_MSG_TYPE_MODIFY_EPS_BEARER_CONTEXT_REQUEST", "0xC9"},
      {"LIBLTE_MME_MSG_TYPE_MODIFY_EPS_BEARER_CONTEXT_ACCEPT", "0xCA"},
      {"LIBLTE_MME_MSG_TYPE_MODIFY_EPS_BEARER_CONTEXT_REJECT", "0xCB"},
      {"LIBLTE_MME_MSG_TYPE_DEACTIVATE_EPS_BEARER_CONTEXT_REQUEST", "0xCD"},
      {"LIBLTE_MME_MSG_TYPE_DEACTIVATE_EPS_BEARER_CONTEXT_ACCEPT", "0xCE"},
      {"LIBLTE_MME_MSG_TYPE_PDN_CONNECTIVITY_REQUEST", "0xD0"},
      {"LIBLTE_MME_MSG_TYPE_PDN_CONNECTIVITY_REJECT", "0xD1"},
      {"LIBLTE_MME_MSG_TYPE_PDN_DISCONNECT_REQUEST", "0xD2"},
      {"LIBLTE_MME_MSG_TYPE_PDN_DISCONNECT_REJECT", "0xD3"},
      {"LIBLTE_MME_MSG_TYPE_BEARER_RESOURCE_ALLOCATION_REQUEST", "0xD4"},
      {"LIBLTE_MME_MSG_TYPE_BEARER_RESOURCE_ALLOCATION_REJECT", "0xD5"},
      {"LIBLTE_MME_MSG_TYPE_BEARER_RESOURCE_MODIFICATION_REQUEST", "0xD6"},
      {"LIBLTE_MME_MSG_TYPE_BEARER_RESOURCE_MODIFICATION_REJECT", "0xD7"},
      {"LIBLTE_MME_MSG_TYPE_ESM_INFORMATION_REQUEST", "0xD9"},
      {"LIBLTE_MME_MSG_TYPE_ESM_INFORMATION_RESPONSE", "0xDA"},
      {"LIBLTE_MME_MSG_TYPE_NOTIFICATION", "0xDB"},
      {"LIBLTE_MME_MSG_TYPE_ESM_STATUS", "0xE8"}};

  char msg_type_hex_to_name_str[61][2][100] = {
      {"0x2", "LIBLTE_MME_PD_EPS_SESSION_MANAGEMENT"},
      {"0x7", "LIBLTE_MME_PD_EPS_MOBILITY_MANAGEMENT"},
      {"0x0", "LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS"},
      {"0x1", "LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY"},
      {"0x2", "LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED"},
      {"0x3", "LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_WITH_NEW_EPS_SECURITY_CONTEXT"},
      {"0x4", "LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED_WITH_NEW_EPS_SECURITY_CONTEXT"},
      {"0xC", "LIBLTE_MME_SECURITY_HDR_TYPE_SERVICE_REQUEST"},
      {"0x41", "LIBLTE_MME_MSG_TYPE_ATTACH_REQUEST"},
      {"0x42", "LIBLTE_MME_MSG_TYPE_ATTACH_ACCEPT"},
      {"0x43", "LIBLTE_MME_MSG_TYPE_ATTACH_COMPLETE"},
      {"0x44", "LIBLTE_MME_MSG_TYPE_ATTACH_REJECT"},
      {"0x45", "LIBLTE_MME_MSG_TYPE_DETACH_REQUEST"},
      {"0x46", "LIBLTE_MME_MSG_TYPE_DETACH_ACCEPT"},
      {"0x48", "LIBLTE_MME_MSG_TYPE_TRACKING_AREA_UPDATE_REQUEST"},
      {"0x49", "LIBLTE_MME_MSG_TYPE_TRACKING_AREA_UPDATE_ACCEPT"},
      {"0x4A", "LIBLTE_MME_MSG_TYPE_TRACKING_AREA_UPDATE_COMPLETE"},
      {"0x4B", "LIBLTE_MME_MSG_TYPE_TRACKING_AREA_UPDATE_REJECT"},
      {"0x4C", "LIBLTE_MME_MSG_TYPE_EXTENDED_SERVICE_REQUEST"},
      {"0x4E", "LIBLTE_MME_MSG_TYPE_SERVICE_REJECT"},
      {"0x50", "LIBLTE_MME_MSG_TYPE_GUTI_REALLOCATION_COMMAND"},
      {"0x51", "LIBLTE_MME_MSG_TYPE_GUTI_REALLOCATION_COMPLETE"},
      {"0x52", "LIBLTE_MME_MSG_TYPE_AUTHENTICATION_REQUEST"},
      {"0x53", "LIBLTE_MME_MSG_TYPE_AUTHENTICATION_RESPONSE"},
      {"0x54", "LIBLTE_MME_MSG_TYPE_AUTHENTICATION_REJECT"},
      {"0x5C", "LIBLTE_MME_MSG_TYPE_AUTHENTICATION_FAILURE"},
      {"0x55", "LIBLTE_MME_MSG_TYPE_IDENTITY_REQUEST"},
      {"0x56", "LIBLTE_MME_MSG_TYPE_IDENTITY_RESPONSE"},
      {"0x5D", "LIBLTE_MME_MSG_TYPE_SECURITY_MODE_COMMAND"},
      {"0x5E", "LIBLTE_MME_MSG_TYPE_SECURITY_MODE_COMPLETE"},
      {"0x5F", "LIBLTE_MME_MSG_TYPE_SECURITY_MODE_REJECT"},
      {"0x60", "LIBLTE_MME_MSG_TYPE_EMM_STATUS"},
      {"0x61", "LIBLTE_MME_MSG_TYPE_EMM_INFORMATION"},
      {"0x62", "LIBLTE_MME_MSG_TYPE_DOWNLINK_NAS_TRANSPORT"},
      {"0x63", "LIBLTE_MME_MSG_TYPE_UPLINK_NAS_TRANSPORT"},
      {"0x64", "LIBLTE_MME_MSG_TYPE_CS_SERVICE_NOTIFICATION"},
      {"0x68", "LIBLTE_MME_MSG_TYPE_DOWNLINK_GENERIC_NAS_TRANSPORT"},
      {"0x69", "LIBLTE_MME_MSG_TYPE_UPLINK_GENERIC_NAS_TRANSPORT"},
      {"0xC1", "LIBLTE_MME_MSG_TYPE_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST"},
      {"0xC2", "LIBLTE_MME_MSG_TYPE_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_ACCEPT"},
      {"0xC3", "LIBLTE_MME_MSG_TYPE_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REJECT"},
      {"0xC5", "LIBLTE_MME_MSG_TYPE_ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REQUEST"},
      {"0xC6", "LIBLTE_MME_MSG_TYPE_ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_ACCEPT"},
      {"0xC7", "LIBLTE_MME_MSG_TYPE_ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REJECT"},
      {"0xC9", "LIBLTE_MME_MSG_TYPE_MODIFY_EPS_BEARER_CONTEXT_REQUEST"},
      {"0xCA", "LIBLTE_MME_MSG_TYPE_MODIFY_EPS_BEARER_CONTEXT_ACCEPT"},
      {"0xCB", "LIBLTE_MME_MSG_TYPE_MODIFY_EPS_BEARER_CONTEXT_REJECT"},
      {"0xCD", "LIBLTE_MME_MSG_TYPE_DEACTIVATE_EPS_BEARER_CONTEXT_REQUEST"},
      {"0xCE", "LIBLTE_MME_MSG_TYPE_DEACTIVATE_EPS_BEARER_CONTEXT_ACCEPT"},
      {"0xD0", "LIBLTE_MME_MSG_TYPE_PDN_CONNECTIVITY_REQUEST"},
      {"0xD1", "LIBLTE_MME_MSG_TYPE_PDN_CONNECTIVITY_REJECT"},
      {"0xD2", "LIBLTE_MME_MSG_TYPE_PDN_DISCONNECT_REQUEST"},
      {"0xD3", "LIBLTE_MME_MSG_TYPE_PDN_DISCONNECT_REJECT"},
      {"0xD4", "LIBLTE_MME_MSG_TYPE_BEARER_RESOURCE_ALLOCATION_REQUEST"},
      {"0xD5", "LIBLTE_MME_MSG_TYPE_BEARER_RESOURCE_ALLOCATION_REJECT"},
      {"0xD6", "LIBLTE_MME_MSG_TYPE_BEARER_RESOURCE_MODIFICATION_REQUEST"},
      {"0xD7", "LIBLTE_MME_MSG_TYPE_BEARER_RESOURCE_MODIFICATION_REJECT"},
      {"0xD9", "LIBLTE_MME_MSG_TYPE_ESM_INFORMATION_REQUEST"},
      {"0xDA", "LIBLTE_MME_MSG_TYPE_ESM_INFORMATION_RESPONSE"},
      {"0xDB", "LIBLTE_MME_MSG_TYPE_NOTIFICATION"},
      {"0xE8", "LIBLTE_MME_MSG_TYPE_ESM_STATUS"}};

#define EMM_CAUSE_N 34
//   char emm_cause_str[35][2][100] = {
//       {"LIBLTE_MME_EMM_CAUSE_IMSI_UNKNOWN_IN_HSS", "0x02"},
//       {"LIBLTE_MME_EMM_CAUSE_ILLEGAL_UE", "0x03"},
//       {"LIBLTE_MME_EMM_CAUSE_IMEI_NOT_ACCEPTED", "0x05"},
//       {"LIBLTE_MME_EMM_CAUSE_ILLEGAL_ME", "0x06"},
//       {"LIBLTE_MME_EMM_CAUSE_EPS_SERVICES_NOT_ALLOWED", "0x07"},
//       {"LIBLTE_MME_EMM_CAUSE_EPS_SERVICES_AND_NON_EPS_SERVICES_NOT_ALLOWED", "0x08"},
//       {"LIBLTE_MME_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK", "0x09"},
//       {"LIBLTE_MME_EMM_CAUSE_IMPLICITLY_DETACHED", "0x0A"},
//       {"LIBLTE_MME_EMM_CAUSE_PLMN_NOT_ALLOWED", "0x0B"},
//       {"LIBLTE_MME_EMM_CAUSE_TRACKING_AREA_NOT_ALLOWED", "0x0C"},
//       {"LIBLTE_MME_EMM_CAUSE_ROAMING_NOT_ALLOWED_IN_THIS_TRACKING_AREA", "0x0D"},
//       {"LIBLTE_MME_EMM_CAUSE_EPS_SERVICES_NOT_ALLOWED_IN_THIS_PLMN", "0x0E"},
//       {"LIBLTE_MME_EMM_CAUSE_NO_SUITABLE_CELLS_IN_TRACKING_AREA", "0x0F"},
//       {"LIBLTE_MME_EMM_CAUSE_MSC_TEMPORARILY_NOT_REACHABLE", "0x10"},
//       {"LIBLTE_MME_EMM_CAUSE_NETWORK_FAILURE", "0x11"},
//       {"LIBLTE_MME_EMM_CAUSE_CS_DOMAIN_NOT_AVAILABLE", "0x12"},
//       {"LIBLTE_MME_EMM_CAUSE_ESM_FAILURE", "0x13"},
//       {"LIBLTE_MME_EMM_CAUSE_MAC_FAILURE", "0x14"},
//       {"LIBLTE_MME_EMM_CAUSE_SYNCH_FAILURE", "0x15"},
//       {"LIBLTE_MME_EMM_CAUSE_CONGESTION", "0x16"},
//       {"LIBLTE_MME_EMM_CAUSE_UE_SECURITY_CAPABILITIES_MISMATCH", "0x17"},
//       {"LIBLTE_MME_EMM_CAUSE_SECURITY_MODE_REJECTED_UNSPECIFIED", "0x18"},
//       {"LIBLTE_MME_EMM_CAUSE_NOT_AUTHORIZED_FOR_THIS_CSG", "0x19"},
//       {"LIBLTE_MME_EMM_CAUSE_NON_EPS_AUTHENTICATION_UNACCEPTABLE", "0x1A"},
//       {"LIBLTE_MME_EMM_CAUSE_CS_SERVICE_TEMPORARILY_NOT_AVAILABLE", "0x27"},
//       {"LIBLTE_MME_EMM_CAUSE_NO_EPS_BEARER_CONTEXT_ACTIVATED", "0x28"},
//       {"LIBLTE_MME_EMM_CAUSE_SEMANTICALLY_INCORRECT_MESSAGE", "0x5F"},
//       {"LIBLTE_MME_EMM_CAUSE_INVALID_MANDATORY_INFORMATION", "0x60"},
//       {"LIBLTE_MME_EMM_CAUSE_MESSAGE_TYPE_NON_EXISTENT_OR_NOT_IMPLEMENTED", "0x61"},
//       {"LIBLTE_MME_EMM_CAUSE_MESSAGE_TYPE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE", "0x62"},
//       {"LIBLTE_MME_EMM_CAUSE_INFORMATION_ELEMENT_NON_EXISTENT_OR_NOT_IMPLEMENTED", "0x63"},
//       {"LIBLTE_MME_EMM_CAUSE_CONDITIONAL_IE_ERROR", "0x64"},
//       {"LIBLTE_MME_EMM_CAUSE_MESSAGE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE", "0x65"},
//       {"LIBLTE_MME_EMM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED", "0x6F"}};
// };

  char emm_cause_str[35][2][100] = {
      {"IMSI_UNKNOWN_IN_HSS", "0x02"},
      {"ILLEGAL_UE", "0x03"},
      {"IMEI_NOT_ACCEPTED", "0x05"},
      {"ILLEGAL_ME", "0x06"},
      {"EPS_SERVICES_NOT_ALLOWED", "0x07"},
      {"EPS_SERVICES_AND_NON_EPS_SERVICES_NOT_ALLOWED", "0x08"},
      {"UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK", "0x09"},
      {"IMPLICITLY_DETACHED", "0x0A"},
      {"PLMN_NOT_ALLOWED", "0x0B"},
      {"TRACKING_AREA_NOT_ALLOWED", "0x0C"},
      {"ROAMING_NOT_ALLOWED_IN_THIS_TRACKING_AREA", "0x0D"},
      {"EPS_SERVICES_NOT_ALLOWED_IN_THIS_PLMN", "0x0E"},
      {"NO_SUITABLE_CELLS_IN_TRACKING_AREA", "0x0F"},
      {"MSC_TEMPORARILY_NOT_REACHABLE", "0x10"},
      {"NETWORK_FAILURE", "0x11"},
      {"CS_DOMAIN_NOT_AVAILABLE", "0x12"},
      {"ESM_FAILURE", "0x13"},
      {"MAC_FAILURE", "0x14"},
      {"SYNCH_FAILURE", "0x15"},
      {"CONGESTION", "0x16"},
      {"UE_SECURITY_CAPABILITIES_MISMATCH", "0x17"},
      {"SECURITY_MODE_REJECTED_UNSPECIFIED", "0x18"},
      {"NOT_AUTHORIZED_FOR_THIS_CSG", "0x19"},
      {"NON_EPS_AUTHENTICATION_UNACCEPTABLE", "0x1A"},
      {"CS_SERVICE_TEMPORARILY_NOT_AVAILABLE", "0x27"},
      {"NO_EPS_BEARER_CONTEXT_ACTIVATED", "0x28"},
      {"SEMANTICALLY_INCORRECT_MESSAGE", "0x5F"},
      {"INVALID_MANDATORY_INFORMATION", "0x60"},
      {"MESSAGE_TYPE_NON_EXISTENT_OR_NOT_IMPLEMENTED", "0x61"},
      {"MESSAGE_TYPE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE", "0x62"},
      {"INFORMATION_ELEMENT_NON_EXISTENT_OR_NOT_IMPLEMENTED", "0x63"},
      {"CONDITIONAL_IE_ERROR", "0x64"},
      {"MESSAGE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE", "0x65"},
      {"PROTOCOL_ERROR_UNSPECIFIED", "0x6F"}};
};

// Progress fields
#define TEST_STATE_STR "nas_test_state="
#define TEST_PROTOCOL_STR "nas_test_protocol="
#define TEST_MESSAGE_STR "nas_test_message="

#define EMM_CAUSE_IDX_STR "emm_cause_idx="
#define SEC_HDR_TYPE_IDX_STR "sec_hdr_type_idx="
#define ID_TYPE_IDX_STR "id_type_idx="
#define MAC_TYPE_IDX_STR "mac_type_idx="
#define START_DAY_STR "start_day="
#define START_HOUR_STR "start_hour="

#define CIPHER_ALGO_STR "cipher_algo="
#define INTEG_ALGO_STR "integ_algo="

#define TEST_LIMIT 6

} // namespace srsepc

#endif
