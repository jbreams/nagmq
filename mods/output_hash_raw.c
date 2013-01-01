/* C code produced by gperf version 3.0.3 */
/* Command-line: gperf -m 10000 -H hash_output_key -N in_output_word_set -C -r  */
/* Computed positions: -k'1,3,6,9,11,$' */

#if !((' ' == 32) && ('!' == 33) && ('"' == 34) && ('#' == 35) \
      && ('%' == 37) && ('&' == 38) && ('\'' == 39) && ('(' == 40) \
      && (')' == 41) && ('*' == 42) && ('+' == 43) && (',' == 44) \
      && ('-' == 45) && ('.' == 46) && ('/' == 47) && ('0' == 48) \
      && ('1' == 49) && ('2' == 50) && ('3' == 51) && ('4' == 52) \
      && ('5' == 53) && ('6' == 54) && ('7' == 55) && ('8' == 56) \
      && ('9' == 57) && (':' == 58) && (';' == 59) && ('<' == 60) \
      && ('=' == 61) && ('>' == 62) && ('?' == 63) && ('A' == 65) \
      && ('B' == 66) && ('C' == 67) && ('D' == 68) && ('E' == 69) \
      && ('F' == 70) && ('G' == 71) && ('H' == 72) && ('I' == 73) \
      && ('J' == 74) && ('K' == 75) && ('L' == 76) && ('M' == 77) \
      && ('N' == 78) && ('O' == 79) && ('P' == 80) && ('Q' == 81) \
      && ('R' == 82) && ('S' == 83) && ('T' == 84) && ('U' == 85) \
      && ('V' == 86) && ('W' == 87) && ('X' == 88) && ('Y' == 89) \
      && ('Z' == 90) && ('[' == 91) && ('\\' == 92) && (']' == 93) \
      && ('^' == 94) && ('_' == 95) && ('a' == 97) && ('b' == 98) \
      && ('c' == 99) && ('d' == 100) && ('e' == 101) && ('f' == 102) \
      && ('g' == 103) && ('h' == 104) && ('i' == 105) && ('j' == 106) \
      && ('k' == 107) && ('l' == 108) && ('m' == 109) && ('n' == 110) \
      && ('o' == 111) && ('p' == 112) && ('q' == 113) && ('r' == 114) \
      && ('s' == 115) && ('t' == 116) && ('u' == 117) && ('v' == 118) \
      && ('w' == 119) && ('x' == 120) && ('y' == 121) && ('z' == 122) \
      && ('{' == 123) && ('|' == 124) && ('}' == 125) && ('~' == 126))
/* The character set is not based on ISO-646.  */
error "gperf generated tables don't work with this execution character set. Please report a bug to <bug-gnu-gperf@gnu.org>."
#endif


#define TOTAL_KEYWORDS 237
#define MIN_WORD_LENGTH 3
#define MAX_WORD_LENGTH 36
#define MIN_HASH_VALUE 18
#define MAX_HASH_VALUE 614
/* maximum key range = 597, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
hash_output_key (str, len)
     register const char *str;
     register unsigned int len;
{
  static const unsigned short asso_values[] =
    {
      615, 615, 615, 615, 615, 615, 615, 615, 615, 615,
      615, 615, 615, 615, 615, 615, 615, 615, 615, 615,
      615, 615, 615, 615, 615, 615, 615, 615, 615, 615,
      615, 615, 615, 615, 615, 615, 615, 615, 615, 615,
      615, 615, 615, 615, 615, 615, 615, 615, 615, 615,
       12,  11, 615, 615, 615, 615, 615, 615, 615, 615,
      615, 615, 615, 615, 615, 615, 615, 615, 615, 615,
      615, 615, 615, 615, 615, 615, 615, 615, 615, 615,
      615, 615, 615, 615, 615, 615, 615, 615, 615, 615,
      615, 615, 615, 615, 615,  15, 615,   5,  18,   7,
       48,   4, 145, 112, 166,  60, 615, 173,  22, 129,
        4,  71, 118, 615,   8,   4,   6, 131, 143,  53,
      117, 184,   6, 615, 615, 615, 615, 615, 615, 615,
      615, 615, 615, 615, 615, 615, 615, 615, 615, 615,
      615, 615, 615, 615, 615, 615, 615, 615, 615, 615,
      615, 615, 615, 615, 615, 615, 615, 615, 615, 615,
      615, 615, 615, 615, 615, 615, 615, 615, 615, 615,
      615, 615, 615, 615, 615, 615, 615, 615, 615, 615,
      615, 615, 615, 615, 615, 615, 615, 615, 615, 615,
      615, 615, 615, 615, 615, 615, 615, 615, 615, 615,
      615, 615, 615, 615, 615, 615, 615, 615, 615, 615,
      615, 615, 615, 615, 615, 615, 615, 615, 615, 615,
      615, 615, 615, 615, 615, 615, 615, 615, 615, 615,
      615, 615, 615, 615, 615, 615, 615, 615, 615, 615,
      615, 615, 615, 615, 615, 615, 615, 615, 615, 615,
      615, 615, 615, 615, 615, 615
    };
  register int hval = (int)len;

  switch (hval)
    {
      default:
        hval += asso_values[(unsigned char)str[10]];
      /*FALLTHROUGH*/
      case 10:
      case 9:
        hval += asso_values[(unsigned char)str[8]];
      /*FALLTHROUGH*/
      case 8:
      case 7:
      case 6:
        hval += asso_values[(unsigned char)str[5]];
      /*FALLTHROUGH*/
      case 5:
      case 4:
      case 3:
        hval += asso_values[(unsigned char)str[2]];
      /*FALLTHROUGH*/
      case 2:
      case 1:
        hval += asso_values[(unsigned char)str[0]];
        break;
    }
  return hval + asso_values[(unsigned char)str[len - 1]];
}

#ifdef __GNUC__
__inline
#ifdef __GNUC_STDC_INLINE__
__attribute__ ((__gnu_inline__))
#endif
#endif
const char *
in_output_word_set (str, len)
     register const char *str;
     register unsigned int len;
{
  static const char * const wordlist[] =
    {
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "state",
      "notes",
      "start",
      "", "",
      "attr",
      "", "", "", "", "", "",
      "contacts",
      "services",
      "",
      "exclusions",
      "",
      "exceptions",
      "email",
      "", "",
      "tv_usec",
      "",
      "tv_sec",
      "execution_time",
      "author_name",
      "",
      "current_state",
      "", "", "",
      "state_str",
      "last_state",
      "current_attempt",
      "accept_passive_checks",
      "current_state_str",
      "",
      "action_url",
      "",
      "accept_passive_host_checks",
      "",
      "retain_status_information",
      "accept_passive_service_checks",
      "service_notification_options",
      "no_more_notifications",
      "stalk_on_unknown",
      "current_notification_number",
      "",
      "start_flex_downtime",
      "stalk_on_unreachable",
      "address",
      "z_3d",
      "event_handler",
      "",
      "last_state_change",
      "last_state_str",
      "alias",
      "",
      "check_interval",
      "",
      "notes_url",
      "retry_interval",
      "last_state_history_update",
      "", "",
      "last_time_critical",
      "", "",
      "stalk_on_critical",
      "", "", "", "",
      "current_event_id",
      "", "",
      "service_description",
      "output",
      "", "", "",
      "checks_enabled",
      "current_notification_id",
      "",
      "last_time_down",
      "end",
      "service_notification_period",
      "child_hosts",
      "service_notifications_enabled",
      "",
      "return_code",
      "notified_on_down",
      "last_event_id",
      "",
      "notified_on_unknown",
      "", "", "",
      "notified_on_unreachable",
      "",
      "event_handler_enabled",
      "event_handlers_enabled",
      "check_options",
      "escalated",
      "", "",
      "end_time",
      "retain_nonstatus_information",
      "circular_path_checked",
      "stalk_on_down",
      "duration",
      "", "",
      "notified_on_critical",
      "type",
      "", "", "", "",
      "expires",
      "", "", "",
      "name",
      "", "", "",
      "total_service_check_interval",
      "daemon_mode",
      "", "",
      "source",
      "persistent",
      "initial_state",
      "", "", "",
      "last_log_rotation",
      "state_type",
      "entry_type",
      "check_type",
      "",
      "percent_change",
      "", "",
      "percent_state_change",
      "in_host_notification_period",
      "check_period",
      "active_host_checks_enabled",
      "start_time",
      "entry_time",
      "contacts_notified",
      "",
      "last_notification",
      "stalk_on_warning",
      "persistent_comment",
      "contactgroups",
      "servicegroups",
      "is_volatile",
      "", "",
      "hosts",
      "x_3d",
      "x_2d",
      "command_line",
      "in_service_notification_period",
      "", "", "", "",
      "last_time_unknown",
      "check_flapping_recovery_notification",
      "notification_interval",
      "host_name",
      "last_time_unreachable",
      "perf_data",
      "should_be_drawn",
      "",
      "ack_data",
      "",
      "should_be_scheduled",
      "", "", "", "", "", "",
      "expire_time",
      "display_name",
      "", "",
      "last_service_notification",
      "statusmap_image",
      "comment_data",
      "",
      "is_executing",
      "notification_period",
      "check_freshness",
      "notifications_enabled",
      "pid",
      "last_time_warning",
      "contact_groups",
      "notified_on_warning",
      "check_command",
      "program_start",
      "last_check",
      "is_being_freshened",
      "parent_hosts",
      "latency",
      "parallelize",
      "last_host_notification",
      "last_problem_id",
      "freshness_threshold",
      "notify_on_service_unknown",
      "notify_on_service_downtime",
      "",
      "flap_detection_on_down",
      "", "",
      "flap_detection_on_unknown",
      "long_output",
      "active_service_checks_enabled",
      "can_submit_commands",
      "flap_detection_on_unreachable",
      "reschedule_check",
      "pager",
      "timeperiod_name",
      "notify_on_critical",
      "early_timeout",
      "y_3d",
      "y_2d",
      "",
      "notify_on_service_critical",
      "obsess_over_hosts",
      "obsess_over_host",
      "obsess_over_service",
      "obsess_over_services",
      "",
      "flap_detection_on_critical",
      "",
      "comment_id",
      "",
      "is_in_effect",
      "", "",
      "last_hard_state",
      "notify_on_down",
      "",
      "next_notification",
      "",
      "notify_on_downtime",
      "",
      "last_hard_state_change",
      "last_hard_state_str",
      "",
      "command_args",
      "current_problem_id",
      "", "",
      "members",
      "flap_detection_enabled",
      "timeout",
      "",
      "modified_attributes",
      "incremented_pending_downtime",
      "downtime_id",
      "long_plugin_output",
      "",
      "stalk_on_up",
      "modified_service_attributes",
      "",
      "command_name",
      "notify_contacts",
      "",
      "last_time_ok",
      "", "", "",
      "state_history",
      "last_time_up",
      "", "",
      "pending_flex_downtime",
      "", "", "", "", "",
      "skip_interval",
      "acknowledgement_type",
      "",
      "next_service_notification_time",
      "hostgroups",
      "", "", "", "",
      "fixed",
      "",
      "icon_image",
      "next_check",
      "", "", "", "",
      "host_notification_options",
      "", "", "", "",
      "next_host_notification_time",
      "in_timeperiod",
      "", "",
      "triggered_by",
      "",
      "contains_circular_path",
      "", "", "",
      "icon_image_alt",
      "notify_on_service_warning",
      "notify_on_service_flapping",
      "group_name",
      "", "",
      "low_flap_threshold",
      "flap_detection_on_warning",
      "flap_detection_on_up",
      "",
      "process_performance_data",
      "",
      "notify_on_unknown",
      "modified_host_attributes",
      "", "",
      "notify_on_unreachable",
      "passive_service_checks_enabled",
      "msg",
      "last_command_check",
      "next_valid_time",
      "", "", "", "",
      "flapping_comment_id",
      "",
      "failure_prediction_options",
      "host_notification_period",
      "",
      "host_notifications_enabled",
      "", "", "", "", "", "",
      "is_flapping",
      "",
      "low_threshold",
      "", "",
      "notify_on_warning",
      "", "", "", "", "",
      "timestamp",
      "notify_on_host_down",
      "", "", "",
      "notify_on_host_downtime",
      "", "",
      "notify_on_host_unreachable",
      "",
      "stalk_on_ok",
      "",
      "ack_author",
      "", "",
      "flap_detection_on_ok",
      "",
      "max_attempts",
      "", "", "", "",
      "notify_on_recovery",
      "failure_prediction_enabled",
      "", "",
      "notify_on_service_recovery",
      "", "", "",
      "have_3d_coords",
      "have_2d_coords",
      "",
      "has_been_checked",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "",
      "problem_has_been_acknowledged",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "",
      "vrml_image",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "",
      "notify_on_flapping",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "",
      "notify_on_host_flapping",
      "", "", "", "", "", "", "", "", "",
      "host_problem_at_last_check",
      "passive_host_checks_enabled",
      "",
      "is_sticky",
      "", "", "",
      "high_threshold",
      "", "", "", "",
      "plugin_output",
      "", "", "", "", "",
      "first_notification_delay",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "",
      "scheduled_check",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "",
      "notify_on_host_recovery",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "",
      "scheduled_downtime_depth",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "",
      "high_flap_threshold"
    };

  if (len <= MAX_WORD_LENGTH && len >= MIN_WORD_LENGTH)
    {
      register int key = hash_output_key (str, len);

      if (key <= MAX_HASH_VALUE && key >= 0)
        {
          register const char *s = wordlist[key];

          if (*str == *s && !strcmp (str + 1, s + 1))
            return s;
        }
    }
  return 0;
}
