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


#define TOTAL_KEYWORDS 252
#define MIN_WORD_LENGTH 3
#define MAX_WORD_LENGTH 36
#define MIN_HASH_VALUE 28
#define MAX_HASH_VALUE 731
/* maximum key range = 704, duplicates = 0 */

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
      732, 732, 732, 732, 732, 732, 732, 732, 732, 732,
      732, 732, 732, 732, 732, 732, 732, 732, 732, 732,
      732, 732, 732, 732, 732, 732, 732, 732, 732, 732,
      732, 732, 732, 732, 732, 732, 732, 732, 732, 732,
      732, 732, 732, 732, 732, 732, 732, 732, 732, 732,
       11,   6, 732, 732, 732, 732, 732, 732, 732, 732,
      732, 732, 732, 732, 732, 732, 732, 732, 732, 732,
      732, 732, 732, 732, 732, 732, 732, 732, 732, 732,
      732, 732, 732, 732, 732, 732, 732, 732, 732, 732,
      732, 732, 732, 732, 732,  34, 732,  13,  10,  16,
       63,   6, 108, 179, 133,  64, 732, 214,  21, 156,
        6, 147, 128,   6,  10,   7,  10, 223, 198,  69,
      164, 195,   8, 732, 732, 732, 732, 732, 732, 732,
      732, 732, 732, 732, 732, 732, 732, 732, 732, 732,
      732, 732, 732, 732, 732, 732, 732, 732, 732, 732,
      732, 732, 732, 732, 732, 732, 732, 732, 732, 732,
      732, 732, 732, 732, 732, 732, 732, 732, 732, 732,
      732, 732, 732, 732, 732, 732, 732, 732, 732, 732,
      732, 732, 732, 732, 732, 732, 732, 732, 732, 732,
      732, 732, 732, 732, 732, 732, 732, 732, 732, 732,
      732, 732, 732, 732, 732, 732, 732, 732, 732, 732,
      732, 732, 732, 732, 732, 732, 732, 732, 732, 732,
      732, 732, 732, 732, 732, 732, 732, 732, 732, 732,
      732, 732, 732, 732, 732, 732, 732, 732, 732, 732,
      732, 732, 732, 732, 732, 732, 732, 732, 732, 732,
      732, 732, 732, 732, 732, 732
    };
  register int hval = len;

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
      "", "", "", "", "", "", "", "", "",
      "",
      "notes",
      "", "",
      "state",
      "",
      "sequence",
      "extra",
      "start",
      "",
      "attr",
      "", "", "", "", "", "", "",
      "email",
      "", "",
      "services",
      "", "", "",
      "exclusions",
      "contacts",
      "",
      "exceptions",
      "", "",
      "execution_time",
      "", "",
      "last_state",
      "", "", "", "", "", "", "",
      "author_name",
      "action_url",
      "current_state",
      "",
      "tv_usec",
      "", "", "",
      "retain_status_information",
      "",
      "current_state_str",
      "current_attempt",
      "z_3d",
      "tv_sec",
      "state_str",
      "service_notification_options",
      "current_notification_number",
      "",
      "accept_passive_checks",
      "",
      "alias",
      "",
      "service_notification_options_int",
      "accept_passive_host_checks",
      "",
      "no_more_notifications",
      "accept_passive_service_checks",
      "event_handler",
      "address",
      "",
      "last_time_critical",
      "",
      "notes_url",
      "last_state_change",
      "last_state_str",
      "children",
      "", "", "", "",
      "retry_interval",
      "last_state_history_update",
      "check_interval",
      "", "", "", "",
      "stalk_on_unknown",
      "recipients",
      "",
      "start_flex_downtime",
      "stalk_on_unreachable",
      "",
      "checks_enabled",
      "current_event_id",
      "", "", "",
      "last_time_down",
      "service_description",
      "", "", "", "", "",
      "current_notification_id",
      "end",
      "stalk_on_critical",
      "notified_on",
      "",
      "service_notification_period",
      "",
      "service_notifications_enabled",
      "notified_on_down",
      "", "",
      "notified_on_unknown",
      "child_hosts",
      "end_time",
      "type",
      "notified_on_unreachable",
      "last_event_id",
      "duration",
      "hosts",
      "",
      "expires",
      "", "",
      "event_handler_enabled",
      "event_handlers_enabled",
      "", "",
      "notified_on_critical",
      "parents",
      "", "", "", "",
      "host_name",
      "", "",
      "escalated",
      "persistent",
      "name",
      "",
      "obsess",
      "", "",
      "total_service_check_interval",
      "circular_path_checked",
      "",
      "initial_state",
      "", "",
      "output",
      "",
      "last_notification",
      "", "", "", "",
      "percent_state_change",
      "", "",
      "percent_change",
      "entry_type",
      "",
      "return_code",
      "",
      "state_type",
      "",
      "check_type",
      "", "", "", "",
      "last_host_notification",
      "is_volatile",
      "", "", "", "",
      "in_host_notification_period",
      "",
      "persistent_comment",
      "retain_nonstatus_information",
      "", "",
      "check_freshness",
      "",
      "freshness_threshold",
      "", "",
      "entry_time",
      "command_line",
      "", "",
      "start_time",
      "expire_time",
      "flap_detection_on_down",
      "flap_detection_options",
      "",
      "flap_detection_on_unknown",
      "",
      "check_options",
      "",
      "flap_detection_on_unreachable",
      "perf_data",
      "x_3d",
      "",
      "check_flapping_recovery_notification",
      "statusmap_image",
      "",
      "x_2d",
      "", "",
      "daemon_mode",
      "parallelize",
      "flap_detection_on_critical",
      "source",
      "latency",
      "last_problem_id",
      "in_service_notification_period",
      "last_hard_state",
      "last_log_rotation",
      "stalk_on_down",
      "notify_on_service_unknown",
      "notify_on_service_downtime",
      "pid",
      "",
      "last_hard_state_change",
      "last_hard_state_str",
      "ack_data",
      "",
      "display_name",
      "notification_options",
      "", "", "",
      "y_3d",
      "stalking_options",
      "",
      "notify_on_service_critical",
      "notify_on_critical",
      "y_2d",
      "",
      "active_host_checks_enabled",
      "comment_data",
      "",
      "is_in_effect",
      "notification_interval",
      "last_service_notification",
      "pending_flex_downtime",
      "", "",
      "last_check",
      "flap_detection_enabled",
      "servicegroups",
      "is_being_freshened",
      "check_period",
      "",
      "last_time_unknown",
      "contactgroups",
      "", "",
      "last_time_unreachable",
      "hostgroups",
      "stalk_on_warning",
      "", "",
      "contacts_notified",
      "notify_on_down",
      "check_command",
      "", "",
      "notify_on_downtime",
      "",
      "host_notification_options",
      "should_be_drawn",
      "reschedule_check",
      "last_time_warning",
      "",
      "is_executing",
      "should_be_scheduled",
      "host_notification_options_int",
      "",
      "comment_id",
      "", "",
      "notified_on_warning",
      "notification_period",
      "",
      "notifications_enabled",
      "pager",
      "",
      "parent_hosts",
      "active_service_checks_enabled",
      "",
      "next_notification",
      "", "", "",
      "program_start",
      "",
      "long_output",
      "", "",
      "members",
      "", "",
      "contains_circular_path",
      "fixed",
      "", "",
      "incremented_pending_downtime",
      "", "", "", "",
      "flap_detection_on_up",
      "failure_prediction_options",
      "", "",
      "next_host_notification_time",
      "modified_attributes",
      "pong_target",
      "stalk_on_up",
      "",
      "modified_service_attributes",
      "command_name",
      "low_flap_threshold",
      "triggered_by",
      "host_notification_period",
      "",
      "host_notifications_enabled",
      "", "", "",
      "downtime_id",
      "long_plugin_output",
      "can_submit_commands",
      "", "", "",
      "skip_interval",
      "timeperiod_name",
      "notify_on_host_down",
      "early_timeout",
      "", "",
      "notify_on_host_downtime",
      "", "",
      "notify_on_host_unreachable",
      "", "",
      "contact_groups",
      "", "",
      "current_problem_id",
      "command_args",
      "notify_contacts",
      "acknowledgement_type",
      "has_been_checked",
      "obsess_over_hosts",
      "obsess_over_service",
      "obsess_over_host",
      "obsess_over_services",
      "", "", "",
      "in_timeperiod",
      "", "", "",
      "flap_detection_on_warning",
      "failure_prediction_enabled",
      "timeout",
      "last_time_up",
      "", "", "", "", "", "", "", "",
      "state_history",
      "last_time_ok",
      "", "", "", "", "", "", "", "",
      "next_check",
      "next_service_notification_time",
      "notify_on_service_warning",
      "notify_on_service_flapping",
      "", "", "", "",
      "flap_detection_on_ok",
      "", "", "",
      "last_command_check",
      "",
      "notify_on_recovery",
      "timestamp",
      "",
      "passive_service_checks_enabled",
      "",
      "notify_on_service_recovery",
      "", "",
      "flapping_comment_id",
      "", "", "", "",
      "low_threshold",
      "", "", "",
      "process_performance_data",
      "", "", "", "", "",
      "notify_on_unknown",
      "", "", "",
      "notify_on_unreachable",
      "", "",
      "icon_image",
      "", "", "", "", "", "", "", "", "",
      "", "",
      "notify_on_warning",
      "", "", "", "",
      "next_valid_time",
      "",
      "first_notification_delay",
      "", "", "", "", "",
      "modified_host_attributes",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "",
      "icon_image_alt",
      "problem_has_been_acknowledged",
      "",
      "max_attempts",
      "",
      "msg",
      "", "", "",
      "have_3d_coords",
      "notify_on_flapping",
      "",
      "host_problem_at_last_check",
      "",
      "have_2d_coords",
      "stalk_on_ok",
      "", "", "", "",
      "group_name",
      "", "", "", "", "",
      "high_threshold",
      "global_host_event_handler",
      "", "", "", "",
      "is_flapping",
      "", "", "", "", "", "", "",
      "notify_on_host_flapping",
      "", "", "", "", "", "", "", "",
      "is_sticky",
      "",
      "passive_host_checks_enabled",
      "", "", "", "",
      "notify_on_host_recovery",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "",
      "global_service_event_handler",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "",
      "vrml_image",
      "", "", "",
      "ack_author",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "",
      "high_flap_threshold",
      "", "", "", "", "",
      "scheduled_downtime_depth",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "",
      "scheduled_check",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "",
      "plugin_output"
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
