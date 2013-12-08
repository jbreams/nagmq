/* C code produced by gperf version 3.0.3 */
/* Command-line: /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/gperf -m 10000 -H hash_output_key -N in_output_word_set -C -r  */
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


#define TOTAL_KEYWORDS 245
#define MIN_WORD_LENGTH 3
#define MAX_WORD_LENGTH 36
#define MIN_HASH_VALUE 34
#define MAX_HASH_VALUE 719
/* maximum key range = 686, duplicates = 0 */

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
      720, 720, 720, 720, 720, 720, 720, 720, 720, 720,
      720, 720, 720, 720, 720, 720, 720, 720, 720, 720,
      720, 720, 720, 720, 720, 720, 720, 720, 720, 720,
      720, 720, 720, 720, 720, 720, 720, 720, 720, 720,
      720, 720, 720, 720, 720, 720, 720, 720, 720, 720,
       49,  12, 720, 720, 720, 720, 720, 720, 720, 720,
      720, 720, 720, 720, 720, 720, 720, 720, 720, 720,
      720, 720, 720, 720, 720, 720, 720, 720, 720, 720,
      720, 720, 720, 720, 720, 720, 720, 720, 720, 720,
      720, 720, 720, 720, 720,  22, 720,  14,  22,   8,
       59,   8, 221, 141, 112,  95, 720, 118,  32, 157,
        8, 119, 138, 720,   9,   9,  12, 205,  54,  77,
      140, 160,   9, 720, 720, 720, 720, 720, 720, 720,
      720, 720, 720, 720, 720, 720, 720, 720, 720, 720,
      720, 720, 720, 720, 720, 720, 720, 720, 720, 720,
      720, 720, 720, 720, 720, 720, 720, 720, 720, 720,
      720, 720, 720, 720, 720, 720, 720, 720, 720, 720,
      720, 720, 720, 720, 720, 720, 720, 720, 720, 720,
      720, 720, 720, 720, 720, 720, 720, 720, 720, 720,
      720, 720, 720, 720, 720, 720, 720, 720, 720, 720,
      720, 720, 720, 720, 720, 720, 720, 720, 720, 720,
      720, 720, 720, 720, 720, 720, 720, 720, 720, 720,
      720, 720, 720, 720, 720, 720, 720, 720, 720, 720,
      720, 720, 720, 720, 720, 720, 720, 720, 720, 720,
      720, 720, 720, 720, 720, 720, 720, 720, 720, 720,
      720, 720, 720, 720, 720, 720
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
      "", "", "", "", "", "", "",
      "notes",
      "",
      "state",
      "", "",
      "attr",
      "start",
      "contacts",
      "",
      "services",
      "", "", "", "", "", "", "", "",
      "exclusions",
      "", "",
      "exceptions",
      "tv_sec",
      "tv_usec",
      "",
      "email",
      "", "", "", "", "", "", "", "", "",
      "current_state",
      "execution_time",
      "",
      "state_str",
      "",
      "current_state_str",
      "",
      "author_name",
      "",
      "current_attempt",
      "",
      "last_state",
      "current_notification_number",
      "",
      "service_notification_options",
      "z_3d",
      "action_url",
      "retain_status_information",
      "accept_passive_checks",
      "",
      "no_more_notifications",
      "service_notification_options_int",
      "",
      "accept_passive_host_checks",
      "", "",
      "accept_passive_service_checks",
      "", "",
      "address",
      "stalk_on_unknown",
      "event_handler",
      "",
      "start_flex_downtime",
      "stalk_on_unreachable",
      "",
      "check_interval",
      "",
      "last_state_str",
      "",
      "last_state_change",
      "retry_interval",
      "", "", "", "",
      "notes_url",
      "current_event_id",
      "last_state_history_update",
      "",
      "last_time_critical",
      "",
      "service_description",
      "",
      "alias",
      "",
      "stalk_on_critical",
      "",
      "current_notification_id",
      "checks_enabled",
      "end",
      "", "",
      "service_notification_period",
      "",
      "service_notifications_enabled",
      "hosts",
      "", "", "", "", "", "",
      "last_time_down",
      "recipients",
      "",
      "last_service_notification",
      "", "", "", "", "",
      "last_event_id",
      "obsess",
      "",
      "host_name",
      "", "",
      "escalated",
      "event_handler_enabled",
      "event_handlers_enabled",
      "",
      "output",
      "type",
      "child_hosts",
      "notified_on",
      "circular_path_checked",
      "", "",
      "ack_data",
      "notified_on_down",
      "expires",
      "",
      "notified_on_unknown",
      "", "",
      "return_code",
      "notified_on_unreachable",
      "name",
      "end_time",
      "duration",
      "", "",
      "check_freshness",
      "",
      "active_service_checks_enabled",
      "last_check",
      "persistent",
      "", "", "", "",
      "check_options",
      "",
      "retain_nonstatus_information",
      "check_type",
      "", "",
      "notified_on_critical",
      "entry_type",
      "percent_change",
      "",
      "state_type",
      "",
      "last_host_notification",
      "", "",
      "percent_state_change",
      "stalk_on_down",
      "", "",
      "total_service_check_interval",
      "", "", "",
      "reschedule_check",
      "x_3d",
      "persistent_comment",
      "entry_time",
      "",
      "latency",
      "start_time",
      "daemon_mode",
      "", "", "", "",
      "obsess_over_hosts",
      "obsess_over_service",
      "obsess_over_host",
      "obsess_over_services",
      "notify_on_service_unknown",
      "notify_on_service_downtime",
      "in_host_notification_period",
      "command_line",
      "check_flapping_recovery_notification",
      "y_3d",
      "source",
      "check_period",
      "stalk_on_warning",
      "last_log_rotation",
      "",
      "contacts_notified",
      "",
      "perf_data",
      "last_hard_state",
      "in_service_notification_period",
      "notify_on_critical",
      "",
      "initial_state",
      "last_hard_state_str",
      "active_host_checks_enabled",
      "last_hard_state_change",
      "x_2d",
      "", "",
      "notify_on_service_critical",
      "",
      "next_service_notification_time",
      "",
      "pid",
      "contactgroups",
      "",
      "servicegroups",
      "",
      "last_notification",
      "", "",
      "display_name",
      "",
      "notify_on_down",
      "comment_data",
      "is_volatile",
      "y_2d",
      "notify_on_downtime",
      "",
      "notification_options",
      "expire_time",
      "should_be_drawn",
      "", "", "",
      "check_command",
      "should_be_scheduled",
      "last_problem_id",
      "", "", "",
      "hostgroups",
      "statusmap_image",
      "", "",
      "last_time_unknown",
      "next_check",
      "pager",
      "",
      "last_time_unreachable",
      "last_time_warning",
      "",
      "is_executing",
      "notification_interval",
      "",
      "parallelize",
      "",
      "stalking_options",
      "acknowledgement_type",
      "notified_on_warning",
      "skip_interval",
      "contact_groups",
      "passive_service_checks_enabled",
      "",
      "last_time_ok",
      "parent_hosts",
      "", "",
      "stalk_on_ok",
      "next_host_notification_time",
      "", "", "",
      "program_start",
      "is_being_freshened",
      "", "", "",
      "notification_period",
      "",
      "notifications_enabled",
      "notify_on_host_down",
      "have_3d_coords",
      "", "",
      "notify_on_host_downtime",
      "long_output",
      "",
      "notify_on_host_unreachable",
      "notify_contacts",
      "freshness_threshold",
      "comment_id",
      "has_been_checked",
      "members",
      "early_timeout",
      "timeperiod_name",
      "next_valid_time",
      "",
      "flap_detection_on_down",
      "flap_detection_options",
      "state_history",
      "flap_detection_on_unknown",
      "",
      "command_args",
      "last_command_check",
      "flap_detection_on_unreachable",
      "low_flap_threshold",
      "host_notification_options",
      "stalk_on_up",
      "", "",
      "long_plugin_output",
      "command_name",
      "current_problem_id",
      "host_notification_options_int",
      "",
      "contains_circular_path",
      "notify_on_service_warning",
      "notify_on_service_flapping",
      "have_2d_coords",
      "can_submit_commands",
      "incremented_pending_downtime",
      "triggered_by",
      "", "",
      "next_notification",
      "flap_detection_on_critical",
      "modified_attributes",
      "",
      "notify_on_recovery",
      "",
      "modified_service_attributes",
      "", "", "", "",
      "downtime_id",
      "notify_on_service_recovery",
      "", "", "", "", "", "", "", "",
      "is_in_effect",
      "timeout",
      "",
      "flap_detection_enabled",
      "", "", "", "", "", "",
      "host_notification_period",
      "",
      "host_notifications_enabled",
      "", "", "",
      "passive_host_checks_enabled",
      "", "", "",
      "pending_flex_downtime",
      "", "", "",
      "last_time_up",
      "",
      "notify_on_unknown",
      "", "",
      "low_threshold",
      "notify_on_unreachable",
      "notify_on_warning",
      "",
      "fixed",
      "", "", "", "", "", "", "",
      "host_problem_at_last_check",
      "", "", "", "", "", "", "", "",
      "msg",
      "", "", "", "", "", "",
      "in_timeperiod",
      "",
      "process_performance_data",
      "flap_detection_on_ok",
      "", "", "", "",
      "group_name",
      "high_threshold",
      "", "", "", "", "",
      "notify_on_host_flapping",
      "vrml_image",
      "timestamp",
      "",
      "icon_image",
      "", "", "",
      "flap_detection_on_up",
      "",
      "problem_has_been_acknowledged",
      "ack_author",
      "", "", "", "",
      "flap_detection_on_warning",
      "", "",
      "notify_on_host_recovery",
      "",
      "modified_host_attributes",
      "", "", "", "", "", "", "", "", "",
      "", "", "",
      "icon_image_alt",
      "max_attempts",
      "", "", "", "", "", "",
      "failure_prediction_options",
      "", "", "", "", "", "", "", "", "",
      "", "", "",
      "is_flapping",
      "", "", "", "", "", "",
      "scheduled_check",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "",
      "is_sticky",
      "", "", "", "", "", "", "",
      "flapping_comment_id",
      "", "", "", "", "", "",
      "failure_prediction_enabled",
      "", "", "", "", "", "", "", "", "",
      "", "",
      "notify_on_flapping",
      "", "", "", "", "", "", "", "", "",
      "", "",
      "scheduled_downtime_depth",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "",
      "first_notification_delay",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "",
      "high_flap_threshold",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "",
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
