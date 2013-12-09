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


#define TOTAL_KEYWORDS 247
#define MIN_WORD_LENGTH 3
#define MAX_WORD_LENGTH 36
#define MIN_HASH_VALUE 16
#define MAX_HASH_VALUE 736
/* maximum key range = 721, duplicates = 0 */

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
      737, 737, 737, 737, 737, 737, 737, 737, 737, 737,
      737, 737, 737, 737, 737, 737, 737, 737, 737, 737,
      737, 737, 737, 737, 737, 737, 737, 737, 737, 737,
      737, 737, 737, 737, 737, 737, 737, 737, 737, 737,
      737, 737, 737, 737, 737, 737, 737, 737, 737, 737,
       16,  10, 737, 737, 737, 737, 737, 737, 737, 737,
      737, 737, 737, 737, 737, 737, 737, 737, 737, 737,
      737, 737, 737, 737, 737, 737, 737, 737, 737, 737,
      737, 737, 737, 737, 737, 737, 737, 737, 737, 737,
      737, 737, 737, 737, 737,  36, 737,   8,   5,  12,
       98,   2, 124, 214, 175,  62, 737, 175,   9, 166,
        2, 154,  86, 737,   3,   3,   6, 163,  64,  21,
      143, 183,   2, 737, 737, 737, 737, 737, 737, 737,
      737, 737, 737, 737, 737, 737, 737, 737, 737, 737,
      737, 737, 737, 737, 737, 737, 737, 737, 737, 737,
      737, 737, 737, 737, 737, 737, 737, 737, 737, 737,
      737, 737, 737, 737, 737, 737, 737, 737, 737, 737,
      737, 737, 737, 737, 737, 737, 737, 737, 737, 737,
      737, 737, 737, 737, 737, 737, 737, 737, 737, 737,
      737, 737, 737, 737, 737, 737, 737, 737, 737, 737,
      737, 737, 737, 737, 737, 737, 737, 737, 737, 737,
      737, 737, 737, 737, 737, 737, 737, 737, 737, 737,
      737, 737, 737, 737, 737, 737, 737, 737, 737, 737,
      737, 737, 737, 737, 737, 737, 737, 737, 737, 737,
      737, 737, 737, 737, 737, 737, 737, 737, 737, 737,
      737, 737, 737, 737, 737, 737
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
      "", "", "", "", "", "", "",
      "notes",
      "",
      "state",
      "", "",
      "attr",
      "start",
      "",
      "email",
      "", "", "", "",
      "services",
      "", "",
      "exclusions",
      "last_state",
      "execution_time",
      "exceptions",
      "",
      "contacts",
      "action_url",
      "",
      "author_name",
      "", "",
      "current_state",
      "", "", "", "",
      "current_state_str",
      "",
      "retain_status_information",
      "",
      "current_attempt",
      "", "",
      "current_notification_number",
      "",
      "service_notification_options",
      "",
      "last_time_critical",
      "",
      "accept_passive_checks",
      "state_str",
      "tv_usec",
      "service_notification_options_int",
      "",
      "accept_passive_host_checks",
      "event_handler",
      "",
      "accept_passive_service_checks",
      "",
      "notes_url",
      "tv_sec",
      "no_more_notifications",
      "last_state_str",
      "",
      "last_state_change",
      "retry_interval",
      "alias",
      "", "", "",
      "check_interval",
      "",
      "last_state_history_update",
      "", "",
      "children",
      "", "", "", "", "", "", "", "",
      "recipients",
      "",
      "type",
      "",
      "expires",
      "", "",
      "stalk_on_unknown",
      "",
      "parents",
      "start_flex_downtime",
      "stalk_on_unreachable",
      "", "",
      "persistent",
      "",
      "stalk_on_critical",
      "",
      "z_3d",
      "", "", "",
      "last_service_notification",
      "address",
      "",
      "notified_on",
      "", "",
      "percent_state_change",
      "",
      "notified_on_down",
      "percent_change",
      "",
      "notified_on_unknown",
      "child_hosts",
      "", "",
      "notified_on_unreachable",
      "last_time_down",
      "current_event_id",
      "checks_enabled",
      "notified_on_critical",
      "", "",
      "service_description",
      "",
      "entry_type",
      "", "",
      "state_type",
      "current_notification_id",
      "",
      "check_type",
      "",
      "total_service_check_interval",
      "service_notification_period",
      "",
      "service_notifications_enabled",
      "persistent_comment",
      "", "",
      "last_notification",
      "initial_state",
      "", "", "", "",
      "last_event_id",
      "", "", "",
      "expire_time",
      "",
      "obsess",
      "event_handler_enabled",
      "event_handlers_enabled",
      "end_time",
      "duration",
      "name",
      "parallelize",
      "source",
      "",
      "output",
      "statusmap_image",
      "return_code",
      "",
      "check_flapping_recovery_notification",
      "",
      "is_volatile",
      "",
      "hosts",
      "circular_path_checked",
      "", "", "", "", "",
      "host_name",
      "", "", "", "",
      "retain_nonstatus_information",
      "",
      "servicegroups",
      "end",
      "last_time_unknown",
      "", "",
      "command_line",
      "last_time_unreachable",
      "ack_data",
      "contactgroups",
      "active_service_checks_enabled",
      "", "",
      "perf_data",
      "",
      "stalking_options",
      "skip_interval",
      "",
      "latency",
      "last_problem_id",
      "last_host_notification",
      "",
      "last_check",
      "entry_time",
      "notify_on_service_unknown",
      "notify_on_service_downtime",
      "start_time",
      "check_options",
      "escalated",
      "", "",
      "last_log_rotation",
      "notify_on_service_critical",
      "notify_on_critical",
      "",
      "in_host_notification_period",
      "", "", "", "",
      "pending_flex_downtime",
      "", "", "", "",
      "reschedule_check",
      "check_freshness",
      "",
      "obsess_over_hosts",
      "obsess_over_service",
      "obsess_over_host",
      "obsess_over_services",
      "",
      "stalk_on_down",
      "notification_options",
      "freshness_threshold",
      "x_3d",
      "next_service_notification_time",
      "", "", "",
      "notification_interval",
      "x_2d",
      "flap_detection_on_down",
      "flap_detection_options",
      "",
      "flap_detection_on_unknown",
      "stalk_on_up",
      "", "",
      "flap_detection_on_unreachable",
      "parent_hosts",
      "daemon_mode",
      "last_time_warning",
      "flap_detection_on_critical",
      "long_output",
      "", "",
      "in_service_notification_period",
      "program_start",
      "",
      "hostgroups",
      "last_time_up",
      "", "", "",
      "pid",
      "",
      "passive_service_checks_enabled",
      "is_in_effect",
      "",
      "next_notification",
      "display_name",
      "", "", "",
      "y_3d",
      "",
      "can_submit_commands",
      "", "",
      "active_host_checks_enabled",
      "y_2d",
      "", "",
      "comment_data",
      "last_hard_state",
      "failure_prediction_options",
      "notify_on_down",
      "pager",
      "",
      "last_hard_state_str",
      "notify_on_downtime",
      "last_hard_state_change",
      "", "",
      "is_being_freshened",
      "",
      "check_period",
      "", "", "",
      "stalk_on_warning",
      "", "",
      "next_valid_time",
      "",
      "acknowledgement_type",
      "", "", "", "",
      "contacts_notified",
      "host_notification_options",
      "",
      "is_executing",
      "check_command",
      "",
      "long_plugin_output",
      "",
      "host_notification_options_int",
      "",
      "notified_on_warning",
      "", "",
      "flap_detection_on_up",
      "members",
      "",
      "notification_period",
      "timeout",
      "notifications_enabled",
      "comment_id",
      "", "", "",
      "next_check",
      "", "",
      "next_host_notification_time",
      "flap_detection_enabled",
      "timestamp",
      "",
      "last_time_ok",
      "command_name",
      "",
      "process_performance_data",
      "",
      "low_flap_threshold",
      "",
      "triggered_by",
      "notify_contacts",
      "fixed",
      "contains_circular_path",
      "should_be_drawn",
      "current_problem_id",
      "incremented_pending_downtime",
      "notify_on_unknown",
      "",
      "should_be_scheduled",
      "",
      "notify_on_unreachable",
      "early_timeout",
      "timeperiod_name",
      "", "", "",
      "last_command_check",
      "", "", "",
      "notify_on_host_down",
      "modified_attributes",
      "", "",
      "notify_on_host_downtime",
      "modified_service_attributes",
      "",
      "notify_on_host_unreachable",
      "notify_on_recovery",
      "", "",
      "state_history",
      "failure_prediction_enabled",
      "", "", "",
      "notify_on_service_recovery",
      "", "", "", "", "",
      "contact_groups",
      "", "", "", "", "",
      "command_args",
      "", "", "", "", "", "",
      "downtime_id",
      "",
      "host_notification_period",
      "",
      "host_notifications_enabled",
      "", "", "",
      "have_3d_coords",
      "flap_detection_on_ok",
      "",
      "notify_on_service_warning",
      "notify_on_service_flapping",
      "",
      "have_2d_coords",
      "in_timeperiod",
      "", "", "", "",
      "stalk_on_ok",
      "notify_on_warning",
      "", "", "", "", "", "", "", "", "",
      "",
      "passive_host_checks_enabled",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "",
      "host_problem_at_last_check",
      "low_threshold",
      "", "", "",
      "flap_detection_on_warning",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "",
      "first_notification_delay",
      "flapping_comment_id",
      "max_attempts",
      "",
      "icon_image",
      "has_been_checked",
      "", "", "", "", "", "", "",
      "ack_author",
      "", "", "", "",
      "vrml_image",
      "plugin_output",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "",
      "is_sticky",
      "", "", "", "", "", "", "",
      "modified_host_attributes",
      "", "", "",
      "problem_has_been_acknowledged",
      "icon_image_alt",
      "notify_on_flapping",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "",
      "notify_on_host_recovery",
      "", "", "", "", "", "", "",
      "group_name",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "",
      "msg",
      "", "", "", "", "", "", "",
      "notify_on_host_flapping",
      "",
      "is_flapping",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "",
      "scheduled_check",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "",
      "high_threshold",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "",
      "high_flap_threshold",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "",
      "scheduled_downtime_depth"
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
