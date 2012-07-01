/* C code produced by gperf version 3.0.3 */
/* Command-line: gperf -m 1000  */
/* Computed positions: -k'1,3-4,6,11,$' */

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


#define TOTAL_KEYWORDS 175
#define MIN_WORD_LENGTH 3
#define MAX_WORD_LENGTH 36
#define MIN_HASH_VALUE 21
#define MAX_HASH_VALUE 381
/* maximum key range = 361, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
hash (str, len)
     register const char *str;
     register unsigned int len;
{
  static unsigned short asso_values[] =
    {
      382, 382, 382, 382, 382, 382, 382, 382, 382, 382,
      382, 382, 382, 382, 382, 382, 382, 382, 382, 382,
      382, 382, 382, 382, 382, 382, 382, 382, 382, 382,
      382, 382, 382, 382, 382, 382, 382, 382, 382, 382,
      382, 382, 382, 382, 382, 382, 382, 382, 382, 382,
       19,  13, 382, 382, 382, 382, 382, 382, 382, 382,
      382, 382, 382, 382, 382, 382, 382, 382, 382, 382,
      382, 382, 382, 382, 382, 382, 382, 382, 382, 382,
      382, 382, 382, 382, 382, 382, 382, 382, 382, 382,
      382, 382, 382, 382, 382,  28, 382,   8,  22,   5,
       44,   2,   7, 107,  74,   3, 382,  15,   3, 133,
        2,  94, 121, 382,  23,   3,  13,   4,  62,   4,
      116,  80,   2, 382, 382, 382, 382, 382, 382, 382,
      382, 382, 382, 382, 382, 382, 382, 382, 382, 382,
      382, 382, 382, 382, 382, 382, 382, 382, 382, 382,
      382, 382, 382, 382, 382, 382, 382, 382, 382, 382,
      382, 382, 382, 382, 382, 382, 382, 382, 382, 382,
      382, 382, 382, 382, 382, 382, 382, 382, 382, 382,
      382, 382, 382, 382, 382, 382, 382, 382, 382, 382,
      382, 382, 382, 382, 382, 382, 382, 382, 382, 382,
      382, 382, 382, 382, 382, 382, 382, 382, 382, 382,
      382, 382, 382, 382, 382, 382, 382, 382, 382, 382,
      382, 382, 382, 382, 382, 382, 382, 382, 382, 382,
      382, 382, 382, 382, 382, 382, 382, 382, 382, 382,
      382, 382, 382, 382, 382, 382, 382, 382, 382, 382,
      382, 382, 382, 382, 382, 382
    };
  register int hval = len;

  switch (hval)
    {
      default:
        hval += asso_values[(unsigned char)str[10]];
      /*FALLTHROUGH*/
      case 10:
      case 9:
      case 8:
      case 7:
      case 6:
        hval += asso_values[(unsigned char)str[5]];
      /*FALLTHROUGH*/
      case 5:
      case 4:
        hval += asso_values[(unsigned char)str[3]];
      /*FALLTHROUGH*/
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
in_word_set (str, len)
     register const char *str;
     register unsigned int len;
{
  static const char * wordlist[] =
    {
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "",
      "email",
      "", "", "",
      "notes",
      "exclusions",
      "alias",
      "", "", "", "", "", "",
      "last_state",
      "exceptions",
      "contacts",
      "", "",
      "action_url",
      "",
      "notified_on_down",
      "",
      "last_notification",
      "notified_on_unknown",
      "contactgroups",
      "notified_on_critical",
      "statusmap_image",
      "notified_on_unreachable",
      "last_check",
      "initial_state",
      "execution_time",
      "start",
      "",
      "last_service_notification",
      "last_time_unknown",
      "child_hosts",
      "notes_url",
      "last_time_critical",
      "last_time_unreachable",
      "accept_passive_host_checks",
      "",
      "stalk_on_unknown",
      "accept_passive_service_checks",
      "state_type",
      "",
      "stalk_on_unreachable",
      "failure_prediction_options",
      "",
      "last_state_change",
      "", "", "",
      "event_handler",
      "start_time",
      "",
      "current_state",
      "last_state_history_update",
      "",
      "retain_nonstatus_information",
      "check_interval",
      "", "",
      "stalk_on_ok",
      "",
      "stalk_on_critical",
      "retain_status_information",
      "end_time",
      "address",
      "can_submit_commands",
      "freshness_threshold",
      "",
      "last_time_down",
      "end",
      "current_attempt",
      "checks_enabled",
      "total_service_check_interval",
      "",
      "hosts",
      "", "", "",
      "event_handler_enabled",
      "host_name",
      "services",
      "check_command",
      "last_event_id",
      "z_3d",
      "failure_prediction_enabled",
      "circular_path_checked",
      "latency",
      "is_volatile",
      "",
      "last_hard_state",
      "icon_image",
      "current_event_id",
      "current_notification_number",
      "service_description",
      "",
      "last_host_notification",
      "last_hard_state_change",
      "notify_on_unknown",
      "contains_circular_path",
      "host_notification_options",
      "notify_on_critical",
      "notify_on_unreachable",
      "",
      "retry_interval",
      "notify_on_service_unknown",
      "notify_on_service_downtime",
      "notify_on_service_critical",
      "",
      "check_freshness",
      "current_notification_id",
      "", "",
      "contact_groups",
      "service_notification_options",
      "",
      "notification_interval",
      "",
      "is_being_freshened",
      "type",
      "name",
      "", "",
      "obsess_over_service",
      "", "",
      "notified_on_warning",
      "check_options",
      "stalk_on_down",
      "",
      "last_time_ok",
      "obsess_over_host",
      "next_notification",
      "is_executing",
      "icon_image_alt",
      "notify_on_down",
      "in_service_notification_period",
      "last_time_warning",
      "next_check",
      "notify_on_downtime",
      "host_notification_period",
      "",
      "host_notifications_enabled",
      "", "", "",
      "last_time_up",
      "parallelize",
      "next_service_notification_time",
      "first_notification_delay",
      "stalk_on_warning",
      "low_flap_threshold",
      "", "",
      "service_notification_period",
      "notification_period",
      "service_notifications_enabled",
      "notifications_enabled",
      "percent_state_change",
      "", "", "",
      "y_3d",
      "",
      "parent_hosts",
      "", "",
      "check_period",
      "y_2d",
      "in_host_notification_period",
      "notify_on_host_down",
      "pending_flex_downtime",
      "timeperiod_name",
      "",
      "notify_on_host_downtime",
      "",
      "check_flapping_recovery_notification",
      "notify_on_host_unreachable",
      "last_problem_id",
      "", "", "", "",
      "should_be_drawn",
      "notify_on_service_recovery",
      "skip_interval",
      "current_problem_id",
      "",
      "should_be_scheduled",
      "perf_data",
      "vrml_image",
      "",
      "modified_service_attributes",
      "",
      "flap_detection_on_down",
      "modified_attributes",
      "notify_on_recovery",
      "flap_detection_on_unknown",
      "x_3d",
      "flap_detection_on_critical",
      "no_more_notifications",
      "flap_detection_on_unreachable",
      "scheduled_downtime_depth",
      "notify_on_warning",
      "x_2d",
      "flap_detection_on_ok",
      "",
      "notify_on_flapping",
      "", "",
      "notify_on_service_warning",
      "notify_on_service_flapping",
      "",
      "next_host_notification_time",
      "in_timeperiod",
      "next_valid_time",
      "state_history",
      "",
      "has_been_checked",
      "", "", "",
      "group_name",
      "", "", "", "", "", "", "", "",
      "host_problem_at_last_check",
      "", "", "",
      "pager",
      "flap_detection_enabled",
      "", "",
      "have_3d_coords",
      "", "", "",
      "long_plugin_output",
      "",
      "have_2d_coords",
      "", "",
      "is_flapping",
      "", "", "",
      "notify_on_host_recovery",
      "", "",
      "process_performance_data",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "",
      "stalk_on_up",
      "flapping_comment_id",
      "", "", "", "", "",
      "notify_on_host_flapping",
      "",
      "modified_host_attributes",
      "", "", "", "", "", "", "", "", "",
      "",
      "problem_has_been_acknowledged",
      "", "",
      "max_attempts",
      "", "",
      "members",
      "",
      "display_name",
      "",
      "flap_detection_on_warning",
      "", "", "", "", "", "", "", "",
      "flap_detection_on_up",
      "", "", "",
      "high_flap_threshold",
      "", "", "", "", "", "", "", "", "",
      "", "",
      "msg",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "",
      "plugin_output"
    };

  if (len <= MAX_WORD_LENGTH && len >= MIN_WORD_LENGTH)
    {
      register int key = hash (str, len);

      if (key <= MAX_HASH_VALUE && key >= 0)
        {
          register const char *s = wordlist[key];

          if (*str == *s && !strcmp (str + 1, s + 1))
            return s;
        }
    }
  return 0;
}
