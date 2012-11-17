#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <float.h>
#include <ctype.h>
#include <stdarg.h>
#include "json.h"

#define PAGE_SIZE 4096

/* victorious:mods jreams$ perl -n tst.pl < nagmq_req.c  | sort -u | \
/* gperf -m 10000 -H hash_key -C -r */
/* C code produced by gperf version 3.0.3 */
/* Command-line: gperf -m 10000 -H hash_key -C -r  */
/* Computed positions: -k'1,3,6,8,11,$' */

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


#define TOTAL_KEYWORDS 196
#define MIN_WORD_LENGTH 3
#define MAX_WORD_LENGTH 36
#define MIN_HASH_VALUE 30
#define MAX_HASH_VALUE 457
/* maximum key range = 428, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
hash_key (str, len)
     register const char *str;
     register unsigned int len;
{
  static const unsigned short asso_values[] =
    {
      458, 458, 458, 458, 458, 458, 458, 458, 458, 458,
      458, 458, 458, 458, 458, 458, 458, 458, 458, 458,
      458, 458, 458, 458, 458, 458, 458, 458, 458, 458,
      458, 458, 458, 458, 458, 458, 458, 458, 458, 458,
      458, 458, 458, 458, 458, 458, 458, 458, 458, 458,
       39,  15, 458, 458, 458, 458, 458, 458, 458, 458,
      458, 458, 458, 458, 458, 458, 458, 458, 458, 458,
      458, 458, 458, 458, 458, 458, 458, 458, 458, 458,
      458, 458, 458, 458, 458, 458, 458, 458, 458, 458,
      458, 458, 458, 458, 458,   8, 458,  15,  16,  49,
       10,   8, 106, 122, 151,  18, 458,  20,  30, 170,
        8,  82, 108, 458,  45,   8,   9,  78,  58,   9,
       53,  62,   9, 458, 458, 458, 458, 458, 458, 458,
      458, 458, 458, 458, 458, 458, 458, 458, 458, 458,
      458, 458, 458, 458, 458, 458, 458, 458, 458, 458,
      458, 458, 458, 458, 458, 458, 458, 458, 458, 458,
      458, 458, 458, 458, 458, 458, 458, 458, 458, 458,
      458, 458, 458, 458, 458, 458, 458, 458, 458, 458,
      458, 458, 458, 458, 458, 458, 458, 458, 458, 458,
      458, 458, 458, 458, 458, 458, 458, 458, 458, 458,
      458, 458, 458, 458, 458, 458, 458, 458, 458, 458,
      458, 458, 458, 458, 458, 458, 458, 458, 458, 458,
      458, 458, 458, 458, 458, 458, 458, 458, 458, 458,
      458, 458, 458, 458, 458, 458, 458, 458, 458, 458,
      458, 458, 458, 458, 458, 458, 458, 458, 458, 458,
      458, 458, 458, 458, 458, 458
    };
  register int hval = (int)len;

  switch (hval)
    {
      default:
        hval += asso_values[(unsigned char)str[10]];
      /*FALLTHROUGH*/
      case 10:
      case 9:
      case 8:
        hval += asso_values[(unsigned char)str[7]];
      /*FALLTHROUGH*/
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
in_word_set (str, len)
     register const char *str;
     register unsigned int len;
{
  static const char * const wordlist[] =
    {
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "",
      "notes",
      "end",
      "", "", "", "", "",
      "start",
      "z_3d",
      "", "", "", "", "", "", "",
      "alias",
      "",
      "address",
      "", "", "", "", "", "", "", "", "",
      "email",
      "",
      "end_time",
      "entry_time",
      "", "", "", "", "",
      "start_time",
      "", "", "",
      "stalk_on_unknown",
      "", "", "",
      "stalk_on_unreachable",
      "downtime_id",
      "notified_on_down",
      "",
      "last_state",
      "notified_on_unknown",
      "",
      "x_3d",
      "",
      "notified_on_unreachable",
      "last_event_id",
      "",
      "statusmap_image",
      "in_host_notification_period",
      "",
      "stalk_on_ok",
      "y_3d",
      "is_volatile",
      "",
      "last_state_change",
      "initial_state",
      "start_flex_downtime",
      "duration",
      "last_notification",
      "",
      "event_handler_enabled",
      "",
      "last_state_history_update",
      "notified_on_critical",
      "author_name",
      "entry_type",
      "x_2d",
      "no_more_notifications",
      "source",
      "notes_url",
      "total_service_check_interval",
      "state_type",
      "retain_status_information",
      "checks_enabled",
      "retain_nonstatus_information",
      "y_2d",
      "", "", "", "", "",
      "next_notification",
      "", "", "",
      "last_check",
      "services",
      "event_handler",
      "last_state_str",
      "type",
      "contacts",
      "stalk_on_critical",
      "",
      "triggered_by",
      "", "", "",
      "in_service_notification_period",
      "execution_time",
      "expires",
      "", "",
      "stalk_on_down",
      "current_attempt",
      "current_event_id",
      "service_description",
      "current_state",
      "",
      "next_check",
      "should_be_drawn",
      "action_url",
      "icon_image",
      "current_notification_id",
      "should_be_scheduled",
      "skip_interval",
      "service_notification_options",
      "service_notification_period",
      "latency",
      "service_notifications_enabled",
      "retry_interval",
      "expire_time",
      "notification_period",
      "check_interval",
      "notifications_enabled",
      "icon_image_alt",
      "exclusions",
      "exceptions",
      "",
      "freshness_threshold",
      "pending_flex_downtime",
      "", "",
      "hosts",
      "last_service_notification",
      "fixed",
      "", "",
      "check_period",
      "",
      "flap_detection_on_down",
      "next_valid_time",
      "flap_detection_enabled",
      "flap_detection_on_unknown",
      "notification_interval",
      "child_hosts",
      "check_command",
      "flap_detection_on_unreachable",
      "current_state_str",
      "persistent",
      "flap_detection_on_ok",
      "name",
      "current_notification_number",
      "stalk_on_warning",
      "notify_on_down",
      "notified_on_warning",
      "",
      "perf_data",
      "notify_on_downtime",
      "", "", "",
      "next_service_notification_time",
      "notify_on_service_unknown",
      "notify_on_service_downtime",
      "",
      "flap_detection_on_critical",
      "state_history",
      "", "", "",
      "is_in_effect",
      "",
      "percent_state_change",
      "", "",
      "circular_path_checked",
      "", "",
      "contact_groups",
      "failure_prediction_options",
      "current_problem_id",
      "failure_prediction_enabled",
      "",
      "accept_passive_host_checks",
      "",
      "notify_on_service_critical",
      "accept_passive_service_checks",
      "host_notification_options",
      "host_notification_period",
      "",
      "host_notifications_enabled",
      "display_name",
      "", "", "",
      "last_host_notification",
      "timeperiod_name",
      "", "",
      "is_being_freshened",
      "parallelize",
      "", "", "",
      "modified_attributes",
      "group_name",
      "",
      "check_flapping_recovery_notification",
      "",
      "last_time_down",
      "obsess_over_host",
      "modified_service_attributes",
      "obsess_over_service",
      "problem_has_been_acknowledged",
      "is_executing",
      "comment_id",
      "",
      "notify_on_service_recovery",
      "notify_on_critical",
      "long_plugin_output",
      "",
      "last_problem_id",
      "",
      "next_host_notification_time",
      "notify_on_unknown",
      "last_hard_state",
      "stalk_on_up",
      "",
      "notify_on_unreachable",
      "max_attempts",
      "",
      "comment_data",
      "last_hard_state_change",
      "",
      "contains_circular_path",
      "",
      "check_options",
      "flap_detection_on_up",
      "",
      "vrml_image",
      "pager",
      "", "", "",
      "check_freshness",
      "",
      "notify_on_recovery",
      "", "", "",
      "process_performance_data",
      "incremented_pending_downtime",
      "", "", "", "",
      "flap_detection_on_warning",
      "", "", "",
      "hostgroups",
      "", "", "", "", "",
      "last_hard_state_str",
      "", "",
      "notify_on_warning",
      "", "", "", "",
      "last_time_critical",
      "",
      "notify_on_service_warning",
      "notify_on_service_flapping",
      "", "",
      "last_time_unknown",
      "",
      "modified_host_attributes",
      "servicegroups",
      "last_time_unreachable",
      "", "",
      "contactgroups",
      "", "", "",
      "last_time_ok",
      "", "", "", "",
      "have_3d_coords",
      "", "",
      "notify_on_host_down",
      "can_submit_commands",
      "",
      "parent_hosts",
      "notify_on_host_downtime",
      "",
      "in_timeperiod",
      "notify_on_host_unreachable",
      "", "", "", "", "",
      "has_been_checked",
      "",
      "host_name",
      "",
      "low_flap_threshold",
      "", "", "",
      "have_2d_coords",
      "", "", "", "",
      "last_time_warning",
      "", "", "", "", "", "",
      "flapping_comment_id",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "",
      "notify_on_host_recovery",
      "", "",
      "members",
      "", "",
      "host_problem_at_last_check",
      "is_flapping",
      "",
      "plugin_output",
      "notify_on_flapping",
      "", "", "", "", "", "", "",
      "last_time_up",
      "",
      "msg",
      "", "", "", "", "", "", "", "", "",
      "", "", "",
      "scheduled_downtime_depth",
      "",
      "high_flap_threshold",
      "first_notification_delay",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "", "", "", "", "",
      "", "", "", "", "",
      "notify_on_host_flapping"
    };

  if (len <= MAX_WORD_LENGTH && len >= MIN_WORD_LENGTH)
    {
      register int key = hash_key (str, len);

      if (key <= MAX_HASH_VALUE && key >= 0)
        {
          register const char *s = wordlist[key];

          if (*str == *s && !strcmp (str + 1, s + 1))
            return s;
        }
    }
  return 0;
}
/* END OF GPERF CODE */

void adjust_payload_len(struct payload * po, size_t len) {
	if(po->bufused + len < po->buflen)
		return;
	po->buflen += ((len / PAGE_SIZE) + 1) * PAGE_SIZE;
	po->json_buf = realloc(po->json_buf, po->buflen);
}

struct payload * payload_new() {
	struct payload * ret = malloc(sizeof(struct payload));
	memset(ret, 0, sizeof(struct payload));
	adjust_payload_len(ret, sizeof("{ "));
	ret->bufused = sprintf(ret->json_buf, "{ ");
	ret->keep_auxdata = 1;
	return ret;
}

int payload_add_key(struct payload * po, char * key) {
	if(key == NULL)
		return 1;
	size_t keylen = strlen(key);
	if(po->use_hash) {
		unsigned int hashval = hash_key(key, keylen);
		if(!po->hashed_keys[hashval])
			return 0;
	}

	adjust_payload_len(po, keylen + sizeof("\"\": "));
	po->bufused += sprintf(po->json_buf + po->bufused,
		"\"%s\": ", key);
	return 1;
}

void payload_new_string(struct payload * po, char * key, char * val) {
	if(!payload_add_key(po, key))
		return;
	if(val == NULL) {
		adjust_payload_len(po, sizeof("null, "));
		po->bufused += sprintf(po->json_buf + po->bufused,
			"null, ");
		return;
	}

	size_t len = 0;
	char * ptr = val, *out;
	char * save;
	unsigned char token;
	while((token=*ptr) && ++len) {
		if(strchr("\"\\\b\f\n\r\t",token))
			len++;
		else if(token < 32 || (token > 127 && token < 160))
			len += 5;
		ptr++;
	}
	
	adjust_payload_len(po, len + sizeof("\"\", "));
	ptr = val;
	po->bufused += sprintf(po->json_buf + po->bufused, "\"");
	out = po->json_buf + po->bufused;
	save = out;
	while(*ptr != '\0') {
		if ((unsigned char)*ptr>31 && *ptr!='\"' && *ptr!='\\')
			*(out++)=*ptr++;
		else
		{
			*(out++) = '\\';
			switch (token=*ptr++)
			{
				case '\\': *(out++)='\\'; break;
				case '\"': *(out++)='\"'; break;
				case '\b': *(out++)='b'; break;
				case '\f': *(out++)='f'; break;
				case '\n': *(out++)='n'; break;
				case '\r': *(out++)='r'; break;
				case '\t': *(out++)='t'; break;
				default: 
					sprintf(out,"u%04x",token);
					out += 5;
					break;	/* escape and print */
			}
		}
	}
	*out = '\0';
	if(po->keep_auxdata) {
		if(key && strcmp(key, "type") == 0)
			po->type = strdup(save);
		else if(key && strcmp(key, "host_name") == 0)
			po->host_name = strdup(save);
		else if(key && strcmp(key, "service_description") == 0)
			po->service_description = strdup(save);
	}
	po->bufused += out - save;
	po->bufused += sprintf(po->json_buf + po->bufused, "\", ");
}

void payload_new_integer(struct payload * po, char * key, long long val) {
	if(!payload_add_key(po, key))
		return;
	adjust_payload_len(po, sizeof("INT64_MAX, "));
	po->bufused += sprintf(po->json_buf + po->bufused,
		"%lli, ", val);
}

void payload_new_boolean(struct payload * po, char * key, int val) {
	if(!payload_add_key(po, key))
		return;
	adjust_payload_len(po, sizeof("false, "));
	if(val > 0)
		po->bufused += sprintf(po->json_buf + po->bufused,
			"true, ");
	else
		po->bufused += sprintf(po->json_buf + po->bufused,
			"false, ");
}

void payload_new_double(struct payload * po, char * key, double val) {
	if(!payload_add_key(po, key))
		return;
	adjust_payload_len(po, DBL_MAX_10_EXP + sizeof(", "));
	po->bufused += snprintf(po->json_buf + po->bufused,
		DBL_MAX_10_EXP, "%f", val) - 1;
	po->bufused += sprintf(po->json_buf + po->bufused,
		", ");
}

void payload_new_timestamp(struct payload * po,
	char* key, struct timeval * tv) {
	if(!payload_add_key(po, key))
		return;
	adjust_payload_len(po, sizeof("{  }, "));
	po->bufused += sprintf(po->json_buf + po->bufused, "{ ");
	payload_new_integer(po, "tv_sec", tv->tv_sec);
	payload_new_integer(po, "tv_usec", tv->tv_usec);
	po->bufused -= 2;
	po->bufused += sprintf(po->json_buf + (po->bufused),
		" }, ");
}

void payload_new_statestr(struct payload * ret, char * key, int state,
	int checked, int svc) {
	char * service_state_strings[] = { "OK", "WARNING", "CRITICAL", "UNKNOWN" };
	char * host_state_strings[] = { "UP", "DOWN", "UNREACHABLE" };

	if(!checked) {
		payload_new_string(ret, key, "PENDING");
		return;
	}
	if(svc)
		payload_new_string(ret, key, service_state_strings[state]);
	else
		payload_new_string(ret, key, host_state_strings[state]);
}


int payload_start_array(struct payload * po, char * key) {
	if(!payload_add_key(po, key))
		return 0;
	adjust_payload_len(po, sizeof("[ "));
	po->bufused += sprintf(po->json_buf + po->bufused, "[ ");
	return 1;
}

void payload_end_array(struct payload * po) {
	adjust_payload_len(po, sizeof(", "));
	if(*(po->json_buf + po->bufused - 2) != '[')
		po->bufused -= 2;
	po->bufused += sprintf(po->json_buf + po->bufused, " ], ");
}

int payload_start_object(struct payload * po, char * key) {
	if(!payload_add_key(po, key))
		return 0;
	adjust_payload_len(po, sizeof("{ "));
	po->bufused += sprintf(po->json_buf + po->bufused, "{ ");
	return 1;
}

void payload_end_object(struct payload * po) {
	adjust_payload_len(po, sizeof(", "));
	if(*(po->json_buf + po->bufused - 2) != '{')
		po->bufused -= 2;
	po->bufused += sprintf(po->json_buf + po->bufused, " }, ");
}

void payload_finalize(struct payload * po) {
	size_t offset = po->bufused;
	if(offset > 2)
		offset -= 2;
	adjust_payload_len(po, sizeof("] "));
	if(po->json_buf[0] == '[')
		sprintf(po->json_buf + offset, " ]");
	else
		sprintf(po->json_buf + offset, " }");
	if(offset == 2)
		po->bufused += 2;
}

void payload_hash_key(struct payload * po, const char * key) {
	size_t keylen = strlen(key);
	unsigned int hashval;

	if(!in_word_set(key, keylen))
		return;

	if(!po->use_hash) {
		memset(po->hashed_keys, 0, sizeof(po->hashed_keys));
		po->use_hash = 1;
	}

	hashval = hash_key(key, keylen);
	po->hashed_keys[hashval] = 1;
}

int payload_has_keys(struct payload * po, ...) {
	va_list ap;
	char * key;
	int okay = 0;

	if(!po->use_hash)
		return 1;

	va_start(ap, po);
	while((key = va_arg(ap, char*)) != NULL) {
		unsigned int keylen = strlen(key);
		unsigned int hashval = hash_key(key, keylen);
		if(po->hashed_keys[hashval] != 1)
			okay++;
	}
	return okay;
}
