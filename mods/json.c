#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <float.h>
#include <ctype.h>
#include "json.h"

#define PAGE_SIZE 4096

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
	return ret;
}

void payload_add_key(struct payload * po, char * key) {
	size_t keylen = strlen(key);
	adjust_payload_len(po, keylen + sizeof("\"\": "));
	po->bufused += sprintf(po->json_buf + po->bufused,
		"\"%s\": ", key);
}

void payload_new_string(struct payload * po, char * key, char * val) {
	payload_add_key(po, key);
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
	if(strcmp(key, "type") == 0)
		po->type = strdup(save);
	po->bufused += out - save;
	po->bufused += sprintf(po->json_buf + po->bufused, "\", ");
}

void payload_new_integer(struct payload * po, char * key, long long val) {
	payload_add_key(po, key);
	adjust_payload_len(po, sizeof("INT64_MAX, "));
	po->bufused += sprintf(po->json_buf + po->bufused,
		"%lli, ", val);
}

void payload_new_boolean(struct payload * po, char * key, int val) {
	payload_add_key(po, key);
	adjust_payload_len(po, sizeof("false, "));
	if(val > 0)
		po->bufused += sprintf(po->json_buf + po->bufused,
			"true, ");
	else
		po->bufused += sprintf(po->json_buf + po->bufused,
			"false, ");
}

void payload_new_double(struct payload * po, char * key, double val) {
	payload_add_key(po, key);
	adjust_payload_len(po, DBL_MAX_10_EXP + sizeof(", "));
	po->bufused += snprintf(po->json_buf + po->bufused,
		DBL_MAX_10_EXP, "%f", val) - 1;
	po->bufused += sprintf(po->json_buf + po->bufused,
		", ");
}

void payload_new_timestamp(struct payload * po,
	char* key, struct timeval * tv) {
	payload_add_key(po, key);
	adjust_payload_len(po, sizeof("{  }, "));
	po->bufused += sprintf(po->json_buf + po->bufused, "{ ");
	payload_new_integer(po, "tv_sec", tv->tv_sec);
	payload_new_integer(po, "tv_usec", tv->tv_usec);
	po->bufused -= 2;
	po->bufused += sprintf(po->json_buf + (po->bufused),
		" }, ");
} 

void payload_finalize(struct payload * po) {
	sprintf(po->json_buf + po->bufused - 2, " }");
}
