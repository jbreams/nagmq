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
	char * ptr = val, *out = po->json_buf + po->bufused;
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
	save = po->json_buf + po->bufused - 1;
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

void payload_new_double(struct payload * po, char * key, double val) {
	payload_add_key(po, key);
	adjust_payload_len(po, DBL_MAX_10_EXP + sizeof(", "));
	po->bufused += snprintf(po->json_buf + po->bufused,
		DBL_MAX_10_EXP, "%f", val);
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
	po->bufused += sprintf(po->json_buf + (po->bufused - 2),
		" }, ");
} 

void payload_finalize(struct payload * po) {
	po->bufused -= 2;
	sprintf(po->json_buf + (po->bufused - 2), " }");
}

static const unsigned char firstByteMark[7] = { 
	0x00, 0x00, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC };
static char * parse_string(char * in, size_t len) {
	char * out, *start = in, *ret;
	unsigned int uc;
	out = malloc(len + 1);
	if(!out)
		return NULL;

	ret = out;
	while(*in != '\"' && in - start < len) {
		if(*in != '\\') {
			*out++ = *in++;
			continue;
		}
		in++;
		switch(*in) {
			case 'b': *out = '\b'; break;
			case 'f': *out = '\f'; break;
			case 'n': *out = '\n'; break;
			case 'r': *out = '\r'; break;
			case 't': *out = '\t'; break;
			case 'u': {
				int flag;
				sscanf(++in, "%4x", &uc);
				in += 4;

				if((uc >= 0xdc00 && uc <= 0xdfff) || uc == 0)
					break;
				if(uc >= 0xd800 && uc <= 0xdbff) {
					unsigned int uc2;
					if(in[1] != '\\' || in[2] != 'u')
						break;
					sscanf(in + 3, "%4x", &uc2);
					in += 6;
					if(uc2 < 0xdc || uc2 > 0xdfff)
						break;
					uc = 0x10000 | ((uc & 0x3ff)<<10) | (uc2 & 0x3ff);
				}
				flag = 4;
				if(uc < 0x80) flag = 1;
				else if(uc < 0x800) flag = 2;
				else if(uc < 0x10000) flag = 3;
				out += flag;
				switch(flag) {
					case 4:
						*--out = ((uc | 0x80) & 0xbf);
						uc >>= 6;
					case 3:
						*--out = ((uc | 0x80) & 0xbf);
						uc >>= 6;
					case 2:
						*--out = ((uc | 0x80) & 0xbf);
						uc >>= 6;
					case 1:
						*--out = (uc | firstByteMark[flag]);
				}
				out += flag;
				break;
			}
			default:
				*out++ = *in;
				break;
		}
		in++;
	}
	*out = '\0';
	return ret;
}

static struct objval * parse_number(char * in) {
	double dout;
	long long iout;
	
	struct objval * ret = malloc(sizeof(struct objval));

	dout = strtod(in, NULL);
	iout = strtoll(in, NULL, 10);
	if(((double)iout) == dout) {
		ret->val.d = dout;
		ret->type = TYPE_DOUBLE;
	} else {
		ret->val.i = iout;
		ret->type = TYPE_INTEGER;
	}
	return ret;
}

struct parsed_payload * parse_payload(char * in, size_t * plen) {
	struct parsed_payload * out = malloc(sizeof(struct parsed_payload));
	char * start = in;
	size_t len = *plen;

	while(*in != '{' && in - start < len) in++;
	out->head = NULL;
		
	while(in - start < len && *in != '}') {
		struct objval * toadd;
		char * end;
		while(*in != '\"' && in - start < len)
			in++;
		if(++in - start == len)
			break;
		end = in;
		while(*end != '\"' && end - start < len)
			end++;
		char * name = parse_string(in, end - in);
		in = end + 1;
		if(in - start == len) {
			free(name);
			break;
		}
		while(*in != ':' && in - start < len)
			in++;
		while(isspace(*in) && in - start < len)
			in++;

		if(*in == '\"') {
			end = (in++) + 1;
			while(*end != '\"')
				end++;
			toadd = malloc(sizeof(struct objval));
			toadd->val.s = parse_string(in, (++end) - in);
			toadd->type = TYPE_STRING;
			in = end;
			if(strcmp(name, "type") == 0)
				out->type = toadd->val.s;
			else if(strcmp(name, "host_name") == 0)
				out->host_name = toadd->val.s;
			else if(strcmp(name, "service_description") == 0)
				out->service_description = toadd->val.s;
		}
		else if(*in == '-' || isdigit(*in))
			toadd = parse_number(in);
		else if(*in == '{') {
			size_t sublen = len - (in - start);
			struct parsed_payload * subpl = parse_payload(in, &sublen);
			toadd = malloc(sizeof(struct objval));
			toadd->val.p = subpl;
			toadd->type = TYPE_OBJECT;
		}
		
		toadd->name = name;
		toadd->next = out->head;
		out->head = toadd;
		while(*in != ',' && *in != '}' && in - start < len)
			in++;
	}
	*plen = in - start;
	return out;
}

void parsed_payload_free(struct parsed_payload * in) {
	struct objval * save;
	while(in->head) {
		save = in->head->next;
		switch(in->head->type) {
			case TYPE_STRING:
				free(in->head->val.s);
				break;
			case TYPE_OBJECT:
				parsed_payload_free(in->head->val.p);
				break;
		}
		free(in->head->name);
		free(in->head);
		in->head = save;
	}
	if(in->type)
		free(in->type);
	if(in->host_name)
		free(in->host_name);
	if(in->service_description)
		free(in->service_description);
	free(in);
}
