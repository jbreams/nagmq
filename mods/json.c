#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <float.h>
#include <ctype.h>
#include <stdarg.h>
#include "json.h"

#define PAGE_SIZE 4096

/* A "mixing table" of 256 distinct values, in pseudo-random order. */
static unsigned char mixtable[256] = {
251, 175, 119, 215, 81, 14, 79, 191, 103, 49, 181, 143, 186, 157, 0,
232, 31, 32, 55, 60, 152, 58, 17, 237, 174, 70, 160, 144, 220, 90, 57,
223, 59, 3, 18, 140, 111, 166, 203, 196, 134, 243, 124, 95, 222, 179,
197, 65, 180, 48, 36, 15, 107, 46, 233, 130, 165, 30, 123, 161, 209, 23,
97, 16, 40, 91, 219, 61, 100, 10, 210, 109, 250, 127, 22, 138, 29, 108,
244, 67, 207, 9, 178, 204, 74, 98, 126, 249, 167, 116, 34, 77, 193,
200, 121, 5, 20, 113, 71, 35, 128, 13, 182, 94, 25, 226, 227, 199, 75,
27, 41, 245, 230, 224, 43, 225, 177, 26, 155, 150, 212, 142, 218, 115,
241, 73, 88, 105, 39, 114, 62, 255, 192, 201, 145, 214, 168, 158, 221,
148, 154, 122, 12, 84, 82, 163, 44, 139, 228, 236, 205, 242, 217, 11,
187, 146, 159, 64, 86, 239, 195, 42, 106, 198, 118, 112, 184, 172, 87,
2, 173, 117, 176, 229, 247, 253, 137, 185, 99, 164, 102, 147, 45, 66,
231, 52, 141, 211, 194, 206, 246, 238, 56, 110, 78, 248, 63, 240, 189,
93, 92, 51, 53, 183, 19, 171, 72, 50, 33, 104, 101, 69, 8, 252, 83, 120,
76, 135, 85, 54, 202, 125, 188, 213, 96, 235, 136, 208, 162, 129, 190,
132, 156, 38, 47, 1, 7, 254, 24, 4, 216, 131, 89, 21, 28, 133, 37, 153,
149, 80, 170, 68, 6, 169, 234, 151
};

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

int payload_add_key(struct payload * po, char * key) {
	if(key == NULL)
		return 1;
	size_t keylen = strlen(key);
	unsigned char hash = keylen;
	int i;
	if(po->keys) {
		for(i = keylen; i > 0;)
			hash = mixtable[hash ^ key[i--]];
		struct keybucket * b = po->keys[hash];
		while(b && strcmp(b->key, key) != 0)
			b = b->next;
		
		if(!b)
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
	if(key && strcmp(key, "type") == 0)
		po->type = strdup(save);
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
	if(po->json_buf[0] == '[')
		sprintf(po->json_buf + po->bufused - 2, " ]");
	else
		sprintf(po->json_buf + po->bufused - 2, " }");
	if(po->keys) {
		int i;
		for(i = 0; i < 255; i++) {
			struct keybucket * t;
			t = po->keys[i];
			while(t) {
				struct keybucket * p = t->next;
				free(t);
				t = p;
			}
		}
		free(po->keys);
	}
}

void payload_hash_key(struct payload * po, const char * key) {
	size_t kl = strlen(key);
	if(!po->keys) {
		po->keys = malloc(kl + 1);
		if(po->keys)
			strcpy(po->keys, key);
		return;
	}

	uint8_t * p = po->keys;
	while(1 & p) {
		struct keybucket * q = (void*)(p - 1);
		uint8_t c = 0;
		if(q->byte < kl)
			c = key[q->byte];
		const int direction = (1 + (q->otherbits|c)) >> 8;
		p = q->child[direction];
	}

	uint8_t newbyte, newotherbits;
	for(newbytes = 0; newbyte < kl; ++newbyte) {
		if(p[newbyte] != key[newbyte]) {
			newotherbites = p[newbyte] ^ key[newbyte];
			goto different_byte_found;
		}
	}

	if(p[newbyte] != 0) {
		newotherbytes = p[newbyte];
		goto different_byte_found;
	}

	return;

different_byte_found:
	while(newotherbites & (newotherbits - 1))
		newotherbites &= newotherbits - 1;
	newotherbits ^= 255;
	uint8_t c = p[newbyte];
	int newdirection = (1 + (newotherbits|c)) >> 8;
}

int payload_has_keys(struct payload * po, ...) {
	va_list ap;
	char * key;
	int okay = 0;

	if(po->keys == NULL)
		return 1;

	va_start(ap, po);
	while((key = va_arg(ap, char*)) != NULL) {
		unsigned char hash = strlen(key);
		int i;
		for(i = hash; i > 0;)
			hash = mixtable[hash ^ key[i--]];
		struct keybucket * n = po->keys[hash];
		while(n && strcmp(n->key, key) != 0)
			n = n->next;
		if(n != NULL)
			okay++;
	}
	return okay;
}
