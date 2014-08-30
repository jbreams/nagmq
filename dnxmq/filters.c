#include "config.h"
#include <stdlib.h>
#ifdef HAVE_PCRE
#include <pcre.h>
#else
#include <regex.h>
#endif
#include <string.h>
#include "mqexec.h"

struct filter {
#ifdef HAVE_PCRE
	pcre * regex;
	pcre_extra * extra;
#else
	regex_t regex;
#endif
	char field[64];
	char or;
	int fqdn;
	int nodename;
	int isnot;
	struct filter * next;
} *filterhead = NULL, *filtertail = NULL;

extern char myfqdn[255], mynodename[255];

int parse_filter(json_t * in, int or) {
	if(json_is_object(in)) {
		char * field = NULL;
		char * match = NULL;
		int icase = 0, dotall = 0;
		json_t * orobj = NULL;

		struct filter * newfilt = calloc(1, sizeof(struct filter));
		if(json_unpack(in, "{ s?:s s:s s?:o s?:b s?:b s?:b s?:b s?b }",
			"match", &match, "field", &field, "or", &orobj,
			"caseless", &icase, "dotall", &dotall, "not", &newfilt->isnot,
			"fqdn", &newfilt->fqdn, "nodename", &newfilt->nodename) < 0) {
			logit(ERR, "Error parsing filter definition.");
			free(newfilt);
			return -1;
		}

		strncpy(newfilt->field, field, sizeof(newfilt->field) - 1);
		if(match) {
#ifdef HAVE_PCRE
			const char * errptr = NULL;
			int errofft = 0, options = PCRE_NO_AUTO_CAPTURE;
			if(icase)
				options |= PCRE_CASELESS;
			if(dotall)
				options |= PCRE_DOTALL;
			newfilt->regex = pcre_compile(match, options, &errptr,
				&errofft, NULL);
			if(newfilt->regex == NULL) {
				logit(ERR, "Error compiling regex for %s at position %d: %s",
					field, errptr, errofft);
				free(newfilt);
				return -1;
			}
			
			newfilt->extra = pcre_study(newfilt->regex, 0, &errptr);
			if(errptr != NULL) {
				logit(ERR, "Error studying regex: %s", errptr);
				free(newfilt);
				return -1;
			}
#else
			int options = REG_EXTENDED | REG_NOSUB;
			if(icase)
				options |= REG_ICASE;
			int rc = regcomp(&newfilt->regex, match, options);
			if(rc != 0) {
				logit(ERR, "Error compiling regex for %s: %s",
					field, strerror(rc));
				free(newfilt);
				return -1;
			}
#endif
		}
		if(!filterhead) {
			filterhead = newfilt;
			filtertail = newfilt;
		} else
			filtertail->next = newfilt;

		if(json_is_true(orobj))
			newfilt->or = 1;	
		else if(orobj)
			parse_filter(orobj, 1);
	} else if(json_is_array(in)) {
		int x;
		for(x = 0; x < json_array_size(in); x++) {
			json_t * t = json_array_get(in, x);
			if(parse_filter(t, or) < 0)
				return -1;
		}
	}
	return 0;
}

int match_filter(json_t * input) {
	if(filterhead == NULL)
		return 1;

	struct filter *cur;
	for(cur = filterhead; cur != NULL; cur = cur->next) {
		int res = 1;
		const char * tomatch;
		json_t * field;
		if((field = json_object_get(input, cur->field)) == NULL)
			continue;
		if(!json_is_string(field))
			continue;
		tomatch = json_string_value(field);
		if(cur->fqdn)
			res = strcasecmp(tomatch, myfqdn);
		else if(cur->nodename)
			res = strcasecmp(tomatch, mynodename);
		else {
#ifdef HAVE_PCRE
			int ovec[33];
			res = pcre_exec(cur->regex, cur->extra,
				tomatch, strlen(tomatch), 0, 0, ovec, 33);
			res = res < 0 ? 1 : 0;
#else
			regmatch_t ovec[33];
			res = regexec(&cur->regex, tomatch, 33, ovec, 0);
#endif
		}
		if(cur->isnot == 1) {
			res = res == 0 ? 1 : 0;
			logit(DEBUG, "Inverting filter because of not clause");
		}
		if(cur->or == 1 && res == 0)
			return 1;
		else if(cur->or == 0 && res != 0)
			return 0;
		else
			break;
	}
	return 1;
}