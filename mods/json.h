
struct payload {
	char * type;
	char * json_buf;
	size_t buflen, bufused;
};

struct payload * payload_new();
void payload_add_key(struct payload * po, char * key);
void payload_new_string(struct payload * po, char * key, char * val);
void payload_new_integer(struct payload * po, char * key, long long val);
void payload_new_double(struct payload * po, char * key, double val);
void payload_new_timestamp(struct payload * po,
	char* key, struct timeval * tv);
void payload_finalize(struct payload * po);


#define TYPE_INTEGER 0
#define TYPE_DOUBLE 1
#define TYPE_OBJECT 2
#define TYPE_STRING 3

struct objval {
	union {
		char * s;
		long long i;
		double d;
		struct parsed_payload * p;
	} val;
	char type;
	char * name;
	struct objval * next;
};

struct parsed_payload {
	char * type;
	char * host_name;
	char * service_description;
	struct objval * head;	
};

struct parsed_payload * parse_payload(char * in, size_t *len);
void parsed_payload_free(struct parsed_payload * in);
