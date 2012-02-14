
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
