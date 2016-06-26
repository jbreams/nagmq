#include "json.h"
#include "jansson.h"
#include <math.h>
#include <string.h>

int get_values(json_t* input, ...) {
    va_list ap;
    char* key;
    int type;
    int required;

    if (!input || !json_is_object(input))
        return -1;

    va_start(ap, input);
    key = va_arg(ap, char*);
    while (key) {
        void* uncast;
        json_t* found;
        int foundtype;

        type = va_arg(ap, int);
        required = va_arg(ap, int);
        uncast = va_arg(ap, void*);
        found = json_object_get(input, key);
        if (found == NULL) {
            if (required)
                return -1;
            key = va_arg(ap, char*);
            continue;
        }

        foundtype = json_typeof(found);
        if (type == JSON_TIMEVAL && foundtype != JSON_REAL && foundtype != JSON_OBJECT) {
            if (required)
                return -1;
            key = va_arg(ap, char*);
            continue;
        } else if (type == JSON_TRUE) {
            if (!json_is_boolean(found)) {
                if (required)
                    return -1;
                key = va_arg(ap, char*);
                continue;
            }
        } else if (type != JSON_TIMEVAL && type != foundtype) {
            if (required)
                return -1;
            key = va_arg(ap, char*);
            continue;
        }

        switch (type) {
            case JSON_STRING:
                *((const char**)uncast) = json_string_value(found);
                break;
            case JSON_OBJECT:
            case JSON_ARRAY:
                *((json_t**)uncast) = found;
                break;
            case JSON_INTEGER:
                *((int*)uncast) = json_integer_value(found);
                break;
            case JSON_REAL:
                *((double*)uncast) = json_real_value(found);
                break;
            case JSON_TRUE:
            case JSON_FALSE:
                *((int*)uncast) = json_is_true(found) ? 1 : 0;
                break;
            case JSON_TIMEVAL: {
                struct timeval* tv = (struct timeval*)uncast;
                memset(tv, 0, sizeof(struct timeval));
                double tv_usec;
                int rc;
                switch (foundtype) {
                    case JSON_REAL:
                        tv->tv_sec = modf(json_real_value(found), &tv_usec);
                        tv->tv_usec = tv_usec * 100000;
                        break;
                    case JSON_OBJECT:
                        rc = json_unpack(
                            found, "{ s:i s?:i }", "tv_sec", &tv->tv_sec, "tv_usec", &tv->tv_usec);
                        if (rc != 0 && required)
                            return -1;
                }
                break;
            }
        }
        key = va_arg(ap, char*);
    }
    va_end(ap);
    return 0;
}
