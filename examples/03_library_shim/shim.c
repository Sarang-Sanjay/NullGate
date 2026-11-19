#define _GNU_SOURCE
#include <nullgate.h>
#include <nullgate_shim.h>
#include "parser.h"

/* Interpose parse_untrusted_data to transparently execute inside Domain 3 */
NG_INTERPOSE_FUNC_2(int, parse_untrusted_data, 3, const char *, input, size_t, len)
