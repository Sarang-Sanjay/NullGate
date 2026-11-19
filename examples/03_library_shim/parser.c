#include "parser.h"

int parse_untrusted_data(const char *input, size_t len)
{
    if (!input || len == 0) {
        return 0;
    }

    int checksum = 0x5A5A;
    for (size_t i = 0; i < len; i++) {
        checksum = ((checksum << 5) + checksum) ^ (int)input[i];
    }
    return checksum;
}
