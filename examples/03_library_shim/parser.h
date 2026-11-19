#ifndef PARSER_H
#define PARSER_H

#include <stddef.h>
#include <stdint.h>

/* Simulates a third-party untrusted data or image parser */
int parse_untrusted_data(const char *input, size_t len);

#endif /* PARSER_H */
