#include <stdio.h>
#include <string.h>
#include "parser.h"

int main(void)
{
    printf("=== NullGate Example 3: Transparent Library Shim ===\n");

    const char *data = "{\"project\": \"NullGate\", \"sandboxed\": true}";
    printf("[*] Invoking parse_untrusted_data with %zu bytes...\n", strlen(data));

    int checksum = parse_untrusted_data(data, strlen(data));

    printf("[+] Computation finished! Checksum: 0x%08X\n", checksum);
    printf("=== Example 3 Completed Successfully ===\n");
    return 0;
}
