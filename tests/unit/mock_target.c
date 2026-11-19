/*
 * NullGate — Mock Target Library for Transparent Interposition Testing
 */

#include <errno.h>

int mock_target_calc(int a, int b)
{
    if (a < 0) {
        errno = EDOM;
        return -1;
    }
    return (a * 10) + b;
}

void mock_target_reset(int *ptr, int val)
{
    if (ptr)
        *ptr = val;
}

int mock_target_recurse(int depth)
{
    if (depth <= 0)
        return 100;
    return mock_target_recurse(depth - 1) + 1;
}

int mock_target_multi(int a, int b, int c, int d)
{
    return a + b + c + d;
}
