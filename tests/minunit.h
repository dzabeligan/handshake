#undef NDEBUG
#ifndef _minunit_h
#define _minunit_h

#include "../dbg.h"
#include <stdio.h>
#include <stdlib.h>

#define mu_suite_start() char* message = NULL

#define mu_assert(test, message, ...)                                          \
    if (!(test)) {                                                             \
        log_err(message, ##__VA_ARGS__);                                       \
        return message[0] == '%' ? "Error" : message;                          \
    }

#define mu_run_test(test)                                                      \
    debug("\n-----%s", " " #test);                                             \
    message = (char*)test();                                                   \
    tests_run++;                                                               \
    if (message)                                                               \
        return message;

#define RUN_TESTS(name)                                                        \
    int main(int argc, char* argv[])                                           \
    {                                                                          \
        (void)argc;                                                            \
        debug("----- RUNNING: %s\n", argv[0]);                                 \
        printf("----\nRUNNING: %s\n", argv[0]);                                \
        const char* result = name();                                           \
        if (result != 0) {                                                     \
            printf("FAILED: %s\n", result);                                    \
        } else {                                                               \
            printf("ALL TESTS PASSED\n");                                      \
        }                                                                      \
        printf("Tests run: %d\n", tests_run);                                  \
        exit(result != 0);                                                     \
    }

int tests_run;

#endif