
// test_malloc.c
#include <stdlib.h>

int main(void) {
    for (int i = 0; i < 10; i++) {
        void *p = malloc(64);
        free(p);
    }
    return 0;
}

