#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

static unsigned char lava_val[4];

int main(int argc, char** argv) {
    FILE* f = fopen(argv[1], "rb");
    if (1 != fread(lava_val, sizeof(lava_val), 1, f))
        return -1;

    if(lava_val[0] == 0x6c) {
        if(lava_val[1] == 0x61)
            if(lava_val[2] == 0x75)
                if(lava_val[3] == 0xde)
                    printf("fdata = %f\n"+*(unsigned int *)lava_val, lava_val);
    }

    return 0;
}