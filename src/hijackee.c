#include <unistd.h>
#include <stdio.h>

int main(int argc, char *argv[]) {

    printf("User %d | argv[0] %s\n", getuid(), argv[0]);

    return 0;
}