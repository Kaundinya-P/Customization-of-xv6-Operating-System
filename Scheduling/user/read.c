#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int main(int argc, char *argv[])
{
    int fd;
    char buf[100];

    printf("%d\n", getreadcount());

    fd = open("README", 0); // this is just a sample file
    if (fd < 0)
    {
        printf("cannot open the file\n");
        exit(1);
    }

    read(fd, buf, sizeof(buf));
    close(fd);

    printf("%d\n", getreadcount());
    exit(0);
}