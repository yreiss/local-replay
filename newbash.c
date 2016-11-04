#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h> 
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
  char *bash_exec = "/bin/bash";
  char *const add_lo_exec[] = {"/sbin/ifconfig", "lo:0", "127.0.0.2", "netmask", "255.0.0.0", "up", NULL};

  uid_t uid = getuid(); 
  uid_t euid = geteuid();

  if (uid && euid) {
    printf("newbash must run as root\n");
    exit (1);
  }
  
  unshare(CLONE_NEWNET);

  execvp(bash_exec, &bash_exec);

  

  return 0;
}
