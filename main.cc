#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <stdarg.h>
#include <errno.h>
#include "debug_log.h"
#include "client.h"




#define PIDFILE				    "/var/run/fc-leekscan.pid"
#define LOCKMODE				(S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)



void output()
{
#define OUTPUT_LOG      "/var/log/fc-firewal.log"

    if(freopen (OUTPUT_LOG, "a", stdout) == NULL)
        fprintf(stderr, "error redirecting stdout\n");
    
    if(freopen (OUTPUT_LOG, "a", stderr) == NULL)
        fprintf(stdout, "error redirecting stderr\n");
}

int Lockfile(int fd)
{
	struct flock fl;

	fl.l_type = F_WRLCK;
	fl.l_start = 0;
	fl.l_whence = SEEK_SET;
	fl.l_len = 0;

	return(fcntl(fd, F_SETLK, &fl));
}

int already_running()
{
	int			fd;
	char			buf[16];

	fd = open(PIDFILE, O_RDWR|O_CREAT, LOCKMODE);
	if(fd < 0)
	{
		//syslog(LOG_ERR, "can't open %s: %s", LOCKFILE, strerror(errno));
		exit(1);
	}

	if(Lockfile(fd) < 0)
	{
		if(errno == EACCES || errno == EAGAIN)
		{
			close(fd);
			puts("already running");
			return 1;
		}
		//syslog(LOG_ERR, "can't lock %s: %s", LOCKFILE, strerror(errno));
		
		exit(1);
	}

	ftruncate(fd, 0);
	sprintf(buf, "%ld", (long)getpid());
	write(fd, buf, strlen(buf) + 1);
	return 0;
	
}


int main(int argc, char **argv)
{
    int ret = 0;

    if(argc > 1 && !strcmp(argv[1], "-d"))
    {        
        if(fork())
        {
            exit(0);
        }
    }

    debug_log_init();
    
    if(already_running())
	{
		printf("already runging!\n");
		exit(0);
	}
    
    if(node_get_db_config())
        exit(-1);

    connect_server();
  
    if(log4c_fini())
      log_error("log4c_fini() failed");
      
    return 0;
}



