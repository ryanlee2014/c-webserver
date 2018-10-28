#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <string>
#include <sys/time.h>
#include "static/static_const.h"
#include <iostream>
#include <string>
#include <pthread.h>
#include <semaphore.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/mman.h>

using std::string;
using std::cin;
using std::cout;
using std::cerr;
using std::to_string;

#ifndef SIGCLD
#   define SIGCLD SIGCHLD
#endif

struct webparam{
    int socketfd,hit;
}webparam;


void logger(int type, const char *s1, const char *s2, int socket_fd) {
    struct timeval start, end;
    gettimeofday(&start, NULL);
    int fd;
    char logbuffer[BUFSIZE * 2];
    char time_stamp[BUFSIZE << 1];
    struct tm *current_time = NULL;
    time_t tt;
    time(&tt);
    current_time = localtime(&tt);
    current_time->tm_year += 1900;
    current_time->tm_mon += 1;
    sprintf(time_stamp, "%d.%d.%d-%d:%d:%d\n", current_time->tm_year, current_time->tm_mon, current_time->tm_mday,
            current_time->tm_hour, current_time->tm_min, current_time->tm_sec);


    switch (type) {
        case ERROR:
            (void) sprintf(logbuffer, "ERROR: %s:%s Errno=%d exiting pid=%d", s1, s2, errno, getpid());
            break;
        case FORBIDDEN:
            (void) write(socket_fd,
                         "HTTP/1.1 403 Forbidden\nContent-Length: 185\nConnection: close\nContent-Type: text/html\n\n<html><head>\n<title>403 Forbidden</title>\n</head><body>\n<h1>Forbidden</h1>\nThe requested URL, file type or operation is not allowed on this simple static file webserver.\n</body></html>\n",
                         271);
            (void) sprintf(logbuffer, "FORBIDDEN: %s:%s", s1, s2);
            break;
        case NOTFOUND:
            (void) write(socket_fd,
                         "HTTP/1.1 404 Not Found\nContent-Length: 136\nConnection: close\nContent-Type: text/html\n\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\nThe requested URL was not found on this server.\n</body></html>\n",
                         224);
            (void) sprintf(logbuffer, "NOT FOUND: %s:%s", s1, s2);
            break;
        case LOG:
            (void) sprintf(logbuffer, " INFO: %s:%s:%d", s1, s2, socket_fd);
            break;
    }

    /* No checks here, nothing can be done with a failure anyway */
    if ((fd = open("/Users/ryan/CLionProjects/webserver/nweb2.log", O_CREAT | O_WRONLY | O_APPEND, 0644)) >= 0) {
        write(fd, time_stamp, strlen(time_stamp));
        write(fd, "\n", 1);
        (void) write(fd, logbuffer, strlen(logbuffer));
        (void) write(fd, "\n", 1);
        (void) close(fd);
    }
    gettimeofday(&end, NULL);
    long timeuse = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;  //微秒级别
    string log = "log function total Run:" + to_string(timeuse) + "microseconds.\n";
    if ((fd = open("/Users/ryan/CLionProjects/webserver/nweb2.log", O_CREAT | O_WRONLY | O_APPEND, 0644)) >= 0) {
        //write(fd, time_stamp, strlen(time_stamp));
        //write(fd, "\n", 1);
        (void) write(fd, log.c_str(), log.length());
        (void) write(fd, "\n", 1);
        (void) close(fd);
    }
    //if (type == ERROR || type == NOTFOUND || type == FORBIDDEN) exit(3);
}

/* this is a child web server process, so we can exit on errors */
void* web(void* webparams) {
    int fd,hit;
    fd = ((struct webparam*)webparams)->socketfd;
    hit = ((struct webparam*)webparams)->hit;
    struct timeval start, end;
    long timeuse = 0;
    int j, file_fd, buflen;
    long i, ret, len;
    char *fstr;
    long readFileTimeuse = 0,writeSocketTimeuse = 0;

    static char buffer[BUFSIZE + 1]; /* static so zero filled */
    gettimeofday(&start, NULL);

    ret = read(fd, buffer, BUFSIZE);   /* read Web request in one go */
    gettimeofday(&end, NULL);
    timeuse = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;  //微秒级别
    string log = "read socket function total Run:" + to_string(timeuse) + "microseconds.\n";
    logger(LOG, "Time", log.c_str(), hit);
    if (ret == 0 || ret == -1) {  /* read failure stop now */
        logger(FORBIDDEN, "failed to read browser request", "", fd);
    }
    if (ret > 0 && ret < BUFSIZE)  /* return code is valid chars */
        buffer[ret] = 0;    /* terminate the buffer */
    else buffer[0] = 0;
    for (i = 0; i < ret; i++)  /* remove CF and LF characters */
        if (buffer[i] == '\r' || buffer[i] == '\n')
            buffer[i] = '*';
    logger(LOG, "request", buffer, hit);
    if (strncmp(buffer, "GET ", 4) && strncmp(buffer, "get ", 4)) {
        logger(FORBIDDEN, "Only simple GET operation supported", buffer, fd);
    }
    for (i = 4; i < BUFSIZE; i++) { /* null terminate after the second space to ignore extra stuff */
        if (buffer[i] == ' ') { /* string is "GET URL " +lots of other stuff */
            buffer[i] = 0;
            break;
        }
    }
    for (j = 0; j < i - 1; j++)   /* check for illegal parent directory use .. */
        if (buffer[j] == '.' && buffer[j + 1] == '.') {
            logger(FORBIDDEN, "Parent directory (..) path names not supported", buffer, fd);
        }
    if (!strncmp(&buffer[0], "GET /\0", 6) ||
        !strncmp(&buffer[0], "get /\0", 6)) /* convert no filename to index file */
        (void) strcpy(buffer, "GET /index.html");

    /* work out the file type and check we support it */
    buflen = strlen(buffer);
    fstr = (char *) 0;
    for (i = 0; extensions[i].ext != 0; i++) {
        len = strlen(extensions[i].ext);
        if (!strncmp(&buffer[buflen - len], extensions[i].ext, len)) {
            fstr = extensions[i].filetype;
            break;
        }
    }
    if (fstr == 0) logger(FORBIDDEN, "file extension type not supported", buffer, fd);

    if ((file_fd = open(&buffer[5], O_RDONLY)) == -1) {  /* open the file for reading */
        logger(NOTFOUND, "failed to open file", &buffer[5], fd);
    }
    logger(LOG, "SEND", &buffer[5], hit);
    len = get_file_size(&buffer[5]); /* lseek to the file end to find the length */
    (void) lseek(file_fd, (off_t) 0, SEEK_SET); /* lseek back to the file start ready for reading */
    (void) sprintf(buffer,
                   "HTTP/1.1 200 OK\nServer: Rypers/%d.0\nContent-Length: %ld\nConnection: close\nContent-Type: %s\n\n",
                   VERSION, len, fstr); /* Header + a blank line */
    logger(LOG, "Header", buffer, hit);
    gettimeofday(&start, NULL);
    (void) write(fd, buffer, strlen(buffer));
    gettimeofday(&end, NULL);
    writeSocketTimeuse = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;  //微秒级别
    /* send file in 8KB block - last block may be smaller */
    while (true) {
        gettimeofday(&start, NULL);
        auto tmp = (ret = read(file_fd, buffer, BUFSIZE));
        gettimeofday(&end, NULL);
        readFileTimeuse = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;  //微秒级别

        if(tmp <= 0)break;
        gettimeofday(&start, NULL);
        (void) write(fd, buffer, ret);
        gettimeofday(&end, NULL);
        writeSocketTimeuse = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;  //微秒级别

    }
    log = "read file function total Run:" + to_string(readFileTimeuse) + "microseconds.\n";
    logger(LOG, "Time", log.c_str(), hit);
    log = "write socket function total Run:" + to_string(writeSocketTimeuse) + "microseconds.\n";
    logger(LOG, "Time", log.c_str(), hit);
    free(webparams);
    close(fd);
}


int main(int argc, char **argv) {
    int i, port, pid, listenfd, socketfd, hit;
    socklen_t length;
    static struct sockaddr_in cli_addr; /* static = initialised to zeros */
    static struct sockaddr_in serv_addr; /* static = initialised to zeros */
    valid_check(argc, argv);
    /* Become deamon + unstopable and no zombies children (= no wait()) */
    if (fork() != 0)
        return 0; /* parent returns OK to shell */
    (void) signal(SIGCLD, SIG_IGN); /* ignore child death */
    (void) signal(SIGHUP, SIG_IGN); /* ignore terminal hangups */
    for (i = 0; i < 32; i++)
        (void) close(i);    /* close open files */
    (void) setpgrp();    /* break away from process group */
    logger(LOG, "WebServer starting", argv[1], getpid());
    /* setup the network socket */
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        logger(ERROR, "system call", "socket", 0);
    port = atoi(argv[1]);
    if (port < 0 || port > 60000)
        logger(ERROR, "Invalid port number (try 1->60000)", argv[1], 0);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(ip_to_num("0.0.0.0"));//INADDR_ANY
    serv_addr.sin_port = htons(port);
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
    pthread_t pth;
    if (bind(listenfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
        logger(ERROR, "system call", "bind", 0);
    if (listen(listenfd, 64) < 0)
        logger(ERROR, "system call", "listen", 0);
    //shared
    /*
    sem_t* psem;
    if((psem=sem_open("sem_example",O_CREAT,0666,1))==SEM_FAILED)
    {
        perror("create semaphore error");
        exit(1);
    }
    int shm_fd;
    if((shm_fd=shm_open("mmap_example",O_RDWR|O_CREAT,0666))<0)
    {
        perror("create shared memory object error");
        exit(1);
    }
    ftruncate(shm_fd,sizeof(clock_t));
    void* memPtr=mmap(NULL,sizeof(clock_t),PROT_READ|PROT_WRITE,MAP_SHARED,shm_fd,0);
    if (memPtr==MAP_FAILED)
    {
        perror("create mmap error");
        exit(1);
    }
    *(clock_t*)memPtr=0;
    //end shared
     */
    struct timeval start, end;
    long timeuse = 0;
    for (hit = 1;; ++hit) {
        length = sizeof(cli_addr);
        //gettimeofday(&start, NULL);
        if ((socketfd = accept(listenfd, (struct sockaddr *) &cli_addr, &length)) < 0)
            logger(ERROR, "system call", "accept", 0);
        //gettimeofday(&end, NULL);
        //timeuse = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;  //微秒级别
        //string log = "Accept function total Run:" + to_string(timeuse) + "microseconds.\n";
        /*logger(LOG, "Time", log.c_str(), hit);
        gettimeofday(&start, NULL);
        pid = fork();
        gettimeofday(&end,NULL);
        timeuse = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;  //微秒级别
        log = "fork functrion total Run:" + to_string(timeuse) + "microseconds.\n";
        logger(LOG, "Time", log.c_str(), hit);
        */
        struct webparam* param = (struct webparam*)(malloc(sizeof(webparam)));
        param->socketfd = socketfd;
        param->hit = hit;
        if(pthread_create(&pth,&attr,web,(void*)param) < 0)
        {
            logger(ERROR,"system call","pthread_create",0);
        }
        /*
        if (pid < 0) {
            logger(ERROR, "system call", "fork", 0);
        } else {
            if (pid == 0) {
                auto mstart = clock();
                (void) close(listenfd);
                gettimeofday(&start, NULL);
                web(socketfd, hit);
                auto mfinish = clock();
                sem_wait(psem);
                *(clock_t*)memPtr = (*(clock_t*)memPtr) + mfinish - mstart;
                sem_post(psem);
                gettimeofday(&end, NULL);
                timeuse = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;  //微秒级别
                log = "Web total Run:" + to_string(timeuse) + "microseconds.\n";
                logger(LOG, "Time", log.c_str(), hit);
                char childbuffer[BUFSIZE * 4];
                int fdd;
                (void)sprintf(childbuffer,"Child timing%f seconds\nChild total timing:%f seconds\n",(double)(mfinish-mstart)/\
                CLOCKS_PER_SEC,(double)(*(clock_t*)memPtr)/CLOCKS_PER_SEC);
                if ((fdd=open("/Users/ryan/CLionProjects/webserver/time.log",O_CREAT|O_WRONLY|O_APPEND,0644))>=0){
                    (void)write(fdd,childbuffer,strlen(childbuffer));
                    (void)write(fdd,"\n",1);
                    (void)close(fdd);
                }
                exit(0);
            } else {
                (void) close(socketfd);
            }
        }
        */
    }
}