#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#define VERSION 23
#define BUFSIZE 8096
#define ERROR      42
#define LOG        44
#define FORBIDDEN 403
#define NOTFOUND  404
#ifndef SIGCLD
#   define SIGCLD SIGCHLD
#endif
#ifdef HASHTHREADED
#include <semaphore.h>
#endif

typedef struct content{
    long length;
    void* address;
}content;

typedef struct hashpair{
    char* key;
    content* cont;
    long condition;
    struct hashpair* next;
}hashpair;

typedef struct hashtable{
    hashpair ** bucket;
    int num_bucket;
#ifdef HASHTHREADED
    volatile int *locks;			// array of locks
	volatile int lock;				// lock for entire table
#endif
}hashtable;

static inline unsigned long int hashString(char * str)
{
    unsigned long hash = 5381;
    int c;

    while (c = *str++)
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    return hash;
}

static inline char * copystring(char * value)
{
    char * copy = (char *)malloc(strlen(value)+1);
    if(!copy) {
        printf("Unable to allocate string value %s\n",value);
        abort();
    }
    strcpy(copy,value);
    return copy;
}

static inline int isEqualContent(content* cont1,content* cont2)
{
    if(cont1->length != cont2->length)
        return 0;
    if(cont1->address != cont2->address)
        return 0;
    return 1;
}

hashtable* createHashTable(int num_bucket)
{
    // allocate space
    hashtable *table= (hashtable *)malloc(sizeof(hashtable));
    if(NULL == table) {
        // unable to allocate
        return NULL;
    }
    // locks
    table->bucket = (hashpair **)malloc(num_bucket*sizeof(void*));
    if( !table->bucket ) {
        free(table);
        return NULL;
    }
    memset(table->bucket,0,num_bucket*sizeof(void*));
    table->num_bucket = num_bucket;
#ifdef HASHTHREADED
    table->locks = (int *)malloc(num_bucket * sizeof(int));
	if( !table->locks ) {
		free(table);
		return NULL;
	}
	memset((int *)&table->locks[0],0,num_bucket*sizeof(int));
#endif
    return table;
}

void freeHashTable(hashtable* table)
{
    if(table == NULL)
        return;
    hashpair* next;
    for(int i = 0; i < table->num_bucket; i++)
    {
        hashpair* pair = table->bucket[i];
        while(pair)
        {
            next = pair->next;
            free(pair->key);
            free(pair->cont->address);
            free(pair->cont);
            free(pair);
            pair = next;
        }
    }
    free(table->bucket);
#ifdef HASHTHREADED
    free(table->locks);
#endif
    free(table);
}

int addltem(hashtable* table,char* key,content* cont)
{
    int hash = hashString(key) % table->num_bucket;
    hashpair* pair = NULL;
    hashpair* pair1 = table->bucket[hash];
    hashpair* pair2 = NULL;
#ifdef HASHTHREADED
    // lock this bucket against changes
	while (__sync_lock_test_and_set(&table->locks[hash], 1))
	{
		
	}
#endif
    if( pair1 == 0 )
    {
        pair = (hashpair*)malloc(sizeof(hashpair));
        pair->key = copystring(key);
        pair->cont = cont;
        pair->next = table->bucket[hash];
        pair->condition = 1;
        table->bucket[hash] = pair;
    }
    else
    {
        while(pair1 != 0)
        {
            if(0 == strcmp(pair1->key,key) && isEqualContent(pair1->cont,cont))
                return 1;
            if(0 == strcmp(pair1->key,key) && !isEqualContent(pair1->cont,cont))
            {
                free(pair1->cont->address);
                free(pair1->cont);

                pair1->cont = cont;
                return 0;
            }
            if(pair1->next == NULL||pair1->next->condition == 1)
            {
                pair = (hashpair*)malloc(sizeof(hashpair));
                pair->key = copystring(key);
                pair->cont = cont;
                pair->condition = 1;
                pair->next = pair1->next;
                pair1->next = pair;
                break;
            }
            pair1 = pair1->next;

        }
    }
#ifdef HASHTHREADED
    __sync_synchronize();
	table->locks[hash] = 0;
#endif
    return 2;
}

int delltem(hashtable* table,char* key)
{
    int hash = hashString(key) % table->num_bucket;
    hashpair* pair = table->bucket[hash];
    hashpair* prev = NULL;
    if(pair == 0)
        return 0;
#ifdef HASHTHREADED
    while(__sync_lock_test_and_set(&table->locks[hash],1))
	{
		
	}
#endif
    while(pair != 0)
    {
        if(0 == strcmp(pair->key,key))
        {
            if(!prev)
                table->bucket[hash] = pair->next;
            else
                prev->next = pair->next;
            free(pair->key);
            free(pair->cont->address);
            free(pair->cont);
            free(pair);
            return 1;
        }
        prev = pair;
        pair = pair->next;
    }
#ifdef HASHTHREADED
    __sync_synchronize();
	table->locks[hash] = 0;
#endif
    return 0;
}

content* getContentByKey(hashtable* table,char* key)
{
    int hash = hashString(key) % table->num_bucket;
    hashpair* pair = table->bucket[hash];
    while(pair)
    {
        if(0 == strcmp(pair->key,key))
            return pair->cont;
        pair = pair->next;
    }
    return NULL;
}

#define NUMTHREADS 8
#define HASHCOUNT 100

typedef struct threadinfo {hashtable* *table; int start;} threadinfo;
/*void * thread_func(void *arg)
{
	threadinfo *info = arg;
	char buffer[512];
	int i = info->start;
	hashtable* table = info->table;
	free(info);
	for(;i<HASHCOUNT;i+=NUMTHREADS)
	{
		sprintf(buffer,"%d",i);
		content* cont = malloc(sizeof(content));
		cont->length = rand()%2048;
		cont->address = malloc(cont->length);
		addltem(table,buffer,cont);
	}
}*/

clock_t start,end;

clock_t start1,end1;

double all = 0,readS = 0,writeS = 0,readW = 0,writeL = 0;
int num = 0;
hashtable* table;
static pthread_mutex_t mutex;
void know_time(char *s1,double i);

void know_time(char *s1,double i)

{

    int fd;

    char log[BUFSIZE*2];

    (void)sprintf(log,"%s: %lf",s1,i);



    if((fd = open("webserver.time",O_CREAT|O_WRONLY|O_APPEND,0644))>=0)

    {

        (void)write(fd,log,strlen(log));

        (void)write(fd,"\n",1);

        (void)close(fd);

    }

}
void flags(char *s1)

{
    int fd;
    if((fd = open("/home/ryan/文档/Tencent Files/617377193/FileRecv/lfu.log",O_CREAT|O_WRONLY|O_APPEND,0644))>=0)

    {

        (void)write(fd,s1,strlen(s1));

        (void)write(fd,"\n",1);

        (void)close(fd);

    }

}
struct{

    char *ext;

    char *filetype;

}extensions [] = {

        {"gif", "image/gif" },

        {"jpg", "image/jpg" },

        {"jpeg","image/jpeg"},

        {"png", "image/png" },

        {"ico", "image/ico" },

        {"zip", "image/zip" },

        {"gz",  "image/gz"  },

        {"tar", "image/tar" },

        {"htm", "text/html" },

        {"html","text/html" },

        {0,0} };

typedef struct {

    int hit;

    int fd;

}webparam;



unsigned long get_file_size(const char *path)

{

    unsigned long filesize = -1;

    struct stat statbuff;

    if(stat(path,&statbuff)<0)

        return filesize;

    else

        filesize = statbuff.st_size;

    return filesize;

}



void logger(int type, char *s1, char *s2, int socket_fd)

{

    int fd ;

    char logbuffer[BUFSIZE*2];

    switch (type) {

        case ERROR: (void)sprintf(logbuffer,"ERROR: %s:%s Errno=%d exiting pid=%d",s1, s2, errno,getpid());

            break;

        case FORBIDDEN:

            (void)write(socket_fd, "HTTP/1.1 403 Forbidden\nContent-Length: 185\nConnection: close\nContent-Type: text/html\n\n<html><head>\n<title>403 Forbidden</title>\n</head><body>\n<h1>Forbidden</h1>\nThe requested URL, file type or operation is not allowed on this simple static file webserver.\n</body></html>\n",271);

            (void)sprintf(logbuffer,"FORBIDDEN: %s:%s",s1, s2);

            break;

        case NOTFOUND:

            (void)write(socket_fd, "HTTP/1.1 404 Not Found\nContent-Length: 136\nConnection: close\nContent-Type: text/html\n\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\nThe requested URL was not found on this server.\n</body></html>\n",224);

            (void)sprintf(logbuffer,"NOT FOUND: %s:%s",s1, s2);

            break;

        case LOG: (void)sprintf(logbuffer," INFO: %s:%s:%d",s1, s2,socket_fd); break;

    }

    /* No checks here, nothing can be done with a failure anyway */

    if((fd = open("nweb.log", O_CREAT| O_WRONLY | O_APPEND,0644)) >= 0) {

        (void)write(fd,logbuffer,strlen(logbuffer));

        (void)write(fd,"\n",1);

        (void)close(fd);

    }

    //if(type == ERROR || type == NOTFOUND || type == FORBIDDEN) exit(3);

}



/* this is a web thread, so we can exit on errors */

void* web(void* data)

{

    int fd,hit;

    int j, file_fd, buflen;

    long i, ret, len, length = 0;

    char * fstr;

    char buffer[BUFSIZE+1]; /* static so zero filled */
    char buffer1[BUFSIZE+1];
    int flag;
    webparam *param=(webparam*)data;

    fd=param->fd;

    hit=param->hit;

    ret =read(fd,buffer,BUFSIZE);   /* read Web request in one go */


    if(ret == 0 || ret == -1) {  /* read failure stop now */

        logger(FORBIDDEN,"failed to read browser request","",fd);

    }

    else{

        if(ret > 0 && ret < BUFSIZE)  /* return code is valid chars */

            buffer[ret]=0;    /* terminate the buffer */

        else buffer[0]=0;

        for(i=0;i<ret;i++)  /* remove CF and LF characters */

            if(buffer[i] == '\r' || buffer[i] == '\n')

                buffer[i]='*';

        logger(LOG,"request",buffer,hit);

        if( strncmp(buffer,"GET ",4) && strncmp(buffer,"get ",4) ) {

            logger(FORBIDDEN,"Only simple GET operation supported",buffer,fd);

        }

        for(i=4;i<BUFSIZE;i++) { /* null terminate after the second space to ignore extra stuff */

            if(buffer[i] == ' ') { /* string is "GET URL " +lots of other stuff */

                buffer[i] = 0;

                break;

            }

        }

        for(j=0;j<i-1;j++)   /* check for illegal parent directory use .. */

            if(buffer[j] == '.' && buffer[j+1] == '.') {

                logger(FORBIDDEN,"Parent directory (..) path names not supported",buffer,fd);

            }

        if( !strncmp(&buffer[0],"GET /\0",6) || !strncmp(&buffer[0],"get /\0",6) ) /* convert no filename to index file */

            (void)strcpy(buffer,"GET /index.html");



        /* work out the file type and check we support it */

        buflen=strlen(buffer);

        fstr = (char *)0;

        for(i=0;extensions[i].ext != 0;i++) {

            len = strlen(extensions[i].ext);

            if( !strncmp(&buffer[buflen-len], extensions[i].ext, len)) {

                fstr =extensions[i].filetype;

                break;

            }

        }



        if(fstr == 0) logger(FORBIDDEN,"file extension type not supported",buffer,fd);



        if(( file_fd = open(&buffer[5],O_RDONLY)) == -1) {  /* open the file for reading */

            logger(NOTFOUND, "failed to open file",&buffer[5],fd);

        }
        len = (long)lseek(file_fd, (off_t)0, SEEK_END); /* lseek to the file end to find the length */

        (void)lseek(file_fd, (off_t)0, SEEK_SET); /* lseek back to the file start ready for reading */

        (void)sprintf(buffer1,"HTTP/1.1 200 OK\nServer: nweb/%d.0\nContent-Length: %ld\nConnection: close\nContent-Type: %s\n\n", VERSION, len, fstr); /* Header + a blank line
*/
        pthread_mutex_lock(&mutex);
        logger(LOG,"Header",buffer1,hit);

        (void)write(fd,buffer1,strlen(buffer1));

        /* send file in 8KB block - last block may be smaller */
        if((getContentByKey(table,&buffer[5] ) == NULL))
        {
            char *contt1 = (char *) malloc(len+1);
            ret = read(file_fd, contt1, len);
            length = len;
            content* cont3 = (content*)malloc(sizeof(content));
            cont3->length = length;
            cont3->address = contt1;
            addltem(table,&buffer[5],cont3);
            (void)write(fd,contt1,length);
            //pthread_mutex_lock(&mutex);
            if(num < 1000)
            {
                num++;
            }
            else
            {
                long hash = hashString(&buffer[5]) % table->num_bucket;
                hashpair* pair = table->bucket[hash];
                hashpair* pair1 = pair->next;
                if(pair1 != NULL)
                {
                    while(pair1->next != NULL)
                    {
                        pair = pair->next;
                        pair1 = pair->next;
                    }
                    pair->next = NULL;
                    free(pair1->key);
                    free(pair1->cont->address);
                    free(pair1->cont);
                    free(pair1);
                }
            }
            //pthread_mutex_unlock(&mutex);
            flags("Miss");
        }
        else
        {
            int hash = hashString(&buffer[5]) % table->num_bucket;
            hashpair* pair = table->bucket[hash];
            hashpair* pair1 = NULL;
            hashpair* pair2 = table->bucket[hash];
            long pos;
            while(pair2)
            {
                if(0 == strcmp(pair2->key,&buffer[5]))
                {
                    pair2->condition = pair2->condition + 1;
                    break;
                }
                pair2 = pair2->next;
            }
            (void)write(fd,pair2->cont->address,pair2->cont->length);
            //pthread_mutex_lock(&mutex);
            if(strcmp(pair->key,&buffer[5]))
            {
                while(pair)
                {
                    pair1 = pair;
                    pair = pair->next;
                    if(0 == strcmp(pair->key,&buffer[5]))
                    {
                        pos = pair->condition;
                        break;
                    }
                }
                hashpair* pair3 = table->bucket[hash];
                hashpair* pair4 = NULL;
                while(pair3)
                {
                    pair4 = pair3;
                    pair3 = pair3->next;
                    if(pair3 != NULL && (pos >= pair3->condition) && strcmp(pair3->key,&buffer[5]))
                    {
                        break;
                    }
                }
                pair4->next = pair;
                pair1->next = pair->next;
                pair->next = pair3;
            }
            else
            {

            }
            flags("Hit");
            //pthread_mutex_unlock(&mutex);

        }
        pthread_mutex_unlock(&mutex);
        usleep(10000);  /* allow socket to drain before signalling the socket is closed */

        close(file_fd);

    }

    close(fd);

    free(param);

}

int main(int argc, char **argv)

{

    int i, port, pid, listenfd, socketfd, hit ,t;
    socklen_t length;

    static struct sockaddr_in cli_addr; /* static = initialised to zeros */

    static struct sockaddr_in serv_addr; /* static = initialised to zeros */
    table = createHashTable(HASHCOUNT);
    pthread_mutex_init(&mutex, NULL);
    if( argc < 3  || argc > 3 || !strcmp(argv[1], "-?") ) {

        (void)printf("hint: nweb Port-Number Top-Directory\t\tversion %d\n\n"

                     "\tnweb is a small and very safe mini web server\n"

                     "\tnweb only servers out file/web pages with extensions named below\n"

                     "\t and only from the named directory or its sub-directories.\n"

                     "\tThere is no fancy features = safe and secure.\n\n"

                     "\tExample: nweb 8181 /home/nwebdir &\n\n"

                     "\tOnly Supports:", VERSION);

        for(i=0;extensions[i].ext != 0;i++)

            (void)printf(" %s",extensions[i].ext);

        (void)printf("\n\tNot Supported: URLs including \"..\", Java, Javascript, CGI\n"

                     "\tNot Supported: directories / /etc /bin /lib /tmp /usr /dev /sbin \n"

                     "\tNo warranty given or implied\n\tNigel Griffiths nag@uk.ibm.com\n"  );

        exit(0);

    }

    if( !strncmp(argv[2],"/"   ,2 ) || !strncmp(argv[2],"/etc", 5 ) ||

        !strncmp(argv[2],"/bin",5 ) || !strncmp(argv[2],"/lib", 5 ) ||

        !strncmp(argv[2],"/tmp",5 ) || !strncmp(argv[2],"/usr", 5 ) ||

        !strncmp(argv[2],"/dev",5 ) || !strncmp(argv[2],"/sbin",6) ){

        (void)printf("ERROR: Bad top directory %s, see nweb -?\n",argv[2]);

        exit(3);

    }

    if(chdir(argv[2]) == -1){

        (void)printf("ERROR: Can't Change to directory %s\n",argv[2]);

        exit(4);

    }

    /* Become deamon + unstopable and no zombies children (= no wait()) */

    if(fork() != 0)

        return 0; /* parent returns OK to shell */

    (void)signal(SIGCLD, SIG_IGN); /* ignore child death */

    (void)signal(SIGHUP, SIG_IGN); /* ignore terminal hangups */

    for(i=0;i<32;i++)

        (void)close(i);    /* close open files */

    (void)setpgrp();    /* break away from process group */

    logger(LOG,"nweb starting",argv[1],getpid());

    /* setup the network socket */

    if((listenfd = socket(AF_INET, SOCK_STREAM,0)) <0)

        logger(ERROR, "system call","socket",0);

    port = atoi(argv[1]);

    if(port < 0 || port >60000)

        logger(ERROR,"Invalid port number (try 1->60000)",argv[1],0);

    //初始化线程属性为分离状态

    pthread_attr_t attr;

    pthread_attr_init(&attr);

    pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);

    //

    pthread_t pth;

    serv_addr.sin_family = AF_INET;

    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    serv_addr.sin_port = htons(port);

    if(bind(listenfd, (struct sockaddr *)&serv_addr,sizeof(serv_addr)) <0)

        logger(ERROR,"system call","bind",0);

    if( listen(listenfd,64) <0)

        logger(ERROR,"system call","listen",0);

    for(hit=1; ;hit++) {

        length = sizeof(cli_addr);

        if((socketfd = accept(listenfd, (struct sockaddr *)&cli_addr, &length)) < 0)

            logger(ERROR,"system call","accept",0);

        webparam *param=malloc(sizeof(webparam));

        param->hit=hit;

        param->fd=socketfd;

        if(pthread_create(&pth,&attr,&web,(void*)param)<0){

            logger(ERROR,"system call","pthread_creat",0);

        }

    }

}