/***********mutify thread***************/


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
#include <pthread.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <stdbool.h>
#define VERSION 23
#define BUFSIZE 8096
#define ERROR      42
#define LOG        44
#define FORBIDDEN 403
#define NOTFOUND  404

#ifndef SIGCLD
#define SIGCLD SIGCHLD
#endif

struct {
    char *ext;
    char *filetype;
} extensions [] = {
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

typedef struct{
    int hit;
    int fd;
}webparam;

/***************thread pool****************/
/*queue status and conditional variable*/

typedef struct stacnov
{
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool status;
}staconv;

/*Task*/
typedef struct task
{
    struct task* next;
    void *(*function)(void* arg);
    void* arg;
}task;

/*Task Queue*/
typedef struct taskqueue
{
    pthread_mutex_t mutex;
    task *front;
    task *rear;
    staconv* has_jobs;
    int len;
}taskqueue;

/*Thread Poll*/
typedef struct threadpool
{
    struct thread* threads;
    volatile int num_threads;
    volatile int num_working;
    pthread_mutex_t thcount_lock;
    pthread_cond_t threads_all_idle;
    taskqueue queue;
    volatile bool is_alive;
}threadpool;

/*Thread*/
typedef struct thread
{
    int id;
    pthread_t pthread;
    threadpool* pool;
}thread;



void* thread_do(void* pthread);
void init_taskqueue(taskqueue* queue);
void push_taskqueue(taskqueue* queue,task* curtask);
task* take_taskqueue(taskqueue* queue);
void destory_taskqueue(taskqueue* queue);
int create_thread(threadpool* pool,thread* pthread,int id);
threadpool* initThreadPool(int num_threads);
void addTask2ThreadPool(threadpool* pool,task* curtask);
int getNumofThreadWorking(threadpool* pool);
void destoryThreadPool(threadpool* pool);
void waitThreadPool(threadpool* pool);


int rem(char *str)
{
    int fdd;
    if((fdd = open("rem.log", O_CREAT| O_WRONLY | O_APPEND,0644)) >= 0) {
        (void)write(fdd,str,strlen(str));
        (void)write(fdd,"\n",1);
        (void)close(fdd);
    }
}
void init_taskqueue(taskqueue* queue)
{

    pthread_mutex_init(&(queue->mutex),NULL);

    queue->front = NULL;
    queue->rear = NULL;
    queue->has_jobs = (staconv*)malloc(sizeof(staconv));
    queue->has_jobs->status = false;

    queue->len = 0;

    pthread_mutex_init(&(queue->has_jobs->mutex),NULL);
    pthread_cond_init(&(queue->has_jobs->cond),NULL);
}

void push_taskqueue(taskqueue* queue,task* curtask)
{
    pthread_mutex_lock (&(queue->mutex));
    curtask->next = NULL;
    if (queue->len == 0)
    {
        queue->rear=curtask;
        queue->front=curtask;
    }
    else
    {
        queue->has_jobs->status=1;
        queue->rear->next = curtask;
        queue->rear = curtask;
    }
    //assert (queue->front != NULL);
    queue->len++;
    if(queue->has_jobs->status == false)
    {
        queue->has_jobs->status = true;
    }
    pthread_cond_signal (&(queue->has_jobs->cond));
    pthread_mutex_unlock (&(queue->mutex));
    return ;
}

task* take_taskqueue(taskqueue* queue)
{
    while(queue->has_jobs->status == false)
    {
        pthread_cond_wait(&(queue->has_jobs->cond),&(queue->mutex));
    }
    task* pro = queue->front;
    queue->front = queue->front->next;
    queue->len--;
    if(queue->len == 0)
        queue->has_jobs->status = false;
    return pro;
}


void destory_taskqueue(taskqueue* queue)
{
    task* head;
    while(queue->front != NULL)
    {
        head = queue->front;
        queue->front = queue->front->next;
        free(head);
    }
    pthread_mutex_destroy(&(queue->has_jobs->mutex));
    pthread_cond_destroy(&(queue->has_jobs->cond));
    pthread_mutex_destroy(&(queue->mutex));
    return ;
}

int create_thread(threadpool* pool,thread* pthread,int id)
{
    //为thread分配空间
    pthread = (thread*)malloc(sizeof(thread));
    if(pthread == NULL)
    {
        perror("creat_thread():Couldn't allocate memory for thread\n");
        return -1;
    }
    //设置thread属性
    (pthread)->pool = pool;
    (pthread)->id = id;
    //创建线程
    pthread_create(&((pthread)->pthread),NULL,thread_do,(pthread));
    pthread_detach((pthread)->pthread);
    return 0;
}

threadpool* initThreadPool(int num_threads)
{
    //创建线程池空间
    threadpool* pool;
    pool = (threadpool*)malloc(sizeof(threadpool));
    pool->num_threads = 0;
    pool->num_working = 0;
    pool->is_alive = true;

    //初始化互斥量和条件变量
    pthread_mutex_init(&(pool->thcount_lock),NULL);
    pthread_cond_init(&(pool->threads_all_idle),NULL);

    //初始化任务队列
    init_taskqueue(&pool->queue);
    //创建线程数组

    pool->threads = (thread *)malloc(num_threads * sizeof(thread));

    //创建线程
    int i;
    for(i = 0;i < num_threads;i++)
        create_thread(pool,&(pool->threads[i]),i);

    while(pool->num_threads != num_threads){}

    return pool;
}

void addTask2ThreadPool(threadpool* pool,task* curtask)
{
    //将任务加入队列
    push_taskqueue(&pool->queue,curtask);
}

void waitThreadPool(threadpool* pool)
{
    pthread_mutex_lock(&pool->thcount_lock);
    if(pool->queue.len || pool->num_working)
    {

        pthread_cond_wait(&pool->threads_all_idle,&pool->thcount_lock);
    }
    pthread_mutex_unlock(&pool->thcount_lock);
}

void destoryThreadPool(threadpool* pool)
{
    waitThreadPool(pool);
    //销毁任务队列
    destory_taskqueue(&pool->queue);
    pool->is_alive = false;
    pthread_cond_broadcast(&(pool->threads_all_idle));
    int i;
    for (i = 0; i < pool->num_threads; ++i)
        free(&(pool->threads[i]));
    free(pool->threads);
    pthread_mutex_destroy(&(pool->thcount_lock));
    pthread_cond_destroy(&(pool->threads_all_idle));
}

int getNumofThreadWorking(threadpool* pool)
{
    return pool->num_working;
}

void* thread_do(void* _thread_p)
{
    /*设置线程名字*/
    thread* thread_p = (thread*)_thread_p;
    char thread_name[128] = {0};
    sprintf(thread_name,"thread-pool-%d",thread_p->id);
    prctl(PR_SET_NAME,thread_name);

    /*获得线程池*/
    threadpool* pool = thread_p->pool;
    taskqueue* queue = &pool->queue;
    pthread_mutex_lock(&(pool->thcount_lock));
    (pool->num_threads)++;
    pthread_mutex_unlock(&(pool->thcount_lock));
    /*线程一直循环往复运行，直到pool->is_alive变为false*/
    while(pool->is_alive)
    {
        /*如果任务队列还有任务，则继续运行，否则阻塞*/
        //waitThreadPool(pool);
        pthread_mutex_lock(&(pool->thcount_lock));
        while(queue->has_jobs->status == false && pool->is_alive)
        {
            pthread_cond_wait(&(queue->has_jobs->cond),&(pool->thcount_lock));
        }
        if(pool->is_alive)
        {
            /*对工作中的线程进行计数*/
            (pool->num_working)++;
            /*从任务队列头部提取任务,执行并在队列中删除此任务*/
            void *(*func)(void*);
            void* arg;

            task* curtask = take_taskqueue(&pool->queue);
            if(curtask)
            {
                pthread_mutex_unlock(&(pool->thcount_lock));
                func = curtask->function;
                arg = curtask->arg;
                //执行任务
                func(arg);
                //释放任务
                free(curtask);
            }
            pthread_mutex_lock(&(pool->thcount_lock));
            (pool->num_working)--;
            if(pool->num_working == 0)
            {
                pthread_cond_signal(&(pool->threads_all_idle));
            }
            pthread_mutex_unlock(&(pool->thcount_lock));
        }
    }
    pthread_mutex_lock(&(pool->thcount_lock));
    (pool->num_threads)--;
    pthread_mutex_unlock(&(pool->thcount_lock));
    return NULL;
}
/***************thread pool****************/



unsigned long get_file_size(const char *path)
{
    unsigned long filesize = -1;
    struct stat statbuff;
    if(stat(path, &statbuff) < 0){
        return filesize;
    }else{
        filesize = statbuff.st_size;
    }
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
    long i, ret, len;
    char * fstr;
    char buffer[BUFSIZE+1]; /* static so zero filled */
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
        logger(LOG,"SEND",&buffer[5],hit);

        len = (long)lseek(file_fd, (off_t)0, SEEK_END); /* lseek to the file end to find the length */
        (void)lseek(file_fd, (off_t)0, SEEK_SET); /* lseek back to the file start ready for reading */
        (void)sprintf(buffer,"HTTP/1.1 200 OK\nServer: nweb/%d.0\nContent-Length: %ld\nConnection: close\nContent-Type: %s\n\n", VERSION, len, fstr); /* Header + a blank line */

        logger(LOG,"Header",buffer,hit);
        (void)write(fd,buffer,strlen(buffer));

        /* send file in 8KB block - last block may be smaller */
        while (  (ret = read(file_fd, buffer, BUFSIZE)) > 0 ) {
            (void)write(fd,buffer,ret);
        }
        usleep(10000);  /* allow socket to drain before signalling the socket is closed */
        close(file_fd);
    }
    close(fd);
    free(param);
}
int main(int argc, char **argv)
{
    int i, port, pid, listenfd, socketfd, hit;
    socklen_t length;
    static struct sockaddr_in cli_addr; /* static = initialised to zeros */
    static struct sockaddr_in serv_addr; /* static = initialised to zeros */
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

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(port);

    struct threadpool* pool = initThreadPool(50);
    if(bind(listenfd, (struct sockaddr *)&serv_addr,sizeof(serv_addr)) <0)
        logger(ERROR,"system call","bind",0);
    if( listen(listenfd,64) <0)
        logger(ERROR,"system call","listen",0);
    for(hit=1; ;hit++)
    {
        rem("***");
        length = sizeof(cli_addr);
        rem("&");
        if((socketfd = accept(listenfd, (struct sockaddr *)&cli_addr, &length)) < 0)
        {
            logger(ERROR,"system call","accept",0);
            rem("!");
        }
        rem("%");
        webparam *param = (webparam*)malloc(sizeof(webparam));
        rem("#");
        param->hit = hit;
        param->fd = socketfd;
        struct task* ltask = (task*)malloc(sizeof(struct task));
        rem("#");
        ltask->function = &web;
        ltask->arg = param;
        ltask->next = ltask;
        addTask2ThreadPool(pool,ltask);
        rem("#");
    }
    return 0;
}

