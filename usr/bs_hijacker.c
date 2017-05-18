#include "bs_hijacker.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h> 
#include <sys/socket.h> 
#include <sys/un.h>
#include <sys/eventfd.h>
#include <string.h> 
#include <stdbool.h>
#include <assert.h>
#include "tgtd.h"
#include "scsi.h"
#include "util.h"

#define HIJACKER_MAGIC (0xAA)

hijacker_volume_mgr_t g_volume_mgr;

/*volume*/
static int bs_volume_init(hijacker_volume_t* volume, char* volume_name, 
                          char* device_path, char* host, short port);
static void bs_volume_deinit(hijacker_volume_t* volume);
static void bs_volume_reinit(hijacker_volume_t* volume);

/*socket*/
static int bs_socket_set_nonblock(int fd)
{
    int flags;
    flags = fcntl(fd, F_GETFL, 0);
    if(flags < 0)
        return flags;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int bs_socket_set_block(int fd)
{
    int flags;
    flags = fcntl(fd, F_GETFL, 0);
    if(flags < 0)
        return flags;

    return fcntl(fd, F_SETFL, flags | ~O_NONBLOCK);
}

static int bs_socket_set_nodelay(int fd)
{
    int disable = 1;
    int ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                         &disable, sizeof(disable));
    return ret;
}

static int bs_socket_set_sndbuf(int fd, int size)
{
    socklen_t len;
    len = sizeof(size);
    return setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, len);
} 

static int bs_socket_set_rcvbuf(int fd, int size)
{
    socklen_t len;
    len = sizeof(size);
    return setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, len);
} 

static int bs_socket_init(hijacker_volume_t* volume, char* host, short port)
{
    int ret = 0;
    volume->jwriter_host = strdup(host);
    volume->jwriter_port = port;

#ifndef _USE_UNIX_DOMAIN
    volume->jwriter_sock = socket(AF_INET, SOCK_STREAM, 0);
#else
    volume->jwriter_sock = socket(AF_UNIX, SOCK_STREAM, 0);
#endif
    if(-1 == volume->jwriter_sock){
        eprintf("failed to create socket err=%d \n", errno);
        ret = -1;
        goto err;
    }

#ifndef _USE_UNIX_DOMAIN
    struct sockaddr_in jwriter_addr;
    memset(&jwriter_addr, 0, sizeof(jwriter_addr));
    jwriter_addr.sin_family = AF_INET;
    jwriter_addr.sin_port = htons(port);
    ret = inet_pton(AF_INET, host, &jwriter_addr.sin_addr);
    if(ret <= 0){
        eprintf("failed to inet_pton, host:%s port:%d errno:%d error:%s \n",
                host, port, errno,strerror(ret));
        goto err;
    }
    ret = connect(volume->jwriter_sock, &jwriter_addr, sizeof(jwriter_addr));
    if(ret < 0){
        eprintf("failed to connect,host:%s port:%d errno:%d error:%s \n",
                host, port, errno, strerror(ret));
        goto err;
    }
#else
    struct sockaddr_un addr;
    memset(&addr,0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, host, strlen(host));
    ret = connect(volume->jwriter_sock, &addr, sizeof(addr));
    if(ret < 0){
        eprintf("connect unix domain name:%s \n", host);
        goto err;
    }
#endif

   // ret = bs_socket_set_nonblock(volume->jwriter_sock);
   // if(ret < 0){
   //     eprintf("failed to socket set nonblock, errno:%d \n", errno);
   //     goto err;
   // }
   
#ifndef _USE_UNIX_DOMAIN
    ret = bs_socket_set_nodelay(volume->jwriter_sock);
    if(ret < 0){
        eprintf("failed to socket set nodelay, errno:%d \n", errno);
        goto err;
    }
    //const int buf_size = 8*1024*1024U;
    //ret = bs_socket_set_sndbuf(volume->jwriter_sock, buf_size);
    //if(ret < 0){
    //    eprintf("failed to socket set sndbuf, errno:%d \n", errno);
    //    goto err;
    //}

    //ret = bs_socket_set_rcvbuf(volume->jwriter_sock, buf_size);
    //if(ret < 0){
    //    eprintf("failed to socket set rcvbuf, errno:%d \n", errno);
    //    goto err;
    //}
#endif

    eprintf("socket init ok \n");
    return ret;
err:
    eprintf("socket init failed \n");
    return ret;
}

static void bs_socket_fini(hijacker_volume_t* volume)
{
    if(volume && -1 != volume->jwriter_sock){
        close(volume->jwriter_sock);
    }
    eprintf("socket fini ok \n");
}

static int bs_socket_send(hijacker_volume_t* volume, char* buf, ssize_t buf_len)
{
    ssize_t nwrite = 0;
    char*   pbuf   = buf;
    ssize_t nleft  = buf_len;
   
   while (0 != nleft) {
        nwrite = write(volume->jwriter_sock, pbuf, nleft);
        if (0 == nwrite) {
            eprintf("failed to socket write err:%d nwrite:%ld \n", 
                    errno, nwrite);
            return nwrite;
        }

        if (-1 == nwrite) {
            if(errno == EAGAIN || errno == EINTR){
                eprintf("socket write busy wait errno:%d \n", errno);
                continue;
            }
            eprintf("failed to socket write err:%d nwrite:%ld \n", 
                    errno, nwrite);
            return nwrite;
        }
        pbuf  += nwrite;
        nleft -= nwrite;
    }
    return buf_len;
}

static int bs_socket_recv(hijacker_volume_t* volume, char* buf, int buf_len)
{
    char*    pbuf  = buf;
    uint32_t nleft = buf_len;
    ssize_t  nread = 0;

   while(0 != nleft){
        nread = read(volume->jwriter_sock, pbuf, nleft);
        if(0 == nread){
            eprintf("failed socket read data err=%d \n", errno);
            return -1;
        }

        if(-1 == nread){
            if(errno == EAGAIN || errno == EINTR){
                eprintf("socket read busy errno:%d nleft:%d \n", errno, nleft);
                continue;
            }
            eprintf("failed socket read data err:%d \n", errno);
            return -1;
        }

        nleft -= nread;
        pbuf  += nread;
    }

    return buf_len;
}

/*eventfd*/
int _eventfd_read(int eventfd)
{
    uint64_t u;
    int ret = read(eventfd, &u, sizeof(uint64_t));
    if(ret != sizeof(uint64_t)){
        eprintf("eventfd read failed ret=%d errno;%d \n", ret, errno);
        return -1;
    }
    return 0;
}

int _eventfd_write(int eventfd)
{
    /*here should not be 0, otherwise will not be trigfer*/
    uint64_t u = 1;
    int ret = write(eventfd, &u, sizeof(uint64_t));
    if(ret != sizeof(uint64_t)){
        eprintf("eventfd write failed ret=%d errno;%d \n", ret, errno);
        return -1;
    }
    return 0;
}

/*basic*/
static inline hijacker_volume_t* bs_volume(struct scsi_lu* lu)
{
    return (hijacker_volume_t*)((char*)lu + sizeof(*lu));
}

static hijacker_request_t* bs_request_create(hijacker_volume_t* volume,
                                             struct scsi_cmd* cmd)
{
    int io_req_len = sizeof(hijacker_request_t);
    hijacker_request_t* io_req = (hijacker_request_t*)malloc(io_req_len);
    assert(NULL != io_req);
    memset(io_req, 0, io_req_len);
    io_req->magic = HIJACKER_MAGIC;
    io_req->seq = volume->request_id++;
    io_req->handle = (uint64_t)cmd;
    switch (cmd->scb[0]) {
        case SYNCHRONIZE_CACHE:
        case SYNCHRONIZE_CACHE_16:
            io_req->type = SYNC_CACHE;
            break;
        case WRITE_6:
        case WRITE_10:
        case WRITE_12:
        case WRITE_16:
            io_req->type  = SCSI_WRITE;
            io_req->offset = cmd->offset;
            io_req->len = scsi_get_out_length(cmd);
            break;
        case READ_6:
        case READ_10:
        case READ_12:
        case READ_16:
            io_req->type = SCSI_READ;
            io_req->offset = cmd->offset;
            io_req->len = scsi_get_in_length(cmd);
            break;
        default:
            eprintf("cmd->scb[0]:%x \n", cmd->scb[0]);
            break;
    }

    return io_req;
}

static void bs_request_destroy(hijacker_request_t* req)
{
    if (req) {
        free(req);
    }
}

/*callback*/
void socket_write_callback(int fd, int events, void* data);
void socket_read_callback(int fd, int events, void* data);
void socket_callback(int fd, int events, void*data);

void eventfd_callback(int fd, int events, void* data)
{
    hijacker_volume_t* volume = (hijacker_volume_t*)data;
  
    _eventfd_read(fd);
    
    list_splice_init(&volume->pending_list, &volume->sending_list);

    tgt_event_del(volume->pending_eventfd);

    int ret = tgt_event_add(volume->jwriter_sock, 
                            EPOLLOUT | EPOLLRDHUP,
                            socket_callback, 
                            volume);
    if(ret){
        eprintf("failed to tgt event add, errno:%d \n", errno);
    }

}

void socket_write_callback(int fd, int events, void* data)
{
    hijacker_volume_t* volume = (hijacker_volume_t*)data;
    struct scsi_cmd* cur_cmd = NULL;
    struct scsi_cmd* next_cmd = NULL;

    if(list_empty(&volume->sending_list)){
        eprintf("socket_write_callback send queue empty \n");
        return;
    }

    list_for_each_entry_safe(cur_cmd, next_cmd, &volume->sending_list, bs_list){
        hijacker_request_t* request = bs_request_create(volume, cur_cmd);
        if(request){
#if 0
            eprintf("send thr request magic:%d id:%d type:%d handle:%ld off=%ld len:%d\n",
                    request->magic, request->seq, request->type, 
                    request->handle, request->offset, request->len);
#endif
            /*send request head*/
            bs_socket_send(volume, (char*)request, sizeof(hijacker_request_t));
            
            /*send request body*/
            if(request->type == SCSI_WRITE){
                bs_socket_send(volume, 
                               scsi_get_out_buffer(cur_cmd), 
                               scsi_get_out_length(cur_cmd));
            }

            bs_request_destroy(request);
        }
    }

    int ret = tgt_event_modify(volume->jwriter_sock, 
                               EPOLLIN|EPOLLRDHUP);
    if(ret < 0){
        eprintf("socket_write_callback modify epolin failed \n");
        return;
    }
}

void socket_read_callback(int fd, int events, void* data)
{
    int ret = 0;
    hijacker_volume_t* volume = (hijacker_volume_t*)data;
    hijacker_reply_t* reply =  NULL;
    do {
        hijacker_reply_t reply_head = {0};
        ret = bs_socket_recv(volume, (char*)&reply_head, sizeof(reply_head));
        if(ret != sizeof(reply_head)){
            eprintf("bs_socket_recv read reply head failed ret:%d want:%ld \n",
                    ret, sizeof(reply_head));
            break;
        }

        if(reply_head.magic != HIJACKER_MAGIC){
            eprintf("bs_socket_recv read reply format failed \n");
            break;
        }

        size_t reply_len = sizeof(hijacker_reply_t) + reply_head.len;
        reply = (hijacker_reply_t*)malloc(reply_len);
        memset(reply, 0, sizeof(hijacker_reply_t));
        memcpy(reply, &reply_head, sizeof(reply_head));

        if(reply->len > 0){
            ret = bs_socket_recv(volume, (char*)reply->data, reply->len);
            if(ret != reply->len){
                eprintf("bs_socket_recv read reply body failed ret:%d want:%d \n",
                        ret, reply->len);
                break;
            }
        }

#if 0
        eprintf("recv thr reply magic:%d id:%d err:%d handle:%ld len:%d \n",
                reply->magic, reply->seq, reply->error, 
                reply->handle, reply->len);
#endif

        struct scsi_cmd* cmd = (struct scsi_cmd*)reply->handle;
        switch(cmd->scb[0])
        {
            case READ_6:
            case READ_10:
            case READ_12:
                memcpy(scsi_get_in_buffer(cmd), reply->data, reply->len);
                cmd->result = reply->error;
                break;
            case WRITE_6:
            case WRITE_10:
            case WRITE_12:
                break;
            default:
                break;
        }

        target_cmd_io_done(cmd, cmd->result);

        /*remove from sending_list*/
        list_del(&cmd->bs_list);  

    }while(0);

    if(reply){
        free(reply);
    }

    if(list_empty(&volume->sending_list)){
        tgt_event_del(volume->jwriter_sock);
        ret = tgt_event_add(volume->pending_eventfd, 
                            EPOLLIN,
                            eventfd_callback, volume);
        if(ret){
            eprintf("rearm pending eventfd read event failed, errno:%d \n", errno);
        }
    }
}

void socket_callback(int fd, int events, void*data)
{
    hijacker_volume_t* volume = (hijacker_volume_t*)data;

    if(events & EPOLLRDHUP){
        eprintf("peer is close, please reconnect \n"); 
        return bs_volume_reinit(volume);
    }

    if(events & EPOLLIN){
        return socket_read_callback(fd, events, data);
    }

    if(events & EPOLLOUT){
        return socket_write_callback(fd, events, data);
    }
}

/*string util*/
static char* util_slurp_to_semi(char **p)
{
    char *end = index(*p, ';');
    char *ret;
    int len;

    if (end == NULL)
        end = *p + strlen(*p);
    len = end - *p;
    ret = malloc(len + 1);
    strncpy(ret, *p, len);
    ret[len] = '\0';
    *p = end;
    /* Jump past the semicolon, if we stopped at one */
    if (**p == ';')
        *p = end + 1;
    return ret;
}

static char* util_slurp_value(char **p)
{
    char *equal = index(*p, '=');
    if (equal) {
        *p = equal + 1;
        return util_slurp_to_semi(p);
    } else {
        return NULL;
    }
}

static int util_is_opt(const char *opt, char *p)
{
    int ret = 0;
    if ((strncmp(p, opt, strlen(opt)) == 0) &&
            (p[strlen(opt)] == '=')) {
        ret = 1;
    }
    return ret;
}

/*business*/
static void bs_volume_mgr_init(hijacker_volume_mgr_t* vol_mgr) 
{
    INIT_LIST_HEAD(&vol_mgr->volumes_list);
    pthread_mutex_init(&vol_mgr->mgr_lock, NULL);
}

static void bs_volume_mgr_fini(hijacker_volume_mgr_t* vol_mgr)
{
    return;
}

/*todo: block notify server start/stop volume protected*/
static int bs_volume_notify(hijacker_volume_t* volume, bool start)
{
    int req_len = sizeof(hijacker_request_t);
    req_len += start ? sizeof(add_vol_req_t) : sizeof(del_vol_req_t);

    hijacker_request_t* req = (hijacker_request_t*)malloc(req_len);
    memset(req, 0, req_len);
    req->magic = HIJACKER_MAGIC;
    req->type = start ? ADD_VOLUME : DEL_VOLUME;
    req->seq = volume->request_id++;
    req->handle = 0;
    req->offset = 0;
    req->len = start ? sizeof(add_vol_req_t) : sizeof(del_vol_req_t);
   
    if(start){
        add_vol_req_t* add_vol = (add_vol_req_t*)req->data;
        strcpy(add_vol->volume_name, volume->volume_name);
        strcpy(add_vol->device_path, volume->device_path);
    } else {
        del_vol_req_t* add_vol = (del_vol_req_t*)req->data;
        strcpy(add_vol->volume_name, volume->volume_name);
    }

    int ret = bs_socket_send(volume, (char*)req, req_len);
    if(ret != req_len){
        eprintf("notify start send err ret:%d size:%d \n", ret, req_len);
        goto out;;
    }

    hijacker_reply_t reply = {0};
    ret = bs_socket_recv(volume, (char*)&reply, sizeof(reply));
    if(ret != sizeof(reply)){
        eprintf("notify start recv err ret:%d size:%ld \n", ret, sizeof(reply));
        goto out;
    }
    
    if(reply.error == 0){
        eprintf("notify %s ok\n", (start ? "start" : "stop"));
        ret = 0;
    } else {
        eprintf("notify %s failed\n", (start ? "start" : "stop"));
        ret = -1;
    }

out:
    if(req){
        free(req);
    }
    return ret;;
}

static int bs_volume_init(hijacker_volume_t* volume, 
                          char* volume_name, 
                          char* device_path,
                          char* host, 
                          short port)
{
    int ret;
    INIT_LIST_HEAD(&volume->volume_list);

    strcpy(volume->volume_name, volume_name);
    strcpy(volume->device_path, device_path);
    volume->request_id  = 0;

    ret = bs_socket_init(volume, host, port);
    if(ret){
        eprintf("failed to socket init., %s \n", strerror(ret));
        goto err;
    }
    ret = bs_volume_notify(volume, true);
    if(ret){
        eprintf("failed to volume notify start \n");
        goto err;
    }

    INIT_LIST_HEAD(&volume->pending_list);
    volume->pending_eventfd = eventfd(0, EFD_NONBLOCK);
    ret = tgt_event_add(volume->pending_eventfd, 
                        EPOLLIN,
                        eventfd_callback, volume);
    if(ret < 0){
        eprintf("failed to add pending read event, errno:%d \n", errno);
        goto err;
    }
    INIT_LIST_HEAD(&volume->sending_list);
    eprintf("volume init ok \n");
    return 0;
err:
    bs_volume_deinit(volume);
    eprintf("volume init failed \n");
    return -1;
}

static void bs_volume_deinit(hijacker_volume_t* volume)
{    
    eprintf("volume deinit \n");
    int ret = bs_volume_notify(volume,false);
    if(ret){
        eprintf("failed to volume notify stop \n");
    }
    bs_socket_fini(volume);
    volume->request_id = 0;
    eprintf("volume deinit ok \n");
    /*todo: other resouce free*/
}

static void bs_volume_reinit(hijacker_volume_t* volume)
{
    bs_volume_deinit(volume);
    const int retry = 5;
    int i;
    int ret = 0;
    for(i = 0; i < retry; i++)
    {
        ret = bs_volume_init(volume, volume->volume_name, volume->device_path,
                             volume->jwriter_host, volume->jwriter_port);
        if(ret == 0){
            eprintf("reconnect journal server ok \n");
            break; 
        }
        bs_volume_deinit(volume);
        sleep(5);
    }
    
    if(i == retry){
        eprintf("reconnect journal server failed");
    }
}

static tgtadm_err bs_hijacker_init(struct scsi_lu* lu, char* bsopts)
{
    hijacker_volume_t* volume = bs_volume(lu);
    if(!volume){
        eprintf("allocate memory failed \n");
        return TGTADM_NOMEM;
    }

    char* host = NULL;
    short port = 0;
    char* volume_name = NULL;
    char* device_path = NULL;

    eprintf("hijacker init bsopts:%s ok \n",bsopts);

    while(bsopts && strlen(bsopts)){
        if(util_is_opt("host", bsopts)){
            host = util_slurp_value(&bsopts);
        } else if (util_is_opt("port", bsopts)){
            char* port_str = util_slurp_value(&bsopts);
            port = atoi(port_str);
        }  else if (util_is_opt("volume", bsopts)){
            volume_name = util_slurp_value(&bsopts);
        }  else if (util_is_opt("device", bsopts)){
            device_path = util_slurp_value(&bsopts);
        } else {
            char* ignore = util_slurp_to_semi(&bsopts);
            eprintf("ignoring unkown option %s \n", ignore);
            free(ignore);
            break;
        }
    }

    if(!host){
        eprintf("Crit: you should config log server host ip \n");
        return TGTADM_UNKNOWN_ERR;
    }

    int ret = bs_volume_init(volume,volume_name,device_path, host, port); 
    if(ret < 0){
        eprintf("failed to bs_volume_init \n");
        return TGTADM_UNKNOWN_ERR;
    }

    eprintf("hijacker init host:%s port:%d volume_name:%s device_path:%s ok \n", 
            host, port, volume_name, device_path);
    return TGTADM_SUCCESS;
}

static void bs_hijacker_exit(struct scsi_lu* lu)
{
    hijacker_volume_t* volume = bs_volume(lu);
    assert(NULL != volume);
    bs_volume_deinit(volume);
    eprintf("hijacker exit ok \n");
}

static int bs_hijacker_open(struct scsi_lu* lu, char* path, 
                            int* fd, uint64_t* size)
{
    uint32_t blksize = 0;

    *fd = backed_file_open(path, O_RDWR | O_LARGEFILE | lu->bsoflags, 
                           size, &blksize);
    if(*fd == -1 && (errno == EACCES || errno == EROFS)){
        *fd = backed_file_open(path, O_RDONLY | O_LARGEFILE | lu->bsoflags, 
                               size, &blksize);
        lu->attrs.readonly = 1;
    }

    if(*fd < 0){
        eprintf("update lbppe size=%ld blksize=%d \n", *size, blksize);
        update_lbppbe(lu, blksize);
    }

    eprintf("open path=%s ok \n", path);
    return 0;
}

static void bs_hijacker_close(struct scsi_lu* lu)
{
    if(lu && (-1 != lu->fd))
        close(lu->fd);
    eprintf("close ok \n");
    return ;
}


static int bs_hijacker_cmd_submit(struct scsi_cmd* cmd)
{
    struct scsi_lu* lu = cmd->dev;
    hijacker_volume_t* volume = bs_volume(lu);

    switch (cmd->scb[0]) {
        case SYNCHRONIZE_CACHE:
        case SYNCHRONIZE_CACHE_16:
        case WRITE_6:
        case WRITE_10:
        case WRITE_12:
        case WRITE_16:
        case READ_6:
        case READ_10:
        case READ_12:
        case READ_16:
            break;
        default:
            cmd->result = 0;
            target_cmd_io_done(cmd, cmd->result);
            set_cmd_async(cmd);
            return 0;
    }

    list_add_tail(&cmd->bs_list, &volume->pending_list);
    _eventfd_write(volume->pending_eventfd);

    set_cmd_async(cmd);
    return 0;
}

static struct backingstore_template hijacker_bst = 
{
    .bs_name = "hijacker",
    .bs_datasize = sizeof(hijacker_volume_t),

    .bs_open = bs_hijacker_open,
    .bs_close = bs_hijacker_close,
    .bs_init  = bs_hijacker_init,
    .bs_exit  = bs_hijacker_exit,
    .bs_cmd_submit = bs_hijacker_cmd_submit,
    .bs_oflags_supported = O_SYNC | O_DIRECT,
};

__attribute__((constructor)) static void bs_hijacker_constructor(void)
{
    bs_volume_mgr_init(&g_volume_mgr);
    register_backingstore_template(&hijacker_bst);
}
