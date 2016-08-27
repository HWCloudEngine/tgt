#include "bs_hijacker.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h> 
#include <sys/socket.h> 
#include <string.h> 
#include <stdbool.h>
#include <assert.h>

#include "tgtd.h"
#include "scsi.h"
#include "util.h"

#include "tracer/tp.h"

#define HIJACKER_MAGIC (0xAA)

hijacker_volume_mgr_t g_volume_mgr;

static void bs_volume_mgr_init(hijacker_volume_mgr_t* vol_mgr) {
    INIT_LIST_HEAD(&vol_mgr->volumes_list);
    pthread_mutex_init(&vol_mgr->mgr_lock, NULL);
}

static inline hijacker_volume_t* bs_volume(struct scsi_lu* lu){
    return (hijacker_volume_t*)((char*)lu + sizeof(*lu));
}

static hijacker_request_t* bs_request_construct(struct scsi_cmd* cmd) {
    hijacker_request_t* io_request = NULL;
    switch (cmd->scb[0]) {
        case SYNCHRONIZE_CACHE:
        case SYNCHRONIZE_CACHE_16:
        {
            io_request = (hijacker_request_t*)malloc(sizeof(hijacker_request_t));
            assert(NULL != io_request);
            io_request->magic = HIJACKER_MAGIC;
            io_request->type = SYNC_CACHE;
            io_request->reserves = 0;
            io_request->handle = (uint64_t) cmd;
            io_request->offset = cmd->offset;
            io_request->len = scsi_get_in_length(cmd);
            break;
        }
        case WRITE_6:
        case WRITE_10:
        case WRITE_12:
        case WRITE_16:
        {
            int req_len = sizeof(hijacker_request_t)+scsi_get_out_length(cmd);
            io_request = (hijacker_request_t*) malloc(req_len);
            assert(NULL != io_request);
            io_request->magic = HIJACKER_MAGIC;
            io_request->type = SCSI_WRITE;
            io_request->reserves = 0;
            io_request->handle = (uint64_t) cmd;
            io_request->offset = cmd->offset;
            io_request->len = scsi_get_out_length(cmd);
            /*fixme: to be optimized, here should avoid memory copy*/
            memcpy(io_request->data, scsi_get_out_buffer(cmd),
                    scsi_get_out_length(cmd));
            break;
        }
        case READ_6:
        case READ_10:
        case READ_12:
        case READ_16:
            io_request=(hijacker_request_t*)malloc(sizeof(hijacker_request_t));
            assert(NULL != io_request);
            io_request->magic = HIJACKER_MAGIC;
            io_request->type = SCSI_READ;
            io_request->reserves = 0;
            io_request->handle = (uint64_t) cmd;
            io_request->offset = cmd->offset;
            io_request->len = scsi_get_in_length(cmd);
            break;
        default:
            eprintf("cmd->scb[0]:%x \n", cmd->scb[0]);
            break;
    }

    return io_request;
}

static void bs_request_deconstruct(hijacker_request_t* req) {
    if (req) {
        free(req);
    }
}

static int bs_socket_init(hijacker_volume_t* volume, char* host, short port)
{
    int ret = 0;
    volume->jwriter_host = strdup(host);
    volume->jwriter_port = port;
    volume->jwriter_sock = socket(AF_INET, SOCK_STREAM, 0);
    if(-1 == volume->jwriter_sock){
        eprintf("failed to create socket err=%d \n", errno);
        goto err;
    }

    struct sockaddr_in jwriter_addr;
    memset(&jwriter_addr, 0, sizeof(jwriter_addr));
    jwriter_addr.sin_family = AF_INET;
    jwriter_addr.sin_port = htons(port);
    ret = inet_pton(AF_INET, host, &jwriter_addr.sin_addr);
    if(ret <= 0){
        eprintf("failed to inet_pton,errno:%d error:%s \n",errno,strerror(ret));
        goto err;
    }

    ret = connect(volume->jwriter_sock, &jwriter_addr, sizeof(jwriter_addr));
    if(ret <= 0){
        eprintf("failed to connect,host:%s errno:%d error:%s \n", host, 
                    errno, strerror(ret));
        goto err;
    }

    int disable = 1;
    ret = setsockopt(volume->jwriter_sock, IPPROTO_TCP, TCP_NODELAY, 
                     &disable, sizeof(disable));
    if(ret < 0){
        eprintf("failed to setsockopt,  errno:%d error:%s \n", 
                    errno, strerror(ret));
        goto err;
    }
    eprintf("socket init ok \n");
    return ret;
err:
    eprintf("socket init failed \n");
    return ret;
}

static void bs_socket_fini(hijacker_volume_t* volume)
{
    if(volume && -1 == volume->jwriter_sock){
        close(volume->jwriter_sock);
    }
}

static int bs_socket_send(hijacker_volume_t*volume, hijacker_request_t*request){
    ssize_t nwrite = 0;
    char* p_buf = (char*) request;
    ssize_t p_buf_len = sizeof(*request) + request->len;
    ssize_t nleft = p_buf_len;

    while (0 != nleft) {
        nwrite = write(volume->jwriter_sock, p_buf, nleft);
        if (0 == nwrite) {
            eprintf("failed to socket writer err:%d \n", errno);
            return nwrite;
        }
        if (-1 == nwrite) {
            eprintf("failed to socket write err:%d \n", errno);
            return -1;
        }
        p_buf += nwrite;
        nleft += nwrite;
    }

    return p_buf_len;
}

static int bs_socket_recv(hijacker_volume_t* volume, hijacker_reply_t** reply){
    hijacker_reply_t reply_head = {0};

    int ret = read(volume->jwriter_sock, &reply_head, sizeof(reply_head));
    if(ret != sizeof(reply_head)){
        eprintf("failed socket read reply head ret=%d want=%ld \n", 
                    ret, sizeof(reply_head));
        return -1;
    }
    
    size_t out_reply_len = sizeof(hijacker_reply_t) + reply_head.len;
    hijacker_reply_t* out_reply = (hijacker_reply_t*)malloc(out_reply_len);
    memset(out_reply, 0, sizeof(hijacker_reply_t));
    memcpy(out_reply, &reply_head, sizeof(reply_head));

    char* p_buf = (char*)out_reply->data;
    uint32_t p_buf_len = reply_head.len;
    uint32_t nleft = p_buf_len;
    uint32_t nread = 0;

    while(0 != nleft)
    {
        nread = read(volume->jwriter_sock, p_buf, nleft);
        if(0 == nread)
        {
            eprintf("failed socket read reply data err=%d \n", errno);
            return -1;
        }

        if(-1 == nread)
        {
            eprintf("failed socket read reply data err=%d \n", errno);
            return -1;
        }

        nleft -= nread;
        p_buf += nread;
    }

    *reply = out_reply;
    return 0;
}

/*todo(optimized): block notify server start/stop volume protected*/
static int bs_volume_notify(hijacker_volume_t* volume, bool start){

    int req_len = sizeof(hijacker_request_t);
    req_len += start ? sizeof(add_vol_req_t) : sizeof(del_vol_req_t);

    hijacker_request_t* req = (hijacker_request_t*)malloc(req_len);
    memset(req, 0, req_len);
    req->magic = HIJACKER_MAGIC;
    req->type  = start ? ADD_VOLUME : DEL_VOLUME;
    req->reserves = 0;
    req->handle = 0;
    req->offset = 0;
    req->len = sizeof(add_vol_req_t);
   
    if(start){
        add_vol_req_t* add_vol = (add_vol_req_t*)req->data;
        strcpy(add_vol->volume_name, volume->volume_name);
        strcpy(add_vol->device_path, volume->device_path);
    } else {
        del_vol_req_t* add_vol = (del_vol_req_t*)req->data;
        strcpy(add_vol->volume_name, volume->volume_name);
    }

    int ret = bs_socket_send(volume, req);
    if(ret != req_len){
        eprintf("notify start send err ret:%d size:%d \n", ret, req_len);
        goto out;;
    }

    hijacker_reply_t* reply = NULL;
    ret = bs_socket_recv(volume, &reply);
    if(ret || NULL == reply){
        eprintf("notify start recv err ret:%d \n", ret);
        goto out;
    }
   
    eprintf("notify %s ok\n", (start ? "start" : "stop"));
out:
    if(reply){
        free(reply);
    }
    if(req){
        free(req);
    }
    return ret;;
}


static void* bs_net_send_thr(void* arg)
{
    hijacker_volume_t* volume = (hijacker_volume_t*)arg;
    struct scsi_cmd* cur_cmd = NULL;
    struct scsi_cmd* next_cmd = NULL;
    struct list_head sending_que;

    INIT_LIST_HEAD(&sending_que);

    while(true){
        pthread_mutex_lock(&volume->pending_lock);
        while(list_empty(&volume->pending_list)){
            eprintf("pending list empty \n");
            pthread_cond_wait(&volume->pending_cond, &volume->pending_lock);
        }
        eprintf("pending list not empty \n");
        list_splice_init(&volume->pending_list, &sending_que);
        pthread_mutex_unlock(&volume->pending_lock);

        int send_req_num = 0;
        int send_req_size = 0;

        list_for_each_entry_safe(cur_cmd, next_cmd, &sending_que, bs_list)
        {
            hijacker_request_t* request = bs_request_construct(cur_cmd);
            if(request){
                eprintf("send thr request magic:%d type:%d handle:%ld len:%d n",
                        request->magic, request->type, 
                        request->handle, request->len);

                send_req_size += bs_socket_send(volume, request);
                send_req_num++; 

                bs_request_deconstruct(request);

                list_del(&cur_cmd->bs_list);
            }
        }

        tracepoint(hijacker_provider,net_send_tracepoint,
                    send_req_num, send_req_size);
    }

    pthread_exit(NULL);
}

static void* bs_net_recv_thr(void* arg)
{
    hijacker_volume_t* volume = (hijacker_volume_t*)arg;

    while(true){
        hijacker_reply_t* reply = NULL;
        int ret = bs_socket_recv(volume, &reply);
        if(ret == -1 || reply == NULL){
            eprintf("failed socket recv reply \n");
            continue;
        }

        eprintf("recv thr reply magic:%d err:%d handle:%ld len:%d \n",
                reply->magic, reply->error, reply->handle, reply->len);
        if(reply->magic != HIJACKER_MAGIC){
            eprintf("failed socket redv reply format error \n");
            continue;
        }

        struct scsi_cmd* cmd = (struct scsi_cmd*)reply->handle;
        eprintf("scsi cdb[0]=%d \n", cmd->scb[0]);

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

        pthread_mutex_lock(&volume->scsi_ack_lock);
        list_add_tail(&cmd->bs_list, &volume->scsi_ack_list);
        pthread_mutex_unlock(&volume->scsi_ack_lock);

        pthread_cond_signal(&volume->scsi_ack_cond);
    }

    pthread_exit(NULL);
}

static void* bs_scsi_ack_thr(void* arg)
{
    hijacker_volume_t* volume = (hijacker_volume_t*)arg;
    struct scsi_cmd* cur_cmd = NULL;
    struct scsi_cmd* next_cmd = NULL;
    struct list_head acking_que;
    INIT_LIST_HEAD(&acking_que);

    while(true){
        pthread_mutex_lock(&volume->scsi_ack_lock);
        while(list_empty(&volume->scsi_ack_list)){
            eprintf("scsi ack list empty \n");
            pthread_cond_wait(&volume->scsi_ack_cond, &volume->scsi_ack_lock);
        }

        list_splice_init(&volume->scsi_ack_list, &acking_que);
        pthread_mutex_unlock(&volume->scsi_ack_lock);

        list_for_each_entry_safe(cur_cmd, next_cmd, &acking_que, bs_list){
            list_del(&cur_cmd->bs_list);
            eprintf("scsi cdb[0]=%d result=%d \n", 
                        cur_cmd->scb[0], cur_cmd->result);
            target_cmd_io_done(cur_cmd, cur_cmd->result);
        }
    }

    pthread_exit(NULL);
}

static void* bs_heart_beat_thr(void* arg)
{
    hijacker_volume_t* volume = (hijacker_volume_t*)arg;

    while(true){
        (void)volume;
    }

    pthread_exit(NULL);
}

static void bs_volume_deinit(hijacker_volume_t* volume)
{
    int ret = bs_volume_notify(volume , false);
    eprintf("stopped notify stop ret:%d \n", ret);

    bs_socket_fini(volume);
    eprintf("stopped socket \n");

    pthread_cancel(volume->heart_beat_thr);
    pthread_join(volume->heart_beat_thr, NULL);
    eprintf("stopped the heart beat thread \n");

    pthread_cancel(volume->scsi_ack_thr);
    pthread_join(volume->scsi_ack_thr, NULL);
    eprintf("stopped the scsi ack thread \n");

    pthread_cancel(volume->recv_thr);
    pthread_join(volume->recv_thr, NULL);
    eprintf("stopped the recv thread \n");

    pthread_cancel(volume->send_thr);
    pthread_join(volume->send_thr, NULL);
    eprintf("stopped the send thread \n");

    pthread_cond_destroy(&volume->scsi_ack_cond);
    pthread_mutex_destroy(&volume->scsi_ack_lock);

    pthread_cond_destroy(&volume->pending_cond);
    pthread_mutex_destroy(&volume->pending_lock);
}

static int bs_volume_init(hijacker_volume_t* volume, 
                          char* volume_name, char* device_path,
                          char* host, short port){
    int ret;
    INIT_LIST_HEAD(&volume->volume_list);

    strcpy(volume->volume_name, volume_name);
    strcpy(volume->device_path, device_path);

    ret = bs_socket_init(volume, host, port);
    if(ret){
        eprintf("failed to socket init., %s \n", strerror(ret));
        goto err;
    }
    
    ret = bs_volume_notify(volume, true);
    if(ret){
        eprintf("failed to notify start., %s \n", strerror(ret));
        goto err;
    }

    pthread_cond_init(&volume->pending_cond, NULL);
    pthread_mutex_init(&volume->pending_lock, NULL);
    INIT_LIST_HEAD(&volume->pending_list);

    pthread_cond_init(&volume->scsi_ack_cond, NULL);
    pthread_mutex_init(&volume->scsi_ack_lock, NULL);
    INIT_LIST_HEAD(&volume->scsi_ack_list);
    
    ret = pthread_create(&volume->send_thr, NULL, bs_net_send_thr, volume);
    if(ret){
        eprintf("failed to create send thread., %s \n", strerror(ret));
        goto err;
    }

    ret = pthread_create(&volume->recv_thr, NULL, bs_net_recv_thr, volume);
    if(ret){
        eprintf("failed to create recv thread., %s \n", strerror(ret));
        goto err;
    }

    ret = pthread_create(&volume->scsi_ack_thr, NULL, bs_scsi_ack_thr, volume);
    if(ret){
        eprintf("failed to create scsi ack thread., %s \n", strerror(ret));
        goto err;
    }

    ret = pthread_create(&volume->heart_beat_thr, NULL, bs_heart_beat_thr, 
                         volume);
    if(ret){
        eprintf("failed to create heart beat thread., %s \n", strerror(ret));
        goto err;
    }

    eprintf("volume init ok \n");
    return 0;
err:
    bs_volume_deinit(volume);
    eprintf("volume init failed \n");
    return -1;
}


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


static tgtadm_err bs_hijacker_init(struct scsi_lu* lu, char* bsopts)
{
    hijacker_volume_t* volume = bs_volume(lu);
    if(!volume){
        eprintf("allocate memory failed \n");
        return TGTADM_NOMEM;
    }

    char* host = "127.0.0.1";
    short port = 1111;
    char* volume_name = "test_vol";
    char* device_path = "/dev/sdx";

    while(bsopts && strlen(bsopts)){
        if(util_is_opt("host", bsopts)){
            host = util_slurp_value(&bsopts);
        } else if (util_is_opt("port", bsopts)){
            char* port_str = util_slurp_value(&bsopts);
            port = atoi(port_str);
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

    eprintf("hijacker init ok \n");
    return TGTADM_SUCCESS;
}

static void bs_hijacker_exit(struct scsi_lu* lu)
{
    hijacker_volume_t* volume = bs_volume(lu);

    assert(NULL != volume);

    bs_volume_deinit(volume);
}

static int bs_hijacker_open(struct scsi_lu* lu, char* path, 
                            int* fd, uint64_t* size){
    uint32_t blksize = 0;
    eprintf("open path=%s \n", path);

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
    return ;
}


static int bs_hijacker_cmd_submit(struct scsi_cmd* cmd)
{
    struct scsi_lu* lu = cmd->dev;
    hijacker_volume_t* volume = bs_volume(lu);

    eprintf("cmd_submit cmd cdb[0]=%d \n", cmd->scb[0]);

    pthread_mutex_lock(&volume->pending_lock);
    list_add_tail(&cmd->bs_list, &volume->pending_list);
    pthread_mutex_unlock(&volume->pending_lock);

    pthread_cond_signal(&volume->pending_cond);

    set_cmd_async(cmd);

    eprintf("cmd submit cmd cdb[0]=%d ok \n", cmd->scb[0]);
    return 0;
}

static struct backingstore_template hijacker_bst = {
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
