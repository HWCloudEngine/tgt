#ifndef __BS_HIJACKER_H_
#define __BS_HIJACKER_H_

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include "list.h"

typedef struct hijacker_volume_magr {
    pthread_mutex_t    mgr_lock;
    struct list_head   volumes_list;
} hijacker_volume_mgr_t;

enum socket_status {
    INIT = 0,
    CONNECTED = 1,
    HEART_BEAT_OK = 10,
    HEART_BEAT_DOWN = 11,
};

typedef struct hijacker_volume {
    struct list_head volume_list;

    /*scsi cmd queue*/
    pthread_cond_t      pending_cond;
    pthread_mutex_t     pending_lock;
    struct list_head    pending_list;

    /*scsi ack queue*/
    pthread_cond_t      scsi_ack_cond;
    pthread_mutex_t     scsi_ack_lock;
    struct list_head    scsi_ack_list;

    /*socket with journal writer*/
    char*               jwriter_host;
    short               jwriter_port;
    int                 jwriter_sock;
    enum socket_status  jwriter_sock_status;

    /*network send and recv thread*/
    pthread_t send_thr;
    pthread_t recv_thr;

    /*scsi ack cmd thread*/
    pthread_t scsi_ack_thr;

    pthread_t heart_beat_thr;

    void* private;
} hijacker_volume_t;

struct hijacker_request {
    uint32_t magic;
    uint32_t type;          /*command type*/
    uint32_t reserves;
    uint64_t handle;        /*command unique identifier*/
    uint32_t offset;
    uint32_t len;
    uint8_t  data[0];
}__attribute__((packed));
typedef struct hijacker_request hijacker_request_t;

struct hijacker_reply {
    uint32_t magic;
    uint32_t error;
    uint32_t reserves;
    uint64_t handle;
    uint32_t len;
    uint8_t  data[0];
}__attribute__((packed));

typedef struct hijacker_reply hijacker_reply_t;

enum hijacker_request_code {
    ADD_VOLUME = 0,
    DEL_VOLUME = 1,

    SCSI_READ  = 3,   /*scsi read command*/
    SCSI_WRITE = 4,   /*scsi write command*/
    SYNC_CACHE = 5    /*synchronize cache when iscsi initiator logout*/ 
};
typedef enum hijacker_request_code hijacker_request_code_t;

#endif
