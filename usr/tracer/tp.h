#undef  TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER hijacker_provider

#undef  TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./tp.h"

#if !defined (_TP_H) || defined (TRACEPOINT_HEADER_MULTI_READ) 
#define _TP_H

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(
    hijacker_provider,
    net_send_tracepoint,

    TP_ARGS(
        int,    send_req_num,
        int,    send_req_size
    ), 

    TP_FIELDS(
        ctf_integer(int, field_send_req_num, send_req_num)     
        ctf_integer(int, field_send_req_size, send_req_size)
    ) 
)

#endif

#include <lttng/tracepoint-event.h>
