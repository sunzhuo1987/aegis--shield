#ifndef DYN_PP_PARSER_H
#define DYN_PP_PARSER_H

#include "sf_types.h"
#include "debug.h"

#define SFP_MIN_ERR_STR 128

/* Convert port value into an index */
#define PORT_INDEX(port) port/8

/* Convert port value into a value for bitwise operations */
#define CONV_PORT(port) 1<<(port%8)

typedef enum _SFP_ret {
    SFP_SUCCESS,
    SFP_ERROR,
} SFP_ret_t;

typedef u_int8_t ports_tbl_t[MAXPORTS/8];

typedef char SFP_errstr_t[SFP_MIN_ERR_STR + 1];

static INLINE char *SFP_GET_ERR(SFP_errstr_t err) 
{
    return (char*)err; 
}

SFP_ret_t SFP_ports(ports_tbl_t ports, char *str, SFP_errstr_t errstr);

SFP_ret_t SFP_snprintfa(char *buf, size_t buf_size, const char *format, ...);

#endif
