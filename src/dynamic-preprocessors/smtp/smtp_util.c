/*
 * smtp_util.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) 2005-2008 Sourcefire, Inc.
 *
 * Author: Andy  Mullican
 *
 * Description:
 *
 * This file contains SMTP helper functions.
 *
 * Entry point functions:
 *
 *    safe_strchr()
 *    safe_strstr()
 *    copy_to_space()
 *    safe_sscanf()
 *
 *
 */

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include "debug.h"
#include "bounds.h"

#include "snort_smtp.h"
#include "smtp_util.h"
#include "sf_dynamic_preprocessor.h"
#include "sf_snort_packet.h"

extern DynamicPreprocessorData _dpd;
extern SMTP *_smtp;
extern char _smtp_normalizing;

void SMTP_GetEOL(const u_int8_t *ptr, const u_int8_t *end,
                 const u_int8_t **eol, const u_int8_t **eolm)
{
    const u_int8_t *tmp_eol;
    const u_int8_t *tmp_eolm;

    /* XXX maybe should fatal error here since none of these 
     * pointers should be NULL */
    if (ptr == NULL || end == NULL || eol == NULL || eolm == NULL)
        return;

    tmp_eol = (u_int8_t *)memchr(ptr, '\n', end - ptr);
    if (tmp_eol == NULL)
    {
        tmp_eol = end;
        tmp_eolm = end;
    }
    else
    {
        /* end of line marker (eolm) should point to marker and 
         * end of line (eol) should point to end of marker */
        if ((tmp_eol > ptr) && (*(tmp_eol - 1) == '\r'))
        {
            tmp_eolm = tmp_eol - 1;
        }
        else
        {
            tmp_eolm = tmp_eol;
        }

        /* move past newline */
        tmp_eol++;
    }

    *eol = tmp_eol;
    *eolm = tmp_eolm;
}

int SMTP_CopyToAltBuffer(SFSnortPacket *p, const u_int8_t *start, int length)
{
    u_int8_t *alt_buf;
    int alt_size;
    u_int16_t *alt_len;
    int ret;

    /* if we make a call to this it means we want to use the alt buffer
     * regardless of whether we copy any data into it or not - barring a failure */
    p->flags |= FLAG_ALT_DECODE;
    _smtp_normalizing = 1;

    /* if start and end the same, nothing to copy */
    if (length == 0)
        return 0;

    alt_buf = &_dpd.altBuffer[0];
    alt_size = _dpd.altBufferLen;
    alt_len = &p->normalized_payload_size;

    ret = SafeMemcpy(alt_buf + *alt_len, start, length, alt_buf, alt_buf + alt_size);

    if (ret != SAFEMEM_SUCCESS)
    {
        p->flags &= ~FLAG_ALT_DECODE;
        _smtp_normalizing = 0;
        *alt_len = 0;

        return -1;
    }

    *alt_len += length;

    return 0;
}

#ifdef DEBUG
char smtp_print_buffer[65537];

const char * SMTP_PrintBuffer(SFSnortPacket *p)
{
    const u_int8_t *ptr = NULL;
    int len = 0;
    int iorig, inew;

    if (_smtp_normalizing)
    {
        ptr = &_dpd.altBuffer[0];
        len = p->normalized_payload_size;
    }
    else
    {
        ptr = p->payload;
        len = p->payload_size;
    }

    for (iorig = 0, inew = 0; iorig < len; iorig++, inew++)
    {
        if (isprint((int)ptr[iorig]) || (ptr[iorig] == '\n'))
        {
            smtp_print_buffer[inew] = ptr[iorig];
        }
        else if (ptr[iorig] == '\r' &&
                 ((iorig + 1) < len) && (ptr[iorig + 1] == '\n'))
        {
            iorig++;
            smtp_print_buffer[inew] = '\n';
        }
        else if (isspace((int)ptr[iorig]))
        {
            smtp_print_buffer[inew] = ' ';
        }
        else
        {
            smtp_print_buffer[inew] = '.';
        }
    }

    smtp_print_buffer[inew] = '\0';

    return &smtp_print_buffer[0];
}
#endif

