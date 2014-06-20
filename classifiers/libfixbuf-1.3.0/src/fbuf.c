/**
 *@internal
 *
 ** fbuf.c
 ** IPFIX Message buffer implementation
 **
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2006-2013 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Brian Trammell, Dan Ruef, Emily Ecoff
 ** ------------------------------------------------------------------------
 ** @OPENSOURCE_HEADER_START@
 ** Use of the libfixbuf system and related source code is subject to the terms
 ** of the following licenses:
 **
 ** GNU Lesser GPL (LGPL) Rights pursuant to Version 2.1, February 1999
 ** Government Purpose License Rights (GPLR) pursuant to DFARS 252.227.7013
 **
 ** NO WARRANTY
 **
 ** ANY INFORMATION, MATERIALS, SERVICES, INTELLECTUAL PROPERTY OR OTHER
 ** PROPERTY OR RIGHTS GRANTED OR PROVIDED BY CARNEGIE MELLON UNIVERSITY
 ** PURSUANT TO THIS LICENSE (HEREINAFTER THE "DELIVERABLES") ARE ON AN
 ** "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY
 ** KIND, EITHER EXPRESS OR IMPLIED AS TO ANY MATTER INCLUDING, BUT NOT
 ** LIMITED TO, WARRANTY OF FITNESS FOR A PARTICULAR PURPOSE,
 ** MERCHANTABILITY, INFORMATIONAL CONTENT, NONINFRINGEMENT, OR ERROR-FREE
 ** OPERATION. CARNEGIE MELLON UNIVERSITY SHALL NOT BE LIABLE FOR INDIRECT,
 ** SPECIAL OR CONSEQUENTIAL DAMAGES, SUCH AS LOSS OF PROFITS OR INABILITY
 ** TO USE SAID INTELLECTUAL PROPERTY, UNDER THIS LICENSE, REGARDLESS OF
 ** WHETHER SUCH PARTY WAS AWARE OF THE POSSIBILITY OF SUCH DAMAGES.
 ** LICENSEE AGREES THAT IT WILL NOT MAKE ANY WARRANTY ON BEHALF OF
 ** CARNEGIE MELLON UNIVERSITY, EXPRESS OR IMPLIED, TO ANY PERSON
 ** CONCERNING THE APPLICATION OF OR THE RESULTS TO BE OBTAINED WITH THE
 ** DELIVERABLES UNDER THIS LICENSE.
 **
 ** Licensee hereby agrees to defend, indemnify, and hold harmless Carnegie
 ** Mellon University, its trustees, officers, employees, and agents from
 ** all claims or demands made against them (and any related losses,
 ** expenses, or attorney's fees) arising out of, or relating to Licensee's
 ** and/or its sub licensees' negligent use or willful misuse of or
 ** negligent conduct or willful misconduct regarding the Software,
 ** facilities, or other rights or assistance granted by Carnegie Mellon
 ** University under this License, including, but not limited to, any
 ** claims of product liability, personal injury, death, damage to
 ** property, or violation of any laws or regulations.
 **
 ** Carnegie Mellon University Software Engineering Institute authored
 ** documents are sponsored by the U.S. Department of Defense under
 ** Contract FA8721-05-C-0003. Carnegie Mellon University retains
 ** copyrights in all material produced under this contract. The U.S.
 ** Government retains a non-exclusive, royalty-free license to publish or
 ** reproduce these documents, or allow others to do so, for U.S.
 ** Government purposes only pursuant to the copyright license under the
 ** contract clause at 252.227.7013.
 **
 ** @OPENSOURCE_HEADER_END@
 ** ------------------------------------------------------------------------
 */

#define _FIXBUF_SOURCE_
#include <fixbuf/private.h>

#ident "$Id: fbuf.c 18739 2013-03-04 15:06:40Z ecoff_svn $"

#define FB_MTU_MIN              32
#define FB_TCPLAN_NULL          -1
#define FB_MAX_TEMPLATE_LEVELS  10

/* Debugger switches. We'll want to stick these in autoinc at some point. */
#define FB_DEBUG_TC         0
#define FB_DEBUG_TMPL       0
#define FB_DEBUG_WR         0
#define FB_DEBUG_RD         0
#define FB_DEBUG_LWR        0
#define FB_DEBUG_LRD        0

typedef struct fbTranscodePlan_st {
    fbTemplate_t    *s_tmpl;
    fbTemplate_t    *d_tmpl;
    int32_t         *si;
} fbTranscodePlan_t;

typedef struct fbDLL_st fbDLL_t;

struct fbDLL_st {
    fbDLL_t *next;
    fbDLL_t *prev;
};

typedef struct fbTCPlanEntry_st fbTCPlanEntry_t;
struct fbTCPlanEntry_st
{
    fbTCPlanEntry_t *next;
    fbTCPlanEntry_t *prev;
    fbTranscodePlan_t  *tcplan;
};

static void detachHeadOfDLL(
    fbDLL_t **head,
    fbDLL_t **tail,
    fbDLL_t **toRemove)
{
    /*  assign the out pointer to the head */
    *toRemove = *head;
    /*  move the head pointer to pointer to the next element*/
    *head = (*head)->next;

    /*  if the new head's not NULL, set its prev to NULL */
    if (*head) {
        (*head)->prev = NULL;
    } else {
        /*  if it's NULL, it means there are no more elements, if
         *  there's a tail pointer, set it to NULL too */
        if (tail) {
            *tail = NULL;
        }
    }
}

static void attachHeadToDLL(
    fbDLL_t **head,
    fbDLL_t **tail,
    fbDLL_t  *newEntry)
{
    /*  if this is NOT the first entry in the list */
    if (*head) {
        /*  typical linked list attachements */
        newEntry->next = *head;
        newEntry->prev = NULL;
        (*head)->prev = newEntry;
        *head = newEntry;
    } else {
        /*  the new entry is the only entry now, set head to it */
        *head = newEntry;
        newEntry->prev = NULL;
        newEntry->next = NULL;
        /*  if we're keeping track of tail, assign that too */
        if (tail) {
            *tail = newEntry;
        }
    }
}

static void moveThisEntryToHeadOfDLL(
    fbDLL_t **head,
    fbDLL_t **tail __attribute__((unused)),
    fbDLL_t  *thisEntry)
{
    if (thisEntry == *head) {
        return;
    }

    if (thisEntry->prev) {
        thisEntry->prev->next = thisEntry->next;
    }

    if (thisEntry->next) {
        thisEntry->next->prev = thisEntry->prev;
    }

    thisEntry->prev = NULL;
    thisEntry->next = *head;
    (*head)->prev = thisEntry;
    *head = thisEntry;
}

static void detachThisEntryOfDLL(
    fbDLL_t **head,
    fbDLL_t **tail,
    fbDLL_t  *entry)
{
    /*  entry already points to the entry to remove, so we're good
     *  there */
    /*  if it's NOT the head of the list, patch up entry->prev */
    if (entry->prev != NULL) {
        entry->prev->next = entry->next;
    } else {
        /*  if it's the head, reassign the head */
        *head = entry->next;
    }
    /*  if it's NOT the tail of the list, patch up entry->next */
    if (entry->next != NULL) {
        entry->next->prev = entry->prev;
    } else {
        /*  it is the last entry in the list, if we're tracking the
         *  tail, reassign */
        if (tail) {
            *tail = entry->prev;
        }
    }

    /*  finish detaching by setting the next and prev pointers to
     *  null */
    entry->prev = NULL;
    entry->next = NULL;
}

struct fBuf_st {
    /** Transport session. Contains template and sequence number state. */
    fbSession_t         *session;
    /** Exporter. Writes messages to a remote endpoint on flush. */
    fbExporter_t        *exporter;
    /** Collector. Reads messages from a remote endpoint on demand. */
    fbCollector_t       *collector;
    /** Automatic mode flag */
    gboolean            automatic;
    /** Cached transcoder plan */
    fbTCPlanEntry_t    *latestTcplan;
    /** Current internal template ID. */
    uint16_t            int_tid;
    /** Current external template ID. */
    uint16_t            ext_tid;
    /** Current special set ID. */
    uint16_t            spec_tid;
    /** Current internal template. */
    fbTemplate_t        *int_tmpl;
    /** Current external template. */
    fbTemplate_t        *ext_tmpl;
    /** Export time in seconds since 0UTC 1 Jan 1970 */
    uint32_t            extime;
    /** Record counter. */
    uint32_t            rc;
    /**
     * Current position pointer.
     * Pointer to the next byte in the buffer to be written or read.
     */
    uint8_t             *cp;
    /**
     * Pointer to first byte in the buffer in the current message.
     * NULL if there is no current message.
     */
    uint8_t             *msgbase;
    /**
     * Message end position pointer.
     * Pointer to first byte in the buffer after the current message.
     */
    uint8_t             *mep;
    /**
     * Pointer to first byte in the buffer in the current message.
     * NULL if there is no current message.
     */
    uint8_t             *setbase;
    /**
     * Set end position pointer.
     * Valid only after a call to fBufNextSetHeader() (called by fBufNext()).
     */
    uint8_t             *sep;
    /** Message buffer. */
    uint8_t             buf[FB_MSGLEN_MAX+1];
};

int transcodeCount = 0;
/*==================================================================
 *
 * Debugger Functions
 *
 *==================================================================*/

#define FB_REM_MSG(_fbuf_) (_fbuf_->mep - _fbuf_->cp)

#define FB_REM_SET(_fbuf_) (_fbuf_->sep - _fbuf_->cp)

#if FB_DEBUG_WR || FB_DEBUG_RD || FB_DEBUG_TC

static uint32_t fBufDebugHexLine(
    GString             *str,
    const char          *lpfx,
    uint8_t             *cp,
    uint32_t            lineoff,
    uint32_t            buflen)
{
    uint32_t            cwr = 0, twr = 0;

    /* stubbornly refuse to print nothing */
    if (!buflen) return 0;

    /* print line header */
    g_string_append_printf(str, "%s %04x:", lpfx, lineoff);

    /* print hex characters */
    for (twr = 0; twr < 16; twr++) {
        if (buflen) {
            g_string_append_printf(str, " %02hhx", cp[twr]);
            cwr++; buflen--;
        } else {
            g_string_append(str, "   ");
        }
    }

    /* print characters */
    g_string_append_c(str, ' ');
    for (twr = 0; twr < cwr; twr++) {
        if (cp[twr] > 32 && cp[twr] < 128) {
            g_string_append_c(str, cp[twr]);
        } else {
            g_string_append_c(str, '.');
        }
    }
    g_string_append_c(str, '\n');

    return cwr;
}

static void fBufDebugHex(
    const char          *lpfx,
    uint8_t             *buf,
    uint32_t            len)
{
    GString             *str = g_string_new("");
    uint32_t            cwr = 0, lineoff = 0;

    do {
        cwr = fBufDebugHexLine(str, lpfx, buf, lineoff, len);
        buf += cwr; len -= cwr; lineoff += cwr;
    } while (cwr == 16);

    fprintf(stderr,"%s", str->str);
    g_string_free(str, TRUE);
}

#endif

#if FB_DEBUG_WR || FB_DEBUG_RD

#if FB_DEBUG_TC

static void fBufDebugTranscodePlan(
    fbTranscodePlan_t   *tcplan)
{
    int                 i;

    fprintf(stderr, "transcode plan %p -> %p\n",
            tcplan->s_tmpl, tcplan->d_tmpl);
    for (i = 0; i < tcplan->d_tmpl->ie_count; i++) {
        fprintf(stderr, "\td[%2u]=s[%2d]\n", i, tcplan->si[i]);
    }
}

static void fBufDebugTranscodeOffsets(
    fbTemplate_t        *tmpl,
    uint16_t            *offsets)
{
    int                 i;

    fprintf(stderr, "offsets %p\n", tmpl);
    for (i = 0; i < tmpl->ie_count; i++) {
        fprintf(stderr, "\to[%2u]=%4x\n", i, offsets[i]);
    }
}

#endif

static void fBufDebugBuffer(
    const char      *label,
    fBuf_t          *fbuf,
    size_t          len,
    gboolean        reverse)
{
    uint8_t         *xcp = fbuf->cp - len;
    uint8_t         *rcp = reverse ? xcp : fbuf->cp;

    fprintf(stderr, "%s len %5lu mp %5u (0x%04x) sp %5u mr %5u sr %5u\n",
            label, len, rcp - fbuf->msgbase, rcp - fbuf->msgbase,
            fbuf->setbase ? (rcp - fbuf->setbase) : 0,
            fbuf->mep - fbuf->cp,
            fbuf->sep ? (fbuf->sep - fbuf->cp) : 0);

    fBufDebugHex(label, rcp, len);
}

#endif

/*==================================================================
 *
 * Transcoder Functions
 *
 *==================================================================*/

#define FB_TC_SBC_OFF(_need_)                                           \
    if (s_rem < (_need_)) {                                             \
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_EOM,                 \
                    "End of message. "                                  \
                    "Underrun on transcode offset calculation "         \
                    "(need %lu bytes, %lu available)",                  \
                    (unsigned long)(_need_), (unsigned long)s_rem);     \
        goto err;                                                       \
    }

#define FB_TC_DBC(_need_, _op_)                                             \
    if (*d_rem < (_need_)) {                                                \
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_EOM,                     \
                    "End of message. "                                      \
                    "Overrun on %s (need %lu bytes, %lu available)",        \
                    (_op_), (unsigned long)(_need_), (unsigned long)*d_rem);\
        return FALSE;                                                       \
    }

/**
 * fbTranscodePlan
 *
 *
 *
 */

static fbTranscodePlan_t *fbTranscodePlan(
    fBuf_t                  *fbuf,
    fbTemplate_t            *s_tmpl,
    fbTemplate_t            *d_tmpl)
{
    void                   *sik, *siv;
    uint32_t                i;
    fbTCPlanEntry_t        *entry;
    fbTranscodePlan_t      *tcplan;

    /* check to see if plan is cached */
    if (fbuf->latestTcplan) {
        entry = fbuf->latestTcplan;
        while (entry) {
            tcplan = entry->tcplan;
            if (tcplan->s_tmpl == s_tmpl &&
                tcplan->d_tmpl == d_tmpl)
            {
                moveThisEntryToHeadOfDLL((fbDLL_t**)(void*)&(fbuf->latestTcplan),
                                         NULL,
                                         (fbDLL_t*)entry);
                return tcplan;
            }
            entry = entry->next;
        }
    }

    entry = g_slice_new0(fbTCPlanEntry_t);

    /* create new transcode plan and cache it */
    entry->tcplan = g_slice_new0(fbTranscodePlan_t);

    tcplan = entry->tcplan;
    /* fill in template refs */
    tcplan->s_tmpl = s_tmpl;
    tcplan->d_tmpl = d_tmpl;

    tcplan->si = g_new0(int32_t, d_tmpl->ie_count);
    /* for each destination element */
    for (i = 0; i < d_tmpl->ie_count; i++) {
        /* find source index */
        if (g_hash_table_lookup_extended(s_tmpl->indices,
                                         d_tmpl->ie_ary[i],
                                         &sik, &siv)) {
            tcplan->si[i] = GPOINTER_TO_INT(siv);
        } else {
            tcplan->si[i] = FB_TCPLAN_NULL;
        }
    }

    attachHeadToDLL((fbDLL_t**)(void*)&(fbuf->latestTcplan),
                    NULL,
                    (fbDLL_t*)entry);
    return tcplan;
}

/**
 * fbTranscodeFreeVarlenOffsets
 *
 *
 *
 *
 */
static void         fbTranscodeFreeVarlenOffsets(
    fbTemplate_t        *s_tmpl,
    uint16_t            *offsets)
{
    if (s_tmpl->is_varlen) g_free(offsets);
}

/**
 *
 * Macros for decode reading
 */


#if HAVE_ALIGNED_ACCESS_REQUIRED

#define FB_READ_U16(_val_, _ptr_) {                     \
    uint16_t _x;                                        \
    memcpy(&_x, _ptr_, sizeof(uint16_t));               \
    _val_ = g_ntohs(_x);                                \
}

#define FB_READ_U32(_val_, _ptr_) {                     \
    uint32_t _x;                                        \
    memcpy(&_x, _ptr_, sizeof(uint32_t));               \
    _val_ = g_ntohl(_x);                                \
}

#else

#define FB_READ_U16(_val_,_ptr_) {                      \
    _val_ = g_ntohs(*((uint16_t *)_ptr_));                            \
}

#define FB_READ_U32(_val_,_ptr_) {                      \
    _val_ = g_ntohl(*((uint32_t *)_ptr_));                            \
}

#endif


#define FB_READ_LIST_LENGTH(_len_, _ptr_)  {    \
        _len_ = *(_ptr_);                       \
        if (_len_ < 255) {                      \
            ++(_ptr_);                          \
        } else {                                \
            FB_READ_U16(_len_, ((_ptr_)+1));    \
            (_ptr_) += 3;                       \
        }                                       \
    }



/**
 * fbTranscodeOffsets
 *
 *
 *
 */
static ssize_t      fbTranscodeOffsets(
    fbTemplate_t        *s_tmpl,
    uint8_t             *s_base,
    uint32_t            s_rem,
    gboolean            decode,
    uint16_t            **offsets_out,
    GError              **err)
{
    fbInfoElement_t     *s_ie;
    uint8_t             *sp;
    uint16_t            *offsets;
    uint32_t            s_len, i;

    /* short circuit - return offset cache if present in template */
    if (s_tmpl->off_cache) {
        if (offsets_out) *offsets_out = s_tmpl->off_cache;
        return s_tmpl->off_cache[s_tmpl->ie_count];
    }

    /* create new offsets array */
    offsets = g_new0(uint16_t, s_tmpl->ie_count + 1);

    /* populate it */
    for (i = 0, sp = s_base; i < s_tmpl->ie_count; i++) {
        offsets[i] = sp - s_base;
        s_ie = s_tmpl->ie_ary[i];
        if (s_ie->len == FB_IE_VARLEN) {
            if (decode) {
                FB_TC_SBC_OFF(1);
                s_len = *sp;
                if (s_len < 255) {
                    sp += 1; s_rem -= 1;
                } else {
                    FB_TC_SBC_OFF(3);
                    FB_READ_U16(s_len,(sp+1));
                    sp += 3; s_rem -= 3;
                }
                FB_TC_SBC_OFF(s_len);

                sp += s_len; s_rem -= s_len;
            } else {
                if (s_ie->num == FB_IE_BASIC_LIST) {
                    FB_TC_SBC_OFF(sizeof(fbBasicList_t));
                    sp += sizeof(fbBasicList_t);
                    s_rem -= sizeof(fbBasicList_t);
                } else if (s_ie->num == FB_IE_SUBTEMPLATE_LIST) {
                    FB_TC_SBC_OFF(sizeof(fbSubTemplateList_t));
                    sp += sizeof(fbSubTemplateList_t);
                    s_rem -= sizeof(fbSubTemplateList_t);
                } else if (s_ie->num == FB_IE_SUBTEMPLATE_MULTILIST) {
                    FB_TC_SBC_OFF(sizeof(fbSubTemplateMultiList_t));
                    sp += sizeof(fbSubTemplateMultiList_t);
                    s_rem -= sizeof(fbSubTemplateMultiList_t);
                } else {
                    FB_TC_SBC_OFF(sizeof(fbVarfield_t));
                    sp += sizeof(fbVarfield_t);
                    s_rem -= sizeof(fbVarfield_t);
                }
            }
        } else {
            FB_TC_SBC_OFF(s_ie->len);
            sp += s_ie->len; s_rem -= s_ie->len;
        }
    }

    /* get EOR offset */
    s_len = offsets[i] = sp - s_base;

    /* cache offsets if possible */
    if (!s_tmpl->is_varlen && offsets_out) {
        s_tmpl->off_cache = offsets;
    }

    /* return offsets if possible */
    if (offsets_out) {
        *offsets_out = offsets;
    } else {
        *offsets_out = NULL;
        fbTranscodeFreeVarlenOffsets(s_tmpl, offsets);
    }

    /* return EOR offset */
    return s_len;

  err:
    g_free(offsets);
    return -1;
}


/**
 * fbTranscodeZero
 *
 *
 *
 *
 *
 */
static gboolean fbTranscodeZero(
    uint8_t             **dp,
    uint32_t            *d_rem,
    uint32_t            len,
    GError              **err)
{
    /* Check for write overrun */
    FB_TC_DBC(len, "zero transcode");

    /* fill zeroes */
    memset(*dp, 0, len);

    /* maintain counters */
    *dp += len; *d_rem -= len;

    return TRUE;
}



#if G_BYTE_ORDER == G_BIG_ENDIAN



/**
 * fbTranscodeFixedBigEndian
 *
 *
 *
 *
 *
 */
static gboolean fbTranscodeFixedBigEndian(
    uint8_t             *sp,
    uint8_t             **dp,
    uint32_t            *d_rem,
    uint32_t            s_len,
    uint32_t            d_len,
    uint32_t            flags,
    GError              **err)
{
    FB_TC_DBC(d_len, "fixed transcode");

    if (s_len == d_len) {
        memcpy(*dp, sp, d_len);
    } else if (s_len > d_len) {
        if (flags & FB_IE_F_ENDIAN) {
            memcpy(*dp, sp + (s_len - d_len), d_len);
        } else {
            memcpy(*dp, sp, d_len);
        }
    } else {
        memset(*dp, 0, d_len);
        if (flags & FB_IE_F_ENDIAN) {
            memcpy(*dp + (d_len - s_len), sp, s_len);
        } else {
            memcpy(*dp, sp, s_len);
        }
    }

    /* maintain counters */
    *dp += d_len; *d_rem -= d_len;

    return TRUE;
}

#define fbEncodeFixed fbTranscodeFixedBigEndian
#define fbDecodeFixed fbTranscodeFixedBigEndian
#else

/**
 *  fbTranscodeSwap
 *
 *
 *
 *
 *
 */
static void fbTranscodeSwap(
    uint8_t             *a,
    uint32_t            len)
{
    uint32_t            i;
    uint8_t             t;
    for (i = 0; i < len/2; i++) {
        t = a[i];
        a[i] = a[(len-1)-i];
        a[(len-1)-i] = t;
    }
}


/**
 * fbEncodeFixedLittleEndian
 *
 *
 *
 *
 *
 */
static gboolean fbEncodeFixedLittleEndian(
    uint8_t             *sp,
    uint8_t             **dp,
    uint32_t            *d_rem,
    uint32_t            s_len,
    uint32_t            d_len,
    uint32_t            flags,
    GError              **err)
{
    FB_TC_DBC(d_len, "fixed LE encode");

    if (s_len == d_len) {
        memcpy(*dp, sp, d_len);
    } else if (s_len > d_len) {
        if (flags & FB_IE_F_ENDIAN) {
            memcpy(*dp, sp, d_len);
        } else {
            memcpy(*dp, sp + (s_len - d_len), d_len);
        }
    } else {
        memset(*dp, 0, d_len);
        if (flags & FB_IE_F_ENDIAN) {
            memcpy(*dp, sp, s_len);
        } else {
            memcpy(*dp + (d_len - s_len), sp, s_len);
        }
    }

    /* swap bytes at destination if necessary */
    if (d_len > 1 && (flags & FB_IE_F_ENDIAN)) {
        fbTranscodeSwap(*dp, d_len);
    }

    /* maintain counters */
    *dp += d_len; *d_rem -= d_len;

    return TRUE;
}


/**
 * fbDecodeFixedLittleEndian
 *
 *
 *
 *
 *
 */
static gboolean fbDecodeFixedLittleEndian(
    uint8_t             *sp,
    uint8_t             **dp,
    uint32_t            *d_rem,
    uint32_t            s_len,
    uint32_t            d_len,
    uint32_t            flags,
    GError              **err)
{
    FB_TC_DBC(d_len, "fixed LE decode");
    if (s_len == d_len) {
        memcpy(*dp, sp, d_len);

    } else if (s_len > d_len) {
        if (flags & FB_IE_F_ENDIAN) {
            memcpy(*dp, sp + (s_len - d_len), d_len);
        } else {
            memcpy(*dp, sp, d_len);
        }
    } else {
        memset(*dp, 0, d_len);
        if (flags & FB_IE_F_ENDIAN) {
            memcpy(*dp + (d_len - s_len), sp, s_len);
        } else {
            memcpy(*dp, sp, s_len);
        }
    }

    /* swap bytes at destination if necessary */
    if (d_len > 1 && (flags & FB_IE_F_ENDIAN)) {
        fbTranscodeSwap(*dp, d_len);
    }

    /* maintain counters */
    *dp += d_len; *d_rem -= d_len;
    return TRUE;
}

#define fbEncodeFixed fbEncodeFixedLittleEndian
#define fbDecodeFixed fbDecodeFixedLittleEndian
#endif


/**
 * fbEncodeVarfield
 *
 *
 *
 *
 *
 */
static gboolean fbEncodeVarfield(
    uint8_t             *sp,
    uint8_t             **dp,
    uint32_t            *d_rem,
    uint32_t            flags __attribute__((unused)),
    GError              **err)
{
    uint32_t            d_len;
    uint16_t            sll;
    fbVarfield_t         *sv = (fbVarfield_t *)sp;

    /* calculate total destination length */
    d_len = sv->len + ((sv->len < 255) ? 1 : 3);

    /* Check buffer bounds */
    FB_TC_DBC(d_len, "variable-length encode");

    /* emit IPFIX variable length */
    if (sv->len < 255) {
        **dp = (uint8_t)sv->len;
        *dp += 1;
    } else {
        **dp = 255;
        sll = g_htons((uint16_t)sv->len);
        memcpy(*dp + 1, &sll, sizeof(uint16_t));
        *dp += 3;
    }

    /* emit buffer contents */
    if (sv->len && sv->buf) memcpy(*dp, sv->buf, sv->len);
    /* maintain counters */
    *dp += sv->len; *d_rem -= d_len;

    return TRUE;
}


/**
 * fbDecodeVarfield
 *
 *
 *
 *
 *
 */
static gboolean fbDecodeVarfield(
    uint8_t             *sp,
    uint8_t             **dp,
    uint32_t            *d_rem,
    uint32_t            flags __attribute__((unused)),
    GError              **err)
{
    uint16_t            s_len;
    fbVarfield_t         *dv = (fbVarfield_t *)*dp;

    /* calculate total source length */
    FB_READ_LIST_LENGTH(s_len, sp);
#if 0
    s_len = *sp;
    if (s_len < 255) {
        sp += 1;
    } else {
        memcpy(&s_len, sp + 1, sizeof(uint16_t));
        s_len = g_ntohs(s_len);
        sp += 3;
    }
#endif  /* 0 */


    /* Okay. We know how long the source is. Check buffer bounds. */
    FB_TC_DBC(sizeof(fbVarfield_t), "variable-length decode");

    /* Do transcode. Don't copy; fbVarfield_t's semantics allow us just
       to return a pointer into the read buffer. */
    dv->len = (uint32_t)s_len;
    dv->buf = s_len ? sp : NULL;

    /* maintain counters */
    *dp += sizeof(fbVarfield_t); *d_rem -= sizeof(fbVarfield_t);

    return TRUE;
}

static gboolean validBasicList(
    fbBasicList_t  *basicList,
    GError        **err)
{

    if (!basicList)
    {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IPFIX,
                    "Null basic list pointer passed to encode");
        return FALSE;
    } else if (!basicList->infoElement)
    {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IPFIX,
                    "Null information element in basic list passed to encode");
        return FALSE;
    } else if (basicList->numElements && !basicList->dataLength)
    {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IPFIX,
                   "Positive num elements, but zero data length in basiclist");
        return FALSE;
    } else if (basicList->dataLength && !basicList->dataPtr) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IPFIX,
                    "Positive data length but null data pointer in basiclist");
        return FALSE;
    }
    return TRUE;
}

static gboolean validSubTemplateList(
    fbSubTemplateList_t *STL,
    GError             **err)
{
    if (!STL) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IPFIX,
                    "Null sub template list pointer passed to encode");
        return FALSE;
    } else if (!STL->tmpl || !STL->tmplID) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IPFIX,
                   "Invalid template pointer %p or ID %d passed to STL encode",
                    STL->tmpl, STL->tmplID);
        return FALSE;
    } else if (STL->numElements && !STL->dataLength.length)
    {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IPFIX,
                    "Positive num elements, but zero data length in STL");
        return FALSE;
    } else if (STL->dataLength.length && !STL->dataPtr)
    {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IPFIX,
                    "Positive data length but null data pointer in STL");
        return FALSE;
    }
    return TRUE;
}

static gboolean validSubTemplateMultiList(
    fbSubTemplateMultiList_t   *sTML,
    GError                    **err)
{
    if (!sTML) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IPFIX,
                    "Null sub template multi list pointer passed to encode");
        return FALSE;
    } else if (sTML->numElements && !sTML->firstEntry)
    {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IPFIX,
                    "Positive num elements, but NULL first Entry in STML");
        return FALSE;
    }
    return TRUE;
}

static gboolean validSubTemplateMultiListEntry(
    fbSubTemplateMultiListEntry_t   *entry,
    GError                         **err)
{
    if (!entry) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IPFIX,
                    "Null sub template multi list entry pointer");
        return FALSE;
    } else if (!entry->tmpl || !entry->tmplID) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IPFIX,
                  "Invalid template pointer %p or ID %d passed to STML encode",
                    entry->tmpl, entry->tmplID);
        return FALSE;
    } else if (entry->dataLength && !entry->dataPtr) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IPFIX,
                    "Positive data length but null data pointer in STML");
        return FALSE;
    }
    return TRUE;
}
/*  parses the data according to the external template to determine the number
    of bytes in the src for this template instance
    this function is intended to be used in decoding
    and assumes the values are still in NETWORK byte order
    data: pointer to the data that came accross the wire
    ext_tmpl: external template...what the data looks like on arrival
    bytesInSrc:  number of bytes in incoming data used by the ext_tmpl
*/

static void    bytesUsedBySrcTemplate(
    const uint8_t       *data,
    const fbTemplate_t  *ext_tmpl,
    uint16_t            *bytesInSrc)
{
    fbInfoElement_t    *ie;
    const uint8_t      *srcWalker = data;
    int                 i;

    if (!ext_tmpl->is_varlen) {
        *bytesInSrc = ext_tmpl->ie_len;
        return;
    }

    for (i = 0; i < ext_tmpl->ie_count; i++) {
        ie = ext_tmpl->ie_ary[i];
        if (ie->len == FB_IE_VARLEN) {
            if (*srcWalker == 255) {
                srcWalker++;
                srcWalker += (2 + g_ntohs(*(uint16_t*)srcWalker));
            } else {
                srcWalker += 1 + *srcWalker;
            }
        } else {
            srcWalker += ie->len;
        }
    }
    *bytesInSrc = srcWalker - data;
}

static gboolean fbTranscode(
    fBuf_t             *fbuf,
    gboolean            decode,
    uint8_t            *s_base,
    uint8_t            *d_base,
    size_t             *s_len,
    size_t             *d_len,
    GError            **err);

static gboolean fbEncodeBasicList(
    uint8_t        *src,
    uint8_t       **dst,
    uint32_t       *d_rem,
    fBuf_t         *fbuf,
    GError        **err);

static gboolean fbDecodeBasicList(
    fbInfoModel_t  *model,
    uint8_t        *src,
    uint8_t       **dst,
    uint32_t       *d_rem,
    fBuf_t         *fbuf,
    GError        **err);

static gboolean fbEncodeSubTemplateList(
    uint8_t    *src,
    uint8_t   **dst,
    uint32_t   *d_rem,
    fBuf_t     *fbuf,
    GError    **err);

static gboolean fbDecodeSubTemplateList(
    uint8_t    *src,
    uint8_t   **dst,
    uint32_t   *d_rem,
    fBuf_t     *fbuf,
    GError    **err);

static gboolean fbEncodeSubTemplateMultiList(
    uint8_t    *src,
    uint8_t   **dst,
    uint32_t   *d_rem,
    fBuf_t     *fbuf,
    GError    **err);

static gboolean fbDecodeSubTemplateMultiList(
    uint8_t    *src,
    uint8_t   **dst,
    uint32_t   *d_rem,
    fBuf_t     *fbuf,
    GError    **err);

static gboolean fBufSetDecodeSubTemplates(
    fBuf_t         *fbuf,
    uint16_t        ext_tid,
    uint16_t        int_tid,
    GError        **err);

static gboolean fBufSetEncodeSubTemplates(
    fBuf_t         *fbuf,
    uint16_t        ext_tid,
    uint16_t        int_tid,
    GError        **err);

static gboolean fBufResetExportTemplate(
    fBuf_t         *fbuf,
    uint16_t        tid,
    GError        **err);


static gboolean fbEncodeBasicList(
    uint8_t        *src,
    uint8_t       **dst,
    uint32_t       *d_rem,
    fBuf_t         *fbuf,
    GError        **err)
{
    uint16_t                    totalLength;
    uint16_t                    headerLength;
    uint16_t                    dataLength      = 0;
    uint16_t                    temp16;
    uint32_t                    temp32;
    uint16_t                    ie_len;
    uint16_t                    ie_num;
    uint16_t                   *lengthPtr       = NULL;
    uint16_t                    i;
    gboolean                    enterprise      = FALSE;
    uint8_t                    *prevDst          = NULL;
    fbBasicList_t              *basicList       = (fbBasicList_t*)src;
    fbVarfield_t               *thisVarfield    = NULL;
    fbBasicList_t              *thisBasicList   = NULL;
    fbSubTemplateList_t        *thisSTL         = NULL;
    fbSubTemplateMultiList_t   *thisSTML        = NULL;

    if (!validBasicList(basicList, err))
    {
        return FALSE;
    }

    /* we need to check the buffer bounds throughout the function at each
       stage then decrement d_rem as we go */

    /* header is 5 bytes:
    1 for the semantic
    2 for the field id
    2 for the field length
    */

    headerLength = 5;
    ie_len = basicList->infoElement->len;

    /* get the info element number */
    temp16 = basicList->infoElement->num;

    /* check for enterprise value in the information element, to set bit
       Need to know if IE is enterprise before adding totalLength for
       fixed length IE's */

    if (basicList->infoElement->ent) {
        enterprise = TRUE;
        temp16 |= 0x8000;
        headerLength += 4;
    }


    /* enter the total bytes */
    if (ie_len == FB_IE_VARLEN) {
        /* if varlen, just set the pointer to the right spot
            initialize it with just the header length */

        /* check for room for the header */
        FB_TC_DBC(headerLength, "basic list encode header");
        (*d_rem) -= headerLength;

        /* encode as variable length field */

        FB_TC_DBC(3, "basic list variable length encode header");
        **dst = 255;
        (*dst)++;
        (*d_rem)--;
        lengthPtr = (uint16_t*)*dst;
        *lengthPtr = headerLength;
    } else {
        /* fixed length info element. */

        dataLength = basicList->numElements * ie_len;
        totalLength = headerLength + dataLength;

        /* we know how long the entire list will be, test its length */
        FB_TC_DBC(totalLength, "basic list encode fixed list");
        (*d_rem) -= totalLength;

        totalLength = g_ntohs(totalLength);

        /* encode as variable length field */

        FB_TC_DBC(3, "basic list variable length encode header");
        **dst = 255;
        (*dst)++;
        (*d_rem)--;
        memcpy(*dst, &totalLength, sizeof(uint16_t));
    }

    /* Total Length of BasicList - if varlen - fill in later */
    (*dst) += 2;
    (*d_rem) -= 2;

    /* add the semantic field */
    **dst = basicList->semantic;
    (*dst)++;

    /* write the element number */
    temp16 = g_htons(temp16);
    memcpy(*dst, &temp16, sizeof(uint16_t));
    (*dst) += 2;

    /* add the info element length */
    temp16 = g_htons(ie_len);
    memcpy(*dst, &temp16, sizeof(uint16_t));
    (*dst) += 2;

    /* if enterprise specific info element, add the enterprise number */
    if (enterprise) {

        /* check room for enterprise field */
        FB_TC_DBC(sizeof(uint32_t), "basic list encode enterprise");
        (*d_rem) -= 4;
        temp32 = g_htonl(basicList->infoElement->ent);
        memcpy(*dst, &temp32, sizeof(uint32_t));
        (*dst) += 4;
    }

    if (basicList->numElements)
    {
        /* add the data */
        if (ie_len == FB_IE_VARLEN) {
            /* all future length checks will be done by the called
                encoding functions */
            ie_num = basicList->infoElement->num;
            if (ie_num == FB_IE_BASIC_LIST) {
                thisBasicList = (fbBasicList_t*)basicList->dataPtr;
                for (i = 0; i < basicList->numElements; i++) {
                    prevDst = *dst;
                    if (!fbEncodeBasicList((uint8_t*)thisBasicList, dst, d_rem,
                                           fbuf, err))
                    {
                        return FALSE;
                    }
                    *lengthPtr += *dst - prevDst;
                    thisBasicList++;
                }
            } else if (ie_num == FB_IE_SUBTEMPLATE_LIST) {
                thisSTL = (fbSubTemplateList_t*)basicList->dataPtr;
                for (i = 0; i < basicList->numElements; i++) {
                    prevDst = *dst;
                    if (!fbEncodeSubTemplateList((uint8_t*)thisSTL, dst, d_rem,
                                                 fbuf, err))
                    {
                        return FALSE;
                    }
                    *lengthPtr += *dst - prevDst;
                    thisSTL++;
                }
            } else if (ie_num == FB_IE_SUBTEMPLATE_MULTILIST) {
                thisSTML = (fbSubTemplateMultiList_t*)basicList->dataPtr;
                for (i = 0; i < basicList->numElements; i++) {
                    prevDst = *dst;
                    if (!fbEncodeSubTemplateMultiList((uint8_t*)thisSTML, dst,
                                                      d_rem, fbuf, err))
                    {
                        return FALSE;
                    }
                    *lengthPtr += *dst - prevDst;
                    thisSTML++;
                }
            } else {
                /* add the varfields, adding up the length field */
                thisVarfield = (fbVarfield_t*)basicList->dataPtr;
                for (i = 0; i < basicList->numElements; i++) {
                    if (!fbEncodeVarfield((uint8_t*)thisVarfield, dst, d_rem,
                                          0, err))
                    {
                        return FALSE;
                    }

                    *lengthPtr += thisVarfield->len +
                                        ((thisVarfield->len < 255) ? 1 : 3);
                    thisVarfield++;
                }
            }
        } else {
            /* fixed length info element, just copy the data we already
            know there's enough room for it */
            memcpy(*dst, basicList->dataPtr, dataLength);
            (*dst) += dataLength;
        }
    }

    if (lengthPtr) {
        *lengthPtr = g_htons(*lengthPtr);
    }

    return TRUE;
}

static gboolean fbDecodeBasicList(
    fbInfoModel_t  *model,
    uint8_t        *src,
    uint8_t       **dst,
    uint32_t       *d_rem,
    fBuf_t         *fbuf,
    GError        **err)
{
    uint16_t                    srcLen;
    uint16_t                    elementLen;
    uint16_t                    ie_num;
    gboolean                    enterprise      = FALSE;
    fbInfoElement_t             tempElement;
    fbBasicList_t              *basicList       = (fbBasicList_t*)*dst;
    uint8_t                    *srcWalker       = NULL;
    fbVarfield_t               *thisVarfield    = NULL;
    fbBasicList_t              *thisBasicList   = NULL;
    fbSubTemplateList_t        *thisSTL         = NULL;
    fbSubTemplateMultiList_t   *thisSTML        = NULL;
    int                         i;

    /* check buffer bounds */
    if (d_rem) {
        FB_TC_DBC(sizeof(fbBasicList_t), "basic-list decode");
    }
    memset(&tempElement, 0, sizeof(fbInfoElement_t));

    /* decode the length field and move the Buf ptr up to the next field */
    FB_READ_LIST_LENGTH(srcLen, src);
#if 0
    srcLen = *src;
    if (srcLen < 255) {
        src++;
    } else {
        memcpy(&srcLen, src + 1, sizeof(uint16_t));
        srcLen = g_ntohs(srcLen);
        src += 3;
    }
#endif  /* 0 */

    if (srcLen < 5) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_EOM,
                    "Not enough bytes for basic list header to decode");
        return FALSE;
    }
    /* add the semantic field */
    basicList->semantic = *src;
    src++;
    srcLen--;

    /* pull the field ID, checking for the enterprise bit as well */
    if (*src & 0x80) {
        enterprise = TRUE;
    }

    FB_READ_U16(tempElement.num, src);

    tempElement.num = tempElement.num & 0x7FFF;
    tempElement.midx = 0;
    src += 2;
    srcLen -= 2;

    /* pull the element length */
    FB_READ_U16(elementLen, src);
    src+= 2;
    srcLen -= 2;

    /* if enterprise bit is set, pull this field */
    if (enterprise) {
        if (srcLen < 4) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_EOM,
                    "Not enough bytes for basic list header enterprise no.");
            return FALSE;
        }
        FB_READ_U32(tempElement.ent, src);
        src += 4;
        srcLen -=4;
    } else {
        tempElement.ent = 0;
    }

    /* find the proper info element pointer based on what we built */
    basicList->infoElement = fbInfoModelGetElement(model, &tempElement);
    if (!basicList->infoElement) {
        g_log(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
              "BasicList Decode Error: No Information Element with ID %d "
              "defined", tempElement.num);
        basicList->semantic = 0;
        basicList->infoElement = NULL;
        basicList->numElements = 0;
        basicList->dataLength = 0;
        basicList->dataPtr = NULL;
        (*dst) += sizeof(fbBasicList_t);
        if (d_rem) {
            *d_rem -= sizeof(fbBasicList_t);
        }
        return TRUE;
    }

    if (elementLen == FB_IE_VARLEN) {
        /* first we need to find out the number of elements */
        basicList->numElements = 0;

        /* if there isn't memory allocated yet, figure out how much */
        srcWalker = src;
        /* while we haven't walked the entire list... */
        while (srcLen > (srcWalker - src)) {
            /* parse the length of each, and jump to the next */
            if (*srcWalker < 255) {
                srcWalker += (1 + *srcWalker);
            } else {
                srcWalker++;
                srcWalker += (2 + g_ntohs(*(uint16_t*)srcWalker));
            }
            basicList->numElements++;
        }

        /* now that we know the number of elements, we need to parse the
           specific varlen field */

        ie_num = basicList->infoElement->num;

        if (ie_num == FB_IE_BASIC_LIST) {
            if (!basicList->dataPtr) {
                basicList->dataLength =
                                basicList->numElements * sizeof(fbBasicList_t);
                basicList->dataPtr = g_slice_alloc0(basicList->dataLength);
            }
            thisBasicList = (fbBasicList_t*)(basicList->dataPtr);
            /* thisBasicList will be incremented by DecodeBasicList's
                dst double pointer */
            for (i = 0; i < basicList->numElements; i++) {
                if (!fbDecodeBasicList(model, src,
                           (uint8_t**)(void*)&thisBasicList, NULL, fbuf, err))
                {
                    return FALSE;
                }
                /* now figure out how much to increment src by and repeat */
                if (*src < 255) {
                    src += *src;
                } else {
                    src++;
                    src += g_ntohs(*(uint16_t*)src);
                    src += 2;
                }
            }
        } else if (ie_num == FB_IE_SUBTEMPLATE_LIST) {
            if (!basicList->dataPtr) {
                basicList->dataLength =
                          basicList->numElements * sizeof(fbSubTemplateList_t);
                basicList->dataPtr = g_slice_alloc0(basicList->dataLength);
            }
            thisSTL = (fbSubTemplateList_t*)basicList->dataPtr;
            /* thisSTL will be incremented by DecodeBasicList's
                dst double pointer */
            for (i = 0; i < basicList->numElements; i++) {
                if (!fbDecodeSubTemplateList(src, (uint8_t**)(void*)&thisSTL,
                                             NULL, fbuf, err))
                {
                    return FALSE;
                }
                /* now figure out how much to increment src by and repeat */
                if (*src < 255) {
                    src += *src;
                } else {
                    src++;
                    src += g_ntohs(*(uint16_t*)src);
                    src += 2;
                }
            }
        } else if (ie_num == FB_IE_SUBTEMPLATE_MULTILIST) {
            if (!basicList->dataPtr) {
                basicList->dataLength =
                     basicList->numElements * sizeof(fbSubTemplateMultiList_t);
                basicList->dataPtr = g_slice_alloc0(basicList->dataLength);
            }
            thisSTML = (fbSubTemplateMultiList_t*)basicList->dataPtr;
            /* thisSTML will be incremented by DecodeBasicList's
                dst double pointer */
            for (i = 0; i < basicList->numElements; i++) {
                if (!fbDecodeSubTemplateMultiList(src,
                                                  (uint8_t**)(void*)&thisSTML,
                                                  NULL, fbuf, err))
                {
                    return FALSE;
                }
                /* now figure out how much to increment src by and repeat */
                if (*src < 255) {
                    src += *src;
                } else {
                    src++;
                    src += g_ntohs(*(uint16_t*)src);
                    src += 2;
                }
            }
        } else {
            if (!basicList->dataPtr) {
                basicList->dataLength =
                                basicList->numElements * sizeof(fbVarfield_t);
                basicList->dataPtr = g_slice_alloc0(basicList->dataLength);
            }

            /* now pull the data numElements times */
            thisVarfield = (fbVarfield_t*)basicList->dataPtr;
            for (i = 0; i < basicList->numElements; i++) {
                /* decode the length */
                if (*src < 255) {
                    thisVarfield[i].len = *src;
                    src++;
                } else {
                    src++;
                    thisVarfield[i].len = g_ntohs(*(uint16_t*)src);
                    src += 2;
                }
                /* assign the buffer pointer */
                thisVarfield[i].buf = src;
                src += thisVarfield[i].len;
            }
        }
    } else {
        if (srcLen) {
            /* fixed length field, allocate if needed, then copy */
            basicList->numElements = srcLen / elementLen;
            if (!basicList->dataPtr) {
                basicList->dataLength = srcLen;
                basicList->dataPtr = g_slice_alloc0(basicList->dataLength);
            }

            memcpy(basicList->dataPtr, src, srcLen);
        }
    }

    (*dst) += sizeof(fbBasicList_t);
    if (d_rem) {
        *d_rem -= sizeof(fbBasicList_t);
    }
    return TRUE;
}

static gboolean fbEncodeSubTemplateList(
    uint8_t    *src,
    uint8_t   **dst,
    uint32_t   *d_rem,
    fBuf_t     *fbuf,
    GError    **err)
{
    fbSubTemplateList_t    *subTemplateList = (fbSubTemplateList_t*)src;
    uint16_t                temp16;
    uint16_t                i;
    size_t                  srcLen          = 0;
    size_t                  dstLen          = 0;
    uint16_t               *lenPtr          = NULL;
    gboolean                rv              = TRUE;
    uint16_t                tempIntID;
    uint16_t                tempExtID;
    uint16_t                dataPtrOffset   = 0;
    size_t                  srcRem          = 0;

    if (!validSubTemplateList(subTemplateList, err)) {
        return FALSE;
    }

    /* check that there are 7 bytes available in the buffer for the header */
    FB_TC_DBC(6, "sub template list header");
    (*d_rem) -= 6;

    /* build the subtemplatelist metadata */
    /* encode as variable length */
    **dst = 255;
    (*dst)++;

    /* set the pointer to the length of this subTemplateList */
    lenPtr = (uint16_t*)*dst;
    (*dst) += 2;

    /* write the semantic value */
    **dst = subTemplateList->semantic;
    (*dst)++;

    /* set the initial length to 3, 1 for semantic, 2 for the template ID */
    *lenPtr = 3;

    /*  encode the template ID */
    temp16 = g_htons(subTemplateList->tmplID);
    memcpy(*dst, &temp16, sizeof(uint16_t));
    (*dst) += 2;

    /* store off the current template ids so we can put them back */
    tempIntID = fbuf->int_tid;
    tempExtID = fbuf->ext_tid;

    /* set the templates to that used for this subTemplateList */
    if (!fBufSetEncodeSubTemplates(fbuf, subTemplateList->tmplID,
                             subTemplateList->tmplID, err))
    {
        return FALSE;
    }


    dataPtrOffset = 0;
    /* max source length is length of dataPtr */
    srcRem = subTemplateList->dataLength.length;

    for (i = 0; i < subTemplateList->numElements && rv; i++) {
        srcLen = srcRem;
        dstLen = *d_rem;

        /* transcode the sub template multi list*/
        rv = fbTranscode(fbuf, FALSE, subTemplateList->dataPtr + dataPtrOffset,
                         *dst, &srcLen, &dstLen, err);

        if (rv) {
            /* move up the dst pointer by how much we used in transcode */
            (*dst) += dstLen;

            /* add that many bytes to the length from above */
            *lenPtr += dstLen;
            /* subtract from d_rem the number of dst bytes used in transcode */
            *d_rem -= dstLen;
            /* more the src offset for the next transcode by src bytes used */
            dataPtrOffset += srcLen;

            /* subtract from the original data len for new max value */
            srcRem -= srcLen;
        } else {
            if (tempIntID == tempExtID) {
                fBufSetEncodeSubTemplates(fbuf, tempExtID, tempIntID, err);
            } else {
                fBufSetInternalTemplate(fbuf, tempIntID, err);
                fBufResetExportTemplate(fbuf, tempExtID, err);
            }
            return FALSE;
        }
    }

    /* once transcoding is done, convert the list length to network order */
    *lenPtr = g_htons(*lenPtr);
    /* reset the templates */
    if (tempIntID == tempExtID) {
        /* if equal tempIntID is an external template */
        /* so calling setInternalTemplate with tempIntID won't find tmpl */
        fBufSetEncodeSubTemplates(fbuf, tempExtID, tempIntID, err);
    } else {
        if (!fBufSetInternalTemplate(fbuf, tempIntID, err)) {
            return FALSE;
        }
        if (!fBufResetExportTemplate(fbuf, tempExtID, err)) {
            return FALSE;
        }
    }

    return TRUE;
}

static gboolean fbDecodeSubTemplateList(
    uint8_t    *src,
    uint8_t   **dst,
    uint32_t   *d_rem,
    fBuf_t     *fbuf,
    GError    **err)
{
    fbSubTemplateList_t    *subTemplateList = (fbSubTemplateList_t*)*dst;
    fbTemplate_t           *extTemplate     = NULL;
    fbTemplate_t           *intTemplate     = NULL;
    size_t                  srcLen;
    size_t                  dstLen;
    uint16_t                srcRem;
    uint16_t                dstRem;
    uint16_t                tempIntID;
    uint16_t                tempExtID;
    fbTemplate_t            *tempIntPtr;
    fbTemplate_t            *tempExtPtr;
    uint32_t                i;
    gboolean                rc              = TRUE;
    uint8_t                *subTemplateDst  = NULL;
    uint16_t                offset          = 0;
    uint16_t                bytesInSrc;
    uint16_t                int_tid;
    uint16_t                ext_tid;

    /* decode the length of the list */
    FB_READ_LIST_LENGTH(srcLen, src);
#if 0
    srcLen = *src;
    if (srcLen < 255) {
        src++;
    } else {
        memcpy(&srcLen, src + 1, sizeof(uint16_t));
        srcLen = g_ntohs(srcLen);
        src += 3;
    }
#endif  /* 0 */

    if (srcLen < 3) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_EOM,
                    "Not enough bytes for the sub template list header");
        return FALSE;
    }

    if (d_rem) {
        FB_TC_DBC(sizeof(fbSubTemplateList_t), "sub-template-list decode");
    }

    subTemplateList->semantic = *src;
    src++;
    srcLen--;

    FB_READ_U16(ext_tid, src);
    src += 2;
    srcLen -= 2;

    /* get the template */
    extTemplate = fbSessionGetTemplate(fbuf->session, FALSE, ext_tid, err);

    if (extTemplate) {
        int_tid = fbSessionLookupTemplatePair(fbuf->session, ext_tid);
        if (int_tid == ext_tid) {
            /* is there an internal tid with the same tid as the
               external tid?  If so, get it.  If not, set
               the internal template to the external template */
            intTemplate = fbSessionGetTemplate(fbuf->session,
                                               TRUE,
                                               int_tid, err);
            if (!intTemplate) {
                g_clear_error(err);
                intTemplate = extTemplate;
            }
        } else if (int_tid != 0) {
            intTemplate = fbSessionGetTemplate(fbuf->session,
                                               TRUE,
                                               int_tid, err);
            if (!intTemplate) {
                return FALSE;
            }
        }
    }

    if (!extTemplate || !intTemplate) {
        /* we need both to continue on this item*/
        if (!extTemplate) {
            g_clear_error(err);
            g_warning("Skipping SubTemplateList.  No Template 0x%02x Present.",
                      ext_tid);
        }
        /*    if (!(extTemplate)) {
              g_clear_error(err);
              g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IPFIX,
              "Template does not exist for template ID: %02x",
              ext_tid);
              return FALSE;
              }

              int_tid = fbSessionLookupTemplatePair(fbuf->session, ext_tid);
              if (int_tid == ext_tid) {
              intTemplate = extTemplate;
              } else if (int_tid != 0){
              intTemplate = fbSessionGetTemplate(fbuf->session,
              TRUE,
              int_tid,
              err);
              } else {*/
        /* the collector doesn't want this template...ever
           don't move the dst pointer at all!
           the source pointer will get moved up in fbTranscode(),
           which won't know we didn't do anything */

        subTemplateList->semantic = 0;
        subTemplateList->tmplID = 0;
        subTemplateList->tmpl = NULL;
        subTemplateList->dataLength.length = 0;
        subTemplateList->dataPtr = NULL;
        subTemplateList->numElements = 0;
        *dst += sizeof(fbSubTemplateList_t);

        return TRUE;
    }

    subTemplateList->tmplID = int_tid;
    subTemplateList->tmpl = intTemplate;

    /* now we wanna transcode length / templateSize elements */
    if (extTemplate->is_varlen) {
        uint8_t         *srcWalker = src;
        subTemplateList->numElements = 0;

        while (srcLen > (size_t)(srcWalker - src)) {
            bytesUsedBySrcTemplate(srcWalker, extTemplate, &bytesInSrc);
            srcWalker += bytesInSrc;
            subTemplateList->numElements++;
        }

        if (!subTemplateList->dataPtr) {

            subTemplateList->dataLength.length = intTemplate->ie_internal_len *
                subTemplateList->numElements;
            if (subTemplateList->dataLength.length) {
                subTemplateList->dataPtr =
                    g_slice_alloc0(subTemplateList->dataLength.length);
            }
            dstRem = subTemplateList->dataLength.length;
        } else {
            if (subTemplateList->dataLength.length <
                (size_t)(intTemplate->ie_internal_len *
                         subTemplateList->numElements))
            {
                subTemplateList->semantic = 0;
                subTemplateList->tmplID = 0;
                subTemplateList->tmpl = NULL;
                subTemplateList->dataLength.length = 0;
                subTemplateList->dataPtr = NULL;
                subTemplateList->numElements = 0;
                *dst += sizeof(fbSubTemplateList_t);
                g_warning("SubTemplateList and Template Length mismatch. "
                          "Was fbSubTemplateListCollectorInit() called "
                          "during setup?");

                return TRUE;
            }

            dstRem =
                intTemplate->ie_internal_len * subTemplateList->numElements;
        }
    } else {
        subTemplateList->numElements = srcLen / extTemplate->ie_len;
        subTemplateList->dataLength.length = subTemplateList->numElements *
                                             intTemplate->ie_internal_len;
        if (!subTemplateList->dataPtr) {
            if (subTemplateList->dataLength.length) {
                subTemplateList->dataPtr =
                    g_slice_alloc0(subTemplateList->dataLength.length);
            }
        }
        dstRem = subTemplateList->dataLength.length;
    }

    tempExtID = fbuf->ext_tid;
    tempIntID = fbuf->int_tid;
    tempExtPtr = fbuf->ext_tmpl;
    tempIntPtr = fbuf->int_tmpl;

    fBufSetDecodeSubTemplates(fbuf, ext_tid, int_tid, err);

    subTemplateDst = subTemplateList->dataPtr;
    srcRem = srcLen;
    offset = 0;
    for (i = 0; i < subTemplateList->numElements && rc; i++) {
        srcLen = srcRem;
        dstLen = dstRem;
        rc = fbTranscode(fbuf, TRUE, src + offset, subTemplateDst, &srcLen,
                         &dstLen, err);
        if (rc) {
            subTemplateDst  += dstLen;
            dstRem          -= dstLen;
            srcRem          -= srcLen;
            offset          += srcLen;
        } else {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IPFIX,
                        "Error Decoding SubTemplateList: %s\n",
                        (*err)->message);
            return FALSE;
        }
        /* transcode numElements number of records */
    }

    if (tempIntPtr == tempExtPtr) {
        fBufSetDecodeSubTemplates(fbuf, tempExtID, tempIntID, err);
    } else {
        if (!fBufSetInternalTemplate(fbuf, tempIntID, err)) {
            return FALSE;
        }
        if (!fBufResetExportTemplate(fbuf, tempExtID, err)) {
            return FALSE;
        }
    }

    *dst += sizeof(fbSubTemplateList_t);
    if (d_rem) {
        *d_rem -= sizeof(fbSubTemplateList_t);
    }
    return TRUE;
}

static gboolean fbEncodeSubTemplateMultiList(
    uint8_t    *src,
    uint8_t   **dst,
    uint32_t   *d_rem,
    fBuf_t     *fbuf,
    GError    **err)
{
    fbSubTemplateMultiList_t    *multiList = (fbSubTemplateMultiList_t*)src;
    fbSubTemplateMultiListEntry_t   *entry = NULL;
    uint16_t                temp16;
    uint16_t                i, j;
    size_t                  srcLen  = 0;
    size_t                  dstLen  = 0;
    uint16_t               *lenPtr  = NULL;
    uint16_t               *entryLenPtr = NULL;
    gboolean                rv      = TRUE;
    uint16_t                tempIntID;
    uint16_t                tempExtID;
    uint16_t                srcPtrOffset = 0;
    uint16_t                dstPtrOffset = 0;
    size_t                  srcRem = 0;

    /* calculate total destination length */

    if (!validSubTemplateMultiList(multiList, err)) {
        return FALSE;
    }
    /* Check buffer bounds */
    FB_TC_DBC(4, "multi list header");
    (*d_rem) -= 4;

    **dst = 255;
    (*dst)++;

    /* set the pointer to the length of this subTemplateList */
    lenPtr = (uint16_t*)*dst;

    (*dst) += 2;

    **dst = multiList->semantic;
    (*dst)++;
    *lenPtr = 1; /* semantic */

    tempIntID = fbuf->int_tid;
    tempExtID = fbuf->ext_tid;

    entry = multiList->firstEntry;

    for (i = 0; i < multiList->numElements; i++) {
        if (!validSubTemplateMultiListEntry(entry, err)) {
            continue;
        }

        /* check to see if there's enough length for the entry header */
        FB_TC_DBC(4, "multi list entry header");
        (*d_rem) -= 4;

        /* at this point, it's very similar to a subtemplatelist */
        /* template ID */
        temp16 = g_htons(entry->tmplID);

        memcpy(*dst, &temp16, sizeof(uint16_t));
        (*dst) += 2;

        /* template data length */
        entryLenPtr = (uint16_t*)*dst;
        *entryLenPtr = 4; /* template id: 2 and length of entry: 2 */
        (*dst) += 2;

        if (!fBufSetEncodeSubTemplates(fbuf, entry->tmplID,entry->tmplID,err))
        {
            return FALSE;
        }
        srcRem = entry->dataLength;

        srcPtrOffset = 0;
        for (j = 0; j < entry->numElements; j++) {
            srcLen = srcRem;
            dstLen = *d_rem;
            rv = fbTranscode(fbuf, FALSE, entry->dataPtr + srcPtrOffset, *dst,
                             &srcLen, &dstLen, err);
            if (rv) {
                (*dst) += dstLen;
                dstPtrOffset += dstLen;
                (*d_rem) -= dstLen;
                srcPtrOffset += srcLen;
                *entryLenPtr += dstLen;
                srcRem -= srcLen;

            } else {
                if (tempIntID == tempExtID) {
                    fBufSetEncodeSubTemplates(fbuf, tempExtID, tempIntID, err);
                } else {
                    fBufSetInternalTemplate(fbuf, tempIntID, err);
                    fBufResetExportTemplate(fbuf, tempExtID, err);
                }
                return FALSE;
            }
        }

        *lenPtr += *entryLenPtr;
        *entryLenPtr = g_htons(*entryLenPtr);
        entry++;

       /* we need to do this every iteration bc we may run out of buffer while
         processing the middle of a subtemplatemultilist and then the templates
         won't get set back */

        if (tempIntID == tempExtID) {
            /* if equal tempIntID is an external template */
            /* so calling setInternalTemplate with tempIntID won't find tmpl */
            fBufSetEncodeSubTemplates(fbuf, tempExtID, tempIntID, err);
        } else {
            if (!fBufSetInternalTemplate(fbuf, tempIntID, err)) {
                return FALSE;
            }
            if (!fBufResetExportTemplate(fbuf, tempExtID, err)) {
                return FALSE;
            }
        }
    }

    *lenPtr = g_htons(*lenPtr);
    return TRUE;
}

static gboolean fbDecodeSubTemplateMultiList(
    uint8_t    *src,
    uint8_t   **dst,
    uint32_t   *d_rem,
    fBuf_t     *fbuf,
    GError    **err)
{
    fbSubTemplateMultiList_t   *multiList   = (fbSubTemplateMultiList_t*)*dst;
    fbTemplate_t               *extTemplate = NULL, *intTemplate = NULL;
    size_t                      srcLen;
    uint16_t                    bytesInSrc;
    size_t                      dstLen;
    size_t                      srcRem;
    size_t                      dstRem;
    uint16_t                    tempIntID;
    fbTemplate_t                *tempIntPtr;
    uint16_t                    tempExtID;
    fbTemplate_t                *tempExtPtr;
    gboolean                    rc = TRUE;
    uint8_t                    *srcWalker  = NULL;
    fbSubTemplateMultiListEntry_t   *entry = NULL;
    uint16_t                    thisTemplateLength;
    uint16_t                    i;
    uint16_t                    j;
    uint16_t                    int_tid;
    uint16_t                    ext_tid;
    uint8_t                    *thisTemplateDst;

    FB_READ_LIST_LENGTH(srcLen, src);
#if 0
    srcLen = *src;
    if (srcLen < 255) {
        src++;
    } else {
        memcpy(&srcLen, src + 1, sizeof(uint16_t));
        srcLen = g_ntohs(srcLen);
        src += 3;
    }
#endif  /* 0 */

    if (d_rem) {
        FB_TC_DBC(sizeof(fbSubTemplateMultiList_t),
                  "sub-template-multi-list decode");
    }

    if (srcLen == 0) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_EOM,
                    "Insufficient bytes for subTemplateMultiList header to "
                    "decode");
        return FALSE;
    }

    multiList->semantic = *src;
    src++;
    srcLen--;

    tempExtID = fbuf->ext_tid;
    tempIntID = fbuf->int_tid;
    tempExtPtr = fbuf->ext_tmpl;
    tempIntPtr = fbuf->int_tmpl;
    multiList->numElements = 0;

    /* figure out how many elements are here */
    srcWalker = src;
    while (srcLen > (size_t)(srcWalker - src)) {
        /* jump over the template ID */
        srcWalker += 2;
        bytesInSrc = g_ntohs(*(uint16_t*)srcWalker);
        if (bytesInSrc < 4) {
            g_warning("Invalid Length (%d) in STML Record", bytesInSrc);
            break;
        }
        srcWalker += bytesInSrc - 2;
        multiList->numElements++;
    }

    multiList->firstEntry = g_slice_alloc0(multiList->numElements *
                                      sizeof(fbSubTemplateMultiListEntry_t));
    entry = multiList->firstEntry;

    for (i = 0; i < multiList->numElements; i++) {
        intTemplate = NULL;
        FB_READ_U16(ext_tid, src);
        src += 2;
        extTemplate = fbSessionGetTemplate(fbuf->session,
                                           FALSE,
                                           ext_tid,
                                           err);
        /* OLD WAY...
        if (!extTemplate) {
        return FALSE;
        }
        int_tid = fbSessionLookupTemplatePair(fbuf->session, ext_tid);

        if (int_tid == ext_tid) {
        intTemplate = extTemplate;
        } else if (int_tid != 0) {
        intTemplate = fbSessionGetTemplate(fbuf->session,
        TRUE,
        int_tid,
        err);
        if (!intTemplate) {
        return FALSE;
        }

        } else {
        entry->tmpl = NULL;
        entry->tmplID = 0;
        entry->dataLength = 0;
        entry->dataPtr = NULL;

        FB_READ_U16(thisTemplateLength, src);
        thisTemplateLength -= 2;

        src += thisTemplateLength;
        entry++;

        continue;
        }*/

        if (extTemplate) {
            int_tid = fbSessionLookupTemplatePair(fbuf->session, ext_tid);
            if (int_tid == ext_tid) {
                /* is it possible that there could be an internal
                   template with the same template id as the external
                   template? - check now */
                intTemplate = fbSessionGetTemplate(fbuf->session,
                                                   TRUE,
                                                   int_tid, err);
                if (!intTemplate) {
                    g_clear_error(err);
                    intTemplate = extTemplate;
                }
            } else if (int_tid != 0) {
                intTemplate = fbSessionGetTemplate(fbuf->session,
                                                   TRUE,
                                                   int_tid, err);
                if (!intTemplate) {
                    return FALSE;
                }
            }
        }
        if (!extTemplate || !intTemplate) {
            /* we need both to continue on this item*/
            if (!extTemplate) {
                g_clear_error(err);
                g_warning("Skipping STML Item.  No Template %02x Present.",
                          ext_tid);
            }
            entry->tmpl = NULL;
            entry->tmplID = 0;
            entry->dataLength = 0;
            entry->dataPtr = NULL;
            FB_READ_U16(thisTemplateLength, src);
            thisTemplateLength -= 2;

            src += thisTemplateLength;
            entry++;
            continue;
        }
        entry->tmpl = intTemplate;
        entry->tmplID = int_tid;
        FB_READ_U16(thisTemplateLength, src);
        thisTemplateLength -= 4; /* "removing" template id and length */

        /* put src at the start of the content */
        src += 2;
        if (!thisTemplateLength) {
            continue;
        }

        if (extTemplate->is_varlen) {

            srcWalker = src;
            entry->numElements = 0;

            while (thisTemplateLength > (size_t)(srcWalker - src)) {
                bytesUsedBySrcTemplate(srcWalker, extTemplate, &bytesInSrc);
                srcWalker += bytesInSrc;
                entry->numElements++;
            }

            entry->dataLength = intTemplate->ie_internal_len *
                                entry->numElements;
            entry->dataPtr = g_slice_alloc0(entry->dataLength);
        } else {
            entry->numElements = thisTemplateLength / extTemplate->ie_len;
            entry->dataLength = entry->numElements *
                                intTemplate->ie_internal_len;
            entry->dataPtr = g_slice_alloc0(entry->dataLength);
        }

        dstRem = entry->dataLength;

        dstLen = dstRem;
        srcRem = thisTemplateLength;

        fBufSetDecodeSubTemplates(fbuf, ext_tid, int_tid, err);

        thisTemplateDst = entry->dataPtr;
        for (j = 0; j < entry->numElements; j++) {
            srcLen = srcRem;
            dstLen = dstRem;
            rc = fbTranscode(fbuf, TRUE, src, thisTemplateDst, &srcLen,
                             &dstLen, err);
            if (rc) {
                src += srcLen;
                thisTemplateDst += dstLen;
                srcRem -= srcLen;
                dstRem -= dstLen;
            } else {
                return FALSE;
            }
        }
        entry++;
    }

    if (tempIntPtr == tempExtPtr) {
        fBufSetDecodeSubTemplates(fbuf, tempExtID, tempIntID, err);
    } else {
        if (!fBufSetInternalTemplate(fbuf, tempIntID, err)) {
            return FALSE;
        }
        if (!fBufResetExportTemplate(fbuf, tempExtID, err)) {
            return FALSE;
        }
    }


    *dst += sizeof(fbSubTemplateMultiList_t);
    if (d_rem) {
        *d_rem -= sizeof(fbSubTemplateMultiList_t);
    }
    return TRUE;
}


/**
 * fbTranscode
 *
 *
 *
 *
 *
 */
static gboolean fbTranscode(
    fBuf_t              *fbuf,
    gboolean            decode,
    uint8_t             *s_base,
    uint8_t             *d_base,
    size_t              *s_len,
    size_t              *d_len,
    GError              **err)
{
    fbTranscodePlan_t   *tcplan;
    fbTemplate_t        *s_tmpl, *d_tmpl;
    ssize_t             s_len_offset;
    uint16_t            *offsets;
    uint8_t             *dp;
    uint32_t            s_off, d_rem, i;
    fbInfoElement_t     *s_ie, *d_ie;
    gboolean            ok = TRUE;
    uint16_t            ie_num;

    /* initialize walk of dest buffer */
    dp = d_base; d_rem = *d_len;
    /* select templates for transcode */
    if (decode) {
        s_tmpl = fbuf->ext_tmpl;
        d_tmpl = fbuf->int_tmpl;
    } else {
        s_tmpl = fbuf->int_tmpl;
        d_tmpl = fbuf->ext_tmpl;
    }

    /* get a transcode plan */
    tcplan = fbTranscodePlan(fbuf, s_tmpl, d_tmpl);

    /* get source record length and offsets */
    if ((s_len_offset = fbTranscodeOffsets(s_tmpl, s_base, *s_len,
                                           decode, &offsets, err)) < 0)
    {
        return FALSE;
    }
    *s_len = s_len_offset;
#if FB_DEBUG_TC && FB_DEBUG_RD && FB_DEBUG_WR
    fBufDebugTranscodePlan(tcplan);
    if (offsets) fBufDebugTranscodeOffsets(s_tmpl, offsets);
    fBufDebugHex("tsrc", s_base, *s_len);
#elif FB_DEBUG_TC && FB_DEBUG_RD
    if (decode) {
        fBufDebugTranscodePlan(tcplan);
        /*        if (offsets) fBufDebugTranscodeOffsets(s_tmpl, offsets);
                  fBufDebugHex("tsrc", s_base, *s_len);*/
    }
    if (!decode) {
        fBufDebugTranscodePlan(tcplan);
        if (offsets) fBufDebugTranscodeOffsets(s_tmpl, offsets);
        fBufDebugHex("tsrc", s_base, *s_len);
    }
#endif

    /* iterate over destination IEs, copying from source */
    for (i = 0; i < d_tmpl->ie_count; i++) {
        /* Get pointers to information elements and source offset */
        d_ie = d_tmpl->ie_ary[i];
        s_ie = (tcplan->si[i] == FB_TCPLAN_NULL) ? NULL : s_tmpl->ie_ary[tcplan->si[i]];
        s_off = s_ie ? offsets[tcplan->si[i]] : 0;
        if (s_ie == NULL) {
            /* Null source */
            uint32_t null_len;
            if (d_ie->len == FB_IE_VARLEN) {
                if (decode) {
                    ie_num = d_ie->num;
                    if (ie_num == FB_IE_BASIC_LIST) {
                        null_len = sizeof(fbBasicList_t);
                    } else if (ie_num == FB_IE_SUBTEMPLATE_LIST) {
                        null_len = sizeof(fbSubTemplateList_t);
                    } else if (ie_num == FB_IE_SUBTEMPLATE_MULTILIST) {
                        null_len = sizeof(fbSubTemplateMultiList_t);
                    } else {
                        null_len = sizeof(fbVarfield_t);
                    }
                } else {
                    null_len = 1;
                }

            } else {
                null_len = d_ie->len;
            }
            if (!(ok = fbTranscodeZero(&dp, &d_rem, null_len, err))) {
                goto end;
            }
        } else if (s_ie->len != FB_IE_VARLEN && d_ie->len != FB_IE_VARLEN) {
            if (decode) {
                ok = fbDecodeFixed(s_base + s_off, &dp, &d_rem,
                                   s_ie->len, d_ie->len,
                                   d_ie->flags, err);
            } else {
                ok = fbEncodeFixed(s_base + s_off, &dp, &d_rem,
                                   s_ie->len, d_ie->len,
                                   d_ie->flags, err);
            }
            if (!ok) {
                goto end;
            }
        } else if (s_ie->len == FB_IE_VARLEN && d_ie->len == FB_IE_VARLEN) {
            /* Varlen transcode */
            if (s_ie->num == FB_IE_BASIC_LIST &&
                d_ie->num == FB_IE_BASIC_LIST)
            {
                if (decode) {
                    ok = fbDecodeBasicList(fbuf->ext_tmpl->model,
                                           s_base + s_off,
                                           &dp, &d_rem, fbuf,
                                           err);
                } else {
                    ok = fbEncodeBasicList(s_base + s_off, &dp, &d_rem,
                                           fbuf, err);
                }
                if (!ok) {
                    goto end;
                }
            }
            else if (s_ie->num == FB_IE_SUBTEMPLATE_LIST &&
                     d_ie->num == FB_IE_SUBTEMPLATE_LIST)
            {
                if (decode) {
                    ok = fbDecodeSubTemplateList(s_base + s_off,
                                                 &dp,
                                                 &d_rem,
                                                 fbuf,
                                                 err);
                } else {
                    ok = fbEncodeSubTemplateList(s_base + s_off,
                                                 &dp,
                                                 &d_rem,
                                                 fbuf,
                                                 err);
                }
                if (!ok) {
                    goto end;
                }
            }
            else if (s_ie->num == FB_IE_SUBTEMPLATE_MULTILIST &&
                     d_ie->num == FB_IE_SUBTEMPLATE_MULTILIST)
            {
                if (decode) {
                    ok = fbDecodeSubTemplateMultiList(s_base + s_off,
                                                      &dp,
                                                      &d_rem,
                                                      fbuf,
                                                      err);
                } else {
                    ok = fbEncodeSubTemplateMultiList(s_base + s_off,
                                                      &dp,
                                                      &d_rem,
                                                      fbuf,
                                                      err);
                }

                if (!ok) {
                    goto end;
                }
            } else {
                if (decode) {
                    ok = fbDecodeVarfield(s_base + s_off, &dp, &d_rem,
                                          d_ie->flags, err);
                } else {
                    ok = fbEncodeVarfield(s_base + s_off, &dp, &d_rem,
                                          d_ie->flags, err);
                }
            }
            if (!ok) {
                goto end;
            }
        } else {
            /* Fixed to varlen or vice versa */
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IMPL,
                        "Transcoding between fixed and varlen IE "
                        "not supported by this version of libfixbuf.");
            ok = FALSE;
            goto end;
        }
    }

    /* Return destination length */
    *d_len = dp - d_base;

#if FB_DEBUG_TC && FB_DEBUG_RD && FB_DEBUG_WR
    fBufDebugHex("tdst", d_base, *d_len);
#elif FB_DEBUG_TC && FB_DEBUG_RD
    if (decode) fBufDebugHex("tdst", d_base, *d_len);
#elif FB_DEBUG_TC && FB_DEBUG_WR
    if (!decode) fBufDebugHex("tdst", d_base, *d_len);
#endif
    /* All done */
  end:
    fbTranscodeFreeVarlenOffsets(s_tmpl, offsets);
    return ok;
}

/*==================================================================
 *
 * Common Buffer Management Functions
 *
 *==================================================================*/


/**
 * fBufRewind
 *
 *
 *
 *
 *
 */
void            fBufRewind(
    fBuf_t          *fbuf)
{
    /* Reset the buffer */
    fbuf->cp = fbuf->buf;
    fbuf->mep = fbuf->cp;

    /* No message or set headers in buffer */
    fbuf->msgbase = NULL;
    fbuf->setbase = NULL;
    fbuf->sep = NULL;

    /* No records in buffer either */
    fbuf->rc = 0;
}


/**
 * fBufSetInternalTemplate
 *
 *
 *
 *
 *
 */
gboolean        fBufSetInternalTemplate(
    fBuf_t          *fbuf,
    uint16_t        int_tid,
    GError          **err)
{
    /* Look up new internal template if necessary */
    if (!fbuf->int_tmpl || fbuf->int_tid != int_tid) {
        fbuf->int_tid = int_tid;
        fbuf->int_tmpl = fbSessionGetTemplate(fbuf->session, TRUE, int_tid,
                                              err);
        if (!fbuf->int_tmpl) {
            return FALSE;
        }
    }

#if FB_DEBUG_TMPL
    fbTemplateDebug("int", int_tid, fbuf->int_tmpl);
#endif
    return TRUE;
}

/**
 * fBufSetAutomaticMode
 *
 *
 *
 *
 *
 */
void            fBufSetAutomaticMode(
    fBuf_t          *fbuf,
    gboolean        automatic)
{
    fbuf->automatic = automatic;
}


/**
 * fBufGetSession
 *
 *
 *
 *
 *
 */
fbSession_t     *fBufGetSession(
    fBuf_t          *fbuf)
{
    return fbuf->session;
}


/**
 * fBufFree
 *
 *
 *
 *
 *
 */
void            fBufFree(
    fBuf_t          *fbuf)
{
    fbTCPlanEntry_t *entry;
    /* free the tcplans */
    while (fbuf->latestTcplan) {
        entry = fbuf->latestTcplan;

        detachHeadOfDLL((fbDLL_t**)(void*)&(fbuf->latestTcplan), NULL,
                        (fbDLL_t**)(void*)&entry);
        g_free(entry->tcplan->si);

        g_slice_free1(sizeof(fbTranscodePlan_t), entry->tcplan);
        g_slice_free1(sizeof(fbTCPlanEntry_t), entry);
    }
    if (fbuf->exporter) {
        fbExporterFree(fbuf->exporter);
    }
    if (fbuf->collector) {
        fbCollectorRemoveListenerLastBuf(fbuf, fbuf->collector);
        fbCollectorFree(fbuf->collector);
    }

    fbSessionFree(fbuf->session);
    g_slice_free(fBuf_t, fbuf);
}

/*==================================================================
 *
 * Buffer Append (Writer) Functions
 *
 *==================================================================*/

#if HAVE_ALIGNED_ACCESS_REQUIRED

#define FB_APPEND_U16(_val_) {                          \
    uint16_t _x = g_htons(_val_);                       \
    memcpy(fbuf->cp, &(_x), sizeof(uint16_t));          \
    fbuf->cp += sizeof(uint16_t);                       \
}

#define FB_APPEND_U32(_val_) {                          \
    uint32_t _x = g_htonl(_val_);                       \
    memcpy(fbuf->cp, &(_x), sizeof(uint32_t));          \
    fbuf->cp += sizeof(uint32_t);                       \
}

#else

#define FB_APPEND_U16(_val_)                            \
    *(uint16_t *)fbuf->cp = g_htons(_val_);             \
    fbuf->cp += sizeof(uint16_t);

#define FB_APPEND_U32(_val_)                            \
    *(uint32_t *)fbuf->cp = g_htonl(_val_);             \
    fbuf->cp += sizeof(uint32_t);

#endif




/**
 * fBufAppendMessageHeader
 *
 *
 *
 *
 *
 */
static void     fBufAppendMessageHeader(
    fBuf_t          *fbuf)
{

    /* can only append message header at start of buffer */
    g_assert(fbuf->cp == fbuf->buf);

    /* can only append message header if we have an exporter */
    g_assert(fbuf->exporter);

    /* get MTU from exporter */
    fbuf->mep += fbExporterGetMTU(fbuf->exporter);
    g_assert(FB_REM_MSG(fbuf) > FB_MTU_MIN);

    /* set message base pointer to show we have an active message */
    fbuf->msgbase = fbuf->cp;

    /* add version to buffer */
    FB_APPEND_U16(0x000A);

    /* add message length to buffer */
    FB_APPEND_U16(0);

    /* add export time to buffer */
    if (fbuf->extime) {
        FB_APPEND_U32(fbuf->extime);
    } else {
        FB_APPEND_U32(time(NULL));
    }

    /* add sequence number to buffer */
    FB_APPEND_U32(fbSessionGetSequence(fbuf->session));

    /* add observation domain ID to buffer */
    FB_APPEND_U32(fbSessionGetDomain(fbuf->session));

#if FB_DEBUG_WR
    fBufDebugBuffer("amsg", fbuf, 16, TRUE);
#endif

}


/**
 * fBufAppendSetHeader
 *
 *
 *
 *
 *
 */
static gboolean fBufAppendSetHeader(
    fBuf_t          *fbuf,
    GError          **err)
{
    uint16_t        set_id, set_minlen;

    /* Select set ID and minimum set size based on special TID */
    if (fbuf->spec_tid) {
        set_id = fbuf->spec_tid;
        set_minlen = 4;
    } else {
        set_id = fbuf->ext_tid;
        set_minlen = (fbuf->ext_tmpl->ie_len + 4);
    }

    /* Need enough space in the message for a set header and a record */
    if (FB_REM_MSG(fbuf) < set_minlen) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_EOM,
                    "End of message. "
                    "Overrun on set header append "
                    "(need %u bytes, %u available)",
                    set_minlen, (uint32_t)FB_REM_MSG(fbuf));
        return FALSE;
    }

    /* set set base pointer to show we have an active set */
    fbuf->setbase = fbuf->cp;

    /* add set ID to buffer */
    FB_APPEND_U16(set_id);
    /* add set length to buffer */
    FB_APPEND_U16(0);

#if FB_DEBUG_WR
    fBufDebugBuffer("aset", fbuf, 4, TRUE);
#endif

    return TRUE;
}


/**
 * fBufAppendSetClose
 *
 *
 *
 *
 *
 */
static void fBufAppendSetClose(
    fBuf_t          *fbuf)
{
    uint16_t        setlen;

    /* If there's an active set... */
    if (fbuf->setbase) {
        /* store set length */
        setlen = g_htons(fbuf->cp - fbuf->setbase);
        memcpy(fbuf->setbase + 2, &setlen, sizeof(setlen));

#if FB_DEBUG_WR
    fBufDebugHex("cset", fbuf->setbase, 4);
#endif

        /* deactivate set */
        fbuf->setbase = NULL;
    }
}

#if HAVE_SPREAD
/**
 * fBufSetSpreadExportGroup
 *
 *
 */
void       fBufSetSpreadExportGroup(
    fBuf_t         *fbuf,
    char           **groups,
    int            num_groups,
    GError         **err)
{
    if (fbExporterCheckGroups(fbuf->exporter, groups, num_groups)) {
        /* need to set to 0 bc if the same tmpl_id is used between groups
         * it won't get set to the new group before using */
        fBufEmit(fbuf, err);
        fbuf->ext_tid = 0;
    }
    fbSessionSetGroup(fbuf->session, (char *)groups[0]);
    fBufSetExportGroups(fbuf, groups, num_groups, err);
}

/**
 *
 * fBufSetExportGroups
 *
 */
void       fBufSetExportGroups(
    fBuf_t         *fbuf,
    char           **groups,
    int            num_groups,
    GError         **err)
{
    (void) err;

    fbExporterSetGroupsToSend(fbuf->exporter, groups, num_groups);
}

#endif
/**
 * fBufSetExportTemplate
 *
 *
 *
 *
 *
 */
gboolean        fBufSetExportTemplate(
    fBuf_t          *fbuf,
    uint16_t        ext_tid,
    GError          **err)
{
    /* Look up new external template if necessary */
    if (!fbuf->ext_tmpl || fbuf->ext_tid != ext_tid) {
        fbuf->ext_tid = ext_tid;
        fbuf->ext_tmpl = fbSessionGetTemplate(fbuf->session, FALSE, ext_tid,
                                              err);
        if (!fbuf->ext_tmpl) return FALSE;

        /* Change of template means new set */
        fBufAppendSetClose(fbuf);
    }

#if FB_DEBUG_TMPL
    fbTemplateDebug("ext", ext_tid, fbuf->ext_tmpl);
#endif

    /* If we're here we're done. */
    return TRUE;
}

/** Set both the external and internal templates to the one referenced in tid.
 * Pull both template pointers from the external list as this template must
 * be external and thus on both sides of the connection
 */
static gboolean fBufSetDecodeSubTemplates(
    fBuf_t         *fbuf,
    uint16_t        ext_tid,
    uint16_t        int_tid,
    GError        **err)
{
    fbuf->ext_tmpl = fbSessionGetTemplate(fbuf->session, FALSE, ext_tid, err);
    if (!fbuf->ext_tmpl) {
        return FALSE;
    }
    fbuf->ext_tid = ext_tid;
    if (ext_tid == int_tid) {
        fbuf->int_tid = int_tid;
        fbuf->int_tmpl = fbSessionGetTemplate(fbuf->session, TRUE, int_tid,
                                              err);

        if (!fbuf->int_tmpl) {
            g_clear_error(err);
            fbuf->int_tmpl = fbuf->ext_tmpl;
        }
    } else {
        fbuf->int_tmpl = fbSessionGetTemplate(fbuf->session, TRUE, int_tid,
                                              err);
        if (!fbuf->int_tmpl) {
            return FALSE;
        }
        fbuf->int_tid = int_tid;
    }

    return TRUE;
}

static gboolean fBufSetEncodeSubTemplates(
    fBuf_t         *fbuf,
    uint16_t        ext_tid,
    uint16_t        int_tid,
    GError        **err)
{
    fbuf->ext_tmpl = fbSessionGetTemplate(fbuf->session, FALSE, ext_tid, err);
    if (!fbuf->ext_tmpl) {
        return FALSE;
    }
    fbuf->ext_tid = ext_tid;
    if (ext_tid == int_tid) {
        fbuf->int_tid = int_tid;
        fbuf->int_tmpl = fbuf->ext_tmpl;
    } else {
        fbuf->int_tmpl = fbSessionGetTemplate(fbuf->session, TRUE, int_tid,
                                              err);
        if (!fbuf->int_tmpl) {
            return FALSE;
        }
        fbuf->int_tid = int_tid;
    }

    return TRUE;
}


static gboolean fBufResetExportTemplate(
    fBuf_t         *fbuf,
    uint16_t        ext_tid,
    GError        **err)
{
    if (!fbuf->ext_tmpl || fbuf->ext_tid != ext_tid) {
        fbuf->ext_tid = ext_tid;
        fbuf->ext_tmpl = fbSessionGetTemplate(fbuf->session, FALSE, ext_tid,
                                              err);
        if (!fbuf->ext_tmpl) {
            return FALSE;
        }
    }


    return TRUE;
}

/**
 * fBufRemoveTemplateTcplan
 *
 */
void fBufRemoveTemplateTcplan(
    fBuf_t         *fbuf,
    fbTemplate_t   *tmpl)
{
    fbTCPlanEntry_t    *entry;
    fbTCPlanEntry_t    *otherEntry;
    if (!fbuf || !tmpl) {
        return;
    }

    entry = fbuf->latestTcplan;

    while (entry) {
        if (entry->tcplan->s_tmpl == tmpl ||
            entry->tcplan->d_tmpl == tmpl)
        {
            if (entry == fbuf->latestTcplan) {
                otherEntry = NULL;
            } else {
                otherEntry = entry->next;
            }

            detachThisEntryOfDLL((fbDLL_t**)(void*)(&(fbuf->latestTcplan)),
                                 NULL,
                                 (fbDLL_t*)entry);

            g_free(entry->tcplan->si);

            g_slice_free1(sizeof(fbTranscodePlan_t), entry->tcplan);
            g_slice_free1(sizeof(fbTCPlanEntry_t), entry);

            if (otherEntry) {
                entry = otherEntry;
            } else {
                entry = fbuf->latestTcplan;
            }
        } else {
            entry = entry->next;
        }
    }
}

/**
 * fBufAppendTemplateSingle
 *
 *
 *
 *
 *
 */
static gboolean fBufAppendTemplateSingle(
    fBuf_t          *fbuf,
    uint16_t        tmpl_id,
    fbTemplate_t    *tmpl,
    gboolean        revoked,
    GError          **err)
{
    uint16_t        spec_tid, tmpl_len, ie_count, scope_count;
    int             i;

    /* Force message closed to start a new template message */
    if (!fbuf->spec_tid) {
        fbuf->spec_tid = (tmpl->scope_count) ? FB_TID_OTS : FB_TID_TS;
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_EOM,
                    "End of message. "
                    "Must start new message for template export.");
        return FALSE;
    }

    /* Start a new message if necessary */
    if (!fbuf->msgbase) {
        fBufAppendMessageHeader(fbuf);
    }

    /* Check for set ID change */
    spec_tid = (tmpl->scope_count) ? FB_TID_OTS : FB_TID_TS;
    if (fbuf->spec_tid != spec_tid) {
        fbuf->spec_tid = spec_tid;
        fBufAppendSetClose(fbuf);
    }

    /* Start a new set if necessary */
    if (!fbuf->setbase) {
        if (!fBufAppendSetHeader(fbuf, err)) return FALSE;
    }

    /*
     * Calculate template length and IE count based on whether this
     * is a revocation.
     */
    if (revoked) {
        tmpl_len = 4;
        ie_count = 0;
        scope_count = 0;
    } else {
        tmpl_len = tmpl->tmpl_len;
        ie_count = tmpl->ie_count;
        scope_count = tmpl->scope_count;
    }

    /* Ensure we have enough space for the template in the message */
    if (FB_REM_MSG(fbuf) < tmpl_len) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_EOM,
                    "End of message. "
                    "Overrun on template append "
                    "(need %u bytes, %u available)",
                    tmpl_len, (uint32_t)FB_REM_MSG(fbuf));
        return FALSE;
    }

    /* Copy the template header to the message */
    FB_APPEND_U16(tmpl_id);

    FB_APPEND_U16(ie_count);

    /* Copy scope IE count if present */
    if (scope_count) {
        FB_APPEND_U16(scope_count);
    }

    /* Now copy information element specifiers to the buffer */
    for (i = 0; i < ie_count; i++) {
        if (tmpl->ie_ary[i]->ent) {
            FB_APPEND_U16(IPFIX_ENTERPRISE_BIT | tmpl->ie_ary[i]->num);
            FB_APPEND_U16(tmpl->ie_ary[i]->len);
            FB_APPEND_U32(tmpl->ie_ary[i]->ent);
        } else {
            FB_APPEND_U16(tmpl->ie_ary[i]->num);
            FB_APPEND_U16(tmpl->ie_ary[i]->len);
        }
    }

    /* Template records are records too. Increment record count. */
    /* Actually, no they're not. Odd. */
    /* ++(fbuf->rc); */

#if FB_DEBUG_TMPL
    fbTemplateDebug("apd", tmpl_id, tmpl);
#endif

#if FB_DEBUG_WR
    fBufDebugBuffer("atpl", fbuf, tmpl_len, TRUE);
#endif

    /* Done */
    return TRUE;
}


/**
 * fBufAppendTemplate
 *
 *
 *
 *
 *
 */
gboolean        fBufAppendTemplate(
    fBuf_t          *fbuf,
    uint16_t        tmpl_id,
    fbTemplate_t    *tmpl,
    gboolean        revoked,
    GError          **err)
{
    /* Attempt single append */
    if (fBufAppendTemplateSingle(fbuf, tmpl_id, tmpl, revoked, err)) {
        return TRUE;
    }

    /* Fail if not EOM or not automatic */
    if (!g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_EOM) ||
        !fbuf->automatic) return FALSE;

    /* Retryable. Clear error. */
    g_clear_error(err);

    /* Emit message */
    if (!fBufEmit(fbuf, err)) return FALSE;

    /* Retry single append */
    return fBufAppendTemplateSingle(fbuf, tmpl_id, tmpl, revoked, err);
}


/**
 * fBufAppendSingle
 *
 *
 *
 *
 *
 */
static gboolean fBufAppendSingle(
    fBuf_t          *fbuf,
    uint8_t         *recbase,
    size_t          recsize,
    GError          **err)
{
    size_t          bufsize;

    /* Buffer must have active templates */
    g_assert(fbuf->int_tmpl);
    g_assert(fbuf->ext_tmpl);

    /* Force message closed to finish any active template message */
    if (fbuf->spec_tid) {
        fbuf->spec_tid = 0;
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_EOM,
                    "End of message. "
                    "Must start new message after template export.");
        return FALSE;
    }

    /* Start a new message if necessary */
    if (!fbuf->msgbase) {
        fBufAppendMessageHeader(fbuf);
    }

    /* Cancel special set mode if necessary */
    if (fbuf->spec_tid) {
        fbuf->spec_tid = 0;
        fBufAppendSetClose(fbuf);
    }

    /* Start a new set if necessary */
    if (!fbuf->setbase) {
        if (!fBufAppendSetHeader(fbuf, err))
            return FALSE;
    }

    /* Transcode bytes into buffer */
    bufsize = FB_REM_MSG(fbuf);

    if (!fbTranscode(fbuf, FALSE, recbase, fbuf->cp, &recsize, &bufsize, err))
        return FALSE;

    /* Move current pointer forward by number of bytes written */
    fbuf->cp += bufsize;
    /* Increment record count */
    ++(fbuf->rc);


#if FB_DEBUG_WR
    fBufDebugBuffer("arec", fbuf, bufsize, TRUE);
#endif

    /* Done */
    return TRUE;
}


/**
 * fBufAppend
 *
 *
 *
 *
 *
 */
gboolean        fBufAppend(
    fBuf_t          *fbuf,
    uint8_t         *recbase,
    size_t          recsize,
    GError          **err)
{

    /* Attempt single append */
    if (fBufAppendSingle(fbuf, recbase, recsize, err)) return TRUE;

    /* Fail if not EOM or not automatic */
    if (!g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_EOM) ||
        !fbuf->automatic) return FALSE;

    /* Retryable. Clear error. */
    g_clear_error(err);

    /* Emit message */
    if (!fBufEmit(fbuf, err)) return FALSE;

    /* Retry single append */
    return fBufAppendSingle(fbuf, recbase, recsize, err);
}


/**
 * fBufEmit
 *
 *
 *
 *
 *
 */
gboolean        fBufEmit(
    fBuf_t          *fbuf,
    GError          **err)
{
    uint16_t        msglen;

    /* Short-circuit on no message available */
    if (!fbuf->msgbase) return TRUE;

    /* Close current set */
    fBufAppendSetClose(fbuf);

    /* Store message length */
    msglen = g_htons(fbuf->cp - fbuf->msgbase);
    memcpy(fbuf->msgbase + 2, &msglen, sizeof(msglen));

/*    for (i = 0; i < g_ntohs(msglen); i++) {
        printf("%02x", fbuf->buf[i]);
        if ((i + 1) % 8 == 0) {
            printf("\n");
        }
    }
    printf("\n\n\n\n\n");*/

#if FB_DEBUG_WR
    fBufDebugHex("emit", fbuf->buf, fbuf->cp - fbuf->msgbase);
#endif
#if FB_DEBUG_LWR
    fprintf(stderr, "emit %u (%04x)\n",
            fbuf->cp - fbuf->msgbase, fbuf->cp - fbuf->msgbase);
#endif

    /* Hand the message content to the exporter */
    if (!fbExportMessage(fbuf->exporter, fbuf->buf,
                         fbuf->cp - fbuf->msgbase, err))
        return FALSE;

    /* Increment next record sequence number */
    fbSessionSetSequence(fbuf->session, fbSessionGetSequence(fbuf->session) +
                         fbuf->rc);

    /* Rewind message */
    fBufRewind(fbuf);

    /* All done */
    return TRUE;
}


/**
 * fBufGetExporter
 *
 *
 *
 *
 *
 */
fbExporter_t    *fBufGetExporter(
    fBuf_t          *fbuf)
{
    if (fbuf) {
        return fbuf->exporter;
    }

    return NULL;
}


/**
 * fBufSetExporter
 *
 *
 *
 *
 *
 */
void            fBufSetExporter(
    fBuf_t          *fbuf,
    fbExporter_t    *exporter)
{
    if (fbuf->collector) {
        fbCollectorFree(fbuf->collector);
        fbuf->collector = NULL;
    }

    if (fbuf->exporter) {
        fbExporterFree(fbuf->exporter);
    }

    fbuf->exporter = exporter;
    fbSessionSetTemplateBuffer(fbuf->session, fbuf);
    fBufRewind(fbuf);
}


/**
 * fBufAllocForExport
 *
 *
 *
 *
 *
 */
fBuf_t          *fBufAllocForExport(
    fbSession_t     *session,
    fbExporter_t    *exporter)
{
    fBuf_t          *fbuf = NULL;

    /* Allocate a new buffer */
    fbuf = g_slice_new0(fBuf_t);

    /* Store reference to session */
    fbuf->session = session;

    /* Set up exporter */
    fBufSetExporter(fbuf, exporter);

    /* Buffers are automatic by default */
    fbuf->automatic = TRUE;

    return fbuf;
}

/**
 * fBufSetExportTime
 *
 *
 *
 *
 *
 */
void            fBufSetExportTime(
    fBuf_t          *fbuf,
    uint32_t        extime)
{
    fbuf->extime = extime;
}

/*==================================================================
 *
 * Buffer Consume (Reader) Functions
 *
 *==================================================================*/

#define FB_CHECK_AVAIL(_op_, _size_)                            \
    if (_size_ > FB_REM_MSG(fbuf)) {                            \
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_EOM,         \
                    "End of message %s "                        \
                    "(need %u bytes, %u available)",            \
                    (_op_), (_size_), (uint32_t)FB_REM_MSG(fbuf));        \
        return FALSE;                                           \
    }


#if HAVE_ALIGNED_ACCESS_REQUIRED

#define FB_NEXT_U16(_val_) {                                    \
        uint16_t _x;                                            \
        memcpy (&_x, fbuf->cp, sizeof(uint16_t));               \
        (_val_) = g_ntohs(_x);                                  \
        fbuf->cp += sizeof(uint16_t);                           \
    }

#define FB_NEXT_U32(_val_) {                                    \
        uint32_t _x;                                            \
        memcpy (&_x, fbuf->cp, sizeof(uint32_t));               \
        (_val_) = g_ntohl(_x);                                  \
        fbuf->cp += sizeof(uint32_t);                           \
    }
#else

#define FB_NEXT_U16(_val_)                                \
    (_val_)   = g_ntohs(*((uint16_t *)fbuf->cp));         \
    fbuf->cp += sizeof(uint16_t);

#define FB_NEXT_U32(_val_)                                \
    (_val_)   = g_ntohl(*((uint32_t *)fbuf->cp));         \
    fbuf->cp += sizeof(uint32_t);

#endif




/**
 * fBufNextMessage
 *
 *
 *
 *
 *
 */
gboolean fBufNextMessage(
    fBuf_t          *fbuf,
    GError          **err)
{
    size_t          msglen;
    uint16_t        mh_version, mh_len;
    uint32_t        ex_sequence, mh_sequence, mh_domain;

    /* Need a collector */
    g_assert(fbuf->collector);
    /* Clear external template */
    fbuf->ext_tid = 0;
    fbuf->ext_tmpl = NULL;
    /* Rewind the buffer before reading a new message */
    fBufRewind(fbuf);

    /* Read next message from the collector */
    msglen = sizeof(fbuf->buf);
    if (!fbCollectMessage(fbuf->collector, fbuf->buf, &msglen, err)) {
        return FALSE;
    }

    /* Set the message end pointer */
    fbuf->mep = fbuf->cp + msglen;

#if FB_DEBUG_RD
    fBufDebugHex("read", fbuf->buf, msglen);
#endif
#if FB_DEBUG_LWR
    fprintf(stderr, "read %lu (%04lx)\n", msglen, msglen);
#endif

    /* Make sure we have at least a message header */
    FB_CHECK_AVAIL("reading message header", 16);

#if FB_DEBUG_RD
    fBufDebugBuffer("rmsg", fbuf, 16, FALSE);
#endif
    /* Read and verify version */
    FB_NEXT_U16(mh_version);
    if (mh_version != 0x000A) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IPFIX,
                    "Illegal IPFIX Message version 0x%04x; "
                    "input is probably not an IPFIX Message stream.",
                    mh_version);
        return FALSE;
    }

    /* Read and verify message length */
    FB_NEXT_U16(mh_len);

    if (mh_len != msglen) {
        if (NULL != fbuf->collector) {
            if (!fbCollectorHasTranslator(fbuf->collector)){
                g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IPFIX,
                            "IPFIX Message length mismatch "
                            "(buffer has %u, read %u)",
                            (uint32_t)msglen, mh_len);
                return FALSE;

            }
        } else {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IPFIX,
                        "IPFIX Message length mismatch "
                        "(buffer has %u, read %u)",
                        (uint32_t)msglen, mh_len);
            return FALSE;
        }
    }

    /* Read and store export time */
    FB_NEXT_U32(fbuf->extime);

    /* Read sequence number */
    FB_NEXT_U32(mh_sequence);

    /* Read observation domain ID and reset domain if necessary */
    FB_NEXT_U32(mh_domain);
    fbSessionSetDomain(fbuf->session, mh_domain);

#if HAVE_SPREAD
    /* Only worry about sequence numbers for first group in list
     * of received groups & only if we subscribe to that group*/
    if (fbCollectorTestGroupMembership(fbuf->collector, 0)) {
#endif
    /* Verify and update sequence number */
    ex_sequence = fbSessionGetSequence(fbuf->session);

    if (ex_sequence != mh_sequence) {
        if (ex_sequence) {
            g_warning("IPFIX Message out of sequence "
                      "(in domain %08x, expected %08x, got %08x)",
                      fbSessionGetDomain(fbuf->session), ex_sequence,
                      mh_sequence);
        }
        fbSessionSetSequence(fbuf->session, mh_sequence);
    }

#if HAVE_SPREAD
    }
#endif

    /*
     * We successfully read a message header.
     * Set message base pointer to start of message.
     */
    fbuf->msgbase = fbuf->cp - 16;

    return TRUE;
}


/**
 * fBufSkipCurrentSet
 *
 *
 *
 *
 *
 */
static void     fBufSkipCurrentSet(
    fBuf_t          *fbuf)
{
    if (fbuf->setbase) {
        fbuf->cp += FB_REM_SET(fbuf);
        fbuf->setbase = NULL;
        fbuf->sep = NULL;
    }
}


/**
 * fBufNextSetHeader
 *
 *
 *
 *
 *
 */
static gboolean fBufNextSetHeader(
    fBuf_t          *fbuf,
    GError          **err)
{
    uint16_t        set_id, setlen;

    /* May loop over sets if we're missing templates */
    while (1) {
        /* Make sure we have at least a set header */
        FB_CHECK_AVAIL("reading set header", 4);

#if FB_DEBUG_RD
        fBufDebugBuffer("rset", fbuf, 4, FALSE);
#endif

        /* Read set ID */
        FB_NEXT_U16(set_id);
        /* Read set length */
        FB_NEXT_U16(setlen);
        /* Verify set length is legal */
        if (setlen < 4) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IPFIX,
                        "Illegal IPFIX Set length %hu",
                        setlen);
            return FALSE;
        }

        /* Verify set body fits in the message */
        FB_CHECK_AVAIL("checking set length", setlen - 4);
        /* Set up special set ID or external templates  */
        if (set_id < FB_TID_MIN_DATA) {
            if ((set_id != FB_TID_TS) &&
                (set_id != FB_TID_OTS)) {
                g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IPFIX,
                            "Illegal IPFIX Set ID %04hx", set_id);
                return FALSE;
            }
            fbuf->spec_tid = set_id;
        } else if (!fbuf->ext_tmpl || fbuf->ext_tid != set_id) {
            fbuf->spec_tid = 0;
            fbuf->ext_tid = set_id;
            fbuf->ext_tmpl = fbSessionGetTemplate(fbuf->session, FALSE,
                                                  set_id, err);
            if (!fbuf->ext_tmpl) {
                if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_TMPL)) {
                    /* Merely warn and skip on missing templates */
                    g_warning("Skipping set: %s", (*err)->message);
                    g_clear_error(err);
                    fbuf->setbase = fbuf->cp - 4;
                    fbuf->sep = fbuf->setbase + setlen;
                    fBufSkipCurrentSet(fbuf);
                    continue;
                }
            }
        }

        /*
        * We successfully read a set header.
        * Set set base and end pointers.
        */
        fbuf->setbase = fbuf->cp - 4;
        fbuf->sep = fbuf->setbase + setlen;

        return TRUE;
    }
}


/**
 * fBufConsumeTemplateSet
 *
 *
 *
 *
 *
 */
static gboolean fBufConsumeTemplateSet(
    fBuf_t          *fbuf,
    GError          **err)
{
    uint16_t        mtl, tid, ie_count, scope_count;
    fbTemplate_t    *tmpl;
    fbInfoElement_t ex_ie = FB_IE_NULL;
    int             i;

    /* Calculate minimum template record length based on type */
    /* FIXME handle revocation sets */
    mtl = (fbuf->spec_tid == FB_TID_OTS) ? 6 : 4;

    /* Keep reading until the set contains only padding. */
    while (FB_REM_SET(fbuf) >= mtl) {
        /* Read template ID */
        FB_NEXT_U16(tid);
        /* Read template IE count */
        FB_NEXT_U16(ie_count);
        /* Read scope count if present */
        if (fbuf->spec_tid == FB_TID_OTS) {
            FB_NEXT_U16(scope_count);

            /* Check for illegal scope count */
            if (scope_count == 0) {
                g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IPFIX,
                            "Illegal IPFIX Options Template Scope Count 0");
                return FALSE;
            } else if (scope_count > ie_count) {
                g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IPFIX,
                            "Illegal IPFIX Options Template Scope Count "
                            "(scope count %hu, element count %hu)",
                            scope_count, ie_count);
                return FALSE;
            }
        } else {
            scope_count = 0;
        }

        /* Allocate a new template */
        tmpl = fbTemplateAlloc(fbSessionGetInfoModel(fbuf->session));

        /* Add information elements to the template */
        for (i = 0; i < ie_count; i++) {
            /* Read information element specifier from buffer */
            FB_NEXT_U16(ex_ie.num);
            FB_NEXT_U16(ex_ie.len);
            if (ex_ie.num & IPFIX_ENTERPRISE_BIT) {
                ex_ie.num &= ~IPFIX_ENTERPRISE_BIT;
                FB_NEXT_U32(ex_ie.ent);
            } else {
                ex_ie.ent = 0;
            }

            /* Add information element to template */
            if (!fbTemplateAppend(tmpl, &ex_ie, err)) return FALSE;
        }

        /* Set scope count in template */
        if (scope_count) fbTemplateSetOptionsScope(tmpl, scope_count);

        /* Add template to session */
        if (!fbSessionAddTemplate(fbuf->session, FALSE, tid, tmpl, err)) {
            return FALSE;
        }

        /* callback (fbuf->session, tid, tmpl) */
        if (fbSessionTemplateCallback(fbuf->session)) {
            (fbSessionTemplateCallback(fbuf->session))(fbuf->session, tid,
                                                       tmpl);
        }
        /* Templates are records too */
        /* Again, no. */
        /* ++(fbuf->rc); */

        /* if the template set on the fbuf has the same tid, reset tmpl */
        /* so we don't reference the old one if a data set follows */
        if (fbuf->ext_tid == tid) {
            fbuf->ext_tmpl = NULL;
            fbuf->ext_tid = 0;
        }

#if FB_DEBUG_RD
    fBufDebugBuffer("rtpl", fbuf, tmpl->tmpl_len, TRUE);
#endif
    }

    /* Skip any padding at the end of the set */
    fBufSkipCurrentSet(fbuf);

    /* Should set spec_tid to 0 so if next set is data */
    fbuf->spec_tid = 0;

    /* All done */
    return TRUE;
}


/**
 * fBufNextDataSet
 *
 *
 *
 *
 *
 */
static gboolean fBufNextDataSet(
    fBuf_t          *fbuf,
    GError          **err)
{
    /* May have to consume multiple template sets */
    while (1) {
        /* Read the next set header */
        if (!fBufNextSetHeader(fbuf, err)) {
            return FALSE;
        }

        /* Check to see if we need to consume a template set */
        if (fbuf->spec_tid) {
            if (!fBufConsumeTemplateSet(fbuf, err)) {
                return FALSE;
            }
            continue;
        }

        /* All done. */
        return TRUE;
    }
}


/**
 * fBufGetCollectionTemplate
 *
 *
 *
 *
 *
 */
fbTemplate_t    *fBufGetCollectionTemplate(
    fBuf_t          *fbuf,
    uint16_t        *ext_tid)
{
    if (fbuf->ext_tmpl) {
        if (ext_tid) *ext_tid = fbuf->ext_tid;
    }
    return fbuf->ext_tmpl;
}


/**
 * fBufNextCollectionTemplateSingle
 *
 *
 *
 *
 *
 */
static fbTemplate_t    *fBufNextCollectionTemplateSingle(
    fBuf_t          *fbuf,
    uint16_t        *ext_tid,
    GError          **err)
{
    /* Read a new message if necessary */
    if (!fbuf->msgbase) {
        if (!fBufNextMessage(fbuf, err)) {
            return FALSE;
        }
    }

    /* Skip any padding at end of current data set */
    if (fbuf->setbase &&
        (FB_REM_SET(fbuf) < fbuf->ext_tmpl->ie_len)) {
        fBufSkipCurrentSet(fbuf);
    }

    /* Advance to the next data set if necessary */
    if (!fbuf->setbase) {
        if (!fBufNextDataSet(fbuf, err)) {
            return FALSE;
        }
    }

    return fBufGetCollectionTemplate(fbuf, ext_tid);
}


/**
 * fBufNextCollectionTemplate
 *
 *
 *
 *
 *
 */
fbTemplate_t    *fBufNextCollectionTemplate(
    fBuf_t          *fbuf,
    uint16_t        *ext_tid,
    GError          **err)
{
    fbTemplate_t    *tmpl;

    while (1) {
        /* Attempt single record read */
        if ((tmpl = fBufNextCollectionTemplateSingle(fbuf, ext_tid, err)))
            return tmpl;

        /* Finish the message at EOM */
        if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_EOM)) {
            /* Store next expected sequence number */
#if HAVE_SPREAD
            /* Only worry about sequence numbers for first group in list
             * of received groups & only if we subscribe to that group*/
            if (fbCollectorTestGroupMembership(fbuf->collector, 0)) {
#endif

            fbSessionSetSequence(fbuf->session,
                                 fbSessionGetSequence(fbuf->session) +
                                 fbuf->rc);
#if HAVE_SPREAD
            }
#endif
            /* Rewind buffer to force next record read
               to consume a new message. */
            fBufRewind(fbuf);

            /* Clear error and try again in automatic mode */
            if (fbuf->automatic) {
                g_clear_error(err);
                continue;
            }
        }

        /* Error. Not EOM or not retryable. Fail. */
        return NULL;
    }
}


/**
 * fBufNextSingle
 *
 *
 *
 *
 *
 */
static gboolean fBufNextSingle(
    fBuf_t          *fbuf,
    uint8_t         *recbase,
    size_t          *recsize,
    GError          **err)
{
    size_t          bufsize;

    /* Buffer must have active internal template */
    g_assert(fbuf->int_tmpl);

    /* Read a new message if necessary */
    if (!fbuf->msgbase) {
        if (!fBufNextMessage(fbuf, err)) {
            return FALSE;
        }
    }

    /* Skip any padding at end of current data set */
    if (fbuf->setbase &&
        (FB_REM_SET(fbuf) < fbuf->ext_tmpl->ie_len)) {
        fBufSkipCurrentSet(fbuf);
    }

    /* Advance to the next data set if necessary */
    if (!fbuf->setbase) {
        if (!fBufNextDataSet(fbuf, err)) {
            return FALSE;
        }
    }

    /* Transcode bytes out of buffer */
    bufsize = FB_REM_SET(fbuf);

    if (!fbTranscode(fbuf, TRUE, fbuf->cp, recbase, &bufsize, recsize, err)) {
        return FALSE;
    }
    /* Advance current record pointer by bytes read */
    fbuf->cp += bufsize;

    /* Increment record count */
    ++(fbuf->rc);
#if FB_DEBUG_RD
    fBufDebugBuffer("rrec", fbuf, bufsize, TRUE);
#endif
    /* Done */
    return TRUE;
}


/**
 * fBufNext
 *
 *
 *
 *
 *
 */
gboolean        fBufNext(
    fBuf_t          *fbuf,
    uint8_t         *recbase,
    size_t          *recsize,
    GError          **err)
{
    while (1) {
        /* Attempt single record read */
        if (fBufNextSingle(fbuf, recbase, recsize, err)) return TRUE;
        /* Finish the message at EOM */
        if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_EOM)) {
#if HAVE_SPREAD
            /* Only worry about sequence numbers for first group in list
             * of received groups & only if we subscribe to that group*/
            if (fbCollectorTestGroupMembership(fbuf->collector, 0)) {
#endif
                /* Store next expected sequence number */
                fbSessionSetSequence(fbuf->session,
                                     fbSessionGetSequence(fbuf->session) +
                                     fbuf->rc);
#if HAVE_SPREAD
            }
#endif
            /* Rewind buffer to force next record read
               to consume a new message. */
            fBufRewind(fbuf);
            /* Clear error and try again in automatic mode */
            if (fbuf->automatic) {
                g_clear_error(err);
                continue;
            }
        }

        /* Error. Not EOM or not retryable. Fail. */
        return FALSE;

    }
}


/**
 * fBufGetCollector
 *
 *
 *
 *
 *
 */
fbCollector_t   *fBufGetCollector(
    fBuf_t          *fbuf)
{
    return fbuf->collector;
}


/**
 * fBufSetCollector
 *
 *
 *
 *
 *
 */
void            fBufSetCollector(
    fBuf_t          *fbuf,
    fbCollector_t   *collector)
{
    if (fbuf->exporter) {
        fbSessionSetTemplateBuffer(fbuf->session, NULL);
        fbExporterFree(fbuf->exporter);
        fbuf->exporter = NULL;
    }

    if (fbuf->collector) {
        fbCollectorFree(fbuf->collector);
    }

    fbuf->collector = collector;

    fbSessionSetTemplateBuffer(fbuf->session, fbuf);

    fBufRewind(fbuf);
}

/**
 * fBufAllocForCollection
 *
 *
 *
 *
 *
 */
fBuf_t          *fBufAllocForCollection(
    fbSession_t     *session,
    fbCollector_t   *collector)
{
    fBuf_t          *fbuf = NULL;

    /* Allocate a new buffer */
    fbuf = g_slice_new0(fBuf_t);

    /* Store reference to session */
    fbuf->session = session;

    /* Set up collection */
    fBufSetCollector(fbuf, collector);

    /* Buffers are automatic by default */

    fbuf->automatic = TRUE;

    return fbuf;
}

/**
 * fBufSetSession
 *
 */
void           fBufSetSession(
    fBuf_t          *fbuf,
    fbSession_t     *session)
{
    fbuf->session = session;
}

/**
 * fBufGetExportTime
 *
 */
uint32_t        fBufGetExportTime(
    fBuf_t          *fbuf)
{
    return fbuf->extime;
}

void fBufInterruptSocket(
    fBuf_t  *fbuf)
{
    fbCollectorInterruptSocket(fbuf->collector);
}

gboolean fbListValidSemantic(
    uint8_t semantic)
{
    if (semantic <= 0x04 || semantic == 0xFF) {
        return TRUE;
    }
    return FALSE;
}

fbBasicList_t*  fbBasicListAlloc(
    void)
{
    fbBasicList_t *bl;

    bl = (fbBasicList_t*)g_slice_alloc0(sizeof(fbBasicList_t));
    return bl;
}

void* fbBasicListInit(
    fbBasicList_t          *basicList,
    uint8_t                 semantic,
    const fbInfoElement_t  *infoElement,
    uint16_t                numElements)
{
    uint16_t    ie_num;

    basicList->semantic     = semantic;
    basicList->infoElement  = infoElement;

    if (!infoElement) {
        return NULL;
    }

    basicList->numElements  = numElements;
    basicList->dataLength = numElements * infoElement->len;
    if (infoElement->len == FB_IE_VARLEN) {
        ie_num = infoElement->num;
        if (ie_num == FB_IE_BASIC_LIST) {
            basicList->dataLength = numElements * sizeof(fbBasicList_t);
        } else if (ie_num == FB_IE_SUBTEMPLATE_LIST) {
            basicList->dataLength = numElements * sizeof(fbSubTemplateList_t);
        } else if (ie_num == FB_IE_SUBTEMPLATE_MULTILIST) {
            basicList->dataLength = numElements * sizeof(fbSubTemplateMultiList_t);
        } else {
            basicList->dataLength = numElements * sizeof(fbVarfield_t);
        }
    }

    basicList->dataPtr = g_slice_alloc0(basicList->dataLength);
    return (void*)basicList->dataPtr;
}

void *fbBasicListInitWithOwnBuffer(
    fbBasicList_t          *basicListPtr,
    uint8_t                 semantic,
    const fbInfoElement_t  *infoElement,
    uint16_t                numElements,
    uint16_t                dataLength,
    uint8_t                *dataPtr)
{
    basicListPtr->semantic      = semantic;
    basicListPtr->infoElement   = infoElement;
    basicListPtr->numElements   = numElements;
    basicListPtr->dataLength    = dataLength;
    basicListPtr->dataPtr       = dataPtr;

    return basicListPtr->dataPtr;
}

void fbBasicListCollectorInit(
    fbBasicList_t  *BL)
{
    BL->semantic = 0;
    BL->infoElement = NULL;
    BL->dataPtr = NULL;
    BL->numElements = 0;
    BL->dataLength = 0;
}

uint8_t fbBasicListGetSemantic(
    fbBasicList_t   *basicListPtr)
{
    return basicListPtr->semantic;
}
const fbInfoElement_t *fbBasicListGetInfoElement(
    fbBasicList_t   *basicListPtr)
{
    return basicListPtr->infoElement;
}
void   *fbBasicListGetDataPtr(
    fbBasicList_t   *basicListPtr)
{
    return (void*)basicListPtr->dataPtr;
}

void   *fbBasicListGetIndexedDataPtr(
    fbBasicList_t   *basicList,
    uint16_t         bl_index)
{
    uint16_t    ie_len;
    uint16_t    ie_num;

    if (bl_index >= basicList->numElements) {
        return NULL;
    }

    ie_len = basicList->infoElement->len;
    if (ie_len == FB_IE_VARLEN) {
        ie_num = basicList->infoElement->num;
        if (ie_num == FB_IE_BASIC_LIST) {
            return basicList->dataPtr + (bl_index * sizeof(fbBasicList_t));
        } else if (ie_num == FB_IE_SUBTEMPLATE_LIST) {
            return basicList->dataPtr +(bl_index *sizeof(fbSubTemplateList_t));
        } else if (ie_num == FB_IE_SUBTEMPLATE_MULTILIST) {
            return basicList->dataPtr +
                                 (bl_index * sizeof(fbSubTemplateMultiList_t));
        } else {
            return basicList->dataPtr + (bl_index * sizeof(fbVarfield_t));
        }
    }

    return basicList->dataPtr + (bl_index * ie_len);
}

void  *fbBasicListGetNextPtr(
    fbBasicList_t   *basicList,
    void            *curPtr)
{
    uint16_t    ie_len;
    uint16_t    ie_num;
    uint8_t    *currentPtr = curPtr;

    if (!currentPtr) {
        return basicList->dataPtr;
    }

    ie_len = basicList->infoElement->len;
    if (ie_len == FB_IE_VARLEN) {
        ie_num = basicList->infoElement->num;
        if (ie_num == FB_IE_BASIC_LIST) {
            ie_len = sizeof(fbBasicList_t);
        } else if (ie_num == FB_IE_SUBTEMPLATE_LIST) {
            ie_len = sizeof(fbSubTemplateList_t);
        } else if (ie_num == FB_IE_SUBTEMPLATE_MULTILIST) {
            ie_len = sizeof(fbSubTemplateMultiList_t);
        } else {
            ie_len = sizeof(fbVarfield_t);
        }
    }

    currentPtr += ie_len;

    if (((currentPtr - basicList->dataPtr) / ie_len) >=
        basicList->numElements)
    {
        return NULL;
    }

    return (void*)currentPtr;
}

void fbBasicListSetSemantic(
    fbBasicList_t   *basicListPtr,
    uint8_t         semantic)
{
    basicListPtr->semantic = semantic;
}

void   *fbBasicListRealloc(
    fbBasicList_t   *basicList,
    uint16_t         newNumElements)
{
    if (newNumElements == basicList->numElements) {
        return basicList->dataPtr;
    }

    g_slice_free1(basicList->dataLength, basicList->dataPtr);

    return fbBasicListInit(basicList, basicList->semantic,
                           basicList->infoElement, newNumElements);
}

void* fbBasicListAddNewElements(
    fbBasicList_t   *basicList,
    uint16_t        numNewElements)
{
    uint8_t    *newDataPtr;
    uint16_t    dataLength = 0;
    uint16_t    numElements = basicList->numElements + numNewElements;
    uint16_t    ie_num;
    const fbInfoElement_t *infoElement = basicList->infoElement;
    uint16_t    offset = basicList->dataLength;

    if (infoElement->len == FB_IE_VARLEN) {
        ie_num = infoElement->num;
        if (ie_num == FB_IE_BASIC_LIST) {
            dataLength = numElements * sizeof(fbBasicList_t);
        } else if (ie_num == FB_IE_SUBTEMPLATE_LIST) {
            dataLength = numElements * sizeof(fbBasicList_t);
        } else if (ie_num == FB_IE_SUBTEMPLATE_MULTILIST) {
            dataLength = numElements * sizeof(fbBasicList_t);
        } else {
            dataLength = numElements * sizeof(fbVarfield_t);
        }
    } else {
        dataLength = numElements * infoElement->len;
    }

    newDataPtr              = g_slice_alloc0(dataLength);
    if (basicList->dataPtr) {
        memcpy(newDataPtr, basicList->dataPtr, basicList->dataLength);
        g_slice_free1(basicList->dataLength, basicList->dataPtr);
    }
    basicList->numElements  = numElements;
    basicList->dataPtr      = newDataPtr;
    basicList->dataLength   = dataLength;

    return basicList->dataPtr + offset;
}

void fbBasicListClear(
    fbBasicList_t *basicList)
{
    basicList->semantic = 0;
    basicList->infoElement = NULL;
    basicList->numElements = 0;
    g_slice_free1(basicList->dataLength, basicList->dataPtr);
    basicList->dataLength = 0;
    basicList->dataPtr = NULL;
}

void fbBasicListClearWithoutFree(
    fbBasicList_t   *basicList)
{
    basicList->semantic = 0;
    basicList->infoElement = NULL;
    basicList->numElements = 0;
}


void fbBasicListFree(
    fbBasicList_t *basicList)
{
    fbBasicListClear(basicList);
    g_slice_free1(sizeof(fbBasicList_t), basicList);
}

fbSubTemplateList_t* fbSubTemplateListAlloc(
    void)
{
    fbSubTemplateList_t *stl;
    stl = (fbSubTemplateList_t*)g_slice_alloc0(sizeof(fbSubTemplateList_t));
    return stl;
}

void* fbSubTemplateListInit(
    fbSubTemplateList_t    *subTemplateList,
    uint8_t                 semantic,
    uint16_t                tmplID,
    const fbTemplate_t     *tmpl,
    uint16_t                numElements)
{
    subTemplateList->semantic = semantic;
    subTemplateList->tmplID = tmplID;
    subTemplateList->numElements = numElements;
    subTemplateList->tmpl = tmpl;
    if (!tmpl) {
        return NULL;
    }
    subTemplateList->dataLength.length = numElements * tmpl->ie_internal_len;
    subTemplateList->dataPtr = g_slice_alloc0(subTemplateList->dataLength.length);
    return (void*)subTemplateList->dataPtr;
}

void* fbSubTemplateListInitWithOwnBuffer(
    fbSubTemplateList_t    *subTemplateList,
    uint8_t                 semantic,
    uint16_t                tmplID,
    const fbTemplate_t     *tmpl,
    uint16_t                numElements,
    uint16_t                dataLength,
    uint8_t                *dataPtr)
{
    subTemplateList->semantic = semantic;
    subTemplateList->tmplID = tmplID;
    subTemplateList->numElements = numElements;
    subTemplateList->tmpl = tmpl;
    subTemplateList->dataLength.length = dataLength;
    subTemplateList->dataPtr = dataPtr;

    return (void*)subTemplateList->dataPtr;
}

void fbSubTemplateListCollectorInit(
    fbSubTemplateList_t    *STL)
{
    STL->semantic = 0;
    STL->numElements = 0;
    STL->dataLength.length = 0;
    STL->tmplID = 0;
    STL->tmpl = NULL;
    STL->dataPtr = NULL;
}

void fbSubTemplateListClear(
    fbSubTemplateList_t *subTemplateList)
{
    subTemplateList->semantic = 0;
    subTemplateList->numElements = 0;
    subTemplateList->tmplID = 0;
    subTemplateList->tmpl = NULL;
    if (subTemplateList->dataLength.length) {
        g_slice_free1(subTemplateList->dataLength.length,
                      subTemplateList->dataPtr);
    }
    subTemplateList->dataPtr = NULL;
    subTemplateList->dataLength.length = 0;
}


void fbSubTemplateListFree(
    fbSubTemplateList_t *subTemplateList)
{
    fbSubTemplateListClear(subTemplateList);
    g_slice_free1(sizeof(fbSubTemplateList_t), subTemplateList);
}

void fbSubTemplateListClearWithoutFree(
    fbSubTemplateList_t *subTemplateList)
{
    subTemplateList->semantic = 0;
    subTemplateList->tmplID = 0;
    subTemplateList->tmpl = NULL;
    subTemplateList->numElements = 0;
}


void* fbSubTemplateListGetDataPtr(
    const fbSubTemplateList_t   *sTL)
{
    return sTL->dataPtr;
}

/* index is 0-based.  Goes from 0 - (numElements-1) */
void* fbSubTemplateListGetIndexedDataPtr(
    const fbSubTemplateList_t   *sTL,
    uint16_t                    stlIndex)
{
    if (stlIndex >= sTL->numElements) {
        return NULL;
    }

    return ((uint8_t*)(sTL->dataPtr) + stlIndex * sTL->tmpl->ie_internal_len);
}

void* fbSubTemplateListGetNextPtr(
    const fbSubTemplateList_t   *sTL,
    void            *curPtr)
{
    uint16_t    tmplLen;
    uint8_t    *currentPtr = curPtr;
    if (!currentPtr) {
        return sTL->dataPtr;
    }

    tmplLen = sTL->tmpl->ie_internal_len;
    currentPtr += tmplLen;

    if (((currentPtr - sTL->dataPtr) / tmplLen) >= sTL->numElements) {
        return NULL;
    }
    return (void*)currentPtr;
}

void fbSubTemplateListSetSemantic(
    fbSubTemplateList_t   *sTL,
    uint8_t         semantic)
{
    sTL->semantic = semantic;
}

uint8_t fbSubTemplateListGetSemantic(
    fbSubTemplateList_t *STL)
{
    return STL->semantic;
}

const fbTemplate_t* fbSubTemplateListGetTemplate(
    fbSubTemplateList_t *STL)
{
    return STL->tmpl;
}

uint16_t fbSubTemplateListGetTemplateID(
    fbSubTemplateList_t *STL)
{
    return STL->tmplID;
}

void* fbSubTemplateListRealloc(
    fbSubTemplateList_t   *subTemplateList,
    uint16_t        newNumElements)
{
    if (newNumElements == subTemplateList->numElements) {
        return subTemplateList->dataPtr;
    }
    g_slice_free1(subTemplateList->dataLength.length,
                  subTemplateList->dataPtr);
    subTemplateList->numElements = newNumElements;
    subTemplateList->dataLength.length = subTemplateList->numElements *
                                        subTemplateList->tmpl->ie_internal_len;
    subTemplateList->dataPtr =
        g_slice_alloc0(subTemplateList->dataLength.length);
    return subTemplateList->dataPtr;
}

void* fbSubTemplateListAddNewElements(
    fbSubTemplateList_t *sTL,
    uint16_t            numNewElements)
{
    uint16_t    offset = sTL->dataLength.length;
    uint16_t    numElements = sTL->numElements + numNewElements;
    uint8_t     *newDataPtr = NULL;
    uint16_t    dataLength = 0;

    dataLength = numElements * sTL->tmpl->ie_internal_len;
    newDataPtr              = g_slice_alloc0(dataLength);
    if (sTL->dataPtr) {
        memcpy(newDataPtr, sTL->dataPtr, sTL->dataLength.length);
        g_slice_free1(sTL->dataLength.length, sTL->dataPtr);
    }
    sTL->numElements  = numElements;
    sTL->dataPtr      = newDataPtr;
    sTL->dataLength.length   = dataLength;

    return sTL->dataPtr + offset;
}

fbSubTemplateMultiListEntry_t* fbSubTemplateMultiListInit(
    fbSubTemplateMultiList_t   *sTML,
    uint8_t                     semantic,
    uint16_t                    numElements)
{
    sTML->semantic = semantic;
    sTML->numElements = numElements;
    sTML->firstEntry = g_slice_alloc0(sTML->numElements *
                                      sizeof(fbSubTemplateMultiListEntry_t));
    return sTML->firstEntry;
}

void fbSubTemplateMultiListSetSemantic(
    fbSubTemplateMultiList_t    *STML,
    uint8_t                     semantic)
{
    STML->semantic = semantic;
}

uint8_t fbSubTemplateMultiListGetSemantic(
    fbSubTemplateMultiList_t    *STML)
{
    return STML->semantic;
}

void fbSubTemplateMultiListClear(
    fbSubTemplateMultiList_t    *sTML)
{
    fbSubTemplateMultiListClearEntries(sTML);

    g_slice_free1(sTML->numElements * sizeof(fbSubTemplateMultiListEntry_t),
                  sTML->firstEntry);
    sTML->numElements = 0;
    sTML->firstEntry = NULL;
}

void fbSubTemplateMultiListClearEntries(
    fbSubTemplateMultiList_t    *sTML)
{
    fbSubTemplateMultiListEntry_t   *entry = NULL;
    while ((entry = fbSubTemplateMultiListGetNextEntry(sTML, entry))) {
        fbSubTemplateMultiListEntryClear(entry);
    }
}

void fbSubTemplateMultiListFree(
    fbSubTemplateMultiList_t    *sTML)
{
    fbSubTemplateMultiListClear(sTML);
    g_slice_free1(sizeof(fbSubTemplateMultiList_t), sTML);
}

fbSubTemplateMultiListEntry_t* fbSubTemplateMultiListRealloc(
    fbSubTemplateMultiList_t    *sTML,
    uint16_t                    newNumElements)
{
    fbSubTemplateMultiListClearEntries(sTML);
    if (newNumElements != sTML->numElements) {
        g_slice_free1(sTML->numElements *
                      sizeof(fbSubTemplateMultiListEntry_t), sTML->firstEntry);
        sTML->numElements = newNumElements;
        sTML->firstEntry =
            g_slice_alloc0(sTML->numElements *
                           sizeof(fbSubTemplateMultiListEntry_t));
    }
    return sTML->firstEntry;
}

fbSubTemplateMultiListEntry_t*  fbSubTemplateMultiListAddNewEntries(
    fbSubTemplateMultiList_t    *sTML,
    uint16_t                     numNewEntries)
{
    fbSubTemplateMultiListEntry_t   *newFirstEntry;
    uint16_t    newNumElements = sTML->numElements + numNewEntries;
    uint16_t    oldNumElements = sTML->numElements;

    newFirstEntry = g_slice_alloc0(newNumElements *
                                   sizeof(fbSubTemplateMultiListEntry_t));
    if (sTML->firstEntry) {
        memcpy(newFirstEntry, sTML->firstEntry,
                 (sTML->numElements * sizeof(fbSubTemplateMultiListEntry_t)));
        g_slice_free1(sTML->numElements *
                      sizeof(fbSubTemplateMultiListEntry_t), sTML->firstEntry);
    }

    sTML->numElements = newNumElements;
    sTML->firstEntry = newFirstEntry;
    return sTML->firstEntry + oldNumElements;
}

fbSubTemplateMultiListEntry_t* fbSubTemplateMultiListGetFirstEntry(
    fbSubTemplateMultiList_t    *sTML)
{
    return sTML->firstEntry;
}

fbSubTemplateMultiListEntry_t* fbSubTemplateMultiListGetIndexedEntry(
    fbSubTemplateMultiList_t   *sTML,
    uint16_t                    stmlIndex)
{
    if (stmlIndex >= sTML->numElements) {
        return NULL;
    }

    return sTML->firstEntry + stmlIndex;
}

fbSubTemplateMultiListEntry_t* fbSubTemplateMultiListGetNextEntry(
    fbSubTemplateMultiList_t       *sTML,
    fbSubTemplateMultiListEntry_t  *currentEntry)
{

    if (!currentEntry) {
        return sTML->firstEntry;
    }

    currentEntry++;

    if ((uint16_t)(currentEntry - sTML->firstEntry) >= sTML->numElements) {
        return NULL;
    }
    return currentEntry;
}

void fbSubTemplateMultiListEntryClear(
    fbSubTemplateMultiListEntry_t   *entry)
{
    g_slice_free1(entry->dataLength, entry->dataPtr);
    entry->dataLength = 0;
    entry->dataPtr = NULL;
}

void* fbSubTemplateMultiListEntryGetDataPtr(
    fbSubTemplateMultiListEntry_t   *entry)
{
    return entry->dataPtr;
}

void* fbSubTemplateMultiListEntryInit(
    fbSubTemplateMultiListEntry_t  *entry,
    uint16_t                        tmplID,
    fbTemplate_t                   *tmpl,
    uint16_t                        numElements)
{

    entry->tmplID = tmplID;
    entry->tmpl = tmpl;
    if (!tmpl) {
        return NULL;
    }
    entry->numElements = numElements;
    entry->dataLength = tmpl->ie_internal_len * numElements;
    entry->dataPtr = g_slice_alloc0(entry->dataLength);

    return entry->dataPtr;
}

const fbTemplate_t* fbSubTemplateMultiListEntryGetTemplate(
    fbSubTemplateMultiListEntry_t   *entry)
{
    return entry->tmpl;
}

uint16_t    fbSubTemplateMultiListEntryGetTemplateID(
    fbSubTemplateMultiListEntry_t   *entry)
{
    return entry->tmplID;
}

void *fbSubTemplateMultiListEntryRealloc(
    fbSubTemplateMultiListEntry_t  *entry,
    uint16_t                        newNumElements)
{
    if (newNumElements == entry->numElements) {
        return entry->dataPtr;
    }
    g_slice_free1(entry->dataLength, entry->dataPtr);
    entry->numElements = newNumElements;
    entry->dataLength = newNumElements * entry->tmpl->ie_internal_len;
    entry->dataPtr = g_slice_alloc0(entry->dataLength);
    return entry->dataPtr;
}

void* fbSubTemplateMultiListEntryNextDataPtr(
    fbSubTemplateMultiListEntry_t   *entry,
    void                            *curPtr)
{
    uint16_t    tmplLen;
    uint8_t     *currentPtr = curPtr;

   if (!currentPtr) {
        return entry->dataPtr;
    }

    tmplLen = entry->tmpl->ie_internal_len;

    currentPtr += tmplLen;

    if ((uint16_t)(currentPtr - entry->dataPtr) >= entry->dataLength) {
        return NULL;
    }

    return (void*)currentPtr;
}

void* fbSubTemplateMultiListEntryGetIndexedPtr(
    fbSubTemplateMultiListEntry_t   *entry,
    uint16_t                         stmleIndex)
{
    if (stmleIndex >= entry->numElements) {
        return NULL;
    }

    return ((uint8_t*)(entry->dataPtr) +
            (stmleIndex * entry->tmpl->ie_internal_len));
}
