/**
 *@internal
 *
 ** private.h
 ** fixbuf IPFIX Implementation Private Interface
 **
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2006-2013 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Brian Trammell
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

#ifndef _FB_PRIVATE_H_
#define _FB_PRIVATE_H_
#include <fixbuf/public.h>

#if HAVE_SPREAD
#include <sp.h>
#include <pthread.h>
#endif

#ident "$Id: private.h 18731 2013-02-28 15:59:53Z ecoff_svn $"

/**
 * @file
 *
 * fixbuf IPFIX protocol library private interface. These calls and structures
 * are intended for the use of libfixbuf modules, and as such are not
 * documented or guaranteed to remain stable in any way. Applications using
 * these calls and structures may have to be modified to track changes to this
 * interface across minor version releases of fixbuf.
 */


/** define the bit in ID's that marks the Enterprise ID's */
#define IPFIX_ENTERPRISE_BIT    0x8000
/** This is the Private Enterprise Number defined in the
    IPFIX standard, see RFC 5102, for reverse flow datum */
#define IPFIX_REVERSE_PEN       29305

/** definition of the max-size of an fbuf_t buffer, or the
    default/only size */
#define FB_MSGLEN_MAX       65535

#ifdef HAVE_SPREAD

typedef struct sp_groupname_st
{
    char    name[MAX_GROUP_NAME];
} sp_groupname_t;

#define FB_SPREAD_NUM_GROUPS    16
#define FB_SPREAD_MTU           8192

typedef struct fbSpreadSpec_st {
    /** pointer to the session, this MUST be set to a valid session before
    *   the spec is passed to fbExporterAllocSpread. */
    fbSession_t     *session;
    /** pointer to the daemon host address, in Spread format.  Must be set
    *   before the spec is passed to fbExporterAllocSpread */
    char *          daemon;
    /** pointer to array of group names, must have at least one, and must be null term array */
    sp_groupname_t  *groups;
    /** number of groups in groups */
    int             num_groups;
    /** groups to send to */
    sp_groupname_t  *groups_to_send;
    int             num_groups_to_send;
    /** the mailbox for the connection */
    mailbox         mbox;
    /** the connection private name */
    char            privgroup[MAX_GROUP_NAME + 2];
    /** Spread write lock */
    pthread_mutex_t write_lock;
    /** the receiver thread */
    pthread_t       recv_thread;
    /** the receiver's mailbox */
    mailbox         recv_mbox;
    /** the connection private name for the receiver */
    char            recv_privgroup[MAX_GROUP_NAME + 2];
    /** GError for thread errors, set by receiver, read by main */
    GError          *recv_err;
    /** flag to tell the thread to exit */
    int             recv_exit;
    /** max size of group name array */
    int             recv_max_groups;
    /** actual size of group name array */
    int             recv_num_groups;
    /** groups array for SP_receive */
    sp_groupname_t  *recv_groups;
    /** length of message buffer */
    int             recv_max;
    /** message buffer for receive */
    char            *recv_mess;
} fbSpreadSpec_t;

#endif /* HAVE_SPREAD */

/**
 * An UDP Connection specifier.  These are managed by the
 * collector.  The collector creates one fbUDPConnSpec_t
 * per "UDP session." A UDP session is defined by a unique
 * IP and observation domain."
 */
typedef struct fbUDPConnSpec_st {
    /** pointer to the session for this peer address */
    fbSession_t             *session;
    /** application context. Created and owned by the app */
    void                    *ctx;
    /** key to this conn spec */
    union {
        struct sockaddr      so;
        struct sockaddr_in   ip4;
        struct sockaddr_in6  ip6;
    } peer;
    /** size of peer */
    size_t                   peerlen;
    /** link to next one in list */
    struct fbUDPConnSpec_st  *next;
    /** doubly linked to timeout faster */
    struct fbUDPConnSpec_st  *prev;
    /** last seen time */
    time_t                   last_seen;
    /** with peer address this is the key */
    uint32_t                 obdomain;
    /** reject flag */
    gboolean                 reject;
} fbUDPConnSpec_t;


/**
 * An IPFIX template or options template structure. Part of the private
 * interface. Applications should use the fbTemplate calls defined in public.h
 * to manipulate templates instead of accessing this structure directly.
 */
struct fbTemplate_st {
    /** Information model (for looking up information elements by spec) */
    fbInfoModel_t       *model;
    /** Reference count */
    int                 ref_count;
    /** Count of information elements in template. */
    uint16_t            ie_count;
    /**
     * Count of scope information elements in template. If sie_count
     * is greater than 0, this template is an options template.
     */
    uint16_t            scope_count;
    /**
     * Total length of information elements in records described by
     * this template. If the is_varlen flag is set, this represents the
     * minimum length of the information elements in the record
     * (i.e. with each variable length IE's length set to 0).
     */
    uint16_t            ie_len;
    /**
     * Total length required to store this template in a data structure.
     * Uses sizeof(fbVarfield_t), sizeof(fbBasicList_t), etc instead of 0
     * as done with ie_len
     */
    uint16_t            ie_internal_len;
    /**
     * Total length of the template record or options template record
     * defining this template. Used during template input and output.
     */
    uint16_t            tmpl_len;
    /** Set to TRUE if this template contains any variable length IEs. */
    gboolean            is_varlen;
    /** Ordered array of pointers to information elements in this template. */
    fbInfoElement_t     **ie_ary;
    /** Map of information element to index in ie_ary. */
    GHashTable          *indices;
        /** Field offset cache. For internal use by the transcoder. */
    uint16_t            *off_cache;
    /** TRUE if this template has been activated (is no longer mutable) */
    gboolean            active;
};

/**
 * fBufRewind
 *
 * @param fbuf
 *
 */
void                fBufRewind(
    fBuf_t              *fbuf);

/**
 * fBufAppendTemplate
 *
 * @param fbuf
 * @param tmpl_id
 * @param tmpl
 * @param revoked
 * @param err
 *
 * @return TRUE on success, FALSE on error
 */
gboolean            fBufAppendTemplate(
    fBuf_t              *fbuf,
    uint16_t            tmpl_id,
    fbTemplate_t        *tmpl,
    gboolean            revoked,
    GError              **err);

#if HAVE_SPREAD
/**
 * fBufSetExportGroups
 *
 *
 *
 */
void                fBufSetExportGroups(
    fBuf_t              *fbuf,
    char                **groups,
    int                 num_groups,
    GError              **err);


#endif

/**
 * fBufRemoveTemplateTcplan
 *
 *
 */
void fBufRemoveTemplateTcplan(
    fBuf_t         *fbuf,
    fbTemplate_t   *tmpl);

/**
 * fBufSetSession
 *
 */
void         fBufSetSession(
    fBuf_t          *fbuf,
    fbSession_t     *session);


/**
 * fbInfoElementHash
 *
 * @param ie
 *
 *
 */
uint32_t            fbInfoElementHash(
    fbInfoElement_t     *ie);

/**
 * fbInfoElementEqual
 *
 * @param a
 * @param b
 *
 *
 */
gboolean            fbInfoElementEqual(
    const fbInfoElement_t   *a,
    const fbInfoElement_t   *b);

/**
 *fbInfoElementDebug
 *
 * @param tmpl
 * @param ie
 *
 */
void                fbInfoElementDebug(
    gboolean            tmpl,
    fbInfoElement_t     *ie);

/**
 * fbInfoModelGetElement
 *
 * @param model
 * @param ex_ie
 *
 */
const fbInfoElement_t     *fbInfoModelGetElement(
    fbInfoModel_t       *model,
    fbInfoElement_t     *ex_ie);

/**
 * fbInfoElementCopyToTemplate
 *
 * @param model
 * @param ex_ie
 * @param tmpl_ie
 *
 */
gboolean            fbInfoElementCopyToTemplate(
    fbInfoModel_t       *model,
    fbInfoElement_t     *ex_ie,
    fbInfoElement_t     *tmpl_ie);

/**
 * fbInfoElementCopyToTemplateByName
 *
 * @param model
 * @param name
 * @param len_override
 * @param tmpl_ie
 *
 *
 */
gboolean            fbInfoElementCopyToTemplateByName(
    fbInfoModel_t       *model,
    const char          *name,
    uint16_t            len_override,
    fbInfoElement_t     *tmpl_ie);

/**
 * fbTemplateRetain
 *
 * @param tmpl
 *
 *
 */
void                fbTemplateRetain(
    fbTemplate_t        *tmpl);

/**
 * fbTemplateRelease
 *
 *
 * @param tmpl
 *
 */
void                fbTemplateRelease(
    fbTemplate_t        *tmpl);

/**
 * fbTemplateFree
 *
 * @param tmpl
 *
 *
 */
void                fbTemplateFree(
    fbTemplate_t        *tmpl);

/**
 * fbTemplateDebug
 *
 * @param label
 * @param tid
 * @param tmpl
 *
 */
void                fbTemplateDebug(
    const char          *label,
    uint16_t            tid,
    fbTemplate_t        *tmpl);

/**
 * Returns the callback function for a given session
 *
 * @param session
 * @return the callback function variable in the session
 */
fbNewTemplateCallback_fn fbSessionTemplateCallback(
    fbSession_t     *session);
/**
 * fbSessionClone
 *
 * @param base
 *
 */
fbSession_t         *fbSessionClone(
    fbSession_t         *base);

/**
 * fbSessionGetSequence
 *
 * @param session
 *
 *
 */
uint32_t            fbSessionGetSequence(
    fbSession_t         *session);

/**
 * fbSessionSetSequence
 *
 * @param session
 * @param sequence
 *
 */
void                fbSessionSetSequence(
    fbSession_t         *session,
    uint32_t            sequence);

/**
 * fbSessionSetTemplateBuffer
 *
 * @param session
 * @param fbuf
 *
 */
void                fbSessionSetTemplateBuffer(
    fbSession_t         *session,
    fBuf_t              *fbuf);

/**
 * fbSessionGetInfoModel
 *
 * @param session
 *
 *
 */
fbInfoModel_t       *fbSessionGetInfoModel(
    fbSession_t         *session);

#if HAVE_SPREAD
/**
 * fbSessionSetGroupParams
 *
 */
void fbSessionSetGroupParams(
    fbSession_t     *session,
    sp_groupname_t  *groups,
    int              num_groups);

/**
 * fbSessionSetPrivateGroup
 *
 *
 */
void fbSessionSetPrivateGroup(
    fbSession_t       *session,
    char              *group,
    char              *privgroup);

/**
 * fbSessionSetGroup
 *
 */
void                fbSessionSetGroup(
    fbSession_t         *session,
    char                *group);

/**
 * fbSessionGetGroupOffset
 *
 */
unsigned int fbSessionGetGroupOffset(
    fbSession_t     *session,
    char            *group);

/**
 * fbSessionGetGroup
 *
 */
unsigned int       fbSessionGetGroup(
    fbSession_t      *session);
#endif
/**
 * fbConnSpecLookupAI
 *
 * @param spec
 * @param passive
 * @param err
 *
 */
gboolean            fbConnSpecLookupAI(
    fbConnSpec_t        *spec,
    gboolean            passive,
    GError              **err);

/**
 * fbConnSpecInitTLS
 *
 * @param spec
 * @param passive
 * @param err
 *
 */
gboolean            fbConnSpecInitTLS(
    fbConnSpec_t        *spec,
    gboolean            passive,
    GError              **err);

/**
 * fbConnSpecCopy
 *
 * @param spec
 *
 *
 */
fbConnSpec_t        *fbConnSpecCopy(
    fbConnSpec_t        *spec);

/**
 * fbConnSpecFree
 *
 * @param spec
 *
 *
 */
void                fbConnSpecFree(
    fbConnSpec_t        *spec);

#if HAVE_SPREAD
/**
 * fbConnSpreadCopy
 *
 * @param spec
 *
 *
 */
fbSpreadSpec_t        *fbConnSpreadCopy(
    fbSpreadParams_t        *spec);

/**
 * fbConnSpreadFree
 *
 * @param spec
 *
 *
 */
void                fbConnSpreadFree(
    fbSpreadSpec_t        *spec);

/**
 * fbConnSpreadError
 *
 * Return a string message for the given Spread error code
 *
 * @param err the spread error code
 * @return the text message
 */
const char * fbConnSpreadError(
    int err );


/**
 * fbExporterSetGroupToSend
 *
 * @param exporter
 * @param groups
 * @param number of groups in above group list
 *
 */

void fbExporterSetGroupsToSend(
    fbExporter_t      *exporter,
    char              **groups,
    int               num_groups);


/**
 * fbExporterCheckGroups
 *
 * @param exporter
 * @param groups
 * @param number of groups in above group list
 * @return TRUE if group is in subscribed group list
 *
 */
gboolean fbExporterCheckGroups(
    fbExporter_t      *exporter,
    char              **groups,
    int                num_groups);


#endif /* HAVE_SPREAD */

/**
 * fbExporterGetMTU
 *
 * @param exporter
 *
 *
 */
uint16_t            fbExporterGetMTU(
    fbExporter_t        *exporter);

/**
 * fbExportMessage
 *
 * @param exporter
 * @param msgbase
 * @param msglen
 * @param err
 *
 */
gboolean            fbExportMessage(
    fbExporter_t        *exporter,
    uint8_t             *msgbase,
    size_t              msglen,
    GError              **err);

/**
 * fbExporterFree
 *
 * @param exporter
 *
 *
 */
void                fbExporterFree(
    fbExporter_t       *exporter);

/**
 * fbCollectorRemoveListenerLastBuf
 *
 * @param fbuf
 * @param collector
 *
 */
void fbCollectorRemoveListenerLastBuf(
    fBuf_t             *fbuf,
    fbCollector_t      *collector);

/**
 * fbCollectorAllocSocket
 *
 * @param listener
 * @param ctx
 * @param fd
 * @param peer
 * @param peerlen
 *
 */
fbCollector_t       *fbCollectorAllocSocket(
    fbListener_t        *listener,
    void                *ctx,
    int                 fd,
    struct sockaddr     *peer,
    size_t              peerlen);

/**
 * fbCollectorAllocTLS
 *
 * @param listener
 * @param ctx
 * @param fd
 * @param peer
 * @param peerlen
 * @param err
 *
 */
fbCollector_t       *fbCollectorAllocTLS(
    fbListener_t        *listener,
    void                *ctx,
    int                 fd,
    struct sockaddr     *peer,
    size_t              peerlen,
    GError              **err);

/**
 * fbCollectMessage
 *
 * @param collector
 * @param msgbase
 * @param msglen
 * @param err
 *
 */
gboolean            fbCollectMessage(
    fbCollector_t       *collector,
    uint8_t             *msgbase,
    size_t              *msglen,
    GError              **err);

/**
 * fbCollectorGetFD
 *
 * @param collector
 *
 *
 */
int                 fbCollectorGetFD(
    fbCollector_t       *collector);

/**
 * fbCollectorFree
 *
 * @param collector
 *
 *
 */
void                fbCollectorFree(
    fbCollector_t       *collector);

/**
 * fbCollectorHasTranslator
 *
 * @param collector
 *
 *
 */
gboolean        fbCollectorHasTranslator(
    fbCollector_t   *collector);


#if HAVE_SPREAD
/**
 * fbCollectorTestGroupMembership
 *
 * @param collector
 * @param group_offset
 *
 */
gboolean       fbCollectorTestGroupMembership(
    fbCollector_t       *collector,
    int                 group_offset);

#endif

/**
 * fbListenerAppFree
 *
 * @param listener
 * @param ctx
 *
 */
void fbListenerAppFree(
    fbListener_t   *listener,
    void           *ctx);

/**
 * fbListenerRemoveLastBuf
 *
 * @param fbuf
 * @param listener
 *
 */
void fbListenerRemoveLastBuf(
    fBuf_t         *fbuf,
    fbListener_t   *listener);

/**
 * fbListenerRemove
 *
 * @param listener
 * @param fd
 *
 */
void fbListenerRemove(
    fbListener_t        *listener,
    int                 fd);

/**
 * fbListenerGetConnSpec
 *
 * @param listener
 *
 *
 */
fbConnSpec_t        *fbListenerGetConnSpec(
    fbListener_t        *listener);

/**
 * Interrupt the socket for a given collector to stop it from reading
 * more data
 *
 * @param collector pointer to the collector to stop reading from
 */
void fbCollectorInterruptSocket(
    fbCollector_t   *collector);

/**
 * call appinit from UDP
 *
 */
gboolean fbListenerCallAppInit(
    fbListener_t       *listener,
    fbUDPConnSpec_t    *spec,
    GError             **err);

/**
 * Set the session on the fbuf and listener.
 *
 */

fbSession_t *fbListenerSetPeerSession(
    fbListener_t        *listener,
    fbSession_t         *session);

#endif
