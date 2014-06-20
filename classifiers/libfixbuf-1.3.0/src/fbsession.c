/*
 ** fbsession.c
 ** IPFIX Transport Session state container
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

#define _FIXBUF_SOURCE_
#include <fixbuf/private.h>

#ident "$Id"

struct fbSession_st {
    /** Information model. */
    fbInfoModel_t               *model;
    /** Current observation domain ID. */
    uint32_t                    domain;
    /**
     * Internal template table. Maps template ID to internal template.
     */
    GHashTable                  *int_ttab;
    /**
     * External template table for current observation domain.
     * Maps template ID to external template.
     */
    GHashTable                  *ext_ttab;

    uint16_t                    *tmpl_pair_array;   
    uint16_t                    num_tmpl_pairs; 

    fbNewTemplateCallback_fn    new_template_callback;

    /**
     * Mutex to guard the ext_ttab when using Spread.  Spread listens for new
     * group memberships.  On a new membership, the Spread transport will send
     * all external templates to the new member privately.  During this
     * process, the external template table cannot be modified, hence the
     * write lock on ext_ttab.
     */
    #if HAVE_SPREAD
    pthread_mutex_t             ext_ttab_wlock;
    /**
     * Group External Template Table.
     * Maps group to the external template table
     */
    GHashTable                  *grp_ttab;
    /**
     * Group Sequence Number Table
     * Maps group to sequence number (only looks at first group in list)
     */
    GHashTable                  *grp_seqtab;
    /**
     * Current Group
     */
    unsigned int                group;
    /**
     * Need to keep track of all groups session knows about
     */
    sp_groupname_t              *all_groups;
    /**
     * Number of groups session knows about.
     */
    int                         num_groups;
    #endif
    /**
     * Domain external template table.
     * Maps domain to external template table.
     */
    GHashTable                  *dom_ttab;
    /**
     * Last/next sequence number in current observation domain.
     */
    uint32_t                    sequence;
    /**
     * Domain last/next sequence number table.
     * Maps domain to sequence number.
     */
    GHashTable                  *dom_seqtab;
    /**
     * Buffer instance to write template dynamics to.
     */
    fBuf_t                      *tdyn_buf;
    /**
     * Error description for fbSessionExportTemplates()
     */
    GError                      *tdyn_err;
};

fbSession_t     *fbSessionAlloc(
    fbInfoModel_t   *model)
{
    fbSession_t     *session = NULL;

    /* Create a new session */
    session = g_slice_new0(fbSession_t);
    memset( session, 0, sizeof( fbSession_t ) );

    /* Store reference to information model */
    session->model = model;

    /* Allocate internal template table */
    session->int_ttab = g_hash_table_new(g_direct_hash, g_direct_equal);

    #if HAVE_SPREAD
    /* this lock is needed only if Spread is enabled */
    pthread_mutex_init( &session->ext_ttab_wlock, 0 );
    #endif

    /* Reset session externals (will allocate domain template tables, etc.) */
    fbSessionResetExternal(session);

    session->tmpl_pair_array = NULL;
    session->num_tmpl_pairs = 0;
    session->new_template_callback = NULL;

    /* All done */
    return session;
}

void fbSessionAddTemplateCallback(
    fbSession_t                *session,
    fbNewTemplateCallback_fn    callback)
{
    session->new_template_callback = callback;
}

fbNewTemplateCallback_fn    fbSessionTemplateCallback(
    fbSession_t *session)
{
    return session->new_template_callback;
}

void fbSessionAddTemplatePair(
    fbSession_t    *session,
    uint16_t        ext_tid,
    uint16_t        int_tid)
{
    gboolean madeTable = FALSE;

    if (!session->tmpl_pair_array) {
        session->tmpl_pair_array = (uint16_t*)g_slice_alloc0(
                                        sizeof(uint16_t) * (UINT16_MAX + 1));
        madeTable = TRUE;
    }

    if ((ext_tid == int_tid) || (int_tid == 0)) {
        session->tmpl_pair_array[ext_tid] = int_tid;
        session->num_tmpl_pairs++;
        return;
    }

    /* external and internal tids are different */
    /* only add the template pair if the internal template exists */
    if (fbSessionGetTemplate(session, TRUE, int_tid, NULL)) {
        session->tmpl_pair_array[ext_tid] = int_tid;
        session->num_tmpl_pairs++;
    } else {
        if (madeTable) {
            g_slice_free1(sizeof(uint16_t) * UINT16_MAX,
                          session->tmpl_pair_array);
            session->tmpl_pair_array = NULL;
        }
    }
}

void fbSessionRemoveTemplatePair(
    fbSession_t    *session,
    uint16_t        ext_tid)
{
    if (!session->tmpl_pair_array) {
        return;
    }

    if (session->tmpl_pair_array[ext_tid]) {
        session->num_tmpl_pairs--;
        if (!session->num_tmpl_pairs) {
            /* this was the last one, free the array */
            g_slice_free1(sizeof(uint16_t) * UINT16_MAX,
                          session->tmpl_pair_array);
            session->tmpl_pair_array = NULL;
            return;
        }
    }
    session->tmpl_pair_array[ext_tid] = 0;
}

uint16_t    fbSessionLookupTemplatePair(
    fbSession_t    *session,
    uint16_t        ext_tid)
{
    /* if there are no current pairs, just return ext_tid because that means
     * we should decode the entire external template
     */
    if (!session->tmpl_pair_array) {
        return ext_tid;
    }

    return session->tmpl_pair_array[ext_tid];
}

static void     fbSessionFreeOneTemplate(
    void            *vtid __attribute__((unused)),
    fbTemplate_t    *tmpl,
    fbSession_t     *session __attribute__((unused)))
{
    fbTemplateRelease(tmpl);
}

static void     fbSessionResetOneDomain(
    void            *vdomain __attribute__((unused)),
    GHashTable      *ttab,
    fbSession_t     *session)
{
    g_hash_table_foreach(ttab,
                         (GHFunc)fbSessionFreeOneTemplate, session);
}

void            fbSessionResetExternal(
    fbSession_t     *session)
{
    /* Clear out the old domain template table if we have one */
    if (session->dom_ttab) {
        /* Release all the external templates (will free unless shared) */
        g_hash_table_foreach(session->dom_ttab,
                            (GHFunc)fbSessionResetOneDomain, session);
        /* Nuke the domain template table */
        g_hash_table_destroy(session->dom_ttab);
    }

    /* Allocate domain template table */
    session->dom_ttab =
        g_hash_table_new_full(g_direct_hash, g_direct_equal,
                              NULL, (GDestroyNotify)g_hash_table_destroy);

    /* Null out stale external template table */
    #if HAVE_SPREAD
    pthread_mutex_lock( &session->ext_ttab_wlock );
    session->ext_ttab = NULL;
    pthread_mutex_unlock( &session->ext_ttab_wlock );
    #else
    session->ext_ttab = NULL;
    #endif

    /* Clear out the old sequence number table if we have one */
    if (session->dom_seqtab) {
        g_hash_table_destroy(session->dom_seqtab);
    }

    /* Allocate domain sequence number table */
    session->dom_seqtab =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
                              NULL);

    /* Zero sequence number and domain */
    session->sequence = 0;
    session->domain = 0;

#if HAVE_SPREAD
    if (session->grp_ttab) {
        g_hash_table_destroy(session->grp_ttab);
    }
    /*Allocate group template table */
    session->grp_ttab =
        g_hash_table_new_full(g_direct_hash, g_direct_equal,
                              NULL, (GDestroyNotify)g_hash_table_destroy);
    if (session->grp_seqtab) {
        g_hash_table_destroy(session->grp_seqtab);
    }
    session->grp_seqtab = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                                NULL, NULL);

    /** Group 0 just means if we never sent a template on a group -
     * we will multicast to every group we know about */

    session->group = 0;
#endif

    /* Set domain to 0 (initializes external template table) */
    fbSessionSetDomain(session, 0);
}

void            fbSessionFree(
    fbSession_t     *session)
{
    fbSessionResetExternal(session);
    g_hash_table_foreach(session->int_ttab,
                         (GHFunc)fbSessionFreeOneTemplate, session);
    g_hash_table_destroy(session->int_ttab);
    g_hash_table_destroy(session->dom_ttab);
    if (session->dom_seqtab) {
        g_hash_table_destroy(session->dom_seqtab);
    }
    if (session->tmpl_pair_array) {
        g_slice_free1(sizeof(uint16_t) * UINT16_MAX,
                      session->tmpl_pair_array);
        session->tmpl_pair_array = NULL;
    }
#if HAVE_SPREAD
    if (session->grp_ttab) {
        g_hash_table_destroy(session->grp_ttab);
    }
    if (session->grp_seqtab) {
        g_hash_table_destroy(session->grp_seqtab);
    }
#endif
    g_slice_free(fbSession_t, session);
}

void            fbSessionSetDomain(
    fbSession_t     *session,
    uint32_t        domain)
{
    /* Short-circuit identical domain if not initializing */
    if (session->ext_ttab && (domain == session->domain)) return;

    /* Update external template table; create if necessary. */
    #if HAVE_SPREAD
    pthread_mutex_lock( &session->ext_ttab_wlock );
    #endif
    session->ext_ttab = g_hash_table_lookup( session->dom_ttab,
                                             GUINT_TO_POINTER(domain) );
    if (!session->ext_ttab)
    {
        session->ext_ttab = g_hash_table_new(g_direct_hash, g_direct_equal);
        g_hash_table_insert(session->dom_ttab, GUINT_TO_POINTER(domain),
                            session->ext_ttab);
    }
    #if HAVE_SPREAD
    pthread_mutex_unlock( &session->ext_ttab_wlock );
    #endif
    /* Stash current sequence number */
    g_hash_table_insert(session->dom_seqtab,
                        GUINT_TO_POINTER(session->domain),
                        GUINT_TO_POINTER(session->sequence));

    /* Get new sequence number */
    session->sequence = GPOINTER_TO_UINT(
        g_hash_table_lookup(session->dom_seqtab,GUINT_TO_POINTER(domain)));

    /* Stash new domain */
    session->domain = domain;
}

#if HAVE_SPREAD
void fbSessionSetGroupParams(
    fbSession_t     *session,
    sp_groupname_t  *groups,
    int              num_groups)
{
    session->all_groups = groups;
    session->num_groups = num_groups;
}

unsigned int fbSessionGetGroupOffset(
    fbSession_t     *session,
    char            *group)
{
    int loop;

    for (loop = 0; loop < session->num_groups; loop++){
        if (strcmp(group, session->all_groups[loop].name) == 0) {
            return (loop + 1);
        }
    }


    return 0;
}

void            fbSessionSetPrivateGroup(
    fbSession_t      *session,
    char             *group,
    char             *privgroup)
{
    int loop, group_offset = 0;
    char **g;
    GError **err = NULL;

    if (group == NULL || privgroup == NULL) {
        return;
    }

    for (loop = 0; loop < session->num_groups; loop++) {
        if (strncmp(group, session->all_groups[loop].name,
                    strlen(session->all_groups[loop].name)) == 0)
        {
            group_offset = loop + 1;
        }
    }

    if (group_offset == 0){
        g_warning("Private Group requesting membership from UNKNOWN group");
        return;
    }

    if (fBufGetExporter(session->tdyn_buf) && session->group > 0) {
        if (!fBufEmit(session->tdyn_buf, err)) {
            g_warning("Could not emit buffer %s", (*err)->message);
            g_clear_error(err);
        }
    }

    /*Update external template table; create if necessary. */

    pthread_mutex_lock(&session->ext_ttab_wlock);
    session->ext_ttab = g_hash_table_lookup(session->grp_ttab,
                                            GUINT_TO_POINTER(group_offset));

    if (!session->ext_ttab) {
        session->ext_ttab = g_hash_table_new(g_direct_hash, g_direct_equal);
        g_hash_table_insert(session->grp_ttab, GUINT_TO_POINTER(group_offset),
                            session->ext_ttab);
    }
    pthread_mutex_unlock(&session->ext_ttab_wlock);

    g_hash_table_insert(session->grp_seqtab, GUINT_TO_POINTER(session->group),
                        GUINT_TO_POINTER(session->sequence));

    /* Get new sequence number */
    session->sequence = GPOINTER_TO_UINT(
        g_hash_table_lookup(session->grp_seqtab,
                            GUINT_TO_POINTER(group_offset)));

    session->group = group_offset;

    g = &privgroup;

    if (fBufGetExporter(session->tdyn_buf)) {
        fBufSetExportGroups(session->tdyn_buf, g, 1, err);
    }

    fbSessionExportTemplates(session, err);
}

/**
 * fbSessionAddTemplatesMulticast
 *
 *
 */
gboolean        fbSessionAddTemplatesMulticast(
    fbSession_t      *session,
    char             **groups,
    gboolean         internal,
    uint16_t         tid,
    fbTemplate_t     *tmpl,
    GError           **err)
{
    int n = 0;
    unsigned int group_offset;
    GHashTable *ttab;
    uint16_t next_tid = 0;

    if (groups == NULL) {
        return FALSE;
    }

    if (fBufGetExporter(session->tdyn_buf) && session->group > 0) {
        /* we are now going to multicast tmpls so we need to emit
           records currently in the buffer */
        if (!fBufEmit(session->tdyn_buf, err)) {
            return FALSE;
        }
    }

    if (tid == FB_TID_AUTO) {
        if (next_tid == 0) next_tid = FB_TID_MIN_DATA;
        while (fbSessionGetTemplate(session, internal, next_tid, NULL)) {
            next_tid++;
            if (next_tid == 0) next_tid = FB_TID_MIN_DATA;
        }
            tid = next_tid++;
    }

    /*Update external template table per group; create if necessary. */
    while (groups[n]) {
        group_offset = fbSessionGetGroupOffset(session, groups[n]);

        if (group_offset == 0) {
            g_warning("Spread Group Not Recognized.");
            return FALSE;
        }

        pthread_mutex_lock(&session->ext_ttab_wlock);
        session->ext_ttab = g_hash_table_lookup(session->grp_ttab,
                                               GUINT_TO_POINTER(group_offset));

        if (!session->ext_ttab) {
            session->ext_ttab = g_hash_table_new(g_direct_hash,g_direct_equal);
            g_hash_table_insert(session->grp_ttab,
                                GUINT_TO_POINTER(group_offset),
                                session->ext_ttab);
        }

        pthread_mutex_unlock(&session->ext_ttab_wlock);
        g_hash_table_insert(session->grp_seqtab,
                            GUINT_TO_POINTER(session->group),
                            GUINT_TO_POINTER(session->sequence));

        /* Get new sequence number */
        session->sequence = GPOINTER_TO_UINT(
            g_hash_table_lookup(session->grp_seqtab,
                                GUINT_TO_POINTER(group_offset)));

        /* keep new group */
        session->group = group_offset;

        /* Select a template table to add the template to */
        ttab = internal ? session->int_ttab : session->ext_ttab;

        /* Revoke old template, ignoring missing template error. */
        if (!fbSessionRemoveTemplate(session, internal, tid, err)) {
            if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_TMPL)) {
                g_clear_error(err);
            } else {
                return FALSE;
            }
        }

        /* Insert template into table */
#if HAVE_SPREAD
        if (!internal)
            pthread_mutex_lock( &session->ext_ttab_wlock );
#endif
        g_hash_table_insert(ttab, GUINT_TO_POINTER((unsigned int)tid), tmpl);

#if HAVE_SPREAD
        if (!internal)
            pthread_mutex_unlock( &session->ext_ttab_wlock );
#endif
        fbTemplateRetain(tmpl);

        if (internal) {
            /* we don't really multicast internal tmpls - we only
               have one internal tmpl table - so once is enough */
            return TRUE;
        }

        n++;
    }

    /* Now set session to group 1 before we multicast */
    group_offset = fbSessionGetGroupOffset(session, groups[0]);

    pthread_mutex_lock(&session->ext_ttab_wlock);
    session->ext_ttab = g_hash_table_lookup(session->grp_ttab,
                                            GUINT_TO_POINTER(group_offset));
    pthread_mutex_unlock(&session->ext_ttab_wlock);

    g_hash_table_insert(session->grp_seqtab, GUINT_TO_POINTER(session->group),
                        GUINT_TO_POINTER(session->sequence));

    /* Get sequence number - since it's the first group in list */
    session->sequence = GPOINTER_TO_UINT(
        g_hash_table_lookup(session->grp_seqtab,
                            GUINT_TO_POINTER(group_offset)));

    /* keep new group */
    session->group = group_offset;

    if (fBufGetExporter(session->tdyn_buf)) {
        if (!fBufAppendTemplate(session->tdyn_buf, tid, tmpl, FALSE, err))
            return 0;

        fBufSetExportGroups(session->tdyn_buf, groups, n, err);
    }

    return TRUE;

}
/**
 * fbSessionSetGroup
 *
 *
 */
void            fbSessionSetGroup(
    fbSession_t      *session,
    char             *group)
{
    unsigned int group_offset;
    GError **err = NULL;

    if (group == NULL && session->ext_ttab) {
        /* ext_ttab should already be setup and we are multicasting
           so no need to setup any tables */
        return;
    }

    group_offset = fbSessionGetGroupOffset(session, group);

    if (group_offset == 0) {
        g_warning("Spread Group Not Recognized.");
        return;
    }

    /* short-circut identical group if not initializing */
    if (session->ext_ttab && (session->group == group_offset))  return;

    if (fBufGetExporter(session->tdyn_buf) && session->group > 0) {
        /* Group is changing - meaning tmpls changing - emit now */
        if (!fBufEmit(session->tdyn_buf, err)) {
            g_warning("Could not emit buffer before setting group: %s",
                      (*err)->message);
            g_clear_error(err);
        }
    }
    /*Update external template table; create if necessary. */

    if (fBufGetExporter(session->tdyn_buf)) {
        /* Only need to do this for exporters */
        /* Collector's templates aren't managed per group */
        pthread_mutex_lock(&session->ext_ttab_wlock);
        session->ext_ttab = g_hash_table_lookup(session->grp_ttab,
                                               GUINT_TO_POINTER(group_offset));

        if (!session->ext_ttab) {
            session->ext_ttab =g_hash_table_new(g_direct_hash, g_direct_equal);
            g_hash_table_insert(session->grp_ttab,
                                GUINT_TO_POINTER(group_offset),
                                session->ext_ttab);
        }

        pthread_mutex_unlock(&session->ext_ttab_wlock);
    }

    g_hash_table_insert(session->grp_seqtab, GUINT_TO_POINTER(session->group),
                        GUINT_TO_POINTER(session->sequence));

    /* Get new sequence number */
    session->sequence = GPOINTER_TO_UINT(
        g_hash_table_lookup(session->grp_seqtab,
                            GUINT_TO_POINTER(group_offset)));

    /* keep new group */
    session->group = group_offset;

}

unsigned int    fbSessionGetGroup(
    fbSession_t *session)
{
    return session->group;
}

#endif


uint32_t        fbSessionGetDomain(
    fbSession_t     *session)
{
    return session->domain;
}


uint16_t        fbSessionAddTemplate(
    fbSession_t     *session,
    gboolean        internal,
    uint16_t        tid,
    fbTemplate_t    *tmpl,
    GError          **err)
{
    GHashTable      *ttab = NULL;
    static uint16_t next_ext_tid = 0;
    static uint16_t next_int_tid = UINT16_MAX;

    /* Select a template table to add the template to */
    ttab = internal ? session->int_ttab : session->ext_ttab;
 
    /* prevent infinite loop when template tables are full */
    if (g_hash_table_size(ttab) == (UINT16_MAX - FB_TID_MIN_DATA)) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_TMPL,
                        "Template table is full, no IDs left");
        return 0;
    }

    /* Automatically assign a new template ID */
    if (tid == FB_TID_AUTO) {
        if (internal) {
            if (next_int_tid == (FB_TID_MIN_DATA - 1)) {
                next_int_tid = UINT16_MAX;
            }
            while (fbSessionGetTemplate(session, internal, next_int_tid, NULL))
            {
                next_int_tid--;
                if (next_int_tid == (FB_TID_MIN_DATA - 1)) {
                    next_int_tid = UINT16_MAX;
                }
            }
            tid = next_int_tid--;
        } else {
            if (next_ext_tid == 0) next_ext_tid = FB_TID_MIN_DATA;
            while (fbSessionGetTemplate(session, internal, next_ext_tid, NULL))             {
                next_ext_tid++;
                if (next_ext_tid == 0) next_ext_tid = FB_TID_MIN_DATA;
            }
            tid = next_ext_tid++;
        }
    }

    /* Revoke old template, ignoring missing template error. */
    if (!fbSessionRemoveTemplate(session, internal, tid, err)) {
        if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_TMPL)) {
            g_clear_error(err);
        } else {
            return 0;
        }
    }

    /* Write template to dynamics buffer */
    if (fBufGetExporter(session->tdyn_buf) && !internal) {
        if (!fBufAppendTemplate(session->tdyn_buf, tid, tmpl, FALSE, err))
            return 0;
    }

    /* Insert template into table */
    #if HAVE_SPREAD
    if (!internal)
        pthread_mutex_lock( &session->ext_ttab_wlock );
    #endif
    g_hash_table_insert(ttab, GUINT_TO_POINTER((unsigned int)tid), tmpl);
    #if HAVE_SPREAD
    if (!internal)
        pthread_mutex_unlock( &session->ext_ttab_wlock );
    #endif
    fbTemplateRetain(tmpl);

    return tid;
}

gboolean        fbSessionRemoveTemplate(
    fbSession_t     *session,
    gboolean        internal,
    uint16_t        tid,
    GError          **err)
{
    GHashTable      *ttab = NULL;
    fbTemplate_t    *tmpl = NULL;
    gboolean        ok = TRUE;

    /* Select a template table to remove the template from */
    ttab = internal ? session->int_ttab : session->ext_ttab;

    /* Get the template to remove */
    tmpl = fbSessionGetTemplate(session, internal, tid, err);
    if (!tmpl) return FALSE;

    /* Write template withdrawal to dynamics buffer */
    if (fBufGetExporter(session->tdyn_buf) && !internal) {
        ok = fBufAppendTemplate(session->tdyn_buf, tid, tmpl, TRUE, err);
    }

    /* Remove template */
    #if HAVE_SPREAD
    if (!internal)
        pthread_mutex_lock( &session->ext_ttab_wlock );
    #endif
    g_hash_table_remove(ttab, GUINT_TO_POINTER((unsigned int)tid));
    fbSessionRemoveTemplatePair(session, tid);

    fBufRemoveTemplateTcplan(session->tdyn_buf, tmpl);

    #if HAVE_SPREAD
    if (!internal)
        pthread_mutex_unlock( &session->ext_ttab_wlock );
    #endif
    fbTemplateRelease(tmpl);

    return ok;
}

fbTemplate_t    *fbSessionGetTemplate(
    fbSession_t     *session,
    gboolean        internal,
    uint16_t        tid,
    GError          **err)
{
    GHashTable      *ttab;
    fbTemplate_t    *tmpl;

    /* Select a template table to get the template from */
    ttab = internal ? session->int_ttab : session->ext_ttab;

    #if HAVE_SPREAD
    if (!internal)
        pthread_mutex_lock( &session->ext_ttab_wlock );
    #endif
    tmpl = g_hash_table_lookup(ttab, GUINT_TO_POINTER((unsigned int)tid));
    #if HAVE_SPREAD
    if (!internal)
        pthread_mutex_unlock( &session->ext_ttab_wlock );
    #endif

    /* Check for missing template */
    if (!tmpl) {
        if (internal) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_TMPL,
                        "Missing internal template %04hx",
                        tid);
        } else {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_TMPL,
                        "Missing external template %08x:%04hx",
                        session->domain, tid);
        }
        return NULL;
    }

    return tmpl;
}

gboolean        fbSessionExportTemplate(
    fbSession_t     *session,
    uint16_t        tid,
    GError          **err)
{
    fbTemplate_t    *tmpl = NULL;

    /* short-circuit on no template dynamics buffer */
    if (!fBufGetExporter(session->tdyn_buf))
        return TRUE;

    /* look up template */
    if (!(tmpl = fbSessionGetTemplate(session, FALSE, tid, err)))
        return FALSE;

    /* export it */
    return fBufAppendTemplate(session->tdyn_buf, tid, tmpl, FALSE, err);
}

static void     fbSessionExportOneTemplate(
    void            *vtid,
    fbTemplate_t    *tmpl,
    fbSession_t     *session)
{
    uint16_t        tid = (uint16_t)GPOINTER_TO_UINT(vtid);

    if (fBufGetExporter(session->tdyn_buf)) {
        if (session->tdyn_err) return;
        if (!fBufAppendTemplate(session->tdyn_buf, tid, tmpl,
                                FALSE, &session->tdyn_err)) {
            if (!session->tdyn_err) {
                g_set_error(&session->tdyn_err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                            "Unspecified template export error");
            }
        }
    }
}

gboolean        fbSessionExportTemplates(
    fbSession_t     *session,
    GError          **err)
{
    gboolean ret = TRUE;

    #if HAVE_SPREAD
    pthread_mutex_lock( &session->ext_ttab_wlock );
    #endif

    g_clear_error(&(session->tdyn_err));

    if (session->ext_ttab)
    {
        g_hash_table_foreach(session->ext_ttab,
                             (GHFunc)fbSessionExportOneTemplate, session);

        if (session->tdyn_err)
        {
            g_propagate_error(err, session->tdyn_err);
            ret = FALSE;
        }
    }

    #if HAVE_SPREAD
    pthread_mutex_unlock( &session->ext_ttab_wlock );
    #endif

    return ret;
}

static void     fbSessionCloneOneTemplate(
    void            *vtid,
    fbTemplate_t    *tmpl,
    fbSession_t     *session)
{
    uint16_t        tid = (uint16_t)GPOINTER_TO_UINT(vtid);
    GError          *err = NULL;
    if (!fbSessionAddTemplate(session, TRUE, tid, tmpl, &err)) {
        g_warning("Session clone internal template copy failed: %s",
                  err->message);
    }
}

fbSession_t     *fbSessionClone(
    fbSession_t     *base)
{
    fbSession_t     *session = NULL;

    /* Create a new session using the information model from the base */
    session = fbSessionAlloc(base->model);

    /* Add each internal template from the base session to the new session */
    g_hash_table_foreach(base->int_ttab,
                         (GHFunc)fbSessionCloneOneTemplate, session);

    /* Return the new session */
    return session;
}

uint32_t        fbSessionGetSequence(
    fbSession_t     *session)
{
    return session->sequence;
}

void            fbSessionSetSequence(
    fbSession_t     *session,
    uint32_t        sequence)
{
    session->sequence = sequence;
}

void            fbSessionSetTemplateBuffer(
    fbSession_t     *session,
    fBuf_t          *fbuf)
{
    session->tdyn_buf = fbuf;
}

fbInfoModel_t       *fbSessionGetInfoModel(
    fbSession_t         *session)
{
    return session->model;
}
