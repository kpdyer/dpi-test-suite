/*
 ** fbtemplate.c
 ** IPFIX Template implementation
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

#ident "$Id: fbtemplate.c 18713 2013-02-21 15:34:28Z ecoff_svn $"

void fbTemplateDebug(
    const char      *label,
    uint16_t        tid,
    fbTemplate_t    *tmpl)
{
    int i;

    fprintf(stderr, "%s template %04x [%p] iec=%u sc=%u len=%u\n", label, tid,
            tmpl, tmpl->ie_count, tmpl->scope_count, tmpl->ie_len);

    for (i = 0; i < tmpl->ie_count; i++) {
        fprintf(stderr,"\t%2u ", i);
        fbInfoElementDebug(TRUE, tmpl->ie_ary[i]);
    }
}

fbTemplate_t        *fbTemplateAlloc(
    fbInfoModel_t       *model)
{
    fbTemplate_t    *tmpl = NULL;

    /* create a new template */
    tmpl = g_slice_new0(fbTemplate_t);

    /* fill it in */
    tmpl->model = model;
    tmpl->tmpl_len = 4;
    tmpl->active = FALSE;

    /* allocate indices table */
    tmpl->indices = g_hash_table_new((GHashFunc)fbInfoElementHash,
                                     (GEqualFunc)fbInfoElementEqual);
    return tmpl;
}

void                fbTemplateRetain(
    fbTemplate_t        *tmpl)
{
    /* Increment reference count */
    ++(tmpl->ref_count);
}

void                fbTemplateRelease(
    fbTemplate_t        *tmpl)
{
    /* Decrement reference count */
    --(tmpl->ref_count);
    /* Free if not referenced */
    fbTemplateFreeUnused(tmpl);
}

void                fbTemplateFreeUnused(
    fbTemplate_t        *tmpl)
{
    if (tmpl->ref_count <= 0) {
        fbTemplateFree(tmpl);
    }
}

void                fbTemplateFree(
    fbTemplate_t        *tmpl)
{
    int                 i;

    /* destroy index table if present */
    if (tmpl->indices) g_hash_table_destroy(tmpl->indices);

    /* destroy IE array */
    for (i = 0; i < tmpl->ie_count; i++) {
        g_slice_free(fbInfoElement_t, tmpl->ie_ary[i]);
    }
    g_free(tmpl->ie_ary);

    /* destroy offset cache if present */
    if (tmpl->off_cache) g_free(tmpl->off_cache);
    /* destroy template */
    g_slice_free(fbTemplate_t, tmpl);

}

static fbInfoElement_t *fbTemplateExtendElements(
    fbTemplate_t        *tmpl)
{
    if (tmpl->ie_count) {
        tmpl->ie_ary =
            g_renew(fbInfoElement_t*, tmpl->ie_ary, ++(tmpl->ie_count));
    } else {
        tmpl->ie_ary = g_new(fbInfoElement_t*, 1);
        ++(tmpl->ie_count);
    }

    tmpl->ie_ary[tmpl->ie_count - 1] = g_slice_new0(fbInfoElement_t);

    return tmpl->ie_ary[tmpl->ie_count - 1];
}

static void     fbTemplateExtendIndices(
    fbTemplate_t        *tmpl,
    fbInfoElement_t     *tmpl_ie)
{
    void                *ign0, *ign1;

    /* search indices table for multiple IE index */
    while (g_hash_table_lookup_extended(tmpl->indices, tmpl_ie, &ign0, &ign1)) {
        ++(tmpl_ie->midx);
    }

    /* increment template lengths */
    tmpl->tmpl_len += tmpl_ie->ent ? 8 : 4;
    if (tmpl_ie->len == FB_IE_VARLEN) {
        tmpl->is_varlen = TRUE;
        tmpl->ie_len += 1;
        if (tmpl_ie->num == FB_IE_BASIC_LIST) {
                tmpl->ie_internal_len += sizeof(fbBasicList_t);
            } else if (tmpl_ie->num == FB_IE_SUBTEMPLATE_LIST) {
                tmpl->ie_internal_len += sizeof(fbSubTemplateList_t);
            } else if (tmpl_ie->num == FB_IE_SUBTEMPLATE_MULTILIST) {
                tmpl->ie_internal_len += sizeof(fbSubTemplateMultiList_t);
            } else {
                tmpl->ie_internal_len += sizeof(fbVarfield_t);
            }
    } else {
        tmpl->ie_len += tmpl_ie->len;
        tmpl->ie_internal_len += tmpl_ie->len;
    }

    /* Add index of this information element to the indices table */
    g_hash_table_insert(tmpl->indices, tmpl_ie,
                        GUINT_TO_POINTER(tmpl->ie_count - 1));
}

gboolean            fbTemplateAppend(
    fbTemplate_t        *tmpl,
    fbInfoElement_t     *ex_ie,
    GError              **err)
{
    fbInfoElement_t     *tmpl_ie;

    /* grow information element array */
    tmpl_ie = fbTemplateExtendElements(tmpl);

    /* copy information element out of the info model */
    if (!fbInfoElementCopyToTemplate(tmpl->model, ex_ie, tmpl_ie)) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NOELEMENT,
                    "No such information element %08x:%04x",
                    ex_ie->ent, ex_ie->num);
        return FALSE;
    }

    /* Handle index and counter updates */
    fbTemplateExtendIndices(tmpl, tmpl_ie);

    /* All done */
    return TRUE;
}

gboolean            fbTemplateAppendSpec(
    fbTemplate_t        *tmpl,
    fbInfoElementSpec_t *spec,
    uint32_t            flags,
    GError              **err)
{
    fbInfoElement_t     *tmpl_ie;

    /* Short-circuit on app flags mismatch */
    if (spec->flags && !((spec->flags & flags) == spec->flags)) {
        return TRUE;
    }

    /* grow information element array */
    tmpl_ie = fbTemplateExtendElements(tmpl);
    /* copy information element out of the info model */

    if (!fbInfoElementCopyToTemplateByName(tmpl->model, spec->name,
                                           spec->len_override, tmpl_ie)) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NOELEMENT,
                    "No such information element %s", spec->name);
        return FALSE;
    }

    /* Handle index and counter updates */
    fbTemplateExtendIndices(tmpl, tmpl_ie);

    /* All done */
    return TRUE;
}

gboolean            fbTemplateAppendSpecArray(
    fbTemplate_t        *tmpl,
    fbInfoElementSpec_t *spec,
    uint32_t            flags,
    GError              **err)
{
    for (; spec->name; spec++) {
        if (!fbTemplateAppendSpec(tmpl, spec, flags, err)) {
            return FALSE;
        }
    }

    return TRUE;
}

void                fbTemplateSetOptionsScope(
    fbTemplate_t        *tmpl,
    uint16_t            scope_count)
{
    /* Cannot set options scope if we've already done so */
    g_assert(!tmpl->scope_count);

    /* Cannot set scope count higher than IE count */
    g_assert(tmpl->ie_count && tmpl->ie_count >= tmpl->scope_count);

    /* scope count of zero means make the last IE the end of scope */
    tmpl->scope_count = scope_count ? scope_count : tmpl->ie_count;

    /* account for scope count in output */
    tmpl->tmpl_len += 2;
 }

gboolean           fbTemplateContainsElement(
    fbTemplate_t            *tmpl,
    const fbInfoElement_t   *ex_ie)
{
    int i;

    if ( ex_ie == NULL || tmpl == NULL ) {
        return FALSE;
    }

    for (i = 0; i < tmpl->ie_count; i++) {
        if (fbInfoElementEqual(ex_ie, tmpl->ie_ary[i])) return TRUE;
    }

    return FALSE;
}

gboolean           fbTemplateContainsElementByName(
    fbTemplate_t        *tmpl,
    fbInfoElementSpec_t *spec)
{
    return fbTemplateContainsElement(
        tmpl, fbInfoModelGetElementByName(tmpl->model, spec->name));
}

gboolean           fbTemplateContainsAllElementsByName(
    fbTemplate_t        *tmpl,
    fbInfoElementSpec_t *spec)
{
    for (; spec->name; spec++) {
        if (!fbTemplateContainsElementByName(tmpl, spec)) return FALSE;
    }

    return TRUE;
}

uint32_t            fbTemplateCountElements(
    fbTemplate_t        *tmpl)
{
    return tmpl->ie_count;
}

uint32_t            fbTemplateGetOptionsScope(
    fbTemplate_t        *tmpl)
{
    return tmpl->scope_count;
}
