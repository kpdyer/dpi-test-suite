/**
 ** @file yafMeta2Pcap
 *
 * This program takes the pcap meta file created by YAF
 * and a flow key hash and start time and creates the pcap file
 * for the flow.
 * Use the getFlowKeyHash program to calculate the flow key hash.
 *
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2006-2013 Carnegie Mellon University.
 ** All Rights Reserved.
 **
 ** ------------------------------------------------------------------------
 ** Author: Emily Sarneso
 ** ------------------------------------------------------------------------
 ** @OPENSOURCE_HEADER_START@
 ** Use of the YAF system and related source code is subject to the terms
 ** of the following licenses:
 **
 ** GNU Public License (GPL) Rights pursuant to Version 2, June 1991
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


#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <libgen.h>
#include <glib.h>
#include <string.h>
#include <pcap.h>

#define MAX_LINE 4096

static char ** meta_file = NULL;
static char * out_file = NULL;
static char * flowkeyhash = NULL;
static char * flowstarttime = NULL;
static char ** pcap = NULL;
static gboolean yaf_out = FALSE;

static GOptionEntry md_core_option[] = {
    {"pcap-meta-file", 'f', 0, G_OPTION_ARG_FILENAME_ARRAY, &meta_file,
     "Pcap meta file[s] created by YAF.", NULL },
    {"pcap", 'p', 0, G_OPTION_ARG_FILENAME_ARRAY, &pcap,
     "Pcap file[s] to read if full path is not specified "
     "\n\t\t\t\tin pcap_meta_file.", NULL },
    {"out", 'o', 0, G_OPTION_ARG_STRING, &out_file,
     "Pcap output file.", NULL },
    {"hash", 'h', 0, G_OPTION_ARG_STRING, &flowkeyhash,
     "Flow Key Hash.", NULL },
    {"time", 't', 0, G_OPTION_ARG_STRING, &flowstarttime, "Time in milliseconds",
     NULL},
    {"full-path", 'y', 0, G_OPTION_ARG_NONE, &yaf_out,
     "Use if format of pcap_meta_file has full path "
     "\n\t\t\t\tname to file",
     NULL},
    { NULL }
};



static void yfPcapWrite(
    pcap_dumper_t *file,
    const struct pcap_pkthdr *hdr,
    const uint8_t *pkt)
{
    pcap_dump((u_char *)file, hdr, pkt);
}

/**
 * main
 *
 */
int
main (int argc, char *argv[]) {

    GOptionContext *ctx = NULL;
    GError *err = NULL;
    uint64_t start = 0;
    uint32_t key_hash = 0;
    FILE *fp = NULL;
    int pcap_files_num = 0;
    int meta_files_num = 0;
    char line[MAX_LINE];
    char old_file_path[500];
    uint64_t offset;
    uint64_t rstart;
    uint32_t rhash;
    gboolean do_once = TRUE;
    int file, pfile, i;
    int counter = 0;
    pcap_t *pcap_in = NULL;
    static char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_dumper_t *dump = NULL;
    int rv;

    ctx = g_option_context_new(" - yafMeta2Pcap Options");

    g_option_context_add_main_entries(ctx, md_core_option, NULL);

    g_option_context_set_help_enabled(ctx, TRUE);

    if (!g_option_context_parse(ctx, &argc, &argv, &err)) {
        fprintf(stderr, "option parsing failed: %s\n", err->message);
        exit(-1);
    }

    if (flowstarttime == NULL) {
        fprintf(stderr, "Error: --time is required.\n");
        fprintf(stderr, "Use --help for usage.\n");
        exit(-1);
    }

    if (flowkeyhash == NULL) {
        fprintf(stderr, "Error: --hash is required\n");
        fprintf(stderr, "Use --help for usage.\n");
        exit(-1);
    }

    if (meta_file == NULL) {
        fprintf(stderr, "Error: --pcap-meta-file is required\n");
        fprintf(stderr, "Use --help for usage.\n");
        exit(-1);
    }

    if (pcap == NULL && !yaf_out) {
        fprintf(stderr, "Error: --pcap is required\n");
        fprintf(stderr, "Use --help for usage.\n");
        exit(-1);
    }

    if (out_file == NULL) {
        fprintf(stderr, "Error: --out is required\n");
        fprintf(stderr, "Use --help for usage.\n");
        exit(-1);
    }

    start = strtoull(flowstarttime, NULL, 10);

    key_hash = strtoul(flowkeyhash, NULL, 10);

    fprintf(stdout, "Looking for hash: %u at start time: %llu\n",
            key_hash, (long long unsigned int)start);


    while (meta_file[meta_files_num]) {
        meta_files_num++;
    }

    while (pcap[pcap_files_num]) {
        pcap_files_num++;
    }

    pfile = -1;

    for (i = 0; i < meta_files_num; i++) {

        if (fp) {
            fclose(fp);
        }

        fprintf(stdout, "Opening PCAP Meta File: %s\n", meta_file[i]);
        fp = fopen(meta_file[i], "r");
        if (fp == NULL) {
            fprintf(stderr, "Can't open file %s\n", meta_file[i]);
            exit(-1);
        }

        while (fgets(line, MAX_LINE, fp)) {

            if (yaf_out) {
                gchar **tok = NULL;
                tok = g_strsplit(line, "|", -1);
                rhash = strtoul(tok[0], NULL, 10);
                rstart = strtoull(tok[1], NULL, 10);
                offset = strtoull(tok[3], NULL, 10);

                if (strcmp(tok[2], old_file_path)) {
                    fprintf(stdout, "Now reading PCAP file: %s\n", tok[2]);
                    if (pcap_in) {
                        pcap_close(pcap_in);
                    }
                    strcpy(old_file_path, tok[2]);
                    pcap_in = pcap_open_offline(tok[2], pcap_errbuf);
                    if (!pcap_in) {
                        fprintf(stderr, "Could not open pcap file %s: %s\n",
                                tok[2], pcap_errbuf);
                        exit(-1);
                    }
                    if (do_once) {
                        dump = pcap_dump_open(pcap_in, out_file);

                        if (dump == NULL) {
                            fprintf(stderr,
                                    "Could not open new pcap file: %s\n",
                                    pcap_geterr(pcap_in));
                            exit(-1);
                        }
                        do_once = FALSE;
                    }
                }
                g_strfreev(tok);
            } else {
                sscanf(line, "%u|%llu|%d|%llu|", &rhash,
                       (long long unsigned int*)&rstart, &file,
                       (long long unsigned int*)&offset);

                if (file != pfile && (file < pcap_files_num)) {
                    if (pcap_in) {
                        pcap_close(pcap_in);
                    }

                    fprintf(stdout, "Opening PCAP File %s\n", pcap[file]);

                    pcap_in = pcap_open_offline(pcap[file], pcap_errbuf);
                    if (!pcap_in) {
                        fprintf(stderr, "could not open pcap file %s: %s\n",
                                pcap[file], pcap_errbuf);
                        exit(-1);
                    }

                    dump = pcap_dump_open(pcap_in, out_file);

                    if (dump == NULL) {
                        fprintf(stderr, "Could not open new pcap file: %s\n",
                                pcap_geterr(pcap_in));
                        exit(-1);
                    }

                    pfile = file;
                }
            }

            if (rhash != key_hash) continue;
            if (start != rstart) continue;

            counter++;
            fseek(pcap_file(pcap_in), offset, SEEK_SET);

            rv = pcap_dispatch(pcap_in, 1, (pcap_handler)yfPcapWrite,
                               (void *)dump);
            if (rv == 0) {
                fprintf(stderr, "Error writing packet %s\n",
                        pcap_geterr(pcap_in));
            }
        }
    }

    fprintf(stdout, "Found %d packets that match criteria.\n", counter);

    fclose(fp);

    pcap_dump_flush(dump);
    pcap_dump_close(dump);

    pcap_close(pcap_in);

    g_option_context_free(ctx);

    return 0;
}
