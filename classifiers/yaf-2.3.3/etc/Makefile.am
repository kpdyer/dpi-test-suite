## Process this file with automake to produce Makefile.in

## ------------------------------------------------------------------------
## Makefile.am (startup)
## autotools build system for NAF applications
## ------------------------------------------------------------------------
## Copyright (C) 2005-2013 Carnegie Mellon University. All Rights Reserved.
## ------------------------------------------------------------------------
## Authors: Brian Trammell 
## ------------------------------------------------------------------------
## GNU General Public License (GPL) Rights pursuant to Version 2, June 1991
## Government Purpose License Rights (GPLR) pursuant to DFARS 252.227-7013
## ------------------------------------------------------------------------

EXTRA_DIST = yaf.conf.in init.d/yaf.in yafApplabelRules.conf

dist_sysconf_DATA = yafApplabelRules.conf

if PLUGINENABLE
dist_sysconf_DATA += yafDPIRules.conf dhcp_fingerprints.conf
endif

if P0FENABLE
dist_sysconf_DATA += p0f.fp
endif