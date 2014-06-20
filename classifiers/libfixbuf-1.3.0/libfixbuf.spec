%define name libfixbuf
%define version 1.3.0
%define release 1

Summary: fixbuf IPFIX implementation library
Name: %{name}
Version: %{version}
Release: %{release}
Group: NetSA
License: LGPL
Source: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}
Packager: Tony Cebzanov <tonyc@cert.org>
Vendor: http://tools.netsa.cert.org/
Provides: libfixbuf
Provides: libfixbuf.so
Requires: glib2 >= 2.4.7
%if "x" == "x1"
Requires: libsctp
%endif
%if "x" == "x1"
Requires: libspread
%endif
%if "x" == "x1"
Requires: openssl
%endif
BuildRequires: glib2-devel >= 2.4.7
BuildRequires: pkgconfig >= 0.8
%if "x" == "x1"
BuildRequires: libsctp-devel
%endif
%if "x" == "x1"
BuildRequires: libspread-devel
%endif
%if "x" == "x1"
BuildRequires: openssl-devel
%endif

%description 
libfixbuf aims to be a compliant implementation of the IPFIX Protocol
and message format, from which IPFIX Collecting Processes and
IPFIX Exporting Processes may be built. 

%package devel
Summary: Static libraries and C header files for libfixbuf
Group: Development/NetSA
Provides: libfixbuf-devel
Requires: %{name} = %{version}
Requires: pkgconfig >= 0.8

%description devel
Static libraries and C header files for libfixbuf.

%prep
%setup -q -n %{name}-%{version}

%build
./configure 
%{__make}

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT%{_bindir}
%makeinstall

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-, root, root)
%doc AUTHORS COPYING NEWS README
%{_libdir}/*.a
%{_libdir}/*.la
%{_libdir}/*.so*

%files devel
%defattr(-,root,root)
%doc doc/html
%{_includedir}/*
%{_libdir}/pkgconfig/*

