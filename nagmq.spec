Name: nagmq
Version: 1.4.4.1
Release: 2%{?dist}
Summary: NagMQ is an event broker that exposes the internal state and events of Nagios
Group: Utilities/Monitoring
License: GPL
Url: https://github.com/jbreams/nagmq
Source0: %{sourcedir}/nagmq-%{version}.tar.gz
Packager: Jonathan Reams <jbreams@gmail.com>
Vendor: Jonathan Reams <jbreams@gmail.com>
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires: zeromq-devel libev-devel jansson-devel
Requires: zeromq libev jansson

%description 
NagMQ is an event broker that exposes the internal state and events of Nagios to endpoings on a ZeroMQ message bus.

Nagios objects and events are available as JSON. The broker exposes three sockets, all of which are optional:

    Publisher - Publishes events coming out of the event broker in real-time
    Pull - Receives passive checks and commands, like the Nagios command pipe
    Request - Sends state data on demand to clients

There is a distributed DNX-style executor (mqexec) designed to have as many workers (possibly at the edge as an NRPE-replacement) and job brokers as you want. It can also submit its results to more than one Nagios instance. Each worker can filter what checks it runs based on any field in the service/host check and event handler initiate messages from the publisher.


##### Client package #####
%package client
Summary: NagMQ is an event broker that exposes the internal state and events of Nagios
Group: Utilities/Monitoring

%description client
NagMQ client package
#####                #####

%prep
%setup -q 

%build
%configure --disable-static --with-libev-include=/usr/include/libev
%{__make} %{?_smp_mflags}

%install
%{__make} DESTDIR=${RPM_BUILD_ROOT} install
%{__mkdir} -p ${RPM_BUILD_ROOT}/%{_docdir}/%{name}-%{version}/
%{__cp} -a LICENSE ${RPM_BUILD_ROOT}/%{_docdir}/%{name}-%{version}/
%{__cp} -a README.rst ${RPM_BUILD_ROOT}/%{_docdir}/%{name}-%{version}/
%{__mkdir} -p ${RPM_BUILD_ROOT}/%{_initrddir}
%{__cp} -a dnxmq/mqexec.init ${RPM_BUILD_ROOT}/%{_initrddir}/mqexec
%{__cp} -a dnxmq/mqbroker.init ${RPM_BUILD_ROOT}/%{_initrddir}/mqbroker

%files
%defattr(-,root,root)
%attr(0775,root,root) %dir %{_libdir}/nagmq/
%attr(0664,root,root) %{_libdir}/nagmq/nagmq.*
%attr(0664,root,root) %{_docdir}/%{name}-%{version}/*
%attr(0755,root,root) %{_bindir}/nag.py

%files client
%attr(0755,root,root) %{_sbindir}/mqexec
%attr(0755,root,root) %{_sbindir}/mqbroker
%attr(0755,root,root) %config %{_initrddir}/mqexec
%attr(0755,root,root) %config %{_initrddir}/mqbroker

%clean
%__rm -rf $RPM_BUILD_ROOT

%changelog
* Sat Apr 14 2012 Daniel Wittenberg <dwittenberg2008@gmail.com> 1.2.2-1
- initial RPM build

