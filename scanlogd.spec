# $Id: Owl/packages/scanlogd/scanlogd/scanlogd.spec,v 1.6 2004/06/10 13:34:05 solar Exp $

Summary: A tool to detect and log TCP port scans.
Name: scanlogd
Version: 2.2.5
Release: owl1
License: relaxed BSD and (L)GPL-compatible
Group: System Environment/Daemons
URL: http://www.openwall.com/scanlogd/
Source: ftp://ftp.openwall.com/pub/projects/scanlogd/scanlogd-%version.tar.gz
PreReq: /sbin/chkconfig, grep, shadow-utils
BuildRoot: /override/%name-%version

%description
scanlogd detects port scans and writes one line per scan via the syslog(3)
mechanism.  If a source address sends multiple packets to different ports
in a short time, the event will be logged.

%prep
%setup -q

%build
make linux CFLAGS="-c -Wall $RPM_OPT_FLAGS"

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT{%_sbindir,%_mandir/man8,/etc/rc.d/init.d}

install -m 700 scanlogd $RPM_BUILD_ROOT%_sbindir/
install -m 644 scanlogd.8 $RPM_BUILD_ROOT%_mandir/man8/
install -m 700 scanlogd.init $RPM_BUILD_ROOT/etc/rc.d/init.d/scanlogd

%pre
grep -q ^scanlogd: /etc/group || groupadd -g 199 scanlogd
grep -q ^scanlogd: /etc/passwd ||
	useradd -g scanlogd -u 199 -d / -s /bin/false -M scanlogd
rm -f /var/run/scanlogd.restart
if [ $1 -ge 2 ]; then
	/etc/rc.d/init.d/scanlogd status && touch /var/run/scanlogd.restart || :
	/etc/rc.d/init.d/scanlogd stop || :
fi

%post
/sbin/chkconfig --add scanlogd
test -f /var/run/scanlogd.restart && /etc/rc.d/init.d/scanlogd start || :
rm -f /var/run/scanlogd.restart

%preun
if [ $1 -eq 0 ]; then
	/etc/rc.d/init.d/scanlogd stop || :
	/sbin/chkconfig --del scanlogd
fi

%files
%defattr(-,root,root)
%_sbindir/scanlogd
%_mandir/man8/scanlogd.8*
%config /etc/rc.d/init.d/scanlogd

%changelog
* Thu Jun 10 2004 Solar Designer <solar@owl.openwall.com> 2.2.5-owl1
- Dropped the cleanup() stuff because it was not async-signal-safe and
to implement it properly would depend on pcap_breakloop() and on a
non-existent(?) equivalent for it with libnids; this code was only used
when running as root which is something to not do anyway.

* Thu Jun 03 2004 Solar Designer <solar@owl.openwall.com> 2.2.4-owl1
- Detach from the tty by opening /dev/null on fd 0, 1, 2.

* Wed Jun 02 2004 Solar Designer <solar@owl.openwall.com> 2.2.3-owl1
- When built with libnids or direct libpcap support, use Pavel Kankovsky's
smart pcap expression, with a minor enhancement.
- Explained "any" and "all" magic device names in a comment in params.h.
- Dropped the rlog stuff; librlog was never released.
- chroot to /var/empty.
- Do register scanlogd with chkconfig, but don't enable it for any runlevels
by default.
- Moved this spec file and the init script to under scanlogd/ to include
them in the non-Owl-specific distribution of scanlogd.

* Sun May 23 2004 Solar Designer <solar@owl.openwall.com> 2.2.2-owl1
- #include <stdlib.h> for exit(3) (apparently this is actually needed on
FreeBSD).
- Obfuscated e-mail addresses in the man page and sources.

* Wed May 08 2002 Solar Designer <solar@owl.openwall.com> 2.2.1-owl1
- Start after syslogd.
- Don't abuse glibc-internal __feature macros.

* Wed Feb 06 2002 Solar Designer <solar@owl.openwall.com>
- Enforce our new spec file conventions.

* Thu Jul 12 2001 Solar Designer <solar@owl.openwall.com>
- Packaged scanlogd for Owl.
