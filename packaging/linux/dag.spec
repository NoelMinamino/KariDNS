Name:           dag
Version:        %{?version}%{!?version:1.0.0}
Release:        1%{?dist}
Summary:        DNS Anomaly Generator - High-performance DNS query tool and fuzzer

License:        BSD-2-Clause
URL:            https://github.com/NoelMinamino/KariDNS
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  openssl-devel
BuildRequires:  zlib-devel
Requires:       openssl-libs
Requires:       zlib

%description
DAG (DNS Anomaly Generator) is a modern, high-performance command-line DNS query tool
and anomaly injection/fuzzer. It supports UDP, TCP, multiple target servers, detailed
wire hexdump analysis, TSIG signing/verification, EDNS options, and intentional packet malformation.

%prep
%autosetup -n KariDNS-%{version}

%build
make dag

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_bindir}
install -m 0755 dag %{buildroot}%{_bindir}/dag

%files
%license LICENSE
%doc README.md docs/dag.md
%{_bindir}/dag

%changelog
* Sun Aug 23 2026 Noel Minamino <noel@karidns.org> - 1.0.0-1
- Initial packaging for dag
