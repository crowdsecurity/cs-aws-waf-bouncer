Name:           crowdsec-aws-waf-bouncer
Version:        %(echo $VERSION)
Release:        %(echo $PACKAGE_NUMBER)%{?dist}
Summary:      AWS WAF bouncer for Crowdsec 

License:        MIT
URL:            https://crowdsec.net
Source0:        https://github.com/crowdsecurity/%{name}/archive/v%(echo $VERSION).tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  git
BuildRequires:  make
%{?fc33:BuildRequires: systemd-rpm-macros}

%define debug_package %{nil}

%description

%define version_number  %(echo $VERSION)
%define releasever  %(echo $RELEASEVER)
%global local_version v%{version_number}-%{releasever}-rpm
%global name crowdsec-aws-waf-bouncer
%global __mangle_shebangs_exclude_from /usr/bin/env

%prep
%setup -n crowdsec-aws-waf-bouncer-%{version}

%build
BUILD_VERSION=%{local_version} make
TMP=`mktemp -p /tmp/`
cp config/%{name}.service ${TMP}
BIN=%{_bindir}/%{name} CFG=/etc/crowdsec/ envsubst < ${TMP} > config/%{name}.service
rm ${TMP}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/bin
install -m 755 -D %{name}  %{buildroot}%{_bindir}/%{name}
install -m 600 -D config/%{name}.yaml %{buildroot}/etc/crowdsec/bouncers/%{name}.yaml 
install -m 644 -D config/%{name}.service %{buildroot}%{_unitdir}/%{name}.service

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
/usr/bin/%{name}
%{_unitdir}/%{name}.service
%config(noreplace) /etc/crowdsec/bouncers/%{name}.yaml 


%post -p /bin/bash
systemctl daemon-reload


START=0

systemctl is-active --quiet crowdsec

if [ "$?" -eq "0" ] ; then
    START=1
    echo "cscli/crowdsec is present, generating API key"
    unique=`date +%s`
    API_KEY=`sudo cscli -oraw bouncers add AWS-WAF-${unique}`
    if [ $? -eq 1 ] ; then
        echo "failed to create API token, service won't be started."
        START=0
        API_KEY="<API_KEY>"
    else
        echo "API Key : ${API_KEY}"
    fi
fi

TMP=`mktemp -p /tmp/`
cp /etc/crowdsec/bouncers/crowdsec-aws-waf-bouncer.yaml ${TMP}
API_KEY=${API_KEY} envsubst < ${TMP} > /etc/crowdsec/bouncers/crowdsec-aws-waf-bouncer.yaml
rm ${TMP}

if [ ${START} -eq 0 ] ; then
    echo "no api key was generated, you can generate one on your LAPI Server by running 'cscli bouncers add <bouncer_name>' and add it to '/etc/crowdsec/bouncers/crowdsec-aws-waf-bouncer.yaml'"
fi

echo "Please configure your AWS WAF ACL in '/etc/crowdsec/bouncers/crowdsec-aws-waf-bouncer.yaml' and start the bouncer via 'sudo systemctl start crowdsec-aws-waf-bouncer' 

 
%changelog
* Fri Mar 11 2022 Sebastien Blot <sebastien@crowdsec.net>
- First initial packaging

%preun -p /bin/bash

if [ "$1" == "0" ] ; then
    systemctl stop crowdsec-aws-waf-bouncer || echo "cannot stop service"
    systemctl disable crowdsec-aws-waf-bouncer || echo "cannot disable service"
fi



%postun -p /bin/bash

if [ "$1" == "1" ] ; then
    systemctl restart  crowdsec-aws-waf-bouncer || echo "cannot restart service"
elif [ "$1" == "0" ] ; then
    systemctl stop crowdsec-aws-waf-bouncer
    systemctl disable crowdsec-aws-waf-bouncer
fi