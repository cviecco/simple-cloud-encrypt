Name:           simple-cloud-encrypt
Version:	0.9.0
Release:	1%{?dist}
Summary:	Simple encryption using clound infrastrcture

#Group:		
License:	ASL 2.0
URL:		https://github.com/cviecco/simple-cloud-encrypt/
Source0:	simple-cloud-encrypt-%{version}.tar.gz

#BuildRequires:	golang
#Requires:	

#no debug package as this is go
%define debug_package %{nil}

%description
Simple encryption using clound infrastrcture


%prep
%setup -n %{name}-%{version} 


%build
go build simple-cloud-encrypt.go 


%install
#%make_install
%{__install} -Dp -m0755 simple-cloud-encrypt %{buildroot}%{_sbindir}/simple-cloud-encrypt


%files
#%doc
%{_sbindir}/simple-cloud-encrypt



%changelog

