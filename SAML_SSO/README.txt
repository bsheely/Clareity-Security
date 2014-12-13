The data directory contains files which are used by the SP and IdP. It must be installed to: C:\Inetpub\wwwroot\SAML_SSO

The SP requires the following file(s):
	FilesystemCredentialResolver.xml
	Note: The SP requires write permission since the cert.pem file will be written at runtime.

The IdP requires the following file(s):
	FilesystemCredentialResolver.xml
	key.pem
	 