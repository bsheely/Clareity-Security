Purpose: 
	SampleIdP is a Web Site which demonstrates the use of the SAMLWrapper library to grant SSO authentication to an SP.

Development Environment: 
	SampleIdP was developed using Visual Studio 2005.

Referenced DLLs: 
	SAMLInterface.dll (11 Jan 2008)
	SAMLWrapper.dll (11 Jan 2008)
	libcurl_7_17_1.dll
	libeay32_0_9_8.dll
	log4shib1_0.dll
	saml2_0.dll
	ssleay32_0_9_8.dll
	xerces-c_2_8.dll
	xmltooling1_0.dll
	xsec_1_4_0.dll

Current Functionality:
	SampleIdP authenticates with the SP. Digital signature verification is done via an X.509 certificate.

SampleIdP setup:
	1. SampleIdP and SAML_SSO directores must be installed to: C:\Inetpub\wwwroot\
	2. Create the SampleIdP web app within IIS using the SampleIdP Properties dialog box.

Known Issues:

Latest Code Modification: 11 Jan 2008
