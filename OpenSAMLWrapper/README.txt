Purpose:
	OpenSAMLWrapper is a native C++ wrapper of, and C# interface to, the OpenSAML 2.0 toolkit. It is designed to be an easy-to-use SDK that will hide the complexity inherit in both the toolkit and the SAML standard. The goal is to make it as easy as possible for developers to utilize SSO functionality. Those wishing to learn more about OpenSAML or the SAML standard should go to: www.opensaml.org.

Development Environment:
	All code, including the required third-party DLLs, was built using Visual Studio 2005.

Directory Contents:
	"OpenSAMLWrapper" contains FilesystemCredentialResolver.xml, this README, and the following directories:
		"SAMLInterface" contains the SAMLInterface C# Source file which is the primary interface for any client.
		"SAMLWrapper" contains the SAMLWrapper class which creates the native C++ wrapper (SAMLWrapper.dll) for the OpenSAML code.
		"testWrapper" contains code to create a simple C++ console application that will test the C++ wrapper
	
Design Decisions:
	* Although it is possible to use the C++ wrapper directly, it is assumed that clients will use the C# interface.
	* The code is designed to be used with the Clareity Security implementations of the SP and IdP. It may not function correctly with other implementations.
	* FilesystemCredentialResolver.xml and its associated data file(s) must be installed to "C:\Inetpub\wwwroot\SAML_SSO\data".

Current Functionality:
	SAMLInterface contains all functionality required to implement both an SP and an IdP.

Known Issues:
	* XMLToolingConfig::getConfig().term() should be called in SAMLWrapper::CleanupSAMLWrapper, but it causes an exception and is currently commented out.

Latest Build:
	11 Jan 2008 - Added code required to implement an IdP.
	NOTE: curl version 7.17.1 will not compile in Windows without modification to curl.h 	

Notes:
	* All third-party dependencies required to build SAMLWrapper are located in the depends directory
	
