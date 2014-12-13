// testWrapper.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "SAMLWrapper.h"
#include <fstream>
#include <iostream>
#include <stdio.h>
#include <string>

using namespace std;

int _tmain(int argc, _TCHAR* argv[])
{
	const int SUCCESS = 0;
	int binding = POST;
	binding = REDIRECT;
	string issuerName = "SampleSP Issuer";
	string id = "001";
	string providerName = "SampleSP Provider";
	string destination = "http://74.239.29.200/SampleIdP/SSOService.aspx";
	string assertionConsumerServiceURL = "http://74.239.29.212/SampleSP/AssertCustServ.aspx";
	bool forceAuthn = false;
	const int SIZE = 8192;
	char* x509cert = new char[SIZE];
	char* authnRequest = new char[SIZE];
	char* response = new char[SIZE];
	char* buffer = new char[SIZE];
	InitializeSAMLWrapper();
	ofstream file("wrapper_output.txt");
	//build AuthnRequest
	ErrorCode errorCode = BuildAuthnRequest(issuerName.c_str(), id.c_str(), providerName.c_str(), destination.c_str(), assertionConsumerServiceURL.c_str(), 
		binding, forceAuthn, authnRequest, SIZE);

	if (errorCode == NO_ERROR) {
		file << "-----Begin AuthnRequest-----\n" << authnRequest << "-----End AuthnRequest-----\n";

		//output the Assertion Consumer Service URL in the AuthnRequest
		if (binding == REDIRECT)
			URLDecode(authnRequest);

		errorCode = GetAssertionConsumerServiceURL(authnRequest, binding, buffer, SIZE);

		if (errorCode == NO_ERROR) 
			file << "The Assertion Consumer Service URL is: " << buffer << endl;
		else 
			file << "GetAssertionConsumerServiceURL ErrorCode: " << errorCode << endl;

		//build the Response
		string issuerName = "SampleIdP Issuer";
		string logonID = "some user";
		errorCode = BuildResponse(issuerName.c_str(), id.c_str(), logonID.c_str(), SUCCESS, 
			authnRequest, binding, response, SIZE);

		if (errorCode == NO_ERROR) {
			file << "-----Begin Response-----\n" << response << "-----End Response-----\n";

			//output the X509Certificate
			errorCode = GetX509CertFromResponse(response, x509cert, SIZE);

			if (errorCode == NO_ERROR) {
				file << "-----Begin X509 Certificate-----\n";
				file << x509cert;
				file << "-----End X509 Certificate-----\n";

				//output the status
				int statusCode = GetStatus(response, x509cert, true);

				if (statusCode == 0)
					file << "The status code indicates a successful authorization" << endl;
				else {
					file << "The status code indicates ";

					switch (statusCode) {
						case UNABLE_TO_OPEN_FILE_FOR_OUTPUT:
							file << "unable to open file for output" << endl;
							break;
						case FILESYSTEM_CREDENTIAL_RESOLVER_XML_FILE_NOT_FOUND: 
							file << "FilesystemCrededtialResolver.xml not found" << endl;
							break;
						case UNABLE_TO_CREATE_CREDENTIAL_RESOLVER: 
							file << "unable to create CredentialResolver" << endl;
							break;
						case INVALID_SIGNATURE: 
							file << "unable to validate signature" << endl;
							break;
						case STATUS_CODE_NOT_FOUND: 
							file << "StatusCode not found in DOMDocument" << endl;
							break;
						default:
							file << "authentication was not successful - Unknown statusCode: " << statusCode << endl;
					}
				}
			}
			else {
				file << "GetX509CertFromResponse ErrorCode: " << errorCode << endl;
				file << "UNABLE TO CONTINUE TESTING!" << endl;
			}
		}
		else {
			file << "BuildResponse ErrorCode: " << errorCode << endl;
			file << "UNABLE TO CONTINUE TESTING!" << endl;
		}
	}
	else {
		file << "BuildAuthnRequest ErrorCode: " << errorCode << endl;
		file << "UNABLE TO CONTINUE TESTING!" << endl;
	}

	CleanupSAMLWrapper();
	delete[] x509cert;
	delete[] response;
	delete[] buffer;
	delete[] authnRequest;
	return 0;
}

