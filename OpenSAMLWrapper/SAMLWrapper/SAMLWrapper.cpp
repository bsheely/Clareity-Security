#include "SAMLWrapper.h"
#include "saml/SAMLConfig.h"
#include "saml/saml2/core/Protocols.h"
#include "saml/saml2/core/Assertions.h"
#include "saml/saml2/binding/SAML2Redirect.h"
#include "saml/util/SAMLConstants.h"
#include "xmltooling/XMLToolingConfig.h"
#include "xmltooling/util/DateTime.h"
#include "xmltooling/util/URLEncoder.h"
#include "xmltooling/security/Credential.h"
#include "xmltooling/security/CredentialResolver.h"
#include "xmltooling/signature/SignatureValidator.h"
#include "xercesc/framework/MemBufFormatTarget.hpp"
#include "xercesc/dom/DOM.hpp"
#include "xercesc/util/Base64.hpp"
#include <string>
#include <fstream>
#include <sstream>
#include <map>
#include <vector>
#include <exception>
#include <time.h>

using namespace opensaml;
using namespace opensaml::saml2p;
using namespace opensaml::saml2;
using namespace samlconstants;
using namespace xmltooling;
using namespace xmlsignature;
using namespace xercesc_2_8;
using namespace std;
using std::exception;

static map<string, int> statusCodes_m;
static vector<string> statusCodes_v;

void InitializeSAMLWrapper() {
	SAMLConfig::getConfig().init();

	statusCodes_m["urn:oasis:names:tc:SAML:2.0:status:Success"] = 0;
	statusCodes_v.push_back("urn:oasis:names:tc:SAML:2.0:status:Success");
	statusCodes_m["urn:oasis:names:tc:SAML:2.0:status:Requester"] = 1;
	statusCodes_v.push_back("urn:oasis:names:tc:SAML:2.0:status:Requester");
	statusCodes_m["urn:oasis:names:tc:SAML:2.0:status:Responder"] = 2;
	statusCodes_v.push_back("urn:oasis:names:tc:SAML:2.0:status:Responder");
	statusCodes_m["urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"] = 3;
	statusCodes_v.push_back("urn:oasis:names:tc:SAML:2.0:status:VersionMismatch");
	statusCodes_m["urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"] = 4;
	statusCodes_v.push_back("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed");
	statusCodes_m["urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue"] = 5;
	statusCodes_v.push_back("urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue");
	statusCodes_m["urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"] = 6;
	statusCodes_v.push_back("urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy");
	statusCodes_m["urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext"] = 7;
	statusCodes_v.push_back("urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext");
	statusCodes_m["urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP"] = 8;
	statusCodes_v.push_back("urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP");
	statusCodes_m["urn:oasis:names:tc:SAML:2.0:status:NoPassive"] = 9;
	statusCodes_v.push_back("urn:oasis:names:tc:SAML:2.0:status:NoPassive");
	statusCodes_m["urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP"] = 10;
	statusCodes_v.push_back("urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP");
	statusCodes_m["urn:oasis:names:tc:SAML:2.0:status:PartialLogout"] = 11;
	statusCodes_v.push_back("urn:oasis:names:tc:SAML:2.0:status:PartialLogout");
	statusCodes_m["urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded"] = 12;
	statusCodes_v.push_back("urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded");
	statusCodes_m["urn:oasis:names:tc:SAML:2.0:status:RequestDenied"] = 13;
	statusCodes_v.push_back("urn:oasis:names:tc:SAML:2.0:status:RequestDenied");
	statusCodes_m["urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported"] = 14;
	statusCodes_v.push_back("urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported");
	statusCodes_m["urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated"] = 15;
	statusCodes_v.push_back("urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated");
	statusCodes_m["urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh"] = 16;
	statusCodes_v.push_back("urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh");
	statusCodes_m["urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow"] = 17;
	statusCodes_v.push_back("urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow");
	statusCodes_m["urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized"] = 18;
	statusCodes_v.push_back("urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized");
	statusCodes_m["urn:oasis:names:tc:SAML:2.0:status:TooManyResponses"] = 19;
	statusCodes_v.push_back("urn:oasis:names:tc:SAML:2.0:status:TooManyResponses");
	statusCodes_m["urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile"] = 20;
	statusCodes_v.push_back("urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile");
	statusCodes_m["urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal"] = 21;
	statusCodes_v.push_back("urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal");
	statusCodes_m["urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding"] = 22;
	statusCodes_v.push_back("urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding");
}

void CleanupSAMLWrapper() {
	SAMLConfig::getConfig().term();
}

ErrorCode BuildAuthnRequest(const char* issuerName,const char* id,const char* providerName,const char* destination,
							const char* assertionConsumerServiceURL,int binding,bool forceAuthn, 
							char* buffer, int bufferSize) {
	buffer[0] = '\0';
	XMLCh* str;
	AuthnRequest* request = NULL;
	Issuer* issuer = NULL;

	try {
		request = opensaml::saml2p::AuthnRequestBuilder::buildAuthnRequest();
		issuer = IssuerBuilder::buildIssuer();
	}
	catch (XMLObjectException& e) {
		cerr << "Exception occured: " << e.what() << endl;
		return XML_OBJECT_EXCEPTION;
	}

	//set issuer name
	str = XMLString::transcode(issuerName);
	issuer->setName(str);
	XMLString::release(&str);

	//set Issuer
	request->setIssuer(issuer);

	//set id
	str = XMLString::transcode(id);
	request->setID(str);
	XMLString::release(&str);

	//set providerName
	str = XMLString::transcode(providerName);
	request->setProviderName(str);
	XMLString::release(&str);

	//set destination
	str = XMLString::transcode(destination);
	request->setDestination(str);
	XMLString::release(&str);

	//set assertionConsumerServiceURL
	str = XMLString::transcode(assertionConsumerServiceURL);
	request->setAssertionConsumerServiceURL(str);
	XMLString::release(&str);

	//set binding
	switch (binding) {
		case POST: 
			str = XMLString::transcode(SAML20_BINDING_HTTP_POST);
			request->setProtocolBinding(str);
			XMLString::release(&str);
			break;
		case REDIRECT:
			str = XMLString::transcode(SAML20_BINDING_HTTP_REDIRECT);
			request->setProtocolBinding(str);
			XMLString::release(&str);
	};

	//set forceAuthn
	if (forceAuthn) 
		request->setForceAuthn(xmlconstants::XML_TRUE);
	else
		request->setForceAuthn(xmlconstants::XML_FALSE);

	//set issueInstant
	request->setIssueInstant(time(NULL));

	//perform marshalling
	static const XMLCh impltype[] = { chLatin_L, chLatin_S, chNull };
	static const XMLCh UTF8[]={ chLatin_U, chLatin_T, chLatin_F, chDigit_8, chNull };
	DOMImplementation* impl = DOMImplementationRegistry::getDOMImplementation(impltype);
	DOMWriter* serializer = (static_cast<DOMImplementationLS*>(impl))->createDOMWriter();
	XercesJanitor<DOMWriter> janitor(serializer);
	serializer->setEncoding(UTF8);
	MemBufFormatTarget target;
	DOMElement* element = request->marshall();
	DOMNode* node = dynamic_cast<DOMNode*>(element);

	if (node == NULL || !serializer->writeNode(&target, *node)) {
		janitor.release();
		return UNABLE_TO_SERIALIZE;
	}

	janitor.release();
	string xmlBuf(reinterpret_cast<const char*>(target.getRawBuffer()));
	XMLByte* encoded;
	unsigned length;

#if (1)
	ofstream file("C:\\Inetpub\\wwwroot\\SAML_SSO\\AuthnRequest.xml");
	file << reinterpret_cast<const char*>(target.getRawBuffer()) << endl;
#endif

	//perform deflating (if required) and base-64 encoding
	if (binding == POST) {
		char* tmp = const_cast<char*>(xmlBuf.c_str());
		encoded = Base64::encode(reinterpret_cast<XMLByte*>(tmp), (int)xmlBuf.length(), &length);
	}
	else {
		char* deflated = deflate(const_cast<char*>(xmlBuf.c_str()), (int)xmlBuf.length(), &length);

		if (!deflated)
			return UNABLE_TO_DEFLATE;

		encoded = Base64::encode(reinterpret_cast<XMLByte*>(deflated), length, &length);
		delete[] deflated;
	}

	if (!encoded)
		return UNABLE_TO_ENCODE;

	if (binding == REDIRECT) {
		const URLEncoder* encoder = XMLToolingConfig::getConfig().getURLEncoder();
		xmlBuf = encoder->encode(reinterpret_cast<char*>(encoded));
		XMLString::release(&encoded);

		if ((int)xmlBuf.length() >= bufferSize) {
			XMLString::release(&encoded);
			return OUTPUT_EXCEEDS_BUFFER_SIZE;
		}

		strcpy(buffer, xmlBuf.c_str());
	}
	else {
		if ((int)length > bufferSize) {
			XMLString::release(&encoded);
			return OUTPUT_EXCEEDS_BUFFER_SIZE;
		}

		strcpy(buffer, reinterpret_cast<char*>(encoded));
		XMLString::release(&encoded);
	}

	return NO_ERROR;
}

ErrorCode MakeStringURISafe(const char* str, char* buffer, int bufferSize) {
	buffer[0] = '\0';
	const URLEncoder* encoder = XMLToolingConfig::getConfig().getURLEncoder();
	string temp = encoder->encode(str);

	if ((int)temp.length() > bufferSize)
		return OUTPUT_EXCEEDS_BUFFER_SIZE;

	strcpy(buffer, temp.c_str());
	return NO_ERROR;	
}

ErrorCode GetX509Cert(DOMDocument* doc, char* buffer, int bufferSize) {
    XercesJanitor<DOMDocument> janitor(doc);
	XMLCh* TAG_x509cert = XMLString::transcode("ds:X509Certificate");
	DOMNodeList* nodes = doc->getElementsByTagName(TAG_x509cert);
	janitor.release();
	XMLString::release(&TAG_x509cert);
	DOMNode* node = nodes->item(0);
	
	if (node) {
		const XMLCh* xmlch_cert = node->getTextContent();
		char* cert = XMLString::transcode(xmlch_cert);

		if ((int)strlen(cert) > bufferSize) {
			XMLString::release(&cert);
			return OUTPUT_EXCEEDS_BUFFER_SIZE;
		}

		buffer[0] = '\0';
		strcpy(buffer, cert);
		XMLString::release(&cert);
		return NO_ERROR;	
	}

	return XML_ELEMENT_OR_ATTRIBUTE_NOT_FOUND;
}

ErrorCode GetX509CertFromResponse(const char* response, char* buffer, int bufferSize) {
	unsigned length;
	XMLByte* decoded = Base64::decode(reinterpret_cast<const XMLByte*>(response), &length);

	if (!decoded) {
		/*Developer's Note: It is impossible to determine whether or not the response contains a certificate */
		return UNABLE_TO_DECODE;
	}

	stringstream stream;
	stream << reinterpret_cast<char*>(decoded);
	XMLString::release(&decoded);
	return GetX509Cert(XMLToolingConfig::getConfig().getParser().parse(stream), buffer, bufferSize);
}

ErrorCode GetX509CertFromMetadata(const char* metadata, char* buffer, int bufferSize) {
	stringstream stream;
	stream << metadata;
	return GetX509Cert(XMLToolingConfig::getConfig().getParser().parse(stream), buffer, bufferSize);
}

ErrorCode CreatePemFile(const char* x509Cert, bool formatted) {
	//format the certificate as required and write to a pem file	
	const string PEM_PATH = "C:\\Inetpub\\wwwroot\\SAML_SSO\\data\\cert.pem";
	ofstream file(PEM_PATH.c_str());

	if (!file)
		return UNABLE_TO_OPEN_FILE_FOR_OUTPUT;

	file << "-----BEGIN CERTIFICATE-----" << endl;

	if (formatted) {
		file << x509Cert;
	}
	else {
		string certificate;
		unsigned length = (unsigned)strlen(x509Cert);

		for (unsigned i = 0; i < length; ++i) {
			char c = x509Cert[i];

			if (isgraph(c))
				certificate += c;
		}

		const int MAX_LENGTH = 64;
		int numBreaks = certificate.length() / MAX_LENGTH;

		for (int i = 1, j = 0; i <= numBreaks; ++i, ++j) 
			certificate.insert(i * MAX_LENGTH + j, "\n");

		file << certificate << endl;
	}
	
	file << "-----END CERTIFICATE-----" << endl;
	return NO_ERROR;
}

ErrorCode CreateCredentialResolver(CredentialResolver* resolver) {
	const string CREDENTIAL_RESOLVER_PATH = "C:\\Inetpub\\wwwroot\\SAML_SSO\\data\\FilesystemCredentialResolver.xml";
	ifstream in(CREDENTIAL_RESOLVER_PATH.c_str());

	if (!in)
		return FILESYSTEM_CREDENTIAL_RESOLVER_XML_FILE_NOT_FOUND;

	DOMDocument* doc = XMLToolingConfig::getConfig().getParser().parse(in);
    XercesJanitor<DOMDocument> janitor(doc);

	try {
		resolver = XMLToolingConfig::getConfig().CredentialResolverManager.newPlugin(FILESYSTEM_CREDENTIAL_RESOLVER, doc->getDocumentElement());
	}
	catch (exception& e) {
		janitor.release();
		cerr << e.what() << endl;
		return UNABLE_TO_CREATE_CREDENTIAL_RESOLVER;
	}

	janitor.release();
	return NO_ERROR;
}

int GetStatus(const char* response, const char* x509Cert, bool formatted) {
	if (!strlen(x509Cert))
		return EMPTY_CERTIFICATE;

#if (1)
	ofstream file("C:\\Inetpub\\wwwroot\\SAML_SSO\\Cert.txt");
	file << "-----BEGIN CERTIFICATE-----\n";
	file << x509Cert;
	file << "-----END CERTIFICATE-----\n";
#endif

	//write certificate to file
	ErrorCode errorCode = CreatePemFile(x509Cert, formatted);

	if (errorCode != NO_ERROR)
		return errorCode;
	
	//create Credential
	CredentialResolver* resolver;
	/* Developer's Note: The ideal approach would be to encapsulate the code to create the CredentialResolver
	 * in a seperate method. However, CredentialResolver would probably need to be created on the heap. */
	const string CREDENTIAL_RESOLVER_PATH = "C:\\Inetpub\\wwwroot\\SAML_SSO\\data\\FilesystemCredentialResolver.xml";
	ifstream in(CREDENTIAL_RESOLVER_PATH.c_str());

	if (!in)
		return FILESYSTEM_CREDENTIAL_RESOLVER_XML_FILE_NOT_FOUND;

	DOMDocument* credentialResolverDoc = XMLToolingConfig::getConfig().getParser().parse(in);
    XercesJanitor<DOMDocument> credentialResolverDocJanitor(credentialResolverDoc);

	try {
		resolver = XMLToolingConfig::getConfig().CredentialResolverManager.newPlugin(FILESYSTEM_CREDENTIAL_RESOLVER, credentialResolverDoc->getDocumentElement());
	}
	catch (exception& e) {
		credentialResolverDocJanitor.release();
		cerr << e.what() << endl;
		return UNABLE_TO_CREATE_CREDENTIAL_RESOLVER;
	}

	credentialResolverDocJanitor.release();
	CredentialCriteria criteria;
	criteria.setUsage(Credential::SIGNING_CREDENTIAL);
	Locker locker(resolver);
	const Credential* credential = resolver->resolve(&criteria);

	//create Response
	unsigned length;
	XMLByte* decoded = Base64::decode(reinterpret_cast<const XMLByte*>(response), &length);

	if (!decoded)
		return UNABLE_TO_CREATE_RESPONSE;

    stringstream stream;
	stream << reinterpret_cast<char*>(decoded);
    XMLString::release(&decoded);
    DOMDocument* doc = XMLToolingConfig::getConfig().getParser().parse(stream);

	if (!doc)
		return UNABLE_TO_CREATE_RESPONSE;

    XercesJanitor<DOMDocument> janitor(doc);
	DOMElement* element = doc->getDocumentElement();
	XMLObject* xmlObject = XMLObjectBuilder::buildOneFromElement(element, true);
	Response* samlResponse = dynamic_cast<Response*>(xmlObject);
	janitor.release();

	if (!samlResponse)
		return UNABLE_TO_CREATE_RESPONSE;

#if (1)
	static const XMLCh impltype[] = { chLatin_L, chLatin_S, chNull };
	static const XMLCh UTF8[]={ chLatin_U, chLatin_T, chLatin_F, chDigit_8, chNull };
	DOMImplementation* impl = DOMImplementationRegistry::getDOMImplementation(impltype);
	DOMWriter* serializer = (static_cast<DOMImplementationLS*>(impl))->createDOMWriter();
	XercesJanitor<DOMWriter> janitor2(serializer);
	serializer->setEncoding(UTF8);
	MemBufFormatTarget target;
	serializer->writeNode(&target, *static_cast<DOMNode*>(element));
	janitor2.release();
	ofstream file2("C:\\Inetpub\\wwwroot\\SAML_SSO\\Response.xml");
	file2 << reinterpret_cast<const char*>(target.getRawBuffer()) << endl;
#endif

	Signature* signature = NULL;

	if (samlResponse->getAssertions().size()) 
		signature = samlResponse->getAssertions().front()->getSignature();

	if (signature) {
		//Validate signature
		SignatureValidator signatureValidator;
		signatureValidator.setCredential(credential);

		try {
			signatureValidator.validate(signature);
		}
		catch (XMLToolingException& e) {
			janitor.release();
			cerr << e.what() << endl;
			return INVALID_SIGNATURE;
		}
	}

	//return status	
	if (samlResponse->getStatus() && samlResponse->getStatus()->getStatusCode()) {
		char* status = XMLString::transcode(samlResponse->getStatus()->getStatusCode()->getValue());
		map<string, int>::iterator itr = statusCodes_m.find(status);
		XMLString::release(&status);

		if (itr != statusCodes_m.end())
			return itr->second;
	}
	
	return STATUS_CODE_NOT_FOUND;
}

ErrorCode GetAssertionConsumerServiceURL(const char* authnRequest, int binding, char* buffer, int bufferSize) {
	buffer[0] = '\0';
	/* Developer's Note: The ideal approach would be to encapsulate the code to create the AuthnRequest
	 * in a seperate method. However, it would probably need to be created on the heap. */
	unsigned length;

	/*Developer's Note: Even if Redirect binding is used, URL decoding of the authnRequest will cause invalid results */
	
	//perform base-64 decoding and inflate (if required)
	XMLByte* decoded = Base64::decode(reinterpret_cast<const XMLByte*>(authnRequest), &length);
	stringstream stream;

	if (!decoded)
		return UNABLE_TO_DECODE;

	if (binding == REDIRECT) {
		if (!inflate(reinterpret_cast<char*>(decoded), length, stream)) {
			XMLString::release(&decoded);
			return UNABLE_TO_INFLATE;
		}
	}
	else 
		stream << reinterpret_cast<char*>(decoded);

	XMLString::release(&decoded);
	DOMDocument* doc = XMLToolingConfig::getConfig().getParser().parse(stream);
	XMLObject* xmlObject = XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(), true);
	AuthnRequest* request = dynamic_cast<AuthnRequest*>(xmlObject);

	if (!request)
		return UNABLE_TO_CREATE_AUTHN_REQUEST;

	char* temp = XMLString::transcode(request->getAssertionConsumerServiceURL());
	strcpy(buffer, temp);
	XMLString::release(&temp);
	return NO_ERROR;
}

ErrorCode GetID(const char* authnRequest, int binding, char* buffer, int bufferSize) {
	buffer[0] = '\0';
	/* Developer's Note: The ideal approach would be to encapsulate the code to create the AuthnRequest
	 * in a seperate method. However, it would probably need to be created on the heap. */
	unsigned length;

	/*Developer's Note: Even if Redirect binding is used, URL decoding of the authnRequest will cause invalid results */
	
	//perform base-64 decoding and inflate (if required)
	XMLByte* decoded = Base64::decode(reinterpret_cast<const XMLByte*>(authnRequest), &length);
	stringstream stream;

	if (!decoded)
		return UNABLE_TO_DECODE;

	if (binding == REDIRECT) {
		if (!inflate(reinterpret_cast<char*>(decoded), length, stream)) {
			XMLString::release(&decoded);
			return UNABLE_TO_INFLATE;
		}
	}
	else 
		stream << reinterpret_cast<char*>(decoded);

	XMLString::release(&decoded);
	DOMDocument* doc = XMLToolingConfig::getConfig().getParser().parse(stream);
	XMLObject* xmlObject = XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(), true);
	AuthnRequest* request = dynamic_cast<AuthnRequest*>(xmlObject);

	if (!request)
		return UNABLE_TO_CREATE_AUTHN_REQUEST;

	char* temp = XMLString::transcode(request->getID());
	strcpy(buffer, temp);
	XMLString::release(&temp);
	return NO_ERROR;
}

ErrorCode BuildResponse(const char* issuerName, const char* id, const char* logonID, unsigned samlStatus, 
						char* authnRequest, int binding, char* buffer, int bufferSize) {
	if (samlStatus >= statusCodes_v.size())	
		return STATUS_CODE_NOT_FOUND;

	const int SIZE = 512;	
	const string CREDENTIAL_RESOLVER_PATH = "C:\\Inetpub\\wwwroot\\SAML_SSO\\data\\FilesystemCredentialResolver.xml";
	Response* response = ResponseBuilder::buildResponse();
	XMLCh* xmlStr;
	char* authnRequestID = new char[SIZE];
	ErrorCode errorCode = GetID(authnRequest, binding, authnRequestID, SIZE);

	if (errorCode != NO_ERROR)
		return errorCode;

	char* assertionConsumerServiceURL = new char[SIZE];
	errorCode = GetAssertionConsumerServiceURL(authnRequest, binding, assertionConsumerServiceURL, SIZE);

	if (errorCode != NO_ERROR)
		return errorCode;

	//set destination
	xmlStr = XMLString::transcode(assertionConsumerServiceURL);
	response->setDestination(xmlStr);
	XMLString::release(&xmlStr);

	//set ID
	xmlStr = XMLString::transcode(id);
	response->setID(xmlStr);
	XMLString::release(&xmlStr);

	//set inResponseTo
	xmlStr = XMLString::transcode(authnRequestID);
	response->setInResponseTo(xmlStr);
	XMLString::release(&xmlStr);

	//set issueInstant
	time_t currentTime = time(NULL);
	response->setIssueInstant(currentTime);

	//set issuerName/issuer
	Issuer* issuer_1 = IssuerBuilder::buildIssuer();
	xmlStr = XMLString::transcode(issuerName);
	issuer_1->setName(xmlStr);
	XMLString::release(&xmlStr);
	response->setIssuer(issuer_1);

	//set status code/status
	StatusCode* statusCode = StatusCodeBuilder::buildStatusCode();
	xmlStr = XMLString::transcode(statusCodes_v.at(samlStatus).c_str());
	statusCode->setValue(xmlStr);
	XMLString::release(&xmlStr);
	Status* status = StatusBuilder::buildStatus();
	status->setStatusCode(statusCode);
	response->setStatus(status);

	//create assertion
	saml2::Assertion* assertion = AssertionBuilder::buildAssertion();
	assertion->setIssueInstant(currentTime);
	Issuer* issuer_2 = IssuerBuilder::buildIssuer();
	xmlStr = XMLString::transcode(issuerName);
	issuer_2->setName(xmlStr);
	XMLString::release(&xmlStr);
	assertion->setIssuer(issuer_2);
	xmlStr = XMLString::transcode(id);
	assertion->setID(xmlStr);
	XMLString::release(&xmlStr);

	//create assertion subject
	Subject* subject = SubjectBuilder::buildSubject();
	NameID* nameID = NameIDBuilder::buildNameID();
	xmlStr = XMLString::transcode("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
	nameID->setFormat(xmlStr);
	XMLString::release(&xmlStr);
	xmlStr = XMLString::transcode(logonID);
	nameID->setName(xmlStr);
	XMLString::release(&xmlStr);
	subject->setNameID(nameID);

	//create subject confirmation and subject confirmation data
	SubjectConfirmation* subjectConfirmation = SubjectConfirmationBuilder::buildSubjectConfirmation();
	xmlStr = XMLString::transcode("urn:oasis:names:tc:SAML:2.0:cm:bearer");
	subjectConfirmation->setMethod(xmlStr);
	XMLString::release(&xmlStr);
	SubjectConfirmationData* subjectConfirmationData = SubjectConfirmationDataBuilder::buildSubjectConfirmationData();
	xmlStr = XMLString::transcode(assertionConsumerServiceURL);
	subjectConfirmationData->setRecipient(xmlStr);	
	XMLString::release(&xmlStr);
	xmlStr = XMLString::transcode(authnRequestID);
	subjectConfirmationData->setInResponseTo(xmlStr);
	XMLString::release(&xmlStr);

	//create conditions
	Conditions* conditions = ConditionsBuilder::buildConditions();
	time_t minus1min = currentTime - 60;
	conditions->setNotBefore(minus1min);
	time_t plus5min = currentTime + (60 * 5);
	conditions->setNotOnOrAfter(plus5min);
	subjectConfirmationData->setNotOnOrAfter(plus5min);
	assertion->setConditions(conditions);

	//add subject to assertion
	subjectConfirmation->setSubjectConfirmationData(subjectConfirmationData);
	subject->getSubjectConfirmations().push_back(subjectConfirmation);
	assertion->setSubject(subject);

	//create authnStatement and add to assertion
	AuthnContextClassRef* authnContextClassRef = AuthnContextClassRefBuilder::buildAuthnContextClassRef();
	xmlStr = XMLString::transcode("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
	authnContextClassRef->setReference(xmlStr);
	XMLString::release(&xmlStr);
	AuthnContext* authnContext = AuthnContextBuilder::buildAuthnContext();
	authnContext->setAuthnContextClassRef(authnContextClassRef);
	AuthnStatement* authnStatement = AuthnStatementBuilder::buildAuthnStatement();
	authnStatement->setAuthnContext(authnContext);
	authnStatement->setAuthnInstant(currentTime);
	assertion->getAuthnStatements().push_back(authnStatement);

	delete[] authnRequestID;
	delete[] assertionConsumerServiceURL;

	//create credential and set signature
	ifstream in(CREDENTIAL_RESOLVER_PATH.c_str());

	if (!in)
		return FILESYSTEM_CREDENTIAL_RESOLVER_XML_FILE_NOT_FOUND;

    DOMDocument* doc = XMLToolingConfig::getConfig().getParser().parse(in);
    XercesJanitor<DOMDocument> janitor1(doc);
    CredentialResolver* resolver;
	
	try {
		resolver = XMLToolingConfig::getConfig().CredentialResolverManager.newPlugin(FILESYSTEM_CREDENTIAL_RESOLVER, doc->getDocumentElement());
	}
	catch (exception& e) {
		janitor1.release();
		cerr << "Exception occured: " << e.what() << endl;
		return UNABLE_TO_CREATE_CREDENTIAL_RESOLVER;
	}
	
	janitor1.release();
	CredentialCriteria criteria;
	criteria.setUsage(Credential::SIGNING_CREDENTIAL);
	Signature* signature = SignatureBuilder::buildSignature();
	assertion->setSignature(signature);
	signature->setSignatureAlgorithm(DSIGConstants::s_unicodeStrURIRSA_SHA1);
	signature->setCanonicalizationMethod(DSIGConstants::s_unicodeStrURIEXC_C14N_NOC);
	opensaml::ContentReference* reference = dynamic_cast<opensaml::ContentReference*>(signature->getContentReference());

	if (!reference)
		return NULL_CONTENT_REFERENCE;

	auto_ptr_XMLCh digestAlgorithm(URI_ID_SHA1);
	auto_ptr_XMLCh transform1(URI_ID_ENVELOPE);
	auto_ptr_XMLCh transform2(URI_ID_EXC_C14N_NOC);
	reference->setDigestAlgorithm(digestAlgorithm.get());
	reference->addInclusivePrefix(transform1.get());
	reference->addInclusivePrefix(transform2.get());
	Locker locker(resolver);
	const Credential* credential = resolver->resolve(&criteria);
	vector<Signature*> signatures(1, signature);

	//add assertion to response
	response->getAssertions().push_back(assertion);

	//perform marshalling and write DOM
	DOMElement* element = response->marshall((DOMDocument*)NULL, &signatures, credential);
	static const XMLCh impltype[] = { chLatin_L, chLatin_S, chNull };
	static const XMLCh UTF8[]={ chLatin_U, chLatin_T, chLatin_F, chDigit_8, chNull };
	DOMImplementation* impl = DOMImplementationRegistry::getDOMImplementation(impltype);
	DOMWriter* serializer = (static_cast<DOMImplementationLS*>(impl))->createDOMWriter();
	XercesJanitor<DOMWriter> janitor2(serializer);
	serializer->setEncoding(UTF8);
	MemBufFormatTarget target;

	if (!serializer->writeNode(&target, *static_cast<DOMNode*>(element))) {
		janitor2.release();
		return UNABLE_TO_SERIALIZE;
	}

#if (1)
	ofstream file("C:\\Inetpub\\wwwroot\\SAML_SSO\\Response.xml");
	file << reinterpret_cast<const char*>(target.getRawBuffer()) << endl;
#endif

	janitor2.release();
	string xmlBuf(reinterpret_cast<const char*>(target.getRawBuffer()));
	XMLByte* encoded;
	unsigned length;

	//perform base-64 encoding
	char* tmp = const_cast<char*>(xmlBuf.c_str());
	encoded = Base64::encode(reinterpret_cast<XMLByte*>(tmp), (int)xmlBuf.length(), &length);

	if (!encoded)
		return UNABLE_TO_ENCODE;

	if ((int)length > bufferSize) {
			XMLString::release(&encoded);
			return OUTPUT_EXCEEDS_BUFFER_SIZE;
		}

	strcpy(buffer, reinterpret_cast<char*>(encoded));
	XMLString::release(&encoded);
	return NO_ERROR;
}

void URLDecode(char* authnRequest) {
	const URLEncoder* encoder = XMLToolingConfig::getConfig().getURLEncoder();
	encoder->decode(authnRequest);
}