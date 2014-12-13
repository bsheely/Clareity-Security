#ifndef SAML_WRAPPER_H
#define SAML_WRAPPER_H

typedef int ErrorCode;

// Return values for getStatus which represent errors
static const int UNABLE_TO_OPEN_FILE_FOR_OUTPUT = -1;
static const int FILESYSTEM_CREDENTIAL_RESOLVER_XML_FILE_NOT_FOUND = -2;
static const int UNABLE_TO_CREATE_CREDENTIAL_RESOLVER = -3;
static const int INVALID_SIGNATURE = -4;
static const int STATUS_CODE_NOT_FOUND = -5;
static const int EMPTY_CERTIFICATE = -6;
static const int UNABLE_TO_CREATE_RESPONSE = -7;

static enum Binding {POST, REDIRECT};

static enum ErrorCodes {NO_ERROR,                   
		                XML_OBJECT_EXCEPTION,       
						UNABLE_TO_SERIALIZE,        
						UNABLE_TO_DEFLATE,
						UNABLE_TO_INFLATE,
						UNABLE_TO_ENCODE,
						UNABLE_TO_DECODE,
						OUTPUT_EXCEEDS_BUFFER_SIZE,
                        XML_ELEMENT_OR_ATTRIBUTE_NOT_FOUND,
						UNABLE_TO_MARSHALL_SIGNATURE,
						UNABLE_TO_CREATE_AUTHN_REQUEST,
						NULL_CONTENT_REFERENCE};

extern "C" __declspec(dllexport) void InitializeSAMLWrapper();

extern "C" __declspec(dllexport) void CleanupSAMLWrapper();

extern "C" __declspec(dllexport) ErrorCode BuildAuthnRequest(const char* issuerName,
															 const char* id,
															 const char* providerName,
															 const char* destination,
															 const char* assertionConsumerServiceURL,
															 int binding,
															 bool forceAuthn,
															 char* buffer,
															 int bufferSize);

extern "C" __declspec(dllexport) ErrorCode MakeStringURISafe(const char* str, 
															 char* buffer, 
															 int bufferSize);

extern "C" __declspec(dllexport) ErrorCode GetX509CertFromResponse(const char* response, 
												                   char* buffer, 
												                   int bufferSize);

extern "C" __declspec(dllexport) ErrorCode GetX509CertFromMetadata(const char* metadata, 
													               char* buffer, 
													               int bufferSize);

extern "C" __declspec(dllexport) int GetStatus(const char* response, const char* x509Cert, bool formatted);

extern "C" __declspec(dllexport) ErrorCode BuildResponse(const char* issuerName,
														 const char* id,
														 const char* logonID,
														 unsigned samlStatus,
														 char* authnRequest,
														 int binding,
														 char* buffer,
														 int bufferSize);

extern "C" __declspec(dllexport) ErrorCode GetAssertionConsumerServiceURL(const char* authnRequest,
																		  int binding,
																		  char* buffer,
																		  int bufferSize);

extern "C" __declspec(dllexport) void URLDecode(char* authnRequest);
#endif