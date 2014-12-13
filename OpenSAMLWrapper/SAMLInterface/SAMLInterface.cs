using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

namespace SAML
{
    public class SAMLInterface
    {
        [DllImport("SAMLWrapper.dll")]
        private static extern void InitializeSAMLWrapper();

        [DllImport("SAMLWrapper.dll")]
        private static extern void CleanupSAMLWrapper();

        [DllImport("SAMLWrapper.dll")]
        private static extern int BuildAuthnRequest(string issuerName, string id, string providerName, string destination,
                                                    string assertionConsumerServiceURL, int binding,
                                                    bool forceAuthn, StringBuilder buffer, int bufferSize);

        [DllImport("SAMLWrapper.dll")]
        private static extern int MakeStringURISafe(string str, StringBuilder buffer, int bufferSize);

        [DllImport("SAMLWrapper.dll")]
        private static extern int GetX509CertFromResponse(string response, StringBuilder buffer, int bufferSize);
        
        [DllImport("SAMLWrapper.dll")]
        private static extern int GetX509CertFromMetadata(string metadata, StringBuilder buffer, int bufferSize);
        
        [DllImport("SAMLWrapper.dll")]
        private static extern int GetStatus(string response, string publicKey, bool formatted);

        [DllImport("SAMLWrapper.dll")]
        private static extern int BuildResponse(string issuerName, string id, string logonID, uint status, 
                                                string authnRequest, int binding, StringBuilder buffer, int bufferSize);

        [DllImport("SAMLWrapper.dll")]
        private static extern int GetAssertionConsumerServiceURL(string authnRequest, int binding, StringBuilder buffer, int bufferSize);

        public enum ProtocolBinding { POST, REDIRECT }

        public enum SAMLStatus
        {
            // Negative values represent processing errors rather than SAML status codes
            ERROR_UNABLE_TO_CREATE_RESPONSE = -7,
            ERROR_EMPTY_CERTIFICATE = -6,
            ERROR_STATUS_CODE_NOT_FOUND = -5,  
            ERROR_INVALID_SIGNATURE = -4,  
            ERROR_UNABLE_TO_CREATE_CREDENTIAL_RESOLVER = -3,
            ERROR_FILESYSTEM_CREDENTIAL_RESOLVER_XML_FILE_NOT_FOUND = -2, 
            ERROR_UNABLE_TO_OPEN_FILE_FOR_OUTPUT = -1, 
            SUCCESS,
            REQUESTER,
            RESPONDER,
            VERSION_MISMATCH,
            AUTHN_FAILED,
            INVALID_ATTR_NAME_OR_VALUE,
            INVALID_NAME_ID_POLICY,
            NO_AUTHN_CONTEXT,
            NO_AVAILABLE_IDP,
            NO_PASSIVE,
            NO_SUPPORTED_IDP,
            PARTIAL_LOGOUT,
            PROXY_COUNT_EXCEEDED,
            REQUEST_DENIED,
            REQUEST_UNSUPPORTED,
            REQUEST_VERSION_DEPRECATED,
            REQUEST_VERSION_TOO_HIGH,
            REQUEST_VERSION_TOO_LOW,
            RESOURCE_NOT_RECOGNIZED,
            TOO_MANY_RESPONSES,
            UNKNOWN_ATTR_PROFILE,
            UNKNOWN_PRINCIPAL,
            UNSUPPORTED_BINDING
        }

        public SAMLInterface()
        {
            InitializeSAMLWrapper();
        }

        ~SAMLInterface() {
            CleanupSAMLWrapper();
        }

        /****************************************************************
         *     The following are the methods used to implement an SP         
         ****************************************************************/
        /**
         * Returns a Base64 string representation of the SAML AuthnRequest message element which is sent to the IdP. 
         * If the binding is set to REDIRECT then the content is compressed prior to encoding. */
        public string BuildAuthnRequest(string issuerName, string id, string providerName, string destination,
                                 string assertionConsumerServiceURL, int binding, bool forceAuthn)
        {
            StringBuilder stringBuilder = new StringBuilder(BUFFER_SIZE);
            BuildAuthnRequest(issuerName, id, providerName, destination, assertionConsumerServiceURL,
                              binding, forceAuthn, stringBuilder, BUFFER_SIZE);
            return stringBuilder.ToString();
        }

        /**
         * Encodes the input string so that it can be used as a URI query string for Redirect binding. */
        public string MakeStringURISafe(string str)
        {
            StringBuilder stringBuilder = new StringBuilder(BUFFER_SIZE);
            MakeStringURISafe(str, stringBuilder, BUFFER_SIZE);
            return stringBuilder.ToString();
        }

        /**
         * Returns the X509 Certificate (formatted) from the SAMLResponse. */
        public string GetX509CertificateFromResponse(string response)
        {
            StringBuilder stringBuilder = new StringBuilder(BUFFER_SIZE);
            GetX509CertFromResponse(response, stringBuilder, BUFFER_SIZE);
            return stringBuilder.ToString();
        }

        /**
         * Returns the X509 Certificate (unformatted) from the IdP metadata file. */
        public string GetX509CertificateFromMetadata(string metadata)
        {
            StringBuilder stringBuilder = new StringBuilder(BUFFER_SIZE);
            GetX509CertFromMetadata(metadata, stringBuilder, BUFFER_SIZE);
            return stringBuilder.ToString();
        }

        /**
         * Returns the status of the corresponding AuthnRequest contained in the Response message 
         * or an error code if the status cannot be obtained. If the X509 Certificate was obtained
         * from the SAMLResponse, it is formatted. */
        public SAMLStatus GetResponseStatus(string response, string x509Cert, bool certFormatted)
        {
            return (SAMLStatus)GetStatus(response, x509Cert, certFormatted);
        }

        /****************************************************************
         *     The following are the methods used to implement an IdP         
         ****************************************************************/
        /**
         * Returns a Base64 string representation of the SAML Response message element which is sent to the SP
         * in response to the authnRequest. */
        public string BuildResponse(string issuerName, string id, string logonID, uint status, string authnRequest, int binding)
        {
            StringBuilder stringBuilder = new StringBuilder(BUFFER_SIZE);
            BuildResponse(issuerName, id, logonID, status, authnRequest, binding, stringBuilder, BUFFER_SIZE);
            return stringBuilder.ToString();
        }

        /**
         * Extracts the SP's Assertion Consumer Service URL from the SAML AuthnRequest. */
        public string GetAssertionConsumerServiceURL(string authnRequest, int binding)
        {
            StringBuilder stringBuilder = new StringBuilder(BUFFER_SIZE);
            GetAssertionConsumerServiceURL(authnRequest, binding, stringBuilder, BUFFER_SIZE);
            return stringBuilder.ToString();
        }

        const int BUFFER_SIZE = 8192;
    }
}
