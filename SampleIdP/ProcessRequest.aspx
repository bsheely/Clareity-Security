<%@ Page Language="C#" EnableViewStateMac="false" EnableEventValidation="false" AutoEventWireup="true" CodeFile="ProcessRequest.aspx.cs" Inherits="ProcessRequest" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<%  
    string issuerName = "SampleIdP Issuer";
    string id = "002";
    string logonID = (string)Session["LogonID"];
    uint status = (uint)SAML.SAMLInterface.SAMLStatus.SUCCESS;
    string samlRequest = (string)Session["SAMLRequest"];
    string relayState = (string)Session["RelayState"];
    int binding = (int)Session["Binding"];
    string samlResponse = ((SAML.SAMLInterface)Application["SAMLInterface"]).BuildResponse(issuerName, id, logonID, status, samlRequest, binding);
    string destination = ((SAML.SAMLInterface)Application["SAMLInterface"]).GetAssertionConsumerServiceURL(samlRequest, binding);
%>

<html xmlns="http://www.w3.org/1999/xhtml" >
<head runat="server">
    <title>Untitled Page</title>
</head>
<body onload="document.forms[0].submit()">
    <form method="post" action="<%Response.Write(destination);%>">
    <input type="hidden" name="SAMLResponse" value="<%Response.Write(samlResponse);%>" />
    <input type="hidden" name="RelayState" value="<%Response.Write(relayState);%>" />
    <noscript>
    <input type="submit" value="Continue" />
    </noscript>
    </form>
</body>
</html>
