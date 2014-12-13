using System;
using System.Data;
using System.Configuration;
using System.Collections;
using System.Web;
using System.Web.Security;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Web.UI.WebControls.WebParts;
using System.Web.UI.HtmlControls;
using SAML;

public partial class SSOService : System.Web.UI.Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        //Determine whether the SP used POST or Redirect to send request and save data
        if (Request.RequestType.ToLower() == "post")
        {
            Session["SAMLRequest"] = Request.Form["SAMLRequest"];
            Session["RelayState"] = Request.Form["RelayState"];
            Session["Binding"] = (int)SAMLInterface.ProtocolBinding.POST;
        }
        else
        {
            Session["SAMLRequest"] = Request.QueryString["SAMLRequest"];
            Session["RelayState"] = Request.QueryString["RelayState"];
            Session["Binding"] = (int)SAMLInterface.ProtocolBinding.REDIRECT;
        }

        if ((bool)Session["ValidLogon"] == false)
            Server.Transfer("~/Logon.aspx");
        else
            Server.Transfer("~/ProcessRequest.aspx");
    }
}
