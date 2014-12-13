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

public partial class Logon : System.Web.UI.Page
{
    protected void Button1_Click(object sender, EventArgs e)
    {
        /*******************************************************
         * Code to determine if user has valid logon goes here!
         * *****************************************************/

        Session["LogonID"] = Text1.Value;
        Session["ValidLogon"] = true;
        Server.Transfer("~/ProcessRequest.aspx");
    }
}