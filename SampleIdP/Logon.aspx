<%@ Page Language="C#" AutoEventWireup="true" CodeFile="Logon.aspx.cs" Inherits="Logon" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" >
<head runat="server">
    <title>Untitled Page</title>

</head>
<body>
    <form id="form1" runat="server">
    <div id="DIV1" runat="server">
        <asp:Label ID="Label1" runat="server" Height="21px" Style="font-size: larger; z-index: 100;
            left: 277px; position: absolute; top: 85px" Text="Sample IdP Logon" Width="157px"></asp:Label>
        <asp:Label ID="Label2" runat="server" Height="21px" Style="z-index: 101; left: 20px;
            position: absolute; top: 262px" Text="User Name:" Width="80px"></asp:Label>
        <input id="Text1" style="z-index: 105; left: 106px; position: absolute; top: 260px"
            type="text" runat="server" />
        <asp:Label ID="Label3" runat="server" Style="z-index: 102; left: 29px; position: absolute;
            top: 303px" Text="Password:" Width="67px"></asp:Label>
        <input id="Password1" style="z-index: 106; left: 106px; width: 148px; position: absolute;
            top: 301px" type="password" runat="server" />
        &nbsp;&nbsp;&nbsp;
        <asp:Button ID="Button1" runat="server" OnClick="Button1_Click" Style="z-index: 103;
            left: 71px; position: absolute; top: 365px" Text="Submit" />
        <input id="Reset1" style="z-index: 107; left: 159px; position: absolute; top: 365px"
            type="reset" value="Reset" />
        <asp:Label ID="Label4" runat="server" Style="z-index: 108; left: 111px; position: absolute;
            top: 196px" Text="Note: Any User Name and Password can be used in the sample IdP" Width="297px" ForeColor="Red"></asp:Label>
    
    </div>
    </form>
</body>
</html>
