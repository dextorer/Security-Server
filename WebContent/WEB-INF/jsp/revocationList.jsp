<%@page import="java.util.Collection"%>
<%@page import="org.bouncycastle.cert.X509CRLHolder"%>
<%@page import="org.bouncycastle.cert.X509CRLEntryHolder"%>

<html>
<head>
	<title>Manager Home page</title>
	<link type="text/css" rel="stylesheet" href="/Sicurezza-Server/screen.css" media="screen" />
</head>
<body>
<div id="header">
<ul id="menu">
<li><a href="certificatesList">Certificates</a></li>
<li><a href="requestsList">Certification Requests</a></li>
<li><a class="current" href="revocationList">Certificates Revocation List</a></li>
<li><a href="logout">Logout</a></li>
</ul>

<h1>CERTIFICATION AUTHORITY - ADMINISTRATOR PANEL</h1>

</div>
<div id="body_content">
<div id="content">

<h2>Certificates Revocation List</h2>
<%
	X509CRLHolder crl = (X509CRLHolder) request.getAttribute("crl");

	out.println("<table>");
	out.println("<tr><th>ID</th><th>Revocation Date</th></tr>");

	Collection<X509CRLEntryHolder> certificates = crl.getRevokedCertificates();
	boolean b = true;
	for (X509CRLEntryHolder val: certificates) {
		if (b) {
			out.println("<tr class=\"rowa\">");
			b = false;
		} else {
			out.println("<tr class=\"rowb\">");
			b = true;
		}
		out.println("<td>" + val.getSerialNumber() + "</td>");
		out.println("<td>" + val.getRevocationDate() + "</td>");
		out.println("</tr>");		
	}
	

	out.println("</table>");
%>

</div>
</div>
</body>
</html>