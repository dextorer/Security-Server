<%@page import="java.util.List"%>
<%@page import="org.megadevs.security.ca.server.utils.CompleteCertificate"%>
<html>
<head>
	<title>Manager Home page</title>
	<link type="text/css" rel="stylesheet" href="/Sicurezza-Server/screen.css" media="screen" />
</head>
<body>
<div id="header">
<ul id="menu">
<li><a class="current" href="certificatesList">Certificates</a></li>
<li><a href="requestsList">Certification Requests</a></li>
<li><a href="revocationList">Certificates Revocation List</a></li>
<li><a href="logout">Logout</a></li>
</ul>
<h1>CERTIFICATION AUTHORITY - ADMINISTRATOR PANEL</h1>

</div>
<div id="body_content">
<div id="content">

<h2>Certificates</h2>
<%
	@SuppressWarnings("unchecked")
	List<CompleteCertificate> certificateList = (List<CompleteCertificate>) request.getAttribute("certificateList");
	
	int numChar = 65;

	if (certificateList.size() > 0 ) {	
		out.println("<table>");
		out.println("<tr><th>ID</th><th>Not Before</th><th>Not After</th><th>Type</th><th>Subject</th><th>Revoked</th><th>Public Key</th></tr>");

		for (int i = 0; i < certificateList.size(); i++) {
			if (i%2 == 0) {
				out.println("<tr class=\"rowa\">");
			} else {
				out.println("<tr class=\"rowb\">");
			}
			out.println("<td>"+ certificateList.get(i).getSerial() +"</td>");
			out.println("<td>"+ certificateList.get(i).getNotBefore() +"</td>");
			out.println("<td>"+ certificateList.get(i).getNotAfter() +"</td>");
			out.println("<td>"+ certificateList.get(i).getType() +"</td>");
			out.println("<td>"+ certificateList.get(i).getSubject() +"</td>");
			
			if (certificateList.get(i).isRevoked())
				out.println("<td>" + "revocato" + "</td>");
			else
				out.println("<td>" + "</td>");
			
			String str = certificateList.get(i).getPublicKey();
			int mod = str.length()/10;
			String str2 = "";
			int j = 0;
			for (j = 0; j < mod && ((j+1)*numChar)<str.length(); j++) {
				str2 += str.substring(j*numChar, (j +1)*numChar) + "<br />";
			}
			if (j*numChar < str.length()) {
				str2 += str.substring(j*numChar, str.length());
			}
			out.println("<td>"+ str2 +"</td>");
			out.println("</tr>");
		}

		out.println("</table>");
	}
%>

</div>
</div>
</body>
</html>