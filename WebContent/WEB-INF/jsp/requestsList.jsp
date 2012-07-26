<%@page import="java.util.List"%>
<%@page import="org.megadevs.security.ca.server.utils.CompleteRequest"%>
<html>
<head>
	<title>Manager Home page</title>
	<link type="text/css" rel="stylesheet" href="/Sicurezza-Server/screen.css" media="screen" />
	<script src="/Sicurezza-Server/jquery-1.7.2.min.js"></script>
	
	<script type="text/javascript">
	$(document).ready(function(){
		   $("tr").click(function(event){
		      var r = confirm("Release certificate to \n"
		    		  + $($(this).find('td')[2]).text()
		    		  + " over request " + $($(this).find('td')[0]).text());
		      if (r == true) {
		    	  window.location = "/Sicurezza-Server/ca/auth/createCertificate?id="
		    			  + $($(this).find('td')[0]).text();
		      }
		   });
		});
	</script>
	
</head>
<body>
<div id="header">
<ul id="menu">
<li><a href="certificatesList">Certificates</a></li>
<li><a class="current" href="requestsList">Certification Requests</a></li>
<li><a href="revocationList">Certificates Revocation List</a></li>
<li><a href="logout">Logout</a></li>
</ul>

<h1>CERTIFICATION AUTHORITY - ADMINISTRATOR PANEL</h1>

</div>
<div id="body_content">
<div id="content">

<h2>Certification Requests</h2>

<%
	@SuppressWarnings("unchecked")
	List<CompleteRequest> requestList = (List<CompleteRequest>) request.getAttribute("requestList");
	
	int numChar = 65;

	if (requestList.size() > 0 ) {	
		out.println("<table>");
		out.println("<tr><th>ID</th><th>Tipo</th><th>Subject</th><th>Public Key</th></tr>");

		for (int i = 0; i < requestList.size(); i++) {
			if (i%2 == 0) {
				out.println("<tr class=\"rowa\">");
			} else {
				out.println("<tr class=\"rowb\">");
			}
			out.println("<td>"+ requestList.get(i).getSerial() +"</td>");
			out.println("<td>"+ requestList.get(i).getType() +"</td>");
			out.println("<td>"+ requestList.get(i).getSubject() +"</td>");
			String str = requestList.get(i).getPublicKey();
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