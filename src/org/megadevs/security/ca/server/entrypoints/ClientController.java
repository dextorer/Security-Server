package org.megadevs.security.ca.server.entrypoints;

import java.io.IOException;
import java.io.StringReader;

import javax.servlet.http.HttpServlet;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.megadevs.security.ca.server.ICertificateRequestModel;
import org.megadevs.security.ca.server.ICertificationAuthorityModel;
import org.megadevs.security.ca.server.ICertificationModel;
import org.megadevs.security.ca.server.utils.NetworkUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.sun.org.apache.xml.internal.security.utils.Base64;

@SuppressWarnings("serial")
@Controller
@RequestMapping(value="/remote")
public class ClientController extends HttpServlet {

	@Autowired
	private ICertificationAuthorityModel mCertificationAuthority;
	
	@Autowired
	private ICertificateRequestModel mCertificateRequestModel;
	
	@Autowired
	private ICertificationModel mCertificationModel;
	
	@ResponseBody
	@ResponseStatus(HttpStatus.OK)
	@RequestMapping(value="/newCertificateRequest", method={RequestMethod.POST})
	public String newCertificateRequest(@RequestParam("message") String message) {
		
		mCertificationModel.loadDB();
		boolean isSignatureValid = NetworkUtils.validateXMLSignature(message);
		String ID = new String(Base64.encode("-1".getBytes()));
		if (isSignatureValid) {
			try {
				DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
				DocumentBuilder db = dbf.newDocumentBuilder();
				Document doc = db.parse(new InputSource(new StringReader(message)));
				
				NodeList nodes = doc.getElementsByTagName("content");
				
				Element element = (Element) nodes.item(0);
				String content = NetworkUtils.getCharacterDataFromElement(element);

				ID = mCertificateRequestModel.newCertificateRequest(content);
				
			} catch (ParserConfigurationException e) {
				e.printStackTrace();
			} catch (SAXException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}

		}
		
		String prepareXMLMessage = NetworkUtils.prepareXMLMessage(ID);
		String signedXML = NetworkUtils.generateXMLSignature(prepareXMLMessage, mCertificationAuthority.getKeyPair());
		return signedXML;
	}
	
	@ResponseBody
	@ResponseStatus(HttpStatus.OK)
	@RequestMapping(value="/checkCertificateRequest", method={RequestMethod.POST})
	public String checkCertificateRequest(@RequestParam("message") String message) {

		mCertificationModel.loadDB();
		String response = "";
		try {
			boolean isSignatureValid = NetworkUtils.validateXMLSignature(message);
			if (isSignatureValid) {
				DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
				DocumentBuilder db;
				db = dbf.newDocumentBuilder();
				Document doc = db.parse(new InputSource(new StringReader(message)));

				NodeList nodes = doc.getElementsByTagName("content");

				Element element = (Element) nodes.item(0);
				String content = NetworkUtils.getCharacterDataFromElement(element);

				response = mCertificationModel.checkCertificate(content);
			}
			
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
		} catch (SAXException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		String prepareXMLMessage = NetworkUtils.prepareXMLMessage(response);
		String signedXML = NetworkUtils.generateXMLSignature(prepareXMLMessage, mCertificationAuthority.getKeyPair());
		return signedXML;
	}

	@ResponseBody
	@ResponseStatus(HttpStatus.OK)
	@RequestMapping(value="/getCRL", method={RequestMethod.POST})
	public String getCRL(@RequestParam("message") String message) {
		
		mCertificationModel.loadDB();
		String response = "";
		boolean isSignatureValid = NetworkUtils.validateXMLSignature(message);
		if (isSignatureValid)
			response = mCertificationAuthority.getEncodedCRL();

		String prepareXMLMessage = NetworkUtils.prepareXMLMessage(response);
		String signedXML = NetworkUtils.generateXMLSignature(prepareXMLMessage, mCertificationAuthority.getKeyPair());
		
		return signedXML;

	}
	
	@RequestMapping(value = "/revokeCertificate", method = RequestMethod.POST)
	@ResponseStatus(HttpStatus.OK)
	@ResponseBody
	public String revokeCertificate(@RequestParam("message") String message) {
		mCertificationAuthority.loadDatabase();
		
		boolean isValid = NetworkUtils.validateXMLSignature(message);
		String respMessage = "";
		if (isValid) {
			try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			DocumentBuilder db = dbf.newDocumentBuilder();
			Document doc = db.parse(new InputSource(new StringReader(message)));

			NodeList nodes = doc.getElementsByTagName("content");

			Element element = (Element) nodes.item(0);
			String content = NetworkUtils.getCharacterDataFromElement(element);
			
			respMessage = mCertificationModel.revokeCertificate(content);
			
			} catch (ParserConfigurationException e) {
				e.printStackTrace();
			} catch (SAXException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		String str = NetworkUtils.prepareXMLMessage(respMessage);
    	return NetworkUtils.generateXMLSignature(str, mCertificationAuthority.getKeyPair());
	}
	
	@RequestMapping(value = "/renewCertificate", method = RequestMethod.POST)
	@ResponseStatus(HttpStatus.OK)
	@ResponseBody
	public String renewCertificate(@RequestParam("message") String message) {
		mCertificationAuthority.loadDatabase();
		
		boolean isValid = NetworkUtils.validateXMLSignature(message);
		String respMessage = "";
		if (isValid) {
			try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			DocumentBuilder db = dbf.newDocumentBuilder();
			Document doc = db.parse(new InputSource(new StringReader(message)));

			NodeList nodes = doc.getElementsByTagName("content");

			Element element = (Element) nodes.item(0);
			String content = NetworkUtils.getCharacterDataFromElement(element);
			
			respMessage = mCertificateRequestModel.newCertificateRenewRequest(content);
			
			} catch (ParserConfigurationException e) {
				e.printStackTrace();
			} catch (SAXException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		String str = NetworkUtils.prepareXMLMessage(respMessage);
    	return NetworkUtils.generateXMLSignature(str, mCertificationAuthority.getKeyPair());

	}
	
	@RequestMapping(value = "/checkCertificateWithOCSP", method = RequestMethod.POST)
	@ResponseStatus(HttpStatus.OK)
	@ResponseBody
	public String checkCertificateWithOCSP(@RequestParam("message") String message) {
		mCertificationAuthority.loadDatabase();
		
		boolean isValid = NetworkUtils.validateXMLSignature(message);
		String respMessage = "";
		if (isValid) {
			try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			DocumentBuilder db = dbf.newDocumentBuilder();
			Document doc = db.parse(new InputSource(new StringReader(message)));

			NodeList nodes = doc.getElementsByTagName("content");

			Element element = (Element) nodes.item(0);
			String content = NetworkUtils.getCharacterDataFromElement(element);
			
			respMessage = mCertificationAuthority.checkCertificateWithOCSP(content);
			
			} catch (ParserConfigurationException e) {
				e.printStackTrace();
			} catch (SAXException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		String str = NetworkUtils.prepareXMLMessage(respMessage);
    	return NetworkUtils.generateXMLSignature(str, mCertificationAuthority.getKeyPair());
	}
	
	@RequestMapping(value = "/getRootCertificate", method = RequestMethod.POST)
	@ResponseStatus(HttpStatus.OK)
	@ResponseBody
	public String getRootCertificate(@RequestParam("message") String message) {
		mCertificationAuthority.loadDatabase();
		
		boolean isValid = NetworkUtils.validateXMLSignature(message);
		String respMessage = "";
		if (isValid) {
			try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			DocumentBuilder db = dbf.newDocumentBuilder();
			Document doc = db.parse(new InputSource(new StringReader(message)));

			NodeList nodes = doc.getElementsByTagName("content");

			Element element = (Element) nodes.item(0);
			String content = NetworkUtils.getCharacterDataFromElement(element);
			
			respMessage = mCertificationAuthority.getRootCertificate(content);
			
			} catch (ParserConfigurationException e) {
				e.printStackTrace();
			} catch (SAXException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		String str = NetworkUtils.prepareXMLMessage(respMessage);
    	return NetworkUtils.generateXMLSignature(str, mCertificationAuthority.getKeyPair());

	}
	
	@RequestMapping(value = "/getActiveDataEnciphermentCertificates", method = RequestMethod.POST)
	@ResponseStatus(HttpStatus.OK)
	@ResponseBody
	public String getActiveDataEnciphermentCertificates(@RequestParam("message") String message) {
		mCertificationAuthority.loadDatabase();
		
		boolean isValid = NetworkUtils.validateXMLSignature(message);
		String respMessage = "";
		if (isValid) {
			try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			DocumentBuilder db = dbf.newDocumentBuilder();
			Document doc = db.parse(new InputSource(new StringReader(message)));

			NodeList nodes = doc.getElementsByTagName("content");

			Element element = (Element) nodes.item(0);
			String content = NetworkUtils.getCharacterDataFromElement(element);
			
			respMessage = mCertificationAuthority.getActiveDataEnciphermentCertificates(content);
			
			} catch (ParserConfigurationException e) {
				e.printStackTrace();
			} catch (SAXException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		String str = NetworkUtils.prepareXMLMessage(respMessage);
    	return NetworkUtils.generateXMLSignature(str, mCertificationAuthority.getKeyPair());

	}
}
