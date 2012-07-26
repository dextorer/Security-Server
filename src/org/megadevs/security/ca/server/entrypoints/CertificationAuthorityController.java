package org.megadevs.security.ca.server.entrypoints;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Enumeration;
import java.util.List;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;

import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.operator.OperatorCreationException;
import org.megadevs.security.ca.server.ICertificateRequestModel;
import org.megadevs.security.ca.server.ICertificationAuthorityModel;
import org.megadevs.security.ca.server.ICertificationModel;
import org.megadevs.security.ca.server.utils.CompleteCertificate;
import org.megadevs.security.ca.server.utils.CompleteRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import com.sun.org.apache.xml.internal.security.utils.Base64;


@SuppressWarnings("serial")
@Controller
@RequestMapping(value="/auth")
public class CertificationAuthorityController extends HttpServlet {

	@Autowired
	private ICertificationAuthorityModel mCertificationAuthority;

	@Autowired
	private ICertificateRequestModel mCertificateRequest;
	
	@Autowired
	private ICertificationModel mCertificationModel;
	
	private static Logger logger;

	public CertificationAuthorityController() {
		logger = LoggerFactory.getLogger(CertificationAuthorityController.class);
	}

	@RequestMapping(value="/init", method={RequestMethod.POST})
	public ModelAndView initSequence(@RequestParam("password") String password) {
		ModelAndView mav = new ModelAndView();

		if (mCertificationAuthority.checkDB()) {
			if (mCertificationAuthority.checkRootCertificateValidity()) {
				mav.setViewName("alreadyInitialized");
			} else {
				mav.setViewName("invalidRootCertificate");
			}
		}
		else {
			try {
				mCertificationAuthority.generateRootCertificate(password);
				mCertificationAuthority.createCRL();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (NoSuchProviderException e) {
				e.printStackTrace();
			} catch (OperatorCreationException e) {
				e.printStackTrace();
			}
			
			mav.setViewName("initalizationCompleted");
		}
		return mav;
	}

	@RequestMapping(value = "/login", method = { RequestMethod.POST })
	@ResponseBody
	public String login(@RequestParam("password") String password, HttpServletRequest request) {
		mCertificationAuthority.loadDatabase();
		String str;
		if (mCertificationAuthority.checkPassword(password)) {
			str = "<html><head><meta http-equiv=\"refresh\" content=\"0;url=/Sicurezza-Server/ca/auth/certificatesList\"></head><body></body></html>";
			request.getSession().setAttribute("managerAuthenticated", true);
		} else {
			str = "<html><head><meta http-equiv=\"refresh\" content=\"0;url=/Sicurezza-Server/login.html\"></head><body></body></html>";
			request.getSession().removeAttribute("managerAuthenticated");
		}
		
		return str;
	}
	

	@RequestMapping(value = "/logout")
	@ResponseBody
	public String logout(HttpServletRequest request) {
		request.getSession().removeAttribute("managerAuthenticated");
		request.getSession().invalidate();
		return "<html><head><meta http-equiv=\"refresh\" content=\"0;url=/Sicurezza-Server/login.html\"></head><body></body></html>";
	}
	

	@RequestMapping(value = "/requestsList")
	public ModelAndView certificateRequestList(HttpServletRequest request) {
		mCertificationAuthority.loadDatabase();
		if (!checkAuthorityLogged(request)) return new ModelAndView("redirectLogin");
		ModelAndView mav = new ModelAndView("requestsList");
		List<CompleteRequest> requestList = mCertificateRequest.retrieveCertificateRequestListInfo();

		mav.addObject("requestList", requestList);		
		return mav;
	}
	

	@RequestMapping(value = "/createCertificate")
	@ResponseBody
	public String createCertFromRequest(HttpServletRequest request, @RequestParam("id") int serial) {
		mCertificationAuthority.loadDatabase();
		if (!checkAuthorityLogged(request)) {
			return "<html><head><meta http-equiv=\"refresh\" content=\"0;url=/Sicurezza-Server/login.html\"></head><body></body></html>";
		}
		
		try {
			mCertificationModel.generateCertificate(serial);
		} catch (Exception e) {
			logger.error("Certifcate creation failed", e);
			return "<html><head></head><body><script type=\"text/javascript\">window.alert('Could not generate certificate from the selected request'); window.location='/Sicurezza-Server/ca/auth/reqcertlist';</script></body></html>";
		}
		
		return "<html><head><meta http-equiv=\"refresh\" content=\"0;url=/Sicurezza-Server/ca/auth/requestsList\"></head><body></body></html>";
	}
	
	@RequestMapping(value = "/certificatesList")
	public ModelAndView certificateList(HttpServletRequest request) {
		mCertificationAuthority.loadDatabase();
		if (!checkAuthorityLogged(request)) return new ModelAndView("redirectLogin");
		ModelAndView mav = new ModelAndView("certificatesList");
		List<CompleteCertificate> certList = mCertificationModel.retrieveCertificateListInfo();

		mav.addObject("certificateList", certList);		
		return mav;
	}
	
	private boolean checkAuthorityLogged (HttpServletRequest request) {
		Enumeration<String> atts = request.getSession().getAttributeNames();
		boolean authLogged = false;
		while (atts.hasMoreElements()) {
			if (atts.nextElement().compareTo("managerAuthenticated") == 0) {
				authLogged = (Boolean) request.getSession().getAttribute("managerAuthenticated");				
			}
		}
		return authLogged;
	}

	@RequestMapping(value = "/revokeCertificateMANUAL")
	@ResponseBody
	public String revokeCertificateMANUAL(HttpServletRequest request, @RequestParam("id") int serial) {
		mCertificationAuthority.loadDatabase();
		if (!checkAuthorityLogged(request)) {
			return "<html><head><meta http-equiv=\"refresh\" content=\"0;url=/Sicurezza-Server/login.html\"></head><body></body></html>";
		}
		
		try {
			mCertificationModel.revokeCertificate(new String(Base64.encode(new Integer(serial).toString().getBytes())));
		} catch (Exception e) {
			logger.error("Certifcate creation failed", e);
//			return "<html><head></head><body><script type=\"text/javascript\">window.alert('Could not generate certificate from the selected request'); window.location='/Sicurezza-Server/ca/auth/reqcertlist';</script></body></html>";
		}
		
		return "<html><head><meta http-equiv=\"refresh\" content=\"0;url=/Sicurezza-Server/ca/auth/requestsList\"></head><body></body></html>";
	}

	@RequestMapping(value = "/revocationList")
	public ModelAndView certificateRevocationList(HttpServletRequest request) {
		mCertificationAuthority.loadDatabase();
		if (!checkAuthorityLogged(request)) return new ModelAndView("redirectLogin");
		ModelAndView mav = new ModelAndView("revocationList");
		X509CRLHolder crl = mCertificationAuthority.getCRL();

		mav.addObject("crl", crl);
		return mav;
	}
}
