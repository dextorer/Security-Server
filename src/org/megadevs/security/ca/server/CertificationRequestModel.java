package org.megadevs.security.ca.server;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.megadevs.security.ca.server.db.Database;
import org.megadevs.security.ca.server.utils.CertificationUtils;
import org.megadevs.security.ca.server.utils.CompleteCertificate;
import org.megadevs.security.ca.server.utils.CompleteRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Service;

@Service
@Scope(value="singleton")
public class CertificationRequestModel implements ICertificateRequestModel {

	@Autowired
	private Database mDatabase;

	@Autowired
	private ICertificationModel mCertificationModel;

	@Override
	public String newCertificateRequest(String message) {
		try {
			byte[] contRaw = Base64.decode(message);
			PKCS10CertificationRequest request = new PKCS10CertificationRequest(contRaw);

			Integer id = mDatabase.storeCertificateRequest(request);
			return new String(Base64.encode(String.valueOf(id.intValue()).getBytes()));

		} catch (IOException e) {
			e.printStackTrace();
		}

		return new String(Base64.encode("-1".getBytes()));
	}

	@Override
	public String newCertificateRenewRequest(String message) {
		try {
			byte[] contRaw = Base64.decode(message);
			PKCS10CertificationRequest request = new PKCS10CertificationRequest(contRaw);
			X500Name subject = request.getSubject();
			KeyUsage keyusage = CertificationUtils.getKeyUsageFromRequest(request);

			X509CertificateHolder activeCertificate = searchActiveCertificateOfSubject(subject, keyusage);

			if (activeCertificate != null) {
				Integer id = mDatabase.storeCertificateRequest(request);
				mCertificationModel.generateCertificate(id);
				
				X509CertificateHolder renewed = mDatabase.getCertificate(id);
				mDatabase.updateCertificateUponRenewal(activeCertificate.getSerialNumber().intValue(), id);
				
				return new String(Base64.encode(renewed.getEncoded()));
			}
			
		} catch (IOException e) {
			e.printStackTrace();
		} catch (OperatorCreationException e) {
			e.printStackTrace();
		}

		return new String(Base64.encode("-1".getBytes()));
	}

	private X509CertificateHolder searchActiveCertificateOfSubject(X500Name subject, KeyUsage usage) {
		try {
			ArrayList<X509CertificateHolder> certificatesList = mDatabase.getCertificatesList();
			List<CompleteCertificate> getCertificateListInfo = mDatabase.retrieveCertificateListInfo();
			X509CRLHolder crl = mDatabase.getCRL();
			
			for (int i=0; i<certificatesList.size(); i++) {
				X509CertificateHolder current = certificatesList.get(i);
				CompleteCertificate details = getCertificateListInfo.get(i);
				ByteArrayInputStream in = new ByteArrayInputStream(current.getEncoded());
				X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(in);

				boolean isDigitalSignatureCurrent = certificate.getKeyUsage()[0];
				boolean isDigitalSignatureCertificate = usage.intValue() == KeyUsage.digitalSignature;

				if (current.getSubject().equals(subject) && 
						(isDigitalSignatureCertificate == isDigitalSignatureCurrent) &&
						current.isValidOn(new Date(System.currentTimeMillis())) &&
						details.getRenewed() == -1 &&
						crl.getRevokedCertificate(current.getSerialNumber()) == null) {
					return current;
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
		
		return null;
	}

	@Override
	public List<CompleteRequest> retrieveCertificateRequestListInfo() {
		return mDatabase.retrieveCertificateRequestListInfo();
	}
}
