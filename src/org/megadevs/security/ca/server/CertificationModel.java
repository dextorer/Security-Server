package org.megadevs.security.ca.server;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLEntryHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.megadevs.security.ca.server.db.IDatabase;
import org.megadevs.security.ca.server.utils.CompleteCertificate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Service;

@Service
@Scope(value="singleton")
public class CertificationModel implements ICertificationModel  {

	@Autowired
	public IDatabase mDatabase;

	@Autowired
	public ICertificationAuthorityModel mCertificationAuthorityModel;
	
	@Override
	public void generateCertificate(Integer serial) throws OperatorCreationException, CertIOException {
		PKCS10CertificationRequest request = mDatabase.getCertificateRequest(serial);

		BigInteger bigSerial = new BigInteger(String.valueOf(serial.intValue()));
		Date notBefore = new Date(System.currentTimeMillis());
		Date notAfter = (new Date(System.currentTimeMillis() + 2 * 30 * 24 * 60 * 60 * 1000L));
		X500Name x500name = X500Name.getInstance(request.getSubject());

		KeyPair rootPair = mDatabase.getKeyPair();
		X509CertificateHolder holder = mDatabase.getRootCertificate();

		ContentSigner sigGen = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(rootPair.getPrivate());

		SubjectPublicKeyInfo key = request.getSubjectPublicKeyInfo();
		X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(holder.getSubject(), bigSerial, notBefore, notAfter, x500name, key);

		Vector<ASN1ObjectIdentifier> oidSS = new Vector<ASN1ObjectIdentifier>();
		Vector<Extension> values = new Vector<Extension>();

		Attribute[] list = request.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
		if (list.length >= 1) {
			Extensions ext = Extensions.getInstance(list[0].getAttrValues().getObjectAt(0));
			ASN1ObjectIdentifier[] obid = ext.getExtensionOIDs();
			for (int i=0; i<obid.length; i++) {
				oidSS.add(obid[i]);
				values.add(ext.getExtension(obid[i]));
			}
		}

		for (int i=0; i<oidSS.size(); i++)
			certGen.addExtension(oidSS.get(i), values.get(i).isCritical(), values.get(i).getParsedValue());

		X509CertificateHolder issuedCert = certGen.build(sigGen);
		mDatabase.storeCertificate(serial, issuedCert);
	}

	@SuppressWarnings("unchecked")
	@Override
	public List<CompleteCertificate> retrieveCertificateListInfo() {
		List<CompleteCertificate> list = mDatabase.retrieveCertificateListInfo();
		
		X509CRLHolder crl = mDatabase.getCRL();
		Collection<X509CRLEntryHolder> certificates = crl.getRevokedCertificates();
		
		for (CompleteCertificate cert : list) {
			for (X509CRLEntryHolder val: certificates) {
				if (val.getSerialNumber().compareTo(new BigInteger(new Integer(cert.getSerial()).toString())) == 0) {
					cert.setRevoked(true);
				}	
			}
		}
		return list;
	}

	@Override
	public String checkCertificate(String serial) {
		
		String response = "";
		Integer ID = Integer.valueOf(new String(Base64.decode(serial)));
		try {
			X509CertificateHolder certificate = mDatabase.getCertificate(ID);
			
			if (certificate != null)
				response = new String(Base64.encode(certificate.getEncoded()));
			else
				response = "[REQ-"+ID+"] not processed yet";
		
		} catch (IOException e) {
			e.printStackTrace();
			response = "[REQ-"+ID+"] request processing error";
		}
		
		return response;
	}
	
	@Override
	public void loadDB() {
		mDatabase.load();
	}

	@Override
	public String revokeCertificate(String serial) {

		Integer ID = Integer.valueOf(new String(Base64.decode(serial)));

		ArrayList<Integer> newEntry = new ArrayList<Integer>();
		newEntry.add(ID);
		
		mCertificationAuthorityModel.setCRL(newEntry);
		
		return "OK";
	}
}

//String pubkeyencholder = new String(Base64.encode(issuedCert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes()));
//System.out.println("h = " + pubkeyencholder);
//
//String pubkeyenccert1 = new String(Base64.encode(certificate.getPublicKey().getEncoded()));
//System.out.println("1 = " + pubkeyenccert1);
//
//String pubkeyenccert2 = new String(Base64.encode(cceerrtt.getPublicKey().getEncoded()));
//System.out.println("2 = " + pubkeyenccert2);
//
//if (certificate.getPublicKey() == null)
//	System.out.println("certificate pubkey null");
//else System.out.println("certificate pubkey not null! yay!");
//
//if (cceerrtt.getPublicKey() == null)
//	System.out.println("cceerrtt pubkey null");
//else System.out.println("cceerrtt pubkey not null! yay!");
//
//System.out.println("----------------");
//
//X509CertificateHolder newHolder = new JcaX509CertificateHolder(cceerrtt);
//String newpubkeyencholder = new String(Base64.encode(newHolder.getSubjectPublicKeyInfo().getPublicKeyData().getBytes()));
//System.out.println("3 = " + newpubkeyencholder);
