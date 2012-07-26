package org.megadevs.security.ca.server;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CRLEntryHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.megadevs.security.ca.server.db.IDatabase;
import org.megadevs.security.ca.server.utils.CompleteCertificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Service;


@Service
@Scope(value="singleton")
public class CertificationAuthorityModel implements ICertificationAuthorityModel {

	public static String PROVIDER_ID = "BC";
	
	private static String CN = "CN=RootCA";
	private static int CERT_TIME_VALIDITY = 86400000; // one year, expressed in seconds
	private static String DIGITAL_SIGNATURE_ALGORITHM = "SHA1withRSA";
	private int RSA_ROOT_CERT_LENGTH = 4096;

	@Autowired
	private IDatabase mDatabase;
	
	private static Logger logger;
	
	public CertificationAuthorityModel() {
		Security.addProvider(new BouncyCastleProvider());
		
		logger = LoggerFactory.getLogger(CertificationAuthorityModel.class);
	}
	
	public boolean checkDB() {
		if (mDatabase.checkDB()) {
			mDatabase.load();
			return true;
		}
		else {
			mDatabase.init();
			return false;
		}
	}
	
	public boolean checkPassword(String password) {
		return mDatabase.checkPassword(password);
	}
	
	public boolean checkRootCertificateValidity() {
		X509CertificateHolder rootCertificate = mDatabase.getRootCertificate();
		if (rootCertificate != null)
			return rootCertificate.isValidOn(new Date(System.currentTimeMillis()));
		else {
			logger.error("Unable to retrieve root certificate!");
			return false;
		}
	}
	
	/**
	 * This method generates a root certificate for the CA: it is supposed not to expire for a long time for testing
	 * purposes.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws OperatorCreationException
	 */
	@Override
	public void generateRootCertificate(String password) throws NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException {
		/// creates the root certificate

		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", PROVIDER_ID);
		generator.initialize(RSA_ROOT_CERT_LENGTH, new SecureRandom());
		KeyPair mRootPair = generator.generateKeyPair();

		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(DIGITAL_SIGNATURE_ALGORITHM);
		byte[] publickeyb = mRootPair.getPublic().getEncoded();

		SubjectPublicKeyInfo subPubKeyInfo = new SubjectPublicKeyInfo(sigAlgId,publickeyb);
		
		/// publicKey.getEncoded() is an encoded KEY + THE ALGORITHM IDENTIFIER.
		
		/// no extensions are used, since this is the root cert for CA
		
		X509v1CertificateBuilder certGen = new X509v1CertificateBuilder(
				new X500Name(CN),
				BigInteger.valueOf(System.currentTimeMillis()),
				new Date(System.currentTimeMillis()),
				new Date(System.currentTimeMillis() + CERT_TIME_VALIDITY),
				new X500Name(CN),
				subPubKeyInfo);

		ContentSigner sigGen = new JcaContentSignerBuilder(DIGITAL_SIGNATURE_ALGORITHM)
				.setProvider(PROVIDER_ID)
				.build(mRootPair.getPrivate());
		
		X509CertificateHolder mCertificate = certGen.build(sigGen);
		
		mDatabase.storeRootCertificate(mCertificate);
		mDatabase.storeCAProperties(password, mRootPair);
		
	}

	@Override
	public void createCRL() {
		try {
			X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(new X500Name(CN), new Date());
			crlBuilder.setNextUpdate(new Date(System.currentTimeMillis() + 60 * 60 * 1000L));
			KeyPair rootPair = mDatabase.getKeyPair();
			ContentSigner sigGen = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(rootPair.getPrivate());
			X509CRLHolder crlHolder = crlBuilder.build(sigGen);
			
			mDatabase.storeCRL(crlHolder);
			
		} catch (OperatorCreationException e) {
			e.printStackTrace();
		}
	}
	
	@Override
	public X509CRLHolder getCRL() {
		return mDatabase.getCRL();
	}
	
	@Override
	public String getEncodedCRL() {
		try {
			return new String(Base64.encode(mDatabase.getCRL().getEncoded()));
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	@Override
	public void setCRL(ArrayList<Integer> serials) {
		try {
			X509CRLHolder holder = mDatabase.getCRL();
			
			X509v2CRLBuilder builder = new X509v2CRLBuilder(holder.getIssuer(), new Date());
			builder.addCRL(holder);
			for (Integer i : serials)
				builder.addCRLEntry(new BigInteger(i.toString()), new Date(), CRLReason.unspecified);
			
			KeyPair rootPair = mDatabase.getKeyPair();
			ContentSigner sigGen;
			sigGen = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(rootPair.getPrivate());
			holder = builder.build(sigGen);
			
			mDatabase.updateCRL(holder);
		} catch (OperatorCreationException e) {
			e.printStackTrace();
		}
	}
	
	public KeyPair getKeyPair() {
		return mDatabase.getKeyPair();
	}
	
	@Override
	public void loadDatabase() {
		mDatabase.load();
	}

	@Override
	public String checkCertificateWithOCSP(String content) {
		try {
			OCSPReq request = new OCSPReq(Base64.decode(content));
			DigestCalculatorProvider provider = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
			BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(mDatabase.getRootCertificate().getSubjectPublicKeyInfo(), provider.get(RespID.HASH_SHA1));
			
			Req[] requestList = request.getRequestList();
			for (Req req : requestList) {
				CertificateID id = req.getCertID();
				
				X509CRLHolder crl = mDatabase.getCRL();
				X509CRLEntryHolder crlEntry = crl.getRevokedCertificate(id.getSerialNumber());
				
				if (crlEntry == null)
					builder.addResponse(id, CertificateStatus.GOOD);
				else {
					RevokedStatus revokedStatus = new RevokedStatus(new Date(crlEntry.getRevocationDate().getTime()), CRLReason.unspecified);
					builder.addResponse(id, revokedStatus);
				}

				BasicOCSPResp response = builder.build(new JcaContentSignerBuilder(DIGITAL_SIGNATURE_ALGORITHM).setProvider("BC").build(mDatabase.getKeyPair().getPrivate()), null, new Date());
				OCSPRespBuilder respBuilder = new OCSPRespBuilder();
				return new String(Base64.encode(respBuilder.build(OCSPRespBuilder.SUCCESSFUL, response).getEncoded()));
			}
			
		} catch (IOException e) {
			e.printStackTrace();
		} catch (OperatorCreationException e) {
			e.printStackTrace();
		} catch (OCSPException e) {
			e.printStackTrace();
		}
		
		return null;
	}

	@Override
	public String getRootCertificate(String content) {
		try {
			X509CertificateHolder rootCertificate = mDatabase.getRootCertificate();
			return new String(Base64.encode(rootCertificate.getEncoded()));
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return "";
	}

	@Override
	public String getActiveDataEnciphermentCertificates(String content) {
		ArrayList<X509CertificateHolder> certificatesList = mDatabase.getCertificatesList();
		List<CompleteCertificate> certificatesInfoList = mDatabase.retrieveCertificateListInfo();
		ArrayList<X509CertificateHolder> activeCertificates = new ArrayList<X509CertificateHolder>();
		X509CRLHolder crl = mDatabase.getCRL();
		
		for (int i=0; i<certificatesList.size(); i++) {
			X509CertificateHolder holder = certificatesList.get(i);
			CompleteCertificate info = certificatesInfoList.get(i);
			if (holder.isValidOn(new Date()) && info.getType() == 2 && info.getRenewed() == -1 && crl.getRevokedCertificate(new BigInteger(String.valueOf(info.getSerial()))) == null)
				activeCertificates.add(holder);
		}
		
		return new String(Base64.encode(encodeCertificates(activeCertificates).getBytes()));
		
	}

	private String encodeCertificates(ArrayList<X509CertificateHolder> activeCertificates) {
		String result = "";
		try {
			for (X509CertificateHolder holder : activeCertificates) {
				String encoded = new String(Base64.encode(holder.getEncoded()));
				result = result + encoded +  ":";
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return result;
	}
	
}
