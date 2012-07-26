package org.megadevs.security.ca.server.db;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.megadevs.security.ca.server.utils.CompleteCertificate;
import org.megadevs.security.ca.server.utils.CompleteRequest;

public interface IDatabase {

	public abstract void storeCAProperties(String password, KeyPair key);

	public abstract void storeRootCertificate(X509CertificateHolder cert);

	public abstract X509CertificateHolder getRootCertificate();

	public abstract int storeCertificateRequest(PKCS10CertificationRequest request);

	public abstract void storeCertificate(Integer serial, X509CertificateHolder cert);

	public abstract boolean checkPassword(String password);

	public abstract KeyPair getKeyPair();

	public abstract X509CertificateHolder getCertificate(Integer serial);

	public abstract ArrayList<X509CertificateHolder> getCertificatesList();

	public abstract PKCS10CertificationRequest getCertificateRequest(Integer serial);

	public abstract ArrayList<PKCS10CertificationRequest> getCertificateRequestsList();

	public abstract boolean checkDB();

	public abstract void load();

	public abstract void init();

	public abstract List<CompleteRequest> retrieveCertificateRequestListInfo();

	public abstract List<CompleteCertificate> retrieveCertificateListInfo();

	public abstract void storeCRL(X509CRLHolder crl);

	public abstract void updateCRL(X509CRLHolder crl);

	public abstract X509CRLHolder getCRL();

	public abstract void updateCertificateUponRenewal(Integer serial, Integer renewedSerial);

}