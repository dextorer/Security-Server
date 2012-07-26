package org.megadevs.security.ca.server;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;

import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.operator.OperatorCreationException;

public interface ICertificationAuthorityModel {

	/**
	 * This method generates a root certificate for the CA: it is supposed not to expire for a long time for testing
	 * purposes.
	 * @param password 
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws OperatorCreationException
	 */
	public abstract void generateRootCertificate(String password) throws NoSuchAlgorithmException,
			NoSuchProviderException, OperatorCreationException;
	
	public abstract boolean checkDB();
	
	public abstract boolean checkPassword(String password);
	
	public abstract boolean checkRootCertificateValidity();

	public abstract KeyPair getKeyPair();

	public abstract void loadDatabase();

	public abstract X509CRLHolder getCRL();

	public abstract void createCRL();

	public abstract String getEncodedCRL();

	public abstract void setCRL(ArrayList<Integer> serials);

	public abstract String checkCertificateWithOCSP(String content);

	public abstract String getRootCertificate(String content);

	public abstract String getActiveDataEnciphermentCertificates(String content);
}