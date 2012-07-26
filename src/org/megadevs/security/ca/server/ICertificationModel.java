package org.megadevs.security.ca.server;

import java.util.List;

import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;
import org.megadevs.security.ca.server.utils.CompleteCertificate;

public interface ICertificationModel {

	public abstract void generateCertificate(Integer serial) throws OperatorCreationException, CertIOException;

	public abstract List<CompleteCertificate> retrieveCertificateListInfo();

	public abstract String checkCertificate(String serial);

	public abstract void loadDB();

	public abstract String revokeCertificate(String serial);

}