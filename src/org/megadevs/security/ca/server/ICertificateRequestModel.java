package org.megadevs.security.ca.server;

import java.util.List;

import org.megadevs.security.ca.server.utils.CompleteRequest;

public interface ICertificateRequestModel {

	public abstract String newCertificateRequest(String message);

	public abstract List<CompleteRequest> retrieveCertificateRequestListInfo();

	public abstract String newCertificateRenewRequest(String message);

}