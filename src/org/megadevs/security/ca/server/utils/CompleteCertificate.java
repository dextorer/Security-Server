package org.megadevs.security.ca.server.utils;

import java.util.Date;

public class CompleteCertificate {

	public static final int DIGITAL_SIGNATURE = 128;
	public static final int DATA_ENCIPHERMENT = 16;
	

	private int mSerial;

	private int mType;

	private Date notBefore;
	
	private Date notAfter;

	private String mSubject;
	
	private String mPublicKey;
	
	private boolean isRevoked;
	
	private int renewed;
	
	public CompleteCertificate() {}
	
	public CompleteCertificate(int mSerial, Date notBefore, Date notAfter, int mType, String mSubject, String mPublicKey, int renewed) {
		this.mSerial = mSerial;
		this.notBefore = notBefore;
		this.notAfter = notAfter;
		this.mType = mType;
		this.mSubject = mSubject;
		this.mPublicKey = mPublicKey;
		this.renewed = renewed;
		this.isRevoked = false;
	}
	
	
	public int getSerial() {
		return mSerial;
	}

	public void setSerial(int mSerial) {
		this.mSerial = mSerial;
	}

	public int getType() {
		return mType;
	}

	public void setType(int mType) {
		this.mType = mType;
	}

	public Date getNotBefore() {
		return notBefore;
	}

	public void setNotBefore(Date notBefore) {
		this.notBefore = notBefore;
	}

	public Date getNotAfter() {
		return notAfter;
	}

	public void setNotAfter(Date notAfter) {
		this.notAfter = notAfter;
	}

	public String getSubject() {
		return mSubject;
	}

	public void setSubject(String mSubject) {
		this.mSubject = mSubject;
	}

	public String getPublicKey() {
		return mPublicKey;
	}

	public void setPublicKey(String mPublicKey) {
		this.mPublicKey = mPublicKey;
	}

	public boolean isRevoked() {
		return this.isRevoked;
	}

	public void setRevoked(boolean isRevoked) {
		this.isRevoked = isRevoked;
	}

	public int getRenewed() {
		return renewed;
	}
}
