package org.megadevs.security.ca.server.utils;


public class CompleteRequest {

	public static final int DIGITAL_SIGNATURE = 128;
	public static final int DATA_ENCIPHERMENT = 16;
	

	private int mSerial;

	private int mType;

	private String mSubject;
	
	private String mPublicKey;
	
	
	public CompleteRequest() {}
	
	public CompleteRequest(int mSerial, int mType, String mSubject, String mPublicKey) {
		this.mSerial = mSerial;
		this.mType = mType;
		this.mSubject = mSubject;
		this.mPublicKey = mPublicKey;
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
	
}
