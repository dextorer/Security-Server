package org.megadevs.security.ca.server.db;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Connection;
import java.sql.Date;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.megadevs.security.ca.server.utils.CertificationUtils;
import org.megadevs.security.ca.server.utils.CompleteCertificate;
import org.megadevs.security.ca.server.utils.CompleteRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Service;

@Service
@Scope(value="singleton")
public class Database implements IDatabase {

	private static final String DB_NAME = "CertificationAuthorityDB";
	
	private static Logger logger;
	
	private static final String KEYWORD = "ODY5MDE2MDI3DQo=";
	
	private Connection mConnection;
	
	public Database() {
		Security.addProvider(new BouncyCastleProvider());
		logger = LoggerFactory.getLogger(Database.class);
	}

	/**
	 * Checks if there is any datafile in the current directory (a datafile ends
	 * with the .db extension). If any, it returns true; otherwise, returns false.
	 * 
	 * @return boolean representing the existance of the database
	 */
	@Override
	public boolean checkDB() {
		File f = new File(DB_NAME + ".db");
		
		if (f.exists())
			return true;
		else
			return false;
	}
	
	@Override
	public void load() {
		try {
			Class.forName("org.sqlite.JDBC");
			mConnection = DriverManager.getConnection("jdbc:sqlite:" + DB_NAME + ".db");
			Security.addProvider(new BouncyCastleProvider());
			
		} catch (ClassNotFoundException e) {
			logger.error("ClassNotFound when initializing DB", e);
		} catch (SQLException e) {
			logger.error("SQLException when initializing DB", e);
		}
	}
	
	@Override
	public void init() {
		try {
			load();
			
			Statement stat = mConnection.createStatement();

			String certificates = "create table CERTIFICATES (" +
					"serial integer PRIMARY KEY, " +
					"not_before datetime, " +
					"not_after datetime, " +
					"subject varchar(256), " +
					"type integer," +
					"renewed integer, " +
					"certificate blob" +
					");";

			String rootCertificate = "create table ROOT_CERTIFICATE (" +
					"cn varchar(256), " +
					"not_before datetime, " +
					"not_after datetime, " +
					"certificate blob" +
					");";
			
			String caProperties = "create table CA_PROPERTIES (" +
					"hash varchar(32), " +
					"privatekey blob, " +
					"publickey blob" +
					");";
			
			String requests = "create table REQUESTS (" +
					"serial integer PRIMARY KEY, " +
					"subject varchar(256), " +
					"type integer," +
					"request blob" +
					");";
			
			String crl = "create table CRL (" +
					"crl blob" +
					");"; 
			
			stat.addBatch(certificates);
			stat.addBatch(requests);
			stat.addBatch(caProperties);
			stat.addBatch(rootCertificate);
			stat.addBatch(crl);
			
			int[] result = stat.executeBatch();
			
			for (int i=0; i<result.length; i++) {
				if (result[i] == Statement.EXECUTE_FAILED) {
					logger.error("Issue in initializing DB (statement #" + i + ")");
					System.exit(-1);
				}
			}
			
			stat.close();
			
		} catch (SQLException e) {
			logger.error("SQLException when initializing DB", e);
		}
	}
	
	@Override
	public void storeCAProperties(String password, KeyPair key) {
		
		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("insert into CA_PROPERTIES values (?, ?, ?);");

			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] thedigest = md.digest(password.getBytes());
			String hash = new String(thedigest);
			stat.setString(1, hash);
			
			Charset charSet = Charset.forName("UTF-8");
			byte[] keyBytes = key.getPrivate().getEncoded();
			byte[] keywordBytes = KEYWORD.getBytes(charSet);
			
			byte[] cipherBytes = new byte[keyBytes.length];
			for (int i = 0; i < keyBytes.length; i++) 
			    cipherBytes[i] = (byte) (keyBytes[i] ^ keywordBytes[i % keywordBytes.length]);
			
			stat.setBytes(2, cipherBytes);
			stat.setBytes(3, key.getPublic().getEncoded());
			
			stat.execute();
			
		} catch (SQLException e) {
			logger.error("SQLException when storing CA properties", e);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		finally {
			try {
				stat.close();
			} catch (SQLException e) {
				logger.error("SQLException when closing statement (CA properties)", e);
			}
		}
	}
	
	@Override
	public void storeRootCertificate(X509CertificateHolder cert) {

		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("insert into ROOT_CERTIFICATE " +
					"values (?, ?, ?, ?);");
			
			stat.setString(1, cert.getSubject().toString());
			stat.setDate(2,	new Date(cert.getNotBefore().getTime()));
			stat.setDate(3,	new Date(cert.getNotAfter().getTime()));
			
			stat.setBytes(4, cert.getEncoded());
			
			stat.execute();
			
		} catch (SQLException e) {
			logger.error("SQLException when inserting root certificate", e);
		} catch (IOException e) {
			logger.error("IOException when inserting root certificate", e);
		}

		finally {
			try {
				stat.close();
			} catch (SQLException e) {
				e.printStackTrace();
			}
		}
	}
	
	@Override
	public int storeCertificateRequest(PKCS10CertificationRequest request) {
		
		PreparedStatement stat = null;
		int resultID = -2;
		
		try {
			stat = mConnection.prepareStatement("insert into REQUESTS values (?, ?, ?, ?);");

			stat.setString(2, request.getSubject().toString());
            stat.setInt(3, CertificationUtils.getKeyUsageFromRequest(request).intValue());
            stat.setBytes(4, request.getEncoded());

			stat.execute();
			
			stat = mConnection.prepareStatement("select last_insert_rowid() as ID;");
			ResultSet result = stat.executeQuery();
			if (result.next()) {
				resultID = result.getInt(1);
			}
			
		} catch (SQLException e) {
			logger.error("SQLException when storing certificate request", e);
		} catch (IOException e) {
			logger.error("IOException when storing certificate request", e);
		}
		
		finally {
			try {
				stat.close();
			} catch (SQLException e) {
				logger.error("SQLException when closing statement (certificate request)", e);
			}
		}
		
		return resultID;
		
	}
	
	@Override
	public void storeCertificate(Integer serial, X509CertificateHolder cert) {
		
		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("insert into CERTIFICATES values (?, ?, ?, ?, ?, ?, ?);");
			
			stat.setInt(1, serial);
			stat.setDate(2,	new Date(cert.getNotBefore().getTime()));
			stat.setDate(3,	new Date(cert.getNotAfter().getTime()));
			stat.setString(4, cert.getSubject().toString());

			ByteArrayInputStream in = new ByteArrayInputStream(cert.getEncoded());
			X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(in);

			stat.setInt(5, certificate.getKeyUsage()[0] ? 0 : 2);//TODO check
			stat.setInt(6, -1);
			stat.setBytes(7, cert.getEncoded());
			
			stat.execute();
			stat.close();
			
		} catch (SQLException e) {
			logger.error("SQLException when storing certificate request", e);
		} catch (IOException e) {
			logger.error("IOException when storing certificate request", e);
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
		
		finally {
			try {
				stat.close();
			} catch (SQLException e) {
				logger.error("SQLException when closing statement (certificate request)", e);
			}
		}
	}
	
	@Override
	public void storeCRL(X509CRLHolder crl) {
		PreparedStatement stat = null;
			try {
				stat = mConnection.prepareStatement("insert into CRL values (?);");
				stat.setBytes(1, crl.getEncoded());
				stat.execute();
				
			} catch (SQLException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
			finally {
				try {
					stat.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}

	}
	
	@Override
	public boolean checkPassword(String password) {
		
		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("select * from CA_PROPERTIES;");
			
			ResultSet result = stat.executeQuery();
			
			if (result.next()) {
				String hash = result.getString(1);
				
				MessageDigest md = MessageDigest.getInstance("MD5");
				byte[] thedigest = md.digest(password.getBytes());
				String passHash = new String(thedigest);

				return hash.equals(passHash);
			}
			
		} catch (SQLException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		finally {
			try {
				stat.close();
			} catch (SQLException e) {
				e.printStackTrace();
			}
		}
		
		return false;
	}
	
	@Override
	public X509CertificateHolder getRootCertificate() {
		PreparedStatement stat = null;
		
		try {
			stat = mConnection.prepareStatement("select * from ROOT_CERTIFICATE;");
			
			ResultSet result = stat.executeQuery();
			
			if (result.next()) {
				byte[] b = result.getBytes(4);
				return new X509CertificateHolder(b);
			}
			else
				throw new SQLException("Null query result");
			
		} catch (SQLException e) {
			logger.error("SQLException when retrieving root certificate", e);
		} catch (IOException e) {
			e.printStackTrace();
		}
		finally {
			try {
				stat.close();
			} catch (SQLException e) {
				logger.error("SQLException when closing statement (root certificate)", e);
			}
		}
		return null;
	}
	
	@Override
	public KeyPair getKeyPair() {
		
		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("select * from CA_PROPERTIES;");
			
			ResultSet result = stat.executeQuery();
			
			if (result.next()) {
				byte[] cipherBytes = result.getBytes(2);
				Charset charSet = Charset.forName("UTF-8");
				byte[] keywordBytes = KEYWORD.getBytes(charSet);
				byte[] plainBytes = new byte[cipherBytes.length];
				
				for (int i = 0; i < cipherBytes.length; i++)
				    plainBytes[i] = (byte) (cipherBytes[i] ^ keywordBytes[i % keywordBytes.length]);

				KeySpec privateKeySpecs = new PKCS8EncodedKeySpec(plainBytes);
		        PrivateKey privateKey = KeyFactory.getInstance("RSA", "BC").generatePrivate(privateKeySpecs);
		        X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(result.getBytes(3));
		        PublicKey publicKey = KeyFactory.getInstance("RSA", "BC").generatePublic(x509Spec);
		        return new KeyPair(publicKey, privateKey);
			}

		} catch (SQLException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		
		finally {
			try {
				stat.close();
			} catch (SQLException e) {
				e.printStackTrace();
			}
		}
		
		return null;
	}
	
	@Override
	public X509CertificateHolder getCertificate(Integer serial) {

		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("select * from CERTIFICATES where serial=" + String.valueOf(serial.intValue()) + ";");

			ResultSet result = stat.executeQuery();

			if (result.next()) {
				byte[] b = result.getBytes(7);
				return new X509CertificateHolder(b);
			}

		} catch (SQLException e) {
			logger.error("SQLException when retrieving certificate", e);
		} catch (IOException e) {
			logger.error("IOException when retrieving certificate ", e);
		}
		finally {
			try {
				stat.close();
			} catch (SQLException e) {
				logger.error("SQLException when closing statement (certificate)", e);
			}
		}

		return null;
	}

	@Override
	public ArrayList<X509CertificateHolder> getCertificatesList() {
		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("select * from CERTIFICATES;");

			ResultSet result = stat.executeQuery();

			ArrayList<X509CertificateHolder> list = new ArrayList<X509CertificateHolder>();

			while (result.next()) {
				byte[] b = result.getBytes(7);
				list.add(new X509CertificateHolder(b));
			}

			return list;

		} catch (SQLException e) {
			logger.error("SQLException when retrieving certificates list", e);
		} catch (IOException e) {
			logger.error("IOException when retrieving certificates list", e);
		}
		finally {
			try {
				stat.close();
			} catch (SQLException e) {
				logger.error("SQLException when closing statement (certificates list)", e);
			}
		}

		return null;

	}

	
	@Override
	public PKCS10CertificationRequest getCertificateRequest(Integer serial) {
		
		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("select * from REQUESTS where serial=" + String.valueOf(serial.intValue()) + ";");
			
			ResultSet result = stat.executeQuery();

			if (result.next()) {
				byte[] b = result.getBytes(4);
				return new PKCS10CertificationRequest(b);
			}
			
		} catch (SQLException e) {
			logger.error("SQLException when retrieving certificate request", e);
		} catch (IOException e) {
			logger.error("IOException when retrieving certificate request", e);
		}
		finally {
			try {
				stat.close();
			} catch (SQLException e) {
				logger.error("SQLException when closing statement (certification request)", e);
			}
		}
		
		return null;
	}
	
	@Override
	public ArrayList<PKCS10CertificationRequest> getCertificateRequestsList() {
		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("select * from REQUESTS;");
			
			ResultSet result = stat.executeQuery();

			ArrayList<PKCS10CertificationRequest> list = new ArrayList<PKCS10CertificationRequest>();
			
			while (result.next()) {
				byte[] b = result.getBytes(4);
				list.add(new PKCS10CertificationRequest(b));
			}
			
			return list;
			
		} catch (SQLException e) {
			logger.error("SQLException when retrieving certificate requests list", e);
		} catch (IOException e) {
			logger.error("IOException when retrieving certificate requests list", e);
		}
		finally {
			try {
				stat.close();
			} catch (SQLException e) {
				logger.error("SQLException when closing statement (certification requests list)", e);
			}
		}
		
		return null;

	}

	@Override
	public List<CompleteRequest> retrieveCertificateRequestListInfo() {
		PreparedStatement stat = null;
		List<CompleteRequest> list = new ArrayList<CompleteRequest>();
		try {
			stat = mConnection.prepareStatement("select * from REQUESTS where serial not in (select serial from CERTIFICATES);");
			ResultSet res = stat.executeQuery();

			while (res.next()) {
				PKCS10CertificationRequest request = new PKCS10CertificationRequest(res.getBytes(4));
				String publicKey = request.getSubjectPublicKeyInfo().getPublicKeyData().toString();
				list.add(new CompleteRequest(res.getInt(1), res.getInt(3), res.getString(2), publicKey));
			}

		} catch (SQLException e) {
			logger.error("Error retriving certificate request list", e);
		} catch (IOException e) {
			logger.error("Error retriving certificate request list", e);
		} finally {
			try {
				stat.close();
			} catch (SQLException e) {
				logger.error("Error retriving certificate request list",e);
			}
		}
		
		return list;
	}

	
	@Override
	public List<CompleteCertificate> retrieveCertificateListInfo() {
		PreparedStatement stat = null;
		List<CompleteCertificate> list = new ArrayList<CompleteCertificate>();
		try {
			stat = mConnection.prepareStatement("SELECT * FROM Certificates;");
			ResultSet res = stat.executeQuery();
			
			while (res.next()) {
				ByteArrayInputStream in = new ByteArrayInputStream(res.getBytes(7));
				X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(in);

				X509CertificateHolder holder = new X509CertificateHolder(certificate.getEncoded());
				
				CompleteCertificate cCert = new CompleteCertificate(
						res.getInt(1),
						res.getDate(2),
						res.getDate(3),
						res.getInt(5),
						res.getString(4),
						new String(holder.getSubjectPublicKeyInfo().getPublicKeyData().getString()),
						res.getInt(6));
				
				list.add(cCert);
			}
			return list;

		} catch (SQLException e) {
			logger.error("Error retriving certificate list",e);
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				stat.close();
			} catch (SQLException e) {
				logger.error("Error retriving certificate list",e);
			}
		}
		return list;
	}
	
	@Override
	public void updateCertificateUponRenewal(Integer serial, Integer renewedSerial) {
		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("update CERTIFICATES set renewed = " + renewedSerial.toString() + " where serial = " + serial.toString() + ";");
			stat.execute();
		} catch (SQLException e) {
			e.printStackTrace();
		}
		finally {
			try {
				stat.close();
			} catch (SQLException e) {
				e.printStackTrace();
			}
		}
	}
	
	@Override
	public X509CRLHolder getCRL() {
		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("select * from CRL;");

			ResultSet result = stat.executeQuery();
			if (result.next())
				return new X509CRLHolder(result.getBytes(1));
		} catch (SQLException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		finally {
			try {
				stat.close();
			} catch (SQLException e) {
				e.printStackTrace();
			}
		}

		return null;
	}
	
	@Override
	public void updateCRL(X509CRLHolder crl) {
		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("update CRL set crl=?");
			stat.setBytes(1, crl.getEncoded());
			stat.execute();
			
		} catch (SQLException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		finally {
			try {
				stat.close();
			} catch (SQLException e) {
				e.printStackTrace();
			}
		}
	}

}
