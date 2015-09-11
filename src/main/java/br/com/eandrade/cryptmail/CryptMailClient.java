package br.com.eandrade.cryptmail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Properties;

import javax.mail.Header;
import javax.mail.Multipart;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import net.suberic.crypto.EncryptionKeyManager;
import net.suberic.crypto.EncryptionManager;
import net.suberic.crypto.EncryptionUtils;
import net.suberic.crypto.bouncycastle.BouncySMIMEEncryptionKey;

public class CryptMailClient {
    
    private String p12KeyStore;
    private String priKeyName;
    private String priKeyPass;
    
	public CryptMailClient(String p12KeyStore, String priKeyName, String priKeyPass) {
		this.p12KeyStore = p12KeyStore;
		this.priKeyName = priKeyName;
		this.priKeyPass = priKeyPass;
	}
    
    public void sendMessage(String from, String to, String subject, String body) throws Exception {
        byte[] pubKeyCer = lookupCertificate();
        if (pubKeyCer == null || pubKeyCer.length == 0) {
            throw new Exception ("Cannot find public key certificate for " + to);
        }
        
        Session session = createSession();
        
        MimeMessage msg = new MimeMessage(session);
        msg.setFrom(new InternetAddress(from));
        msg.setSender(new InternetAddress(from));
        msg.addRecipient(javax.mail.Message.RecipientType.TO, new InternetAddress(to));
        msg.setSubject(subject);
        msg.setText(body);
        
        msg = signMsg(session, msg);
        msg = encryptMsg(session, msg, pubKeyCer);
        msg.saveChanges();
        
        transport(session, msg);
    }
    
    public void sendMessage(String from, String to, String subject, Multipart multipart) throws Exception {
        byte [] pubKeyCer = lookupCertificate();
        if (pubKeyCer == null || pubKeyCer.length == 0) {
            throw new Exception ("Cannot find public key certificate for " + to);
        }
        
        Session session = createSession();
        
        MimeMessage msg = new MimeMessage(session);
        msg.setFrom(new InternetAddress(from));
        msg.setSender(new InternetAddress(from));
        msg.addRecipient(javax.mail.Message.RecipientType.TO, new InternetAddress(to));
        msg.setSubject(subject);
        msg.setContent(multipart);
        
        msg = signMsg(session, msg);
        msg = encryptMsg(session, msg, pubKeyCer);
        msg.saveChanges();
        
        transport(session, msg);
    }
    
	protected byte[] lookupCertificate() {
		InputStream is = null;
		try {
			String pem = System.getProperty("PEM");
			is = new ByteArrayInputStream(pem.getBytes());
			
			CertificateFactory factory = CertificateFactory.getInstance("X.509");
			X509Certificate certificate = (X509Certificate)factory.generateCertificate(is);
			return certificate.getEncoded();
		} catch (CertificateException e) {
			e.printStackTrace();
		} finally {
			if (is != null) {
				try {
					is.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		return null;
	}
    
    protected MimeMessage encryptMsg(Session session, MimeMessage msg, byte [] pubKeyCer) throws Exception {
        EncryptionUtils encUtils = EncryptionManager.getEncryptionUtils(EncryptionManager.SMIME);
        
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(pubKeyCer));
       
        // wrap certificate in BouncySMIMEEncryptionKey 
        BouncySMIMEEncryptionKey smimekey = new BouncySMIMEEncryptionKey();
        smimekey.setCertificate(cert);

        return encUtils.encryptMessage(session, msg, smimekey);
    }
    
    protected MimeMessage signMsg(Session session, MimeMessage mimeMessage) throws Exception {
    	if (this.p12KeyStore == null || this.priKeyName == null || this.priKeyPass == null) {
    		System.out.println("WARN : Missing parameters, message will not be signed!");
    		return mimeMessage;
    	}
    	
        // Getting of the S/MIME EncryptionUtilities.
        EncryptionUtils encUtils = EncryptionManager.getEncryptionUtils(EncryptionManager.SMIME);

        // Loading of the S/MIME keystore from the file (stored as resource).
        char[] keystorePass = priKeyPass.toCharArray();
        EncryptionKeyManager encKeyManager = encUtils.createKeyManager();
        encKeyManager.loadPrivateKeystore(CryptMailClient.class.getResourceAsStream(p12KeyStore), keystorePass);

        // Getting of the S/MIME private key for signing.
        Key privateKey = encKeyManager.getPrivateKey(priKeyName, keystorePass);

        // Signing the message.
        return encUtils.signMessage(session, mimeMessage, privateKey);
    }
    
	protected Session createSession() {
		Properties props = new Properties();
		props.put("mail.transport.protocol", "smtp");
		props.put("mail.smtp.host", "smtp.host.com");
		props.put("mail.from", "crypt-mail@mail.com");
		props.put("mail.debug", "true");
		
		return Session.getInstance(props, null);
	}

	@SuppressWarnings("rawtypes")
	protected void transport(Session session, MimeMessage msg) throws Exception {
        Enumeration headers = msg.getAllHeaders();
        while (headers.hasMoreElements()) {
            Header h = (Header) headers.nextElement();
            System.out.println("(HEADER) --> " + h.getName() + ": " + h.getValue());
        }
		
		Transport transport = session.getTransport("smtp");
		transport.connect();
		Transport.send(msg);
		transport.close();
	}
    
}