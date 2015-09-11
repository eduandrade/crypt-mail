package br.com.eandrade.cryptmail;

import org.junit.Test;

import br.com.eandrade.cryptmail.CryptMailClient;

public class TestCryptMailClient {

	@Test
	public void testSend() throws Exception {
		String from = System.getProperty("FROM");
		String to = System.getProperty("TO");
		String subject = System.getProperty("SUBJECT");
		String body = System.getProperty("BODY");

		CryptMailClient client = new CryptMailClient(null, null, null);
		client.sendMessage(from, to, subject, body);
	}

}
