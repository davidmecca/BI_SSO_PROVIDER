package com.infa.sso.server;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import org.apache.log4j.Logger;

import com.infa.sso.common.Base64Tool;
import com.infa.sso.common.SSOConstants;

public class SsoPayloadDecoder {
	private static final Logger logger = Logger.getLogger(SsoPayloadDecoder.class);
	private static final String PREFIX = SSOConstants.PAYLOAD_PREFIX + SSOConstants.PAYLOAD_SEPARATOR;

	private String data;

	public SsoPayloadDecoder(byte[] payload) {
		try {
			data = new String(payload, SSOConstants.PAYLOAD_CHAR_ENCODING);
		} catch (UnsupportedEncodingException e) {
			logger.error("Failed to create string representation of Security payload.", e);
		}
	}

	public boolean isAcceptable() {
		logger.debug("Encoded payload data -> " + data);
		return (data != null) && data.startsWith(PREFIX);
	}

	public CustomBDDPayload decode() throws IOException {
		String rawData = data.substring(PREFIX.length());
		String decodedData = decryptData(Base64Tool.decodeBytes(rawData));
		if (decodedData.startsWith(PREFIX)) {
			String[] parts = decodedData.split(SSOConstants.PAYLOAD_SEPARATOR);
			CustomBDDPayload bddPayload = new CustomBDDPayload();
			bddPayload.setUsername(parts[1]);
			logger.debug("Decoded UserId -> " + parts[1]);
			bddPayload.setSessionId(parts[2]);
			logger.debug("Decoded SessionId -> " + parts[2]);
			return bddPayload;
		} else {
			throw new IOException("Decoded payload doesn't start with expected prefix");
		}
	}

	private String decryptData(byte[] bytes) throws UnsupportedEncodingException {
		return new String(bytes, SSOConstants.PAYLOAD_CHAR_ENCODING);
	}
}
