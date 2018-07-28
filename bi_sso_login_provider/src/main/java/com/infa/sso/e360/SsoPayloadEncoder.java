package com.infa.sso.e360;

import java.io.UnsupportedEncodingException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.infa.sso.common.Base64Tool;
import com.infa.sso.common.SSOConstants;

public class SsoPayloadEncoder {
	private static final Logger LOG = LoggerFactory.getLogger(SsoPayloadEncoder.class);
	private String userName;
	private String sessionId;

	public SsoPayloadEncoder(String userName, String sessionId) {
		this.userName = userName;
		this.sessionId = sessionId;

		if (LOG.isDebugEnabled()) {
			LOG.debug(String.format("Payload for user: %s and sessionId: %s", userName, sessionId));
		}
	}

	public byte[] encode() throws UnsupportedEncodingException {
		StringBuilder mainPayload = new StringBuilder(SSOConstants.PAYLOAD_PREFIX);
		mainPayload.append(SSOConstants.PAYLOAD_SEPARATOR);
		mainPayload.append(userName).append(SSOConstants.PAYLOAD_SEPARATOR).append(sessionId);
		byte[] payload1 = encryptData(mainPayload.toString().getBytes(SSOConstants.PAYLOAD_CHAR_ENCODING));

		StringBuilder outer = new StringBuilder(SSOConstants.PAYLOAD_PREFIX);
		outer.append(SSOConstants.PAYLOAD_SEPARATOR);
		outer.append(Base64Tool.encode(payload1));
		return outer.toString().getBytes(SSOConstants.PAYLOAD_CHAR_ENCODING);
	}

	private byte[] encryptData(byte[] bytes) {
		return bytes;
	}
}
