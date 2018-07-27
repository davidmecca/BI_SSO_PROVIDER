//=====================================================================
// project:   Informatica MDM Hub
//---------------------------------------------------------------------
// copyright: Informatica (c) 2003-2017.  All rights reserved.
//=====================================================================

package com.infa.sso.server;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import org.apache.log4j.Logger;

public class SsoPayloadDecoder {
	private static final Logger logger = Logger.getLogger(SsoPayloadDecoder.class);

	private String data;

	public SsoPayloadDecoder(byte[] payload) {

	}

	public boolean isAcceptable() {
		return false;
		
	}

	public CustomBDDPayload decode() throws IOException {
		return null;

	}

	private String decryptData(byte[] bytes) throws UnsupportedEncodingException {
		return data;

	}
}
