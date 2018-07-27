//=====================================================================
// project:   Informatica MDM Hub
//---------------------------------------------------------------------
// copyright: Informatica (c) 2003-2017.  All rights reserved.
//=====================================================================

package com.infa.sso.e360;

import java.io.UnsupportedEncodingException;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.infa.sso.common.Base64Tool;
import com.infa.sso.common.SSOConstants;

/**
 * This is a class that takes User Credentials data and generates security payload byte array out of it.
 * All the logic for encryption and all other transformations can be placed here.
 *
 * Sample implementation just performs Base64 encoding of the provided data.
 *
 * Note that SSOConstants.PAYLOAD_PREFIX is used twice: once it is used for main payload and this part will be
 * encoded and/or encrypted. So that later during decoding server code could verify that decoding has been performed
 * successfully and extracted string starts with readable prefix.
 * Second occurrence of PAYLOAD_PREFIX is in outer string. This one is not encrypted, so it will be sued by server
 * code to check is payload is of proper format and code knows how to handle it.
 *
 * @author achigrin
 * @since 17/04/2017.
 */
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
        mainPayload.append(userName).append(SSOConstants.PAYLOAD_SEPARATOR)
                .append(sessionId);
        byte[] payload1 = encryptData(mainPayload.toString().getBytes(SSOConstants.PAYLOAD_CHAR_ENCODING));

        StringBuilder outer = new StringBuilder(SSOConstants.PAYLOAD_PREFIX);
        outer.append(SSOConstants.PAYLOAD_SEPARATOR);
        outer.append(Base64Tool.encode(payload1));
        return outer.toString().getBytes(SSOConstants.PAYLOAD_CHAR_ENCODING);
    }

    private byte[] encryptData(byte[] bytes) {
        // This is a placeholder.
        // Method just returns incoming array. In a real application here must be a logic that does real encryption
        // and it must return array produced by encrypting algorithm (say, RSA encryption).
        return bytes;
    }
}
