package com.infa.sso.saml;

public class SamlException extends Exception {

	private static final long serialVersionUID = 7213080947790399084L;

	public SamlException(String message) {
		super(message);
	}

	public SamlException(String message, Throwable cause) {
		super(message, cause);
	}
}
