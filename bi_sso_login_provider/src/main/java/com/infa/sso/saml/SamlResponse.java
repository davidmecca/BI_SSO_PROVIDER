package com.infa.sso.saml;

import java.util.List;

import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.xml.XMLObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.infa.sso.e360.CustomLoginProvider;

public class SamlResponse {

	private static final Logger logger = LoggerFactory.getLogger(SamlResponse.class);
	private Assertion assertion;

	public SamlResponse(Assertion assertion) {
		this.assertion = assertion;
	}

	/**
	 * Retrieves the {@link Assertion} for the SAML response.
	 *
	 * @return The assertion for the SAML response.
	 */
	public Assertion getAssertion() {
		return assertion;
	}

	/**
	 * Retrieves the Name ID from the SAML response. This is normally the name of
	 * the authenticated user.
	 *
	 * @return The Name ID from the SAML response.
	 */
	public String getNameID() {
		return assertion.getSubject().getNameID().getValue();
	}

	public String getUid() {

		String uid = null;
		List<AttributeStatement> attrList = assertion.getAttributeStatements();
		for (AttributeStatement statement : assertion.getAttributeStatements()) {

			for (Attribute attribute : statement.getAttributes()) {

				if ("UID".equalsIgnoreCase(attribute.getName())) {
					List<XMLObject> attributeValues = attribute.getAttributeValues();
					if (!attributeValues.isEmpty()) {
						uid = attributeValues.get(0).getDOM().getTextContent();
						if (logger.isDebugEnabled())
							logger.debug("SAML UID::" + uid);
						return uid;
					}
				}
			}

		}

		if (uid == null) {
			logger.error("UID element not found in SAML response.");
		}
		
		return uid;
	}
}
