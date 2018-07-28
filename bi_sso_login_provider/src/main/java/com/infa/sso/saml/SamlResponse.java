package com.infa.sso.saml;

import java.util.List;

import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.xml.XMLObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SamlResponse {

	private static final Logger logger = LoggerFactory.getLogger(SamlResponse.class);
	private Assertion assertion;

	public SamlResponse(Assertion assertion) {
		this.assertion = assertion;
	}

	public Assertion getAssertion() {
		return assertion;
	}

	public String getAssertionId() {
		return assertion.getID();
	}

	public String getUserId() {

		for (AttributeStatement statement : assertion.getAttributeStatements()) {

			for (Attribute attribute : statement.getAttributes()) {
				if ("UID".equalsIgnoreCase(attribute.getName())) {
					List<XMLObject> attributeValues = attribute.getAttributeValues();
					if (!attributeValues.isEmpty()) {
						return attributeValues.get(0).getDOM().getTextContent();
					}
				}

			}
		}
		return null;
	}

	public String getUserFirstName() {

		for (AttributeStatement statement : assertion.getAttributeStatements()) {

			for (Attribute attribute : statement.getAttributes()) {
				if ("firstname".equalsIgnoreCase(attribute.getName())) {
					List<XMLObject> attributeValues = attribute.getAttributeValues();
					if (!attributeValues.isEmpty()) {
						return attributeValues.get(0).getDOM().getTextContent();
					}
				}

			}
		}
		return null;
	}

	public String getUserLastName() {

		for (AttributeStatement statement : assertion.getAttributeStatements()) {

			for (Attribute attribute : statement.getAttributes()) {
				if ("lastname".equalsIgnoreCase(attribute.getName())) {
					List<XMLObject> attributeValues = attribute.getAttributeValues();
					if (!attributeValues.isEmpty()) {
						return attributeValues.get(0).getDOM().getTextContent();
					}
				}

			}
		}
		return null;
	}
}
