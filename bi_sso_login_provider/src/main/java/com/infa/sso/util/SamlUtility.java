package com.infa.sso.util;

import java.io.StringWriter;
import java.security.NoSuchAlgorithmException;

import javax.xml.namespace.QName;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

public class SamlUtility {
	private static Logger logger = LoggerFactory.getLogger(SamlUtility.class);
	private static SecureRandomIdentifierGenerator secureRandomIdGenerator;

	static {
		try {
			secureRandomIdGenerator = new SecureRandomIdentifierGenerator();
		} catch (NoSuchAlgorithmException e) {
			logger.error(e.getMessage(), e);
		}
	}

	public static <T> T buildSAMLObject(final Class<T> clazz) {
		try {
			XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
			QName defaultElementName = (QName) clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
			return (T) builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);
		} catch (IllegalAccessException e) {
			throw new IllegalArgumentException("Could not create SAML object");
		} catch (NoSuchFieldException e) {
			throw new IllegalArgumentException("Could not create SAML object");
		}

	}

	public static String getSecureRandomId() {
		return secureRandomIdGenerator.generateIdentifier();
	}

	public static void logSAMLObject(final XMLObject object) throws MarshallingException {
		Element element = null;

		if (object instanceof SignableSAMLObject && ((SignableSAMLObject) object).isSigned()
				&& object.getDOM() != null) {
			element = object.getDOM();
		} else {
			Marshaller out = Configuration.getMarshallerFactory().getMarshaller(object);
			out.marshall(object);
			element = object.getDOM();
		}

		try {
			Transformer transformer = TransformerFactory.newInstance().newTransformer();
			transformer.setOutputProperty(OutputKeys.INDENT, "yes");
			StreamResult result = new StreamResult(new StringWriter());
			DOMSource source = new DOMSource(element);

			transformer.transform(source, result);
			String xmlString = result.getWriter().toString();
			logger.info(xmlString);
		} catch (TransformerException e) {
			e.printStackTrace();
		}
	}

	public static Envelope wrapInSOAPEnvelope(final XMLObject xmlObject) throws IllegalAccessException {
		Envelope envelope = SamlUtility.buildSAMLObject(Envelope.class);
		Body body = SamlUtility.buildSAMLObject(Body.class);

		body.getUnknownXMLObjects().add(xmlObject);

		envelope.setBody(body);

		return envelope;
	}
}
