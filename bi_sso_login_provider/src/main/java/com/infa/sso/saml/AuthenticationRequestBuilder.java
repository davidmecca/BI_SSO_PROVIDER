package com.infa.sso.saml;

import java.util.UUID;

import javax.servlet.http.HttpServletResponse;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;

import com.infa.sso.util.SamlUtility;

public class AuthenticationRequestBuilder {

	private static final String SAML2_NAME_ID_POLICY = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
	private static final String SAML2_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
	private static final String SAML2_POST_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
	private static final String SAML2_PASSWORD_PROTECTED_TRANSPORT = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
	private static final String SAML2_ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
	private static final String IDP_SSO_URL = "https://pfq1.boehringer.com/idp/SSO.saml2";
	private static final String SP_ENTITY_ID = "onecustomer.boehringer.com";

	public AuthnRequest buildAuthenticationRequest() {

		DateTime issueInstant = new DateTime();
		AuthnRequestBuilder authRequestBuilder = new AuthnRequestBuilder();
		AuthnRequest authRequest = authRequestBuilder.buildObject(SAML2_PROTOCOL, "AuthnRequest", "samlp");
		authRequest.setForceAuthn(Boolean.FALSE);
		authRequest.setIsPassive(Boolean.FALSE);
		authRequest.setIssueInstant(issueInstant);
		authRequest.setProtocolBinding(SAML2_POST_BINDING);
		authRequest.setAssertionConsumerServiceURL(IDP_SSO_URL);
		authRequest.setIssuer(buildIssuer());
		authRequest.setNameIDPolicy(buildNameIDPolicy());
		authRequest.setRequestedAuthnContext(buildRequestedAuthnContext());
		authRequest.setID(UUID.randomUUID().toString());
		authRequest.setVersion(SAMLVersion.VERSION_20);

		return authRequest;
	}

	private Issuer buildIssuer() {
		Issuer issuer = SamlUtility.buildSAMLObject(Issuer.class);
		issuer.setValue(getSPIssuerValue());

		return issuer;
	}

	private String getSPIssuerValue() {
		return SP_ENTITY_ID;
	}

	private static NameIDPolicy buildNameIDPolicy() {
		NameIDPolicy nameIDPolicy = new NameIDPolicyBuilder().buildObject();
		nameIDPolicy.setFormat(SAML2_NAME_ID_POLICY);
		nameIDPolicy.setAllowCreate(Boolean.TRUE);
		return nameIDPolicy;
	}

	private static RequestedAuthnContext buildRequestedAuthnContext() {

		// Create AuthnContextClassRef
		AuthnContextClassRefBuilder authnContextClassRefBuilder = new AuthnContextClassRefBuilder();
		AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder.buildObject(SAML2_ASSERTION,
				"AuthnContextClassRef", "saml");
		authnContextClassRef.setAuthnContextClassRef(SAML2_PASSWORD_PROTECTED_TRANSPORT);

		// Create RequestedAuthnContext
		RequestedAuthnContextBuilder requestedAuthnContextBuilder = new RequestedAuthnContextBuilder();
		RequestedAuthnContext requestedAuthnContext = requestedAuthnContextBuilder.buildObject();
		requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
		requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);

		return requestedAuthnContext;
	}

	public void redirectUserWithRequest(HttpServletResponse httpServletResponse, AuthnRequest authnRequest) {
		HttpServletResponseAdapter responseAdapter = new HttpServletResponseAdapter(httpServletResponse, true);
		BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject> context = new BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject>();
		context.setPeerEntityEndpoint(getIDPEndpoint());
		context.setOutboundSAMLMessage(authnRequest);
		context.setOutboundMessageTransport(responseAdapter);

		HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
		try {
			encoder.encode(context);
		} catch (MessageEncodingException e) {
			throw new RuntimeException(e);
		}
	}

	private Endpoint getIDPEndpoint() {
		SingleSignOnService endpoint = SamlUtility.buildSAMLObject(SingleSignOnService.class);
		endpoint.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		endpoint.setLocation(IDP_SSO_URL);

		return endpoint;
	}

}