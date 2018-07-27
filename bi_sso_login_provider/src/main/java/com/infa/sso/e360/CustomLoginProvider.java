package com.infa.sso.e360;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.Enumeration;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.validator.ResponseSchemaValidator;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import com.infa.sso.common.StringUtilities;
import com.infa.sso.saml.SamlResponse;
import com.siperian.bdd.security.LoginCredentials;
import com.siperian.bdd.security.LoginProvider;
import com.siperian.bdd.security.LoginProviderException;

public class CustomLoginProvider implements LoginProvider {

	private static final Logger logger = LoggerFactory.getLogger(CustomLoginProvider.class);
	private static final String ASSERTION_ISSUER = "onecustomer.boehringer.com";
	private static final String LOGOUT_TARGET = "/mdm/entity360view/?logoutParam=gotoLogoutPage";
	private static final String SAML_RESPONSE_PARAM = "SAMLResponse";

	public CustomLoginProvider() {
		super();
	}

	public LoginCredentials extractLoginCredentials(HttpServletRequest httpServletRequest)
			throws LoginProviderException {

		if (logger.isDebugEnabled()) {
			logger.debug("Entering method CustomLoginProvider.extractLoginCredentials");

			Enumeration headerNames = httpServletRequest.getHeaderNames();
			if (!headerNames.hasMoreElements()) {
				logger.debug("Header is empty");
			}
			while (headerNames.hasMoreElements()) {
				String key = (String) headerNames.nextElement();
				String value = httpServletRequest.getHeader(key);
				logger.debug("Header key:" + key + " -- Value:" + value);
			}

			logger.debug("Servlet Request URI :: " + httpServletRequest.getRequestURI());
			logger.debug("SAML_RESPONSE_PARAM :: " + httpServletRequest.getParameter(SAML_RESPONSE_PARAM));

		}
		try {
			decodeAndValidateSamlResponse(httpServletRequest.getParameter(SAML_RESPONSE_PARAM));
		} catch (Exception e) {
			logger.error(e.getMessage());
		}

		String payload = "sso;samluser;12345";
		LoginCredentials lc = null;
		try {
			lc = new LoginCredentials(payload.getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			logger.error("Wrong encoding: UTF-8", e);
			throw new LoginProviderException("Wrong encoding: UTF-8", e);
		}
		// in case if you get the correct firstname and last name from sso
		// provider, set it here
		lc.setFirstName("ssotest");

		return lc;
	}

	public InputStream getLogoImageBody() {
		return null;
	}

	public void initialize(Properties properties) {

		logger.debug("In initialize");
		if (logger.isDebugEnabled()) {
			for (String key : properties.stringPropertyNames()) {
				String value = properties.getProperty(key);
				logger.debug("Property key: " + key + " -- Value: " + value);
			}

		}

	}

	public boolean isUseIDDLoginForm() {

		logger.debug("Entering isUseIDDLoginForm");

		return false;
	}

	public void onLogout(HttpServletRequest request, HttpServletResponse response) {

		response.setContentType("application/json");
		try {
			response.getWriter()
					.write("{\"kerberos\": \"true\", \"logoutURL\": \"/mdm/entity360view/?logoutInd=true\"}");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		logger.debug("Logging out.  Session ID:" + request.getSession().getId());
		Enumeration headerNames = request.getHeaderNames();
		if (!headerNames.hasMoreElements()) {
			logger.debug("Header is empty");
		}
		while (headerNames.hasMoreElements()) {
			String key = (String) headerNames.nextElement();
			String value = request.getHeader(key);
			logger.debug("Logout Header key:" + key + " -- Value:" + value);
		}

		try {
			if (!response.isCommitted()) {
				try {
					response.setContentType("application/json");
					response.setHeader("Cache-Control", "no-cache, no-store");

					String jsonFormat = "{\"kerberos\":\"true\", \"logoutURL\":\"%s\"}";
					String jsonStr = String.format(jsonFormat, LOGOUT_TARGET);
					response.getOutputStream().write(jsonStr.getBytes());
					response.getOutputStream().flush();
				} catch (Exception e) {
					logger.error("Error sending redirect in onLogout", e);
				}
			}
		} catch (LinkageError err) {
			logger.debug("onLogout called from old IDD. Linkage Error handled.");
		}

	}

	public void redirectToProviderLoginPage(HttpServletRequest request, HttpServletResponse response,
			String originalRequest) throws LoginProviderException {

		logger.debug("Entering redirectToProviderLoginPage");
		logger.debug("logoutInd: " + request.getParameter("logoutParam"));
		try {
			logger.debug("Issuing rediection to IdP");
			if ("gotoLogoutPage".equalsIgnoreCase(request.getParameter("logoutParam"))) {
				response.sendRedirect("http://www.google.com");
			} else {
				response.sendRedirect("https://pfq1.boehringer.com/idp/SSO.saml2");
			}
		} catch (IOException e) {
			logger.error(e.getMessage());
		}
	}

	public LoginCredentials requestLoginCredentials(String arg0, String arg1) throws LoginProviderException {
		logger.debug("Entering requestLoginCredentials");
		return null;
	}

	public String encodeComponentUrl(String arg0) throws LoginProviderException {

		return null;
	}

	private SamlResponse decodeAndValidateSamlResponse(String samlResponse) throws Exception {
		String samlXml;

		try {
			samlXml = new String(Base64.decode(samlResponse), "UTF-8");
		} catch (Exception ex) {
			logger.error("Error executing Base64 decoding of SAML response.  Response may not be Base64 encoded.\n\n"
					+ StringUtilities.stackTraceToString(ex.getStackTrace()));
			samlXml = samlResponse;
		}

		if (logger.isDebugEnabled())
			logger.debug("Validating SAML response:: " + samlXml);

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		DocumentBuilder db;
		db = dbf.newDocumentBuilder();
		Document document = db.parse(samlXml);

		Response response = (Response) document.getDocumentElement();
		validateResponse(response);
		validateAssertion(response);
		validateSignature(response);

		Assertion assertion = response.getAssertions().get(0);
		return new SamlResponse(assertion);
	}

	private void validateResponse(Response response) throws Exception {
		try {
			new ResponseSchemaValidator().validate(response);
		} catch (ValidationException ex) {
			throw new Exception("The response schema validation failed", ex);
		}

		if (!response.getIssuer().getValue().equals(ASSERTION_ISSUER)) {
			throw new Exception("The response issuer didn't match the expected value");
		}

		String statusCode = response.getStatus().getStatusCode().getValue();

		if (!statusCode.equals("urn:oasis:names:tc:SAML:2.0:status:Success")) {
			throw new Exception("Invalid status code: " + statusCode);
		}
	}

	private void validateAssertion(Response response) throws Exception {

		if (response.getAssertions().size() != 1) {
			throw new Exception("The SAML response contains more than one assertion.");
		}

		Assertion assertion = response.getAssertions().get(0);
		if (!assertion.getIssuer().getValue().equals(ASSERTION_ISSUER)) {
			throw new Exception("The assertion Issuer element does not contain the expected value.");
		}

		if (assertion.getSubject().getNameID() == null) {
			throw new Exception(
					"The NameID value is missing from the SAML response; this is likely an IDP configuration issue");
		}

	}

	private void validateSignature(Response response) throws Exception {
		Signature responseSignature = response.getSignature();
		Signature assertionSignature = response.getAssertions().get(0).getSignature();

		if (responseSignature == null && assertionSignature == null) {
			throw new Exception("No signature is present in either response or assertion");
		}

		if (responseSignature != null && !validate(responseSignature)) {
			throw new Exception("The response signature is invalid");
		}

		if (assertionSignature != null && !validate(assertionSignature)) {
			throw new Exception("The assertion signature is invalid");
		}
	}

	private boolean validate(Signature signature) {
		if (signature == null) {
			return false;
		}
		return true;
	}

}
