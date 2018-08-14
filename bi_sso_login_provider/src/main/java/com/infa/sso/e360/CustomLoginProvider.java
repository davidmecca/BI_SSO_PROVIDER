package com.infa.sso.e360;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.io.IOUtils;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.validator.ResponseSchemaValidator;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509Util;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.infa.sso.common.SSOConstants;
import com.infa.sso.common.StringUtilities;
import com.infa.sso.saml.AuthenticationRequestBuilder;
import com.infa.sso.saml.SamlException;
import com.infa.sso.saml.SamlResponse;
import com.infa.sso.util.SamlUtility;
import com.siperian.bdd.security.LoginCredentials;
import com.siperian.bdd.security.LoginProvider;
import com.siperian.bdd.security.LoginProviderException;

public class CustomLoginProvider implements LoginProvider {

	private static final Logger logger = LoggerFactory.getLogger(CustomLoginProvider.class);
	private static final String ASSERTION_ISSUER = "pfq1.boehringer.com";
	private static final String LOGOUT_TARGET = "/mdm/entity360view/?logoutInd=true";
	private static final String LOGOUT_REDIRECT_TARGET = "https://www.boehringer-ingelheim.com/";
	private static final String SAML_RESPONSE_PARAM = "SAMLResponse";
	private static final String FILE_LOC = "/app/infamdm/hub/server/custom_resources/";

	private Properties loginProperies = new Properties();

	public CustomLoginProvider() {

		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			e.printStackTrace();
		}

		loadProperties();

	}

	private void loadProperties() {

		try {
			InputStream is = new FileInputStream(FILE_LOC + "custom_login_provider.properties");
			loginProperies.load(is);
		} catch (FileNotFoundException e) {
			logger.warn("Cannot find file custom_login_provider.properties");
		} catch (IOException e) {
			logger.error(
					"Error reading file custom_login_provider.properties");
		}

	}

	@Override
	public LoginCredentials extractLoginCredentials(HttpServletRequest httpServletRequest)
			throws LoginProviderException {

		StringBuilder credentialBuilder = new StringBuilder();
		String userId = null;
		SamlResponse samlResponseObj = null;
		String samlDecoded = null;
		SamlUtility samlUtility = new SamlUtility();

		String requestBodySamlResponse = httpServletRequest.getParameter(SAML_RESPONSE_PARAM);

		if (logger.isDebugEnabled())
			logger.debug("SAML Response: " + requestBodySamlResponse);

		if (requestBodySamlResponse == null || requestBodySamlResponse.length() == 0) {
			logger.error("Request does not contains a SAMLResponse parameter.  SSO authentication will fail.");
			return null; // Returning null will force a redirect to Ping Federate
		}

		try {
			samlDecoded = new String(Base64.decode(requestBodySamlResponse));
		} catch (Exception ex) {
			logger.error(
					"Error executing Base64 decoding of SAML response.  Response may not be Base64 encoded.  Error: "
							+ ex.getMessage());
			return null;
		}

		logger.debug("SAML Response decoded: " + samlDecoded);

		try {
			samlResponseObj = decodeAndValidateSamlResponse(samlDecoded);
			userId = samlResponseObj.getUserId().trim();
			if (userId == null) {
				logger.error("SAML response UID field is null");
				return null; // Returning null will force a redirect to Ping Federate
			}
		} catch (Exception e) {
			logger.error(e.getMessage());
			// throw new LoginProviderException(e);
			return null;
		}

		if (logger.isDebugEnabled()) {
			logger.debug("SAML UID (user ID) -> " + userId);
			logger.debug("SAML First Name -> " + samlResponseObj.getUserFirstName());
			logger.debug("SAML Last Name -> " + samlResponseObj.getUserLastName());
		}

		credentialBuilder.append(SSOConstants.PAYLOAD_PREFIX);
		credentialBuilder.append(SSOConstants.PAYLOAD_SEPARATOR);
		credentialBuilder.append(StringUtilities.removeNonPrintChars(userId));
		credentialBuilder.append(SSOConstants.PAYLOAD_SEPARATOR);
		credentialBuilder.append(samlUtility.getSecureRandomId());

		LoginCredentials lc = null;
		try {
			lc = new LoginCredentials(credentialBuilder.toString().getBytes(SSOConstants.PAYLOAD_CHAR_ENCODING));
			lc.setFirstName(StringUtilities.removeNonPrintChars(samlResponseObj.getUserFirstName().trim()));
			lc.setLastName(StringUtilities.removeNonPrintChars(samlResponseObj.getUserLastName().trim()));
			if (logger.isDebugEnabled()) {
				logger.debug("Created LoginCredential");
			}
		} catch (Exception e) {
			logger.error("Credential creation error", e);
			throw new LoginProviderException("Credential creation error", e);
		}

		return lc;
	}

	@Override
	public InputStream getLogoImageBody() {
		return null;
	}

	@Override
	public void initialize(Properties properties) {

		String redirectInd = properties.getProperty("enable.redirect");
		logger.debug("Redirect indicator - > " + redirectInd);

	}

	@Override
	public boolean isUseIDDLoginForm() {
		return false;
	}

	@Override
	public void onLogout(HttpServletRequest request, HttpServletResponse response) {

		logger.debug("Issue IDD logout request");

		try {
			if (!response.isCommitted()) {
				response.setContentType("application/json");
				response.setHeader("Cache-Control", "no-cache, no-store");
				String jsonFormat = "{\"kerberos\":\"true\", \"logoutURL\":\"%s\"}";
				String jsonStr = String.format(jsonFormat, LOGOUT_TARGET);
				response.getOutputStream().write(jsonStr.getBytes());
				response.getOutputStream().flush();
			}
		} catch (LinkageError err) {
			logger.debug("onLogout called from old IDD. Linkage Error handled.");
		} catch (Exception e) {
			logger.error("Error sending redirect in onLogout", e);
		}

	}

	@Override
	public void redirectToProviderLoginPage(HttpServletRequest request, HttpServletResponse response,
			String originalRequest) throws LoginProviderException {

		if (logger.isDebugEnabled())
			logger.debug("Entering redirectToProviderLoginPage");

		try {
			if ("true".equalsIgnoreCase(request.getParameter("logoutInd"))) {
				if (logger.isDebugEnabled())
					logger.debug("Issuing logout response");
				/*
				 * Since there was not a requirement for a specific logout target page, the BI homepage is being used.
				 */
				response.sendRedirect(LOGOUT_REDIRECT_TARGET); 
			} else {
				/* David Mecca (HighPoint)
				 * 
				 * Per Steve Yannatuono, we won't need service provider initiated authentication.  Therefore, the logic
				 * to create an authentication request has been commented out.
				 * 
				 */
				// redirectUserForAuthentication(response);
				response.sendRedirect("https://pfq1.boehringer.com/idp/SSO.saml2");
			}
		} catch (IOException | LinkageError e) {
			logger.error(e.getMessage());
		}

	}

	@Override
	public LoginCredentials requestLoginCredentials(String arg0, String arg1) throws LoginProviderException {
		return null;
	}

	@Override
	public String encodeComponentUrl(String arg0) throws LoginProviderException {
		return null;
	}

	private SamlResponse decodeAndValidateSamlResponse(String samlXml) throws Exception {
		Response response = null;
		InputStream inputStream = null;
		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			DocumentBuilder db = dbf.newDocumentBuilder();
			inputStream = IOUtils.toInputStream(samlXml, StandardCharsets.UTF_8);
			Document document = db.parse(inputStream);
			Element samlElement = document.getDocumentElement();
			UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
			Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(samlElement);
			XMLObject responseXmlObj = unmarshaller.unmarshall(samlElement);
			response = (Response) responseXmlObj;
		} catch (Exception e) {
			throw e;
		} finally {
			try {
				inputStream.close();
			} catch (IOException ioex) {
				logger.warn(ioex.getMessage());
			}
		}

		if (logger.isDebugEnabled())
			logger.debug("Starting SAML validation.");

		validateResponse(response);
		validateAssertion(response);

		if (isValidateSignature())
			validateSignature(response);
		else
			logger.warn("Skipping SAML signature validation based on property file configuration.");

		if (logger.isDebugEnabled())
			logger.debug("SAML validation completed.");

		try {
			Assertion assertion = response.getAssertions().get(0);
			return new SamlResponse(assertion);
		} catch (Exception e) {
			logger.error("Error retrieving assertion from SAML response. It may be null.");
			throw new SamlException(
					"Error retrieving assertion from SAML response. It may be null.  Error: " + e.getMessage());
		}
	}

	private boolean isValidateSignature() {

		return loginProperies.getProperty("validate.saml.signature") == null
				|| loginProperies.getProperty("validate.saml.signature").isEmpty() ? true
						: Boolean.valueOf(loginProperies.getProperty("validate.saml.signature"));

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

		try {
			String statusCode = response.getStatus().getStatusCode().getValue();
			if (!("urn:oasis:names:tc:SAML:2.0:status:Success")
					.equals(response.getStatus().getStatusCode().getValue())) {
				throw new Exception("Invalid SAML response status code: " + statusCode);
			}
		} catch (Exception e) {
			logger.error("Error retrieving SAML response status code.  It may be null");
			throw new Exception("Error retrieving SAML response status code");
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

	private boolean validate(Signature signature) throws Exception {
		if (signature == null) {
			return false;
		}

		try {
			SignatureValidator signatureValidator = new SignatureValidator(getCredential());

			signatureValidator.validate(signature);
			return true;
		} catch (ValidationException ex) {
			return false;
		}

	}

	private Credential getCredential() throws Exception {

		FilesystemMetadataProvider idpMetaDataProvider = new FilesystemMetadataProvider(
				new File(FILE_LOC + "saml_metadata.xml"));
		idpMetaDataProvider.setRequireValidMetadata(true);
		idpMetaDataProvider.setParserPool(new BasicParserPool());
		idpMetaDataProvider.initialize();
		EntityDescriptor entityDescriptor = (EntityDescriptor) idpMetaDataProvider.getMetadata();
		IDPSSODescriptor idpSsoDescriptor = getIDPSSODescriptor(entityDescriptor);

		X509Certificate certificate = getCertificate(idpSsoDescriptor);
		BasicX509Credential credential = new BasicX509Credential();
		credential.setEntityCertificate(certificate);
		logger.info("SAML metadata certificate obtained from system resources.");
		return credential;

	}

	private IDPSSODescriptor getIDPSSODescriptor(EntityDescriptor entityDescriptor) throws SamlException {
		IDPSSODescriptor idpssoDescriptor = entityDescriptor
				.getIDPSSODescriptor("urn:oasis:names:tc:SAML:2.0:protocol");
		if (idpssoDescriptor == null) {
			throw new SamlException("Cannot retrieve IDP SSO descriptor");
		}

		return idpssoDescriptor;
	}

	private X509Certificate getCertificate(IDPSSODescriptor idpSsoDescriptor) throws SamlException {

		try {
			Collection<X509Certificate> certs = X509Util
					.decodeCertificate(Base64.decode(idpSsoDescriptor.getKeyDescriptors().get(0).getKeyInfo()
							.getX509Datas().get(0).getX509Certificates().get(0).getValue()));
			if (certs != null && certs.iterator().hasNext()) {
				return certs.iterator().next();
			} else {
				return null;
			}
		} catch (Exception e) {
			throw new SamlException("Exception in getCertificates", e);
		}

	}

	/*
	 * Logic to create a service provider initiated authentication request to the IdP.  For now, this is not being used.
	 */
	private void redirectUserForAuthentication(HttpServletResponse httpServletResponse) {
		AuthenticationRequestBuilder arb = new AuthenticationRequestBuilder();
		AuthnRequest authnRequest = arb.buildAuthenticationRequest();
		arb.redirectUserWithRequest(httpServletResponse, authnRequest);

	}

}
