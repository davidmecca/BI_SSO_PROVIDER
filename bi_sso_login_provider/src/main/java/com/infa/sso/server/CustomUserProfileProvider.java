package com.infa.sso.server;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;

import com.infa.sso.common.SSOConstants;
import com.siperian.sam.SecurityCredential;
import com.siperian.sam.UserProfile;
import com.siperian.sam.UserProfileProvider;

public class CustomUserProfileProvider implements UserProfileProvider {
	public static final Long EXPIRATION = 60000L;
	public static final Long LIFE_SPAN = 86400000L;
	private static final Logger logger = Logger.getLogger(CustomUserProfileProvider.class);

	private Map properties = new HashMap();

	void setProperties(Map props) {
		this.properties.putAll(props);
	}

	@Override
	public UserProfile createUserProfile(SecurityCredential securityCredential) {
		if ((securityCredential.getPayload() == null) || (securityCredential.getPayload().length == 0)) {
			return null;
		}

		CustomBDDPayload bddPayload = new CustomBDDPayload();
		try {
			String credPayload = new String(securityCredential.getPayload(), "UTF-8");
			if (logger.isDebugEnabled())
				logger.debug("Credential payload -> " + credPayload);
			if (!credPayload.startsWith(SSOConstants.PAYLOAD_PREFIX)) {
				logger.error("Credential payload not sent from IdP.");
				return null;
			}
			String[] payloadValues = credPayload.split(SSOConstants.PAYLOAD_SEPARATOR);
			bddPayload.setUsername(payloadValues[1]);
			bddPayload.setSessionId(payloadValues[2]);
		} catch (IOException e) {
			logger.error("Error decoding security payload.", e);
			return null;
		}
		bddPayload.setDatabaseId(securityCredential.getDatabaseId());

		UserProfile userProfile = new UserProfile();
		userProfile.setUsername(bddPayload.getUsername());
		userProfile.setPayload(bddPayload);
		
		userProfile.setCacheKey(bddPayload.getSessionId());
		userProfile.setCacheable(Boolean.TRUE);
		userProfile.setExpiration(EXPIRATION);
		userProfile.setLifeSpan(LIFE_SPAN);

		if (logger.isDebugEnabled()) {
			logger.debug("UserName -> " + bddPayload.getUsername());
			logger.debug("SessionID -> " + bddPayload.getSessionId());
			logger.debug("DatabaseId -> " + bddPayload.getDatabaseId());
		}

		return userProfile;

	}

	@Override
	public List getCapabilties() {
		return null;
	}

	@Override
	public boolean hasCapability(String capability) {
		return getCapabilties().contains(capability);
	}

}
