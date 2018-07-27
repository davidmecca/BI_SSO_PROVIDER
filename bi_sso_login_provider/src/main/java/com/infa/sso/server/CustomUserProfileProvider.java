package com.infa.sso.server;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import org.apache.log4j.Logger;

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
		if ((securityCredential.getPayload() == null)
				|| (securityCredential.getPayload().length == 0)) {
			return null;
		}

		// Decipher the payload that you set in LoginProvider
		String sessionAndServer = null;
		try {
			sessionAndServer = new String(securityCredential.getPayload(),
					"UTF-8");
		} catch (UnsupportedEncodingException e) {
			logger.error("Wrong encoding.", e);
			return null;
		}
		if (!sessionAndServer.startsWith("sso")) {
			return null;
		}

		StringTokenizer tokenizer = new StringTokenizer(sessionAndServer, ";");
		if (tokenizer.hasMoreTokens()) {
			tokenizer.nextToken();
		}

		String user = "";
		if (tokenizer.hasMoreTokens()) {
			user = tokenizer.nextToken();
		}

		String sessionId = "";
		if (tokenizer.hasMoreTokens()) {
			sessionId = tokenizer.nextToken();
		}

		CustomBDDPayload bddPayload = new CustomBDDPayload();
		bddPayload.setUsername(user);
		bddPayload.setSessionId(sessionId);
		bddPayload.setDatabaseId(securityCredential.getDatabaseId());

		logger.info("UserName ->" + user);
		logger.info("SessionId ->" + sessionId);
		logger.info("DatabaseId ->" + securityCredential.getDatabaseId());

		UserProfile userProfile = new UserProfile();
		userProfile.setUsername(user);
		userProfile.setPayload(bddPayload);

		// cache user profile
		userProfile.setCacheKey(sessionId);
		userProfile.setCacheable(Boolean.TRUE);
		userProfile.setExpiration(new Long(60000L));
		userProfile.setLifeSpan(new Long(86400000L));

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
