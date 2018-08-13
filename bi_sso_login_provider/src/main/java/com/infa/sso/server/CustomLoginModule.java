package com.infa.sso.server;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.apache.log4j.Logger;

import com.siperian.common.SipRuntimeException;
import com.siperian.sam.Role;
import com.siperian.sam.SamUtils;
import com.siperian.sam.UserProfile;
import com.siperian.sam.UserProfileCallback;
import com.siperian.sam.common.SamUtilsHelper;

public class CustomLoginModule implements LoginModule {
	private static final Logger logger = Logger.getLogger(CustomLoginModule.class);
	private CallbackHandler callbackHandler;

	public CustomLoginModule() {
		super();
	}

	@Override
	public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
			Map<String, ?> options) {
		this.callbackHandler = callbackHandler;
	}

	@Override
	public boolean login() throws LoginException {

		log("Entering login() method");
		try {
			UserProfileCallback userProfileCallback = new UserProfileCallback();
			this.callbackHandler.handle(new Callback[] { userProfileCallback });
			UserProfile userProfile = userProfileCallback.getUserProfile();

			if ((userProfile.getPayload() == null)) {
				return false;
			}

			if ((!(userProfile.getPayload() instanceof CustomBDDPayload))) {
				logger.warn("UserProfile is not an instance of CustomBDDPayload.");
				return false;
			}
			CustomBDDPayload payload = (CustomBDDPayload) userProfile.getPayload();

			String username = userProfile.getUsername();
			if (logger.isDebugEnabled()) {
				logger.debug("UserName -> " + username);
				logger.debug("DatabaseId -> " + payload.getDatabaseId());
			}

			if (username == null) {
				throw new LoginException("User name was not specified.");
			}

			if ((payload.getDatabaseId() != null) && (!payload.getDatabaseId().isEmpty())) {
				userProfile.setCacheable(true);
				setupUserRoles(userProfile, payload);
			} else {
				userProfile.setCacheable(false);
			}

			return true;
		} catch (UnsupportedCallbackException e) {
			throw new SipRuntimeException("SIP-18006", e.getMessage(), callbackHandler, e);
		} catch (IOException e) {
			throw new SipRuntimeException("SIP-18005", e.getMessage(), callbackHandler, e);
		}

	}

	private void setupUserRoles(UserProfile userProfile, CustomBDDPayload payload) {
		List<String> roleIds = new ArrayList<String>();
		List<String> roleNames = new ArrayList<String>();
		SamUtils samUtils = SamUtils.getInstance();
		List<Role> roles = samUtils.getAllRoles(payload.getDatabaseId(), userProfile.getUsername());
		logger.debug("User roles count -> " + roles.size());
		for (Role role : roles) {
			if (logger.isDebugEnabled()) {
				logger.debug(String.format("Role Name - %s, ROWID - %s", role.getName(), role.getRowid()));
			}
			roleIds.add(role.getRowid());
			roleNames.add(role.getName());
		}
		userProfile.setUserRoles(roleIds);
		userProfile.setUserRoleNames(roleNames);
	}

	@Override
	public boolean commit() throws LoginException {
		return true;
	}

	@Override
	public boolean abort() throws LoginException {
		return true;
	}

	@Override
	public boolean logout() throws LoginException {
		return true;
	}

	private void log(String msg) {
		if (logger.isDebugEnabled()) {
			logger.debug(msg);
		}
	}
}
