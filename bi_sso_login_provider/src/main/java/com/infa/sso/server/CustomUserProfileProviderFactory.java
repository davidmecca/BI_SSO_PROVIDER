package com.infa.sso.server;

import java.util.HashMap;
import java.util.Map;

import com.siperian.sam.UserProfileProvider;
import com.siperian.sam.UserProfileProviderFactory;

public class CustomUserProfileProviderFactory implements UserProfileProviderFactory {
	private Map properties = new HashMap();

	@Override
	public UserProfileProvider getUserProfileProvider() {
		CustomUserProfileProvider profileProvider = new CustomUserProfileProvider();
		profileProvider.setProperties(this.properties);
		return profileProvider;
	}

	@Override
	public void initialize(Map props) {
		if (props != null)
			this.properties.putAll(props);
	}
}
