package com.infa.sso.server;

public class CustomBDDPayload {
	  private String username;
	  private String sessionId;
	  private String databaseId;

	  public String getUsername()
	  {
	    return this.username;
	  }

	  public void setUsername(String username)
	  {
	    this.username = username;
	  }

	  public String getSessionId()
	  {
	    return this.sessionId;
	  }

	  public void setSessionId(String sessionId)
	  {
	    this.sessionId = sessionId;
	  }

	  public String getDatabaseId()
	  {
	    return this.databaseId;
	  }

	  public void setDatabaseId(String databaseId)
	  {
	    this.databaseId = databaseId;
	  }
}
