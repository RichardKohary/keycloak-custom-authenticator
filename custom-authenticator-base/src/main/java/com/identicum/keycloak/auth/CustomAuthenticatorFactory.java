package com.identicum.keycloak.auth;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

public class CustomAuthenticatorFactory implements AuthenticatorFactory  {

    @Override
    public String getDisplayType() {
        return "Custom authenticator";
    }

    @Override
    public String getReferenceCategory() {
        return "";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        AuthenticationExecutionModel.Requirement[] requirements = {
                AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.DISABLED
        };
        return requirements;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "This is TB custom authenticator";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        final List<ProviderConfigProperty> configProperties = new ArrayList<>();

        ProviderConfigProperty authorizationPortalProperty = new ProviderConfigProperty();
        authorizationPortalProperty.setName("tb.auth.portal.url");
        authorizationPortalProperty.setLabel("TB auth portal url");
        authorizationPortalProperty.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(authorizationPortalProperty);

        return configProperties;
    }

    @Override
    public Authenticator create(KeycloakSession keycloakSession) {
        return new CustomAuthenticator();
    }

    @Override
    public void init(Config.Scope scope) {

    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return "CUSTOM-AUTHENTICATOR";
    }
}
