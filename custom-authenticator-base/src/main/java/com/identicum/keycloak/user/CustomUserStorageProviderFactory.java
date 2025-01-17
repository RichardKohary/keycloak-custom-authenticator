package com.identicum.keycloak.user;

import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.storage.UserStorageProviderFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class CustomUserStorageProviderFactory implements UserStorageProviderFactory<CustomUserStorageProvider> {


    private final static String  PROVIDER_ID = "CUSTOM-TB-USER-STORAGE";


    @Override
    public CustomUserStorageProvider create(KeycloakSession keycloakSession, ComponentModel componentModel) {
        return new CustomUserStorageProvider(keycloakSession,componentModel);
    }

    @Override
    public String getId() {
        return PROVIDER_ID ;
    }

    @Override
    public int order() {
        return UserStorageProviderFactory.super.order();
    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        return UserStorageProviderFactory.super.getConfigMetadata();
    }

    @Override
    public void init(Config.Scope config) {
        UserStorageProviderFactory.super.init(config);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        UserStorageProviderFactory.super.postInit(factory);
    }

    @Override
    public void close() {
        UserStorageProviderFactory.super.close();
    }

    @Override
    public String getHelpText() {
        return "TB user storage manager";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        final List<ProviderConfigProperty> configProperties = new ArrayList<>();

        ProviderConfigProperty authorizationPortalProperty = new ProviderConfigProperty();
        authorizationPortalProperty.setName("tb.user.provider.base.url");
        authorizationPortalProperty.setLabel("TB user provider base url");
        authorizationPortalProperty.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(authorizationPortalProperty);

        ProviderConfigProperty authorizationPortalPropertyAN = new ProviderConfigProperty();
        authorizationPortalPropertyAN.setName("tb.user.provider.auth.name");
        authorizationPortalPropertyAN.setLabel("TB user provider auth name");
        authorizationPortalPropertyAN.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(authorizationPortalPropertyAN);

        ProviderConfigProperty authorizationPortalPropertyAP= new ProviderConfigProperty();
        authorizationPortalPropertyAP.setName("tb.user.provider.auth.pass");
        authorizationPortalPropertyAP.setLabel("TB user provider auth pass");
        authorizationPortalPropertyAP.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(authorizationPortalPropertyAP);

        return configProperties;
    }

    @Override
    public <C> C getConfig() {
        return UserStorageProviderFactory.super.getConfig();
    }



    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel config) throws ComponentValidationException {
        UserStorageProviderFactory.super.validateConfiguration(session, realm, config);
    }

    @Override
    public void onCreate(KeycloakSession session, RealmModel realm, ComponentModel model) {
        UserStorageProviderFactory.super.onCreate(session, realm, model);
    }

    @Override
    public void onUpdate(KeycloakSession session, RealmModel realm, ComponentModel oldModel, ComponentModel newModel) {
        UserStorageProviderFactory.super.onUpdate(session, realm, oldModel, newModel);
    }

    @Override
    public void preRemove(KeycloakSession session, RealmModel realm, ComponentModel model) {
        UserStorageProviderFactory.super.preRemove(session, realm, model);
    }

    @Override
    public List<ProviderConfigProperty> getCommonProviderConfigProperties() {
        return UserStorageProviderFactory.super.getCommonProviderConfigProperties();
    }

    @Override
    public Map<String, Object> getTypeMetadata() {
        return UserStorageProviderFactory.super.getTypeMetadata();
    }
}
