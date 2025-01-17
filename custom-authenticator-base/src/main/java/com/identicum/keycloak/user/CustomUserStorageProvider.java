package com.identicum.keycloak.user;

import com.identicum.keycloak.auth.CustomAuthenticator;
import com.identicum.keycloak.external.User;
import com.identicum.keycloak.external.UserHttpClient;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.*;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class CustomUserStorageProvider implements UserStorageProvider, UserLookupProvider {

    public static final Logger LOG = Logger.getLogger(CustomUserStorageProvider.class);
    private final KeycloakSession session;
    private final ComponentModel model;
    private final com.identicum.keycloak.external.UserClient client;

    protected Map<String, UserModel> loadedUsers = new HashMap<>();


    public CustomUserStorageProvider(KeycloakSession session, ComponentModel model) {
        this.session = session;
        this.model = model;
        this.client = new UserHttpClient(session, model);
    }

    @Override
    public void preRemove(RealmModel realm) {
        UserStorageProvider.super.preRemove(realm);
    }

    @Override
    public void preRemove(RealmModel realm, GroupModel group) {
        UserStorageProvider.super.preRemove(realm, group);
    }

    @Override
    public void preRemove(RealmModel realm, RoleModel role) {
        UserStorageProvider.super.preRemove(realm, role);
    }

    @Override
    public void close() {

    }

    @Override
    public UserModel getUserById(RealmModel realmModel, String s) {
        try {
            LOG.infof("Bola hitnuta metoda getUserById");
            User user = client.getUser(s);
            LOG.infof("User nacitany %s",user.toString());
            return new UserAdapter(session,realmModel,model,user);
        }catch (IOException e) {
            LOG.infof("Zosypalo sa to %s",e.getMessage());
            throw new RuntimeException(e);
        }

    }

    @Override
    public UserModel getUserByUsername(RealmModel realmModel, String s) {
        return null;
    }

    @Override
    public UserModel getUserByEmail(RealmModel realmModel, String s) {
        return null;
    }
}
