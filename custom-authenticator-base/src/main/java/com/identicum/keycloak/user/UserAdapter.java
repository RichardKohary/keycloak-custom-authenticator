package com.identicum.keycloak.user;

import jakarta.ws.rs.core.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.UserCredentialManager;
import org.keycloak.models.*;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.adapter.AbstractUserAdapter;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

public class UserAdapter extends AbstractUserAdapter {

    private final com.identicum.keycloak.external.User user;
    public UserAdapter(KeycloakSession session, RealmModel realm, ComponentModel storageProviderModel, com.identicum.keycloak.external.User user) {
        super(session, realm, storageProviderModel);
        this.storageId = new StorageId(storageProviderModel.getId(), user.getName());
        this.user= user;

    }

    @Override
    public String getUsername() {
        return user.getName();
    }

    @Override
    public String getId() {
        return user.getUserId();
    }

    @Override
    public String getEmail() {
        return user.getEmail();
    }

    @Override
    public String getFirstName() {
        return user.getName();
    }

    @Override
    public boolean isEmailVerified() {
        return user.isEmailVerified();
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        MultivaluedHashMap<String, String> attributes = new MultivaluedHashMap<>();
        attributes.add(UserModel.USERNAME, getUsername());
        attributes.add(UserModel.EMAIL, getEmail());
        attributes.add(UserModel.FIRST_NAME, getFirstName());
        attributes.add(UserModel.LAST_NAME, getLastName());
        attributes.add("birthday", user.getBirthDate());
        attributes.add("gender", user.getGender());
        attributes.add("personalId", user.getPersonalId());
        return attributes;
    }

    @Override
    public Stream<GroupModel> getGroupsStream(String search, Integer first, Integer max) {
        return super.getGroupsStream(search, first, max);
    }

    @Override
    public long getGroupsCount() {
        return super.getGroupsCount();
    }

    @Override
    public long getGroupsCountByNameContaining(String search) {
        return super.getGroupsCountByNameContaining(search);
    }

    @Override
    public void joinGroup(GroupModel group, MembershipMetadata metadata) {
        super.joinGroup(group, metadata);
    }

    @Override
    public boolean isFederated() {
        return super.isFederated();
    }

    @Override
    public SubjectCredentialManager credentialManager() {
        return null;
    }


    @Override
    public boolean hasDirectRole(RoleModel role) {
        return super.hasDirectRole(role);
    }
}
