package com.identicum.keycloak.external;

import jakarta.ws.rs.WebApplicationException;
import com.identicum.keycloak.helpers.Constants;
import org.apache.http.impl.client.CloseableHttpClient;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.KeycloakSession;

import java.io.IOException;

public class UserHttpClient implements com.identicum.keycloak.external.UserClient {

    private final KeycloakSession session;
    private final String baseUrl;
    private final String basicUsername;
    private final String basicPassword;

    public UserHttpClient(KeycloakSession session, ComponentModel model) {
        this.session = session;
        this.baseUrl = model.get(Constants.BASE_URL);
        this.basicUsername = model.get(Constants.AUTH_USER_NAME);
        this.basicPassword = model.get(Constants.AUTH_USER_PASS);
    }

    @Override
    public com.identicum.keycloak.external.User getUser(String tbuserId) throws IOException {
        String url = String.format("/%s/users/%s", baseUrl, tbuserId);
        SimpleHttp.Response response = SimpleHttp.doGet(url,  session).authBasic(basicUsername, basicPassword).asResponse();
        if (response.getStatus() == 404) {
            throw new WebApplicationException(response.getStatus());
        }
        return response.asJson(com.identicum.keycloak.external.User.class);
    }
}
