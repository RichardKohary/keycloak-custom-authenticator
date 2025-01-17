package com.identicum.keycloak.external;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.io.IOException;

@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public interface UserClient {

    @GET
    @Path("/{user-id}")
    com.identicum.keycloak.external.User getUser(@PathParam("user-id") String tbuserId) throws IOException;

}
