package com.identicum.keycloak.auth;


import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.RsaKeyUtil;
import org.jose4j.lang.JoseException;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.*;
import org.keycloak.models.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Base64;
import java.util.List;

import org.jboss.logging.Logger;
import jakarta.ws.rs.core.UriBuilder;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.sessions.AuthenticationSessionModel;



public class CustomAuthenticator implements Authenticator {

	public static final Logger LOG = Logger.getLogger(CustomAuthenticator.class);

	public static Integer test = 1;
	@Override
	public void authenticate(AuthenticationFlowContext context) {


		try {
			//location = new URI("http://myservice/validation/?realm="+realm+"&session_code="+accessCode+"&tab_id="+tabId+"&client_id="+clientId+"&execution="+execution+"&mydata=aaa");
			AuthenticatorConfigModel config = context.getAuthenticatorConfig();
			String authPortalUrl = "";
			if (config != null) {
				authPortalUrl = config.getConfig().get("tb.auth.portal.url");
			}else{
				authPortalUrl = "https://mycustomdmojatatrabanka.sk/paap";
			}

			String actionUrlBase64 = Base64.getEncoder().encodeToString(getActionUrl(context).toString().getBytes(StandardCharsets.UTF_8));
			LOG.infof("Created base64Encoded actionUrl %s", actionUrlBase64);

			UriBuilder uriBulder = UriBuilder.fromUri(authPortalUrl);
			//uriBulder.queryParam("actionUrl",);
			uriBulder.queryParam("request_to_paap",buildSignedJWT(actionUrlBase64,context));

			Response response = Response.seeOther(uriBulder.build()).build();
			LOG.infof("Redirecting to %s", uriBulder.build().toString());
			context.forceChallenge(response);
			return;
		} catch (Exception e) {
			LOG.infof(e.getMessage());
		}
	}



	//Tato metoda je pouzita, pretoze v 24 generuje linku na getActionUrl, ktora nefunguje
	private URI getActionUrl(AuthenticationFlowContext context){
		String accessCode = new ClientSessionCode<>(context.getSession(), context.getRealm(), context.getAuthenticationSession()).getOrGenerateCode();
		String clientId = context.getAuthenticationSession().getClient().getClientId();
		String tabId = context.getAuthenticationSession().getTabId();
		String execution = context.getExecution().getId();
		String realm = context.getRealm().getName();
		String base = "http://localhost:8080/realms/"+realm+"/login-actions/authenticate";
		UriBuilder uriBuilder = UriBuilder.fromUri(base);
		uriBuilder.queryParam("session_code",accessCode);
		uriBuilder.queryParam("tab_id",tabId);
		uriBuilder.queryParam("client_id",clientId);
		uriBuilder.queryParam("execution",execution);
		//toto bude doplnat paap, teraz to tu davam, aby som to nemusel robit na dev pri kazdom
		uriBuilder.queryParam("signed_request","eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.cThIIoDvwdueQB468K5xDc5633seEFoqwxjF_xSJyQQ");
		return uriBuilder.build();
	}

	@Override
	public void action(AuthenticationFlowContext context) {
		// "http://localhost:8080/auth/realms/"+realm+"/login-actions/authenticate?session_code="+accessCode+"&tab_id="+tabId+"&client_id="+clientId+"&execution="+execution

		logAuthenticationFlowContext(context);
		String queryParams = context.getHttpRequest().getUri().getQueryParameters().getFirst("signed_request");
		///toto pride jwt nateraz len ako parameter
		String userId = context.getHttpRequest().getUri().getQueryParameters().getFirst("sub");
		//verifikacia JWT overenie podpisu
//		JwtConsumer jwtConsumer = new JwtConsumerBuilder()
//				.setSkipSignatureVerification() // Preskočí validáciu podpisu (iba na parsovanie)
//				.build();
//		try {
//			// Rozparsovanie JWT
//			JwtClaims claims = jwtConsumer.processToClaims(queryParams);
//
//			UserModel user = context.getSession().users().getUserById(context.getRealm(),"67ef3abb-6ed4-4977-9458-e86a9c22f44f");
//
//			user.setEnabled(true);
//
//			context.setUser(user);
//			LOG.infof("Success");
//			context.success();
//
//		} catch (InvalidJwtException e) {
//            throw new RuntimeException(e);
//        }
		LOG.infof("Idem nacitat usera z Custom User adaptera");
		//nacitanie z User providera
		UserModel user = context.getSession().users().getUserById(context.getRealm(),userId);
		user.setEnabled(true);

		context.setUser(user);
		LOG.infof("Success");
		context.success();

	}

//	@Override
//	public void authenticate(AuthenticationFlowContext authenticationFlowContext) {
//		LOG.infof("Authenticate called '%s'",authenticationFlowContext.toString());
//		logAuthenticationFlowContext(authenticationFlowContext);
//		LOG.infof("authenticate volane:: '%s' x",test.toString());
//		LOG.info("idem urobit skusku , ci mi prisiel JWT");
//
//		LOG.infof("RequestPath : %s", authenticationFlowContext.getHttpRequest().getUri().toString());
//
//		String confirm_request = authenticationFlowContext.getHttpRequest().getUri().getQueryParameters().getFirst("execution");
//		LOG.infof("confirm_request hodnota: %s", confirm_request);
//
//		if(confirm_request != null && !confirm_request.isEmpty()){
//			LOG.info("nasiel som hodnotu confirm_request");
//			//todo over ci sedi platny certifikat a kody
//			//ak ano dokonci session
//			authenticationFlowContext.success();
//			return;
//		}else {
//
//
//			test = test + 1;
//
//
//			String baseUrl = "https://your-custom-tbportal.com/login";
//			UriBuilder redirectToAuthPortal = UriBuilder.fromUri(baseUrl);
//			UriBuilder actionUrl = UriBuilder.fromUri(authenticationFlowContext.getActionUrl("confirmation"));
//			actionUrl.queryParam("confirm_request", "tu bude podpisane JWT zo strany PAAP");
//			redirectToAuthPortal.queryParam("actionUrl", actionUrl.build());
//			redirectToAuthPortal.queryParam("request_to_auth", "Tu bude podpisany JWT zo strany IDP");
//
//			authenticationFlowContext.getSession().setAttribute("confirm_request", "the confirmationbalue");
//			authenticationFlowContext.getAuthenticationSession().setAuthNote("confirmation_auth_session", "the value");
//
//			Response response = authenticationFlowContext.form().setAttribute("redirectToAuthPortal", redirectToAuthPortal.build()).createForm("login.ftl");
//			authenticationFlowContext.forceChallenge(response);
//		}
//	}
//
//	@Override
//	public void action(AuthenticationFlowContext authenticationFlowContext) {
//
//		LOG.info("Custom log: I am going to finish context");
////		setCookie(context);
//		authenticationFlowContext.success();
//		return;
//	}
	private String buildSignedJWT(String actionUrlBase64,AuthenticationFlowContext context){

		String originalClientId = context.getHttpRequest().getUri().getQueryParameters().getFirst("login_hint");
		LOG.infof("originalClientId %s", originalClientId);
		JwtClaims claims = new JwtClaims();
		KeyPair keyPair;
		claims.setIssuer("Issuer");
		claims.setExpirationTimeMinutesInTheFuture(5);
		claims.setClaim("actionUrlBase64",actionUrlBase64 );
		if(originalClientId!=null)
			claims.setClaim("original_client_id",originalClientId);
		claims.setClaim("scopes",context.getAuthenticationSession().getClientNote(OAuth2Constants.SCOPE));
		RsaKeyUtil rsaKeyUtil = new RsaKeyUtil();
        try {
			//privatnym klucom budeme tu podpisovat. Public key bude mat k dispozicii PAAPortal
            keyPair = rsaKeyUtil.generateKeyPair(2048);
			// Create the JWT and sign it with RS256
			JsonWebSignature jws = new JsonWebSignature();
			jws.setPayload(claims.toJson());
			jws.setKey(keyPair.getPrivate());
			jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
			jws.sign();
			String jwt = jws.getCompactSerialization();
			LOG.infof("Signed JWT %s", jwt);
			return jwt;
        } catch (JoseException e) {
			LOG.infof("Zlyhalo vytvaranie kluca %s", e.getMessage());
        }
		return "";
    }
  // private String buildSignedJWT(String actionUrlBase64){


//	   try {
//		   KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//
//		   keyPairGenerator.initialize(1024);
//
//		   // generate the key pair
//		   KeyPair keyPair = keyPairGenerator.genKeyPair();
//		// create KeyFactory and RSA Keys Specs
//		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//		RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(keyPair.getPublic(), RSAPublicKeySpec.class);
//		RSAPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(keyPair.getPrivate(), RSAPrivateKeySpec.class);
//
//		LOG.infof("Private %s", privateKeySpec);
//		LOG.infof("Public %s", publicKeySpec);
//		// generate (and retrieve) RSA Keys from the KeyFactory using Keys Specs
//       RSAPublicKey publicRsaKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
//
//       RSAPrivateKey privateRsaKey  = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
//
//	   JWTClaimsSet claimsSet =  new JWTClaimsSet.Builder()
//			   .issuer("https://my-auth-server.com")
//			   .subject("John Kerr")
//					   .expirationTime(new Date(new Date().getTime() + 1000*60*10))
//			   .claim("actionUrl",actionUrlBase64)
//			   .jwtID(String.valueOf(UUID.randomUUID())).build();
//
//
//
//		// create the JWT header and specify:
//		//  RSA-OAEP as the encryption algorithm
//		//  128-bit AES/GCM as the encryption method
//		JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM);
//
//		// create the EncryptedJWT object
//		EncryptedJWT jwt = new EncryptedJWT(header, claimsSet);
//
//		// create an RSA encrypter with the specified public RSA key
//		RSAEncrypter encrypter = new RSAEncrypter(publicRsaKey);
//
//		// do the actual encryption
//		jwt.encrypt(encrypter);
//
//		// serialize to JWT compact form
//		String jwtString = jwt.serialize();
//		return jwtString;
//
//	   } catch (Exception e) {
//
//		   LOG.infof("Zlyhalo vytvaranie kluca %s", e.getMessage());
//	   }
//	   return "";
//	}

	public void logAuthenticationFlowContext(AuthenticationFlowContext context) {
		// Získanie Realm
		RealmModel realm = context.getRealm();

		// Získanie používateľa
		UserModel user = context.getUser();

		// Získanie klienta
		AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();

		// Získanie identifikátora session
		String sessionId = context.getAuthenticationSession().getAuthNote("session_code");

		MultivaluedMap<String, String> queryParams = context.getHttpRequest().getUri().getQueryParameters();
		queryParams.forEach((key, value) -> {
			LOG.infof("Param: %s, Value: %s", key, value);
		});

		// Vytvorenie detailného reťazca s informáciami
		StringBuilder contextInfo = new StringBuilder();
		contextInfo.append("AuthenticationFlowContext Details: \n");
		contextInfo.append("Realm: ").append(realm != null ? realm.getName() : "N/A").append("\n");
		contextInfo.append("User: ").append(user != null ? user.getUsername() : "N/A").append("\n");
		contextInfo.append("Session ID: ").append(sessionId).append("\n");
		contextInfo.append("Context flow path: ").append(context.getFlowPath()).append("\n");
		contextInfo.append("Execution id: ").append(context.getExecution().getId()).append("\n");

		if (authenticationSession != null) {
			contextInfo.append("authenticationSession Session: ").append(authenticationSession.getClient().getClientId()).append("\n");
		} else {
			contextInfo.append("Client Session: N/A\n");
		}

		// Prípadne ďalšie relevantné informácie z kontextu (napr. logovanie samotného 'execution')
		contextInfo.append("Execution ID: ").append(context.getExecution().getId()).append("\n");

		// Výpis do logu
		LOG.infof("AuthenticationFlowContext Information: %s", contextInfo.toString());
	}


//	protected void setCookie(AuthenticationFlowContext context) {
//		AuthenticatorConfigModel config = context.getAuthenticatorConfig();
//		int maxCookieAge = 60 * 60 * 24 * 30; // 30 days
//		if (config != null) {
//			maxCookieAge = Integer.valueOf(config.getConfig().get("cookie.max.age"));
//
//		}
//		URI uri = context.getUriInfo().getBaseUriBuilder().path("realms").path(context.getRealm().getName()).build();
//		addCookie(context, "SECRET_QUESTION_ANSWERED", "true",
//				uri.getRawPath(),
//				null, null,
//				maxCookieAge,
//				false, true);
//	}

	@Override
	public boolean requiresUser() {
		return false;
	}

	@Override
	public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
		return false;
	}

	@Override
	public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {

	}

	@Override
	public List<RequiredActionFactory> getRequiredActions(KeycloakSession session) {
		return null;
	}

	@Override
	public boolean areRequiredActionsEnabled(KeycloakSession session, RealmModel realm) {
		return false;
	}

	@Override
	public void close() {

	}
}
