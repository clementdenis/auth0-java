package com.auth0.client.mgmt;

import com.auth0.client.auth.AuthAPI;
import com.auth0.client.auth.RSAClientAssertionSigner;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.TokenHolder;
import com.auth0.net.Response;

import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

/**
 * A {@link TokenProvider} instance that refreshes access tokens automatically before they expire.
 */
public class AutoRefreshTokenProvider implements TokenProvider {

    private final AuthAPI authAPI;
    private final String audience;
    private final Long minExpirationDelay;
    private TokenHolder tokenHolder;

    /**
     * @param authAPI            the Auth API instance
     * @param audience           the audience to obtain a management API token for
     * @param minExpirationDelay the minimum delay in seconds to token expiration before triggering a refresh.
     *                           If null, will be 1/10th of the token validity duration.
     * @throws Auth0Exception if the initial token retrieval fails
     */
    private AutoRefreshTokenProvider(AuthAPI authAPI, String audience, Long minExpirationDelay) throws Auth0Exception {
        this.authAPI = authAPI;
        this.audience = audience;
        this.tokenHolder = refreshToken();
        this.minExpirationDelay = minExpirationDelay != null ? minExpirationDelay : tokenHolder.getExpiresIn() / 10;
    }

    /**
     * This can be used to get additional information on the token, like scopes.
     *
     * @return the currently cached token holder (does not perform a refresh)
     */
    public TokenHolder getTokenHolder() {
        return tokenHolder;
    }

    /**
     * Note: this method is synchronized to avoid multiple refreshes if used concurrently.
     *
     * @return a token valid for at least {@code refreshDelay} seconds
     * @throws Auth0Exception if the token refresh fails
     * @see TokenProvider#getTokenAsync()
     */
    @Override
    public synchronized String getToken() throws Auth0Exception {
        if (tokenHolder == null || tokenHolder.getExpiresAt().toInstant().isBefore(Instant.now().minusSeconds(minExpirationDelay))) {
            tokenHolder = refreshToken();
        }
        return tokenHolder.getAccessToken();
    }

    /**
     * @see TokenProvider#getTokenAsync()
     */
    @Override
    public CompletableFuture<String> getTokenAsync() {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return getToken();
            } catch (Auth0Exception e) {
                throw new CompletionException(e);
            }
        });
    }

    private TokenHolder refreshToken() throws Auth0Exception {
        Response<TokenHolder> response = authAPI
            .requestToken(audience)
            .execute();
        TokenHolder holder = response.getBody();
        if (minExpirationDelay != null && holder.getExpiresIn() < minExpirationDelay) {
            throw new Auth0Exception("");
        }
        return holder;
    }

    /**
     * Builder for {@link AutoRefreshTokenProvider} token providers.
     */
    public static class Builder {

        private final AuthAPI authApi;
        private final String domain;
        private Long minExpirationDelay;

        /**
         * @param domain       the tenant's domain. Must be a non-null valid HTTPS URL.
         * @param clientId     the application's client ID.
         * @param clientSecret the applications client secret.
         */
        public Builder(String domain, String clientId, String clientSecret) {
            this.authApi = AuthAPI.newBuilder(domain, clientId, clientSecret).build();
            this.domain = domain;
        }

        /**
         * Initialize a new {@link Builder} to configure and create an instance. Use this to construct an instance
         * with a client assertion signer with provided {@code privateKey} used in place of a client secret when calling
         * token APIs.
         *
         * @param domain     the tenant's domain. Must be a non-null valid HTTPS URL.
         * @param clientId   the application's client ID.
         * @param privateKey the {@code privateKey} used to create the signed client assertion.
         */
        public Builder(String domain, String clientId, RSAPrivateKey privateKey) {
            this.authApi = AuthAPI.newBuilder(domain, clientId, new RSAClientAssertionSigner(privateKey)).build();
            this.domain = domain;
        }

        /**
         * Initialize a new {@link Builder} to configure and create an instance. Use this to construct an instance
         * with a client assertion signer used in place of a client secret when calling token APIs.
         *
         * @param domain  the tenant's domain. Must be a non-null valid HTTPS URL.
         * @param authAPI the {@code authAPI} instance to use to obtain tokens
         */
        public Builder(String domain, AuthAPI authAPI) throws Auth0Exception {
            this.authApi = authAPI;
            this.domain = domain;
        }

        /**
         * Configures the minimum delay in seconds to token expiration before triggering a refresh.
         *
         * @param minExpirationDelay the minimum delay in seconds to token expiration before triggering a refresh.
         * @return the builder instance.
         */
        public Builder withMinExpirationDelay(long minExpirationDelay) {
            this.minExpirationDelay = minExpirationDelay;
            return this;
        }

        /**
         * Builds an {@link AutoRefreshTokenProvider} instance using this builder's configuration.
         *
         * @return the configured {@code AutoRefreshTokenProvider} instance.
         */
        public AutoRefreshTokenProvider build() throws Auth0Exception {
            return new AutoRefreshTokenProvider(authApi, "https://" + domain + "/api/v2/", minExpirationDelay);
        }

    }

}
