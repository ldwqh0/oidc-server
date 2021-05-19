package org.xyyh.oidc.core;

import java.util.Optional;

public interface OAuth2ResourceServerTokenService {
    Optional<OidcAuthentication> loadAuthentication(String accessToken);

    Optional<OAuth2ServerAccessToken> readAccessToken(String accessToken);
}
