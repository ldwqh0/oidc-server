package org.xyyh.oidc.core;

import java.util.Optional;

public interface OAuth2ResourceServerTokenService {
    // 根据access
    Optional<OidcAuthentication> loadAuthentication(String accessToken);

    Optional<OAuth2ServerAccessToken> readAccessToken(String accessToken);
}
