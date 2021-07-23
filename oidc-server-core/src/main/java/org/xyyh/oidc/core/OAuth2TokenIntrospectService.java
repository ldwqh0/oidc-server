package org.xyyh.oidc.core;

import java.util.Map;
import java.util.Optional;

public interface OAuth2TokenIntrospectService {

    Optional<Map<String, Object>> introspectAccessToken(String token);

    Optional<Map<String, Object>> introspectRefreshToken(String token);

}
