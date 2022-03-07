package org.xzcode.oidc.provider;

import org.xzcode.oidc.core.OidcAuthentication;
import org.xzcode.oidc.core.OAuth2AuthorizationCode;
import org.xzcode.oidc.core.OAuth2AuthorizationCodeStore;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryAuthorizationCodeStore implements OAuth2AuthorizationCodeStore {

    private final Map<String, OAuth2AuthorizationCode> codeRepository = new ConcurrentHashMap<>();
    private final Map<String, OidcAuthentication> authenticationRepository = new ConcurrentHashMap<>();

    @Override
    public OAuth2AuthorizationCode save(OAuth2AuthorizationCode code, OidcAuthentication authentication) {
        String codeKey = code.getValue();
        codeRepository.put(codeKey, code);
        authenticationRepository.put(codeKey, authentication);
        return code;
    }

    @Override
    public Optional<OidcAuthentication> consume(String code) {
        OAuth2AuthorizationCode authorizationCode = codeRepository.remove(code);
        OidcAuthentication authentication = authenticationRepository.remove(code);
        if (!Objects.isNull(authorizationCode) && !Objects.isNull(authentication)
                && Instant.now().isBefore(authorizationCode.getExpiresAt())
        ) {
            return Optional.of(authentication);
        } else {
            return Optional.empty();
        }
    }
}
