package org.xyyh.oidc.provider;

import org.xyyh.oidc.collect.CollectionUtils;
import org.xyyh.oidc.core.OAuth2RequestScopeValidator;
import org.xyyh.oidc.exception.InvalidScopeException;

import java.util.Set;

public class DefaultOAuth2RequestScopeValidator implements OAuth2RequestScopeValidator {

    @Override
    public void validateScope(Set<String> requestScopes, Set<String> clientScopes) throws InvalidScopeException {
        if (CollectionUtils.isEmpty(requestScopes)) {
            throw new InvalidScopeException();
        } else {
            for (String scope : requestScopes) {
                if (!clientScopes.contains(scope)) {
                    throw new InvalidScopeException();
                }
            }
        }
    }
}
