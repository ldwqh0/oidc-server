package org.xyyh.oidc.provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xyyh.oidc.collect.CollectionUtils;
import org.xyyh.oidc.core.OAuth2RedirectUriValidator;
import org.xyyh.oidc.exception.UnRegisteredRedirectUriException;

import java.util.Set;

public class DefaultOAuth2RedirectUriValidator implements OAuth2RedirectUriValidator {

    private static final Logger log = LoggerFactory.getLogger(DefaultOAuth2RedirectUriValidator.class);

    @Override
    public void validate(String requestUri, Set<String> registeredUris) throws UnRegisteredRedirectUriException {
        if (CollectionUtils.isNotEmpty(registeredUris) && registeredUris.contains(requestUri)) {
            // do nothing here
        } else {
            throw new UnRegisteredRedirectUriException();
        }
    }
}
