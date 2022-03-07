package org.xzcode.oidc.provider;

import org.xzcode.oidc.core.PkceValidator;
import org.xzcode.oidc.exception.TokenRequestValidationException;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class CompositePkceValidator implements PkceValidator {
    private final List<PkceValidator> validators;

    public CompositePkceValidator(PkceValidator... validators) {
        this.validators = Collections.unmodifiableList(Arrays.asList(validators));
    }

    @Override
    public void validate(String codeChallenge, String codeVerifier, String codeChallengeMethod) throws TokenRequestValidationException {
        for (PkceValidator validator : validators) {
            validator.validate(codeChallenge, codeVerifier, codeChallengeMethod);
        }
    }
}
