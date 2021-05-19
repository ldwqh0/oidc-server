package org.xyyh.oidc.exception;

public class PkceRequiredException extends Exception {
    private static final long serialVersionUID = -8044040955810190722L;

    public PkceRequiredException() {
        super();
    }

    public PkceRequiredException(String message) {
        super(message);
    }
}
