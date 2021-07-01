package org.xyyh.oidc.exception;

/**
 * 表示客户端未授权的异常,或者Client的密码确认不正确
 */
public class ClientUnauthorizedException extends Exception {
    private static final long serialVersionUID = 7259661136397678720L;

    public ClientUnauthorizedException(String message) {
        super(message);
    }

    public ClientUnauthorizedException(String message, Throwable cause) {
        super(message, cause);
    }
}
