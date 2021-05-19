package org.xyyh.oidc.client;

import org.xyyh.oidc.exception.NoSuchClientException;

public interface ClientDetailsService {
    ClientDetails loadClientByClientId(String clientId) throws NoSuchClientException;
}
