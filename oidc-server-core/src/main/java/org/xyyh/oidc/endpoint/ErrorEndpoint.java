package org.xyyh.oidc.endpoint;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

public interface ErrorEndpoint {
    @GetMapping
    ModelAndView error(
        @RequestAttribute("error") Exception error,
        @RequestParam(value = "client_id", required = false) String client,
        @RequestParam(value = "redirect_uri", required = false) String redirect
    );
}
