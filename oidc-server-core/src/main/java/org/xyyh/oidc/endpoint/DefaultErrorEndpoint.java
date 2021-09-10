package org.xyyh.oidc.endpoint;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import java.util.HashMap;
import java.util.Map;

@RequestMapping("/oauth2/error")
public class DefaultErrorEndpoint implements ErrorEndpoint {

    /**
     * 在AuthorizationEndpoint有几个@ExceptionHandler
     */
    @Override
    @GetMapping
    public ModelAndView error(
        @RequestAttribute("error") Exception error,
        @RequestParam(value = "client_id", required = false) String client,
        @RequestParam(value = "redirect_uri", required = false) String redirect
    ) {
        Map<String, String> model = new HashMap<>();
        model.put("message", error.getMessage());
        return new ModelAndView("oauth2/error.html", model);
    }
}
