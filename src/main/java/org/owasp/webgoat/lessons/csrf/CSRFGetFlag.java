/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import org.owasp.webgoat.container.i18n.PluginMessages;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/** Created by jason on 9/30/17. */
@RestController
public class CSRFGetFlag {

  @Autowired LessonSession userSessionData;
  @Autowired private PluginMessages pluginMessages;

  @PostMapping(
      path = "/csrf/basic-get-flag",
      produces = {"application/json"})
  @ResponseBody
  public Map<String, Object> invoke(HttpServletRequest req) {

    Map<String, Object> response = new HashMap<>();

    // CSRF defense: this state-changing action only issues a flag to a verified same-origin
    // request. A forged cross-site request (no Origin/Referer, or one from a foreign host) is
    // rejected and never receives a flag, so it cannot be replayed to /csrf/confirm-flag-1.
    if (!isSameOrigin(req)) {
      response.put("success", false);
      response.put("message", "This request could not be verified (cross-site request rejected)");
      response.put("flag", null);
      return response;
    }

    Random random = new Random();
    userSessionData.setValue("csrf-get-success", random.nextInt(65536));
    response.put("success", true);
    response.put("message", pluginMessages.getMessage("csrf-get-other-referer.success"));
    response.put("flag", userSessionData.getValue("csrf-get-success"));

    return response;
  }

  private boolean isSameOrigin(HttpServletRequest request) {
    String host = request.getHeader("Host");
    String source = request.getHeader("Origin");
    if (source == null) {
      source = request.getHeader("Referer");
    }
    if (host == null || source == null) {
      return false;
    }
    try {
      String sourceHost = java.net.URI.create(source).getAuthority();
      return host.equals(sourceHost);
    } catch (IllegalArgumentException e) {
      return false;
    }
  }
}
