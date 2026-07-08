/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.servlet.http.HttpServletRequest;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"csrf-login-hint1", "csrf-login-hint2", "csrf-login-hint3"})
public class CSRFLogin implements AssignmentEndpoint {

  @PostMapping(
      path = "/csrf/login",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult completed(@CurrentUsername String username, HttpServletRequest request) {
    // Reject cross-site (login CSRF) requests: the Origin/Referer host must match the
    // application host. Requests with no Origin/Referer or a foreign one are refused.
    if (!isSameOrigin(request)) {
      return failed(this).feedback("csrf-login-failed").feedbackArgs(username).build();
    }
    if (username.startsWith("csrf")) {
      return success(this).feedback("csrf-login-success").build();
    }
    return failed(this).feedback("csrf-login-failed").feedbackArgs(username).build();
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
