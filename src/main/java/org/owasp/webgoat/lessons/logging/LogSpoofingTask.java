/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.logging;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import org.apache.logging.log4j.util.Strings;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LogSpoofingTask implements AssignmentEndpoint {

  private static final Logger log = LoggerFactory.getLogger(LogSpoofingTask.class);

  // Remove CR, LF and all other ASCII control characters so a user cannot forge new log lines.
  private static String sanitizeForLog(String input) {
    if (input == null) {
      return "";
    }
    return input.replaceAll("[\\p{Cntrl}]", "");
  }

  @PostMapping("/LogSpoofing/log-spoofing")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    if (Strings.isEmpty(username)) {
      return failed(this).output("Username is required").build();
    }

    // SECURE: neutralize control characters before the value reaches any log statement, so an
    // injected newline can no longer forge an "admin" login line.
    String safeUsername = sanitizeForLog(username);
    log.info("Login attempt: username={}", safeUsername);

    // No completion path relies on injected log content anymore; the spoofing exploit is blocked.
    return failed(this).output("Logged: " + safeUsername).build();
  }
}
