/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.logging;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.util.UUID;
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
public class LogBleedingTask implements AssignmentEndpoint {

  private static final Logger log = LoggerFactory.getLogger(LogBleedingTask.class);
  private final String password;

  public LogBleedingTask() {
    this.password = UUID.randomUUID().toString();
    // SECURE: never write the credential (even base64-encoded) to the application log.
    log.info("Admin password initialized (value redacted)");
  }

  @PostMapping("/LogSpoofing/log-bleeding")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    if (Strings.isEmpty(username) || Strings.isEmpty(password)) {
      return failed(this).output("Please provide username (Admin) and password").build();
    }

    if (username.equals("Admin") && password.equals(this.password)) {
      return success(this).build();
    }

    return failed(this).build();
  }
}
