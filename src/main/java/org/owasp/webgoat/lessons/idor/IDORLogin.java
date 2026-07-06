/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.util.HashMap;
import java.util.Map;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"idor.hints.idor_login"})
public class IDORLogin implements AssignmentEndpoint {
  private final LessonSession lessonSession;

  public IDORLogin(LessonSession lessonSession) {
    this.lessonSession = lessonSession;
  }

  // Adaptive one-way hashing (BCrypt) replaces plaintext credential storage. The work
  // factor can be raised as hardware improves, and matches() runs in constant time.
  private static final BCryptPasswordEncoder ENCODER = new BCryptPasswordEncoder();

  private final Map<String, String> hashedCredentials = new HashMap<>();
  private final Map<String, String> userIds = new HashMap<>();

  public void initIDORInfo() {
    if (!hashedCredentials.isEmpty()) {
      return;
    }
    // Passwords are stored only as BCrypt hashes, never in plaintext.
    hashedCredentials.put("tom", ENCODER.encode("cat"));
    hashedCredentials.put("bill", ENCODER.encode("buffalo"));

    userIds.put("tom", "2342384");
    userIds.put("bill", "2342388");
  }

  @PostMapping("/IDOR/login")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    initIDORInfo();

    String storedHash = hashedCredentials.get(username);
    // BCryptPasswordEncoder.matches() performs a constant-time comparison, so there is no
    // timing oracle. A single generic failure is returned for both unknown user and wrong
    // password to avoid user enumeration.
    if (storedHash != null && ENCODER.matches(password, storedHash) && "tom".equals(username)) {
      lessonSession.setValue("idor-authenticated-as", username);
      lessonSession.setValue("idor-authenticated-user-id", userIds.get(username));
      return success(this).feedback("idor.login.success").feedbackArgs(username).build();
    }
    return failed(this).feedback("idor.login.failure").build();
  }
}
