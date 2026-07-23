/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge1;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.challenges.Flags;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Assignment1 implements AssignmentEndpoint {

  private final Flags flags;

  // SECURE: admin password is a high-entropy value generated with SecureRandom at startup and
  // held only in memory. It is not derivable from any served asset (the PIN stego is gone).
  private static final String ADMIN_PASSWORD;

  static {
    byte[] pwBytes = new byte[24];
    new SecureRandom().nextBytes(pwBytes);
    ADMIN_PASSWORD = Base64.getUrlEncoder().withoutPadding().encodeToString(pwBytes);
  }

  public Assignment1(Flags flags) {
    this.flags = flags;
  }

  @PostMapping("/challenge/1")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    boolean ipAddressKnown = true;
    boolean usernameMatch =
        MessageDigest.isEqual(
            "admin".getBytes(StandardCharsets.UTF_8), username.getBytes(StandardCharsets.UTF_8));
    boolean passwordMatch =
        MessageDigest.isEqual(
            ADMIN_PASSWORD.getBytes(StandardCharsets.UTF_8),
            password.getBytes(StandardCharsets.UTF_8));
    boolean passwordCorrect = usernameMatch && passwordMatch;
    if (passwordCorrect && ipAddressKnown) {
      return success(this).feedback("challenge.solved").feedbackArgs(flags.getFlag(1)).build();
    } else if (passwordCorrect) {
      return failed(this).feedback("ip.address.unknown").build();
    }
    return failed(this).build();
  }
}
