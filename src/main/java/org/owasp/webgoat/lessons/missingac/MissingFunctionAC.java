/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import java.security.SecureRandom;
import java.util.Base64;
import org.owasp.webgoat.container.lessons.Category;
import org.owasp.webgoat.container.lessons.Lesson;
import org.springframework.stereotype.Component;

@Component
public class MissingFunctionAC extends Lesson {

  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  // The salts are no longer hard-coded, source-visible constants. Each is a high-entropy value
  // generated once per JVM start, so an attacker who can read the source can no longer precompute
  // a user's hash offline from a known salt; the derived hash's secrecy no longer depends on a
  // constant embedded in the code.
  public static final String PASSWORD_SALT_SIMPLE = generateSalt();
  public static final String PASSWORD_SALT_ADMIN = generateSalt();

  private static String generateSalt() {
    byte[] saltBytes = new byte[16];
    SECURE_RANDOM.nextBytes(saltBytes);
    return Base64.getEncoder().encodeToString(saltBytes);
  }

  @Override
  public Category getDefaultCategory() {
    return Category.A1;
  }

  @Override
  public String getTitle() {
    return "missing-function-access-control.title";
  }
}
