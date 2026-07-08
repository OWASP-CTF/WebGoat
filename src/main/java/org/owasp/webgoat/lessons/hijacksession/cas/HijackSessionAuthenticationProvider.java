/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.hijacksession.cas;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.LinkedList;
import java.util.Queue;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.DoublePredicate;
import java.util.function.Supplier;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;
import org.springframework.web.context.annotation.ApplicationScope;

@ApplicationScope
@Component
public class HijackSessionAuthenticationProvider implements AuthenticationProvider<Authentication> {

  private Queue<String> sessions = new LinkedList<>();
  protected static final int MAX_SESSIONS = 50;

  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  private static final DoublePredicate PROBABILITY_DOUBLE_PREDICATE = pr -> pr < 0.75;

  // Session identifiers are unpredictable: the entropy is a 160-bit value drawn from a CSPRNG,
  // never a counter or timestamp. There is no sequential id-part and no time-based part, so an
  // attacker cannot enumerate ids left by neighbouring (auto-login) sessions to hijack one. The
  // fixed "0-" prefix keeps the identifier well formed without contributing any predictability.
  private static final Supplier<String> GENERATE_SESSION_ID =
      () -> {
        byte[] bytes = new byte[20];
        SECURE_RANDOM.nextBytes(bytes);
        return "0-" + new BigInteger(1, bytes);
      };
  public static final Supplier<Authentication> AUTHENTICATION_SUPPLIER =
      () -> Authentication.builder().id(GENERATE_SESSION_ID.get()).build();

  @Override
  public Authentication authenticate(Authentication authentication) {
    if (authentication == null) {
      return AUTHENTICATION_SUPPLIER.get();
    }

    if (StringUtils.isNotEmpty(authentication.getId())
        && sessions.contains(authentication.getId())) {
      authentication.setAuthenticated(true);
      return authentication;
    }

    if (StringUtils.isEmpty(authentication.getId())) {
      authentication.setId(GENERATE_SESSION_ID.get());
    }

    authorizedUserAutoLogin();

    return authentication;
  }

  protected void authorizedUserAutoLogin() {
    if (!PROBABILITY_DOUBLE_PREDICATE.test(ThreadLocalRandom.current().nextDouble())) {
      Authentication authentication = AUTHENTICATION_SUPPLIER.get();
      authentication.setAuthenticated(true);
      addSession(authentication.getId());
    }
  }

  protected boolean addSession(String sessionId) {
    if (sessions.size() >= MAX_SESSIONS) {
      sessions.remove();
    }
    return sessions.add(sessionId);
  }

  protected int getSessionsSize() {
    return sessions.size();
  }
}
