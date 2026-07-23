/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.bypassrestrictions;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.util.Set;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BypassRestrictionsFieldRestrictions implements AssignmentEndpoint {

  private static final Set<String> VALID_SELECT = Set.of("option1", "option2");
  private static final Set<String> VALID_RADIO = Set.of("option1", "option2");
  private static final Set<String> VALID_CHECKBOX = Set.of("on", "off");
  private static final int MAX_SHORT_INPUT_LENGTH = 5;
  private static final String EXPECTED_READONLY = "change";

  @PostMapping("/BypassRestrictions/FieldRestrictions")
  @ResponseBody
  public AttackResult completed(
      @RequestParam String select,
      @RequestParam String radio,
      @RequestParam String checkbox,
      @RequestParam String shortInput,
      @RequestParam String readOnlyInput) {
    // Enforce the same constraints server-side that the HTML form enforces client-side.
    // Any value outside the allow-list / boundary is rejected instead of being accepted.
    if (!VALID_SELECT.contains(select)) {
      return failed(this).build();
    }
    if (!VALID_RADIO.contains(radio)) {
      return failed(this).build();
    }
    if (!VALID_CHECKBOX.contains(checkbox)) {
      return failed(this).build();
    }
    if (shortInput == null || shortInput.length() > MAX_SHORT_INPUT_LENGTH) {
      return failed(this).build();
    }
    if (!EXPECTED_READONLY.equals(readOnlyInput)) {
      return failed(this).build();
    }
    return success(this).build();
  }
}
