/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.htmltampering;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.math.BigDecimal;
import java.math.RoundingMode;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"hint1", "hint2", "hint3"})
public class HtmlTamperingTask implements AssignmentEndpoint {

  // Authoritative unit price held server-side; never derived from client input.
  private static final BigDecimal UNIT_PRICE = new BigDecimal("2999.99");

  @PostMapping("/HtmlTampering/task")
  @ResponseBody
  public AttackResult completed(@RequestParam String QTY, @RequestParam String Total) {
    try {
      int qty = Integer.parseInt(QTY.trim());
      if (qty <= 0) {
        return failed(this).feedback("html-tampering.tamper.failure").build();
      }
      // The total is recomputed authoritatively from the server-side unit price.
      // A client-supplied Total is only accepted when it matches the server's own
      // computation, so a tampered Total (e.g. 0) is rejected.
      BigDecimal submittedTotal = new BigDecimal(Total.trim()).setScale(2, RoundingMode.HALF_UP);
      BigDecimal serverTotal =
          UNIT_PRICE.multiply(BigDecimal.valueOf(qty)).setScale(2, RoundingMode.HALF_UP);
      if (serverTotal.compareTo(submittedTotal) == 0) {
        return success(this).feedback("html-tampering.tamper.success").build();
      }
      return failed(this).feedback("html-tampering.tamper.failure").build();
    } catch (NumberFormatException e) {
      return failed(this).feedback("html-tampering.tamper.failure").build();
    }
  }
}
