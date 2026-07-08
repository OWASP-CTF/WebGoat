/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.vulnerablecomponents;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import com.thoughtworks.xstream.XStream;
import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"vulnerable.hint"})
public class VulnerableComponentsLesson implements AssignmentEndpoint {

  @PostMapping("/VulnerableComponents/attack1")
  public @ResponseBody AttackResult completed(@RequestParam String payload) {
    XStream xstream = new XStream();
    xstream.setClassLoader(Contact.class.getClassLoader());
    xstream.alias("contact", ContactImpl.class);
    xstream.ignoreUnknownElements();
    Contact contact = null;

    try {
      if (!StringUtils.isEmpty(payload)) {
        payload = sanitize(payload);
      }
      // SECURE: deny-by-default — reject any payload that tries to instantiate types other than
      // a plain <contact>. XStream 1.4.5 has no type-permission API, so we refuse dynamic proxies
      // and arbitrary class references (CVE-2013-7285) before they are ever deserialized.
      if (!isSafeContactPayload(payload)) {
        return failed(this)
            .feedback("vulnerable-components.close")
            .output("Payload rejected: only a simple <contact> is allowed")
            .build();
      }
      contact = (Contact) xstream.fromXML(payload);
    } catch (Exception ex) {
      return failed(this).feedback("vulnerable-components.close").output(ex.getMessage()).build();
    }

    // SECURE: only operate on a genuine ContactImpl. Never invoke a method on a deserialized
    // proxy — the CVE-2013-7285 dynamic-proxy gadget executes its payload on method invocation.
    if (contact instanceof ContactImpl) {
      contact.getFirstName();
      return success(this).feedback("vulnerable-components.success").build();
    }
    return failed(this).feedback("vulnerable-components.fromXML").feedbackArgs(contact).build();
  }

  private String sanitize(String input) {
    return input
        .replace("+", "")
        .replace("\r", "")
        .replace("\n", "")
        .replace("> ", ">")
        .replace(" <", "<");
  }

  private boolean isSafeContactPayload(String payload) {
    if (StringUtils.isEmpty(payload)) {
      return false;
    }
    String lower = payload.toLowerCase();
    // Reject dynamic proxies and any explicit class-mapping / package reference that would let
    // an attacker steer XStream into instantiating an arbitrary type.
    return !(lower.contains("dynamic-proxy")
        || lower.contains("class=")
        || lower.contains("java.")
        || lower.contains("javax.")
        || lower.contains("sun.")
        || lower.contains("eventhandler")
        || lower.contains("processbuilder")
        || lower.contains("<handler")
        || lower.contains("<interface"));
  }
}
