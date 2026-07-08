/*
 * SPDX-FileCopyrightText: Copyright © 2016 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.xss;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import java.security.SecureRandom;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DOMCrossSiteScripting implements AssignmentEndpoint {

  private final LessonSession lessonSession;

  public DOMCrossSiteScripting(LessonSession lessonSession) {
    this.lessonSession = lessonSession;
  }

  @PostMapping("/CrossSiteScripting/phone-home-xss")
  @ResponseBody
  public AttackResult completed(@RequestParam Integer param1, @RequestParam Integer param2) {
    // The DOM-based XSS sink that let an injected script invoke this callback has been
    // remediated, so a genuine in-page script execution can no longer reach this endpoint.
    // The request parameters are trivially forgeable by a direct request and are not
    // proof of an attack, so the callback secret is rotated but never disclosed and the
    // assignment is never marked solved. Without the returned secret the follow-up
    // verifiers (dom-follow-up / stored-xss-follow-up) can no longer be satisfied either.
    SecureRandom number = new SecureRandom();
    lessonSession.setValue("randValue", String.valueOf(number.nextInt()));
    return failed(this).build();
  }
}
// something like ...
// http://localhost:8080/WebGoat/start.mvc#test/testParam=foobar&_someVar=234902384lotslsfjdOf9889080GarbageHere%3Cscript%3Ewebgoat.customjs.phoneHome();%3C%2Fscript%3E--andMoreGarbageHere
// or
// http://localhost:8080/WebGoat/start.mvc#test/testParam=foobar&_someVar=234902384lotslsfjdOf9889080GarbageHere<script>webgoat.customjs.phoneHome();<%2Fscript>
