/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge1;

import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.POST;

import java.io.IOException;
import java.util.Random;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ImageServlet {

  // Retained only so existing tests still reference a valid symbol. It is NOT embedded in the
  // served image any more (see logo()), so no secret leaks through the public asset.
  public static final int PINCODE = new Random().nextInt(10000);

  @RequestMapping(
      method = {GET, POST},
      value = "/challenge/logo",
      produces = MediaType.IMAGE_PNG_VALUE)
  @ResponseBody
  public byte[] logo() throws IOException {
    // SECURE: serve the image unmodified — no secret (PIN) is embedded in a public asset.
    return new ClassPathResource("lessons/challenges/images/webgoat2.png")
        .getInputStream()
        .readAllBytes();
  }
}
