package com.friendship41.didclient.controller;

import com.friendship41.didclient.service.MainService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/did")
public class MainController {
  private final MainService mainService;

  @Autowired
  public MainController(MainService mainService) {
    this.mainService = mainService;
  }

  @GetMapping("/check")
  public Object getCheckDid(@RequestParam("did") final String did) {
    return this.mainService.getCheckDID(did);
  }

  @PostMapping("/check")
  public Object postCheckDid(@RequestBody Map<String, String> body) {
    try {
      return this.mainService.postCheckDID(String.valueOf(body.get("did")), String.valueOf(body.get("decodedText")));
    } catch (Exception e) {
      return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }
  }

  @PostMapping("/info")
  public Object postDidInfo(@RequestBody Map<String, Object> body) {
    return this.mainService.authenticateUser(String.valueOf(body.get("did")), (Map<String, String>) body.get("data"));
  }


  @GetMapping("/keys")
  public Object getKeys() {
    return mainService.getKeys();
  }
}