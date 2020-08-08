package ru.mgprojects.controller;

import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import ru.mgprojects.service.SecretService;

import java.util.Map;

@RestController
public class JwtController {

    @Autowired
    private SecretService secretService;

    @PostMapping("/token")
    public ResponseEntity<String> getToken(
            @RequestBody Map<String, Object> claims
    ) {
        return new ResponseEntity(secretService.generateToken(SignatureAlgorithm.HS256, claims), HttpStatus.OK);
    }

    @PostMapping("/token/parse")
    public ResponseEntity<String> getToken(
            @RequestBody String token
    ) {
        String parseStatus = secretService.parseToken(token);
        if (parseStatus.equals(SecretService.STATUS_OK)) {
            return new ResponseEntity(HttpStatus.OK);
        } if(parseStatus.equals(SecretService.STATUS_EXPIRED)) {
            return new ResponseEntity(SecretService.TOKEN_EXPIRED_MESSAGE, HttpStatus.UNAUTHORIZED);
        } else {
            return new ResponseEntity(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

}
