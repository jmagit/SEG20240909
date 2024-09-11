package com.example.application.resources;

import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

import com.example.security.models.BasicCredential;

import jakarta.validation.Valid;

@RestController
public class UserResource {
	@PostMapping(path = "/login", consumes = "application/json")
	public String loginJSON(@Valid @RequestBody BasicCredential credential)  {
		RestClient restClient = RestClient.builder().requestFactory(new SimpleClientHttpRequestFactory()).build();//.create()
		var res = restClient.post().uri("http://127.0.0.1:8091/login").contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.body("username=" + credential.getUsername() + "&password=" + credential.getPassword())
				.retrieve().toBodilessEntity(); //.body(String.class);
		if(res.getStatusCode() == HttpStatus.FOUND) {
			res = restClient.post().uri(res.getHeaders().getLocation())
					.retrieve().toBodilessEntity(); //.body(String.class);
		}
		return res.toString();
//		var item = dao.findById(credential.getUsername());
//		if (item.isEmpty() || !item.get().isActive() || !passwordEncoder.matches(credential.getPassword(), item.get().getPassword()))
//			return new AuthToken();
//		return getAuthToken(item.get());
//		RestClient restClient = RestClient.builder()
//			    .baseUrl(properties.getUrl())
//			    .defaultHeader(HttpHeaders.AUTHORIZATION,
//			        encodeBasic(properties.getUsername(), 
//			                    properties.getPassword())
//			    ).build();
	}
	
	@GetMapping("/authorized")
	public Map<String, String> authorized(@RequestParam String code) {
		return Map.of("code", code);
	}
	
//	@GetMapping("/authorized")
//	public String authorized(@RequestParam String code) {
//		return code;
////		RestClient restClient = RestClient.builder()
////		    .baseUrl("http://127.0.0.1:8091")
////		    .defaultHeaders(headers -> headers.setBasicAuth("service-client", "12345"))
////		    .requestFactory(new SimpleClientHttpRequestFactory())
////		    .build();
////		var res = restClient.post().uri("http://127.0.0.1:8091/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
////				.body("grant_type=authorization_code&redirect_uri=http://127.0.0.1:8080/authorized&code=" + code)
////				.retrieve().toBodilessEntity(); //.body(String.class);
////		System.out.println(res);
////		if(res.getStatusCode() == HttpStatus.FOUND) {
////			res = restClient.post().uri(res.getHeaders().getLocation()).contentType(MediaType.APPLICATION_FORM_URLENCODED)
////					.body("grant_type=authorization_code&redirect_uri=http://127.0.0.1:8080/authorized&code=" + code)
////					.retrieve().toBodilessEntity(); //.body(String.class);
////		}
////		return res.toString();
//	}

}
