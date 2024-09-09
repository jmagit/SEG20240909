package com.example.application.resources;

import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.security.SecurityRequirement;

@RestController
//@RequestMapping("/permisos")
public class PermisosResource {

	@GetMapping(path = "/permisos/anonimos")
	public String anonimos() {
		return "para todos";
	}
	
	@GetMapping(path = "/permisos/read")
	@SecurityRequirement(name = "bearerAuth")
	public String conLectura() {
		return "solo con lectura";
	}
	@GetMapping(path = "/permisos/write")
	@SecurityRequirement(name = "bearerAuth")
	public String conEscritura() {
		return "solo con escritura";
	}
	
	@GetMapping("/authorized")
	public Map<String, String> authorized(@RequestParam String code) {
		return Map.of("code", code);
	}
}
