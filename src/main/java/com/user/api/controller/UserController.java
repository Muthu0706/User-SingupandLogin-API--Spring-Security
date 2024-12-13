package com.user.api.controller;

import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import com.user.api.entity.User;
import com.user.api.serviceImp.UserService;
import com.user.api.util.JwtUtil;

@RestController
@RequestMapping("/api/user")
public class UserController {
	
	
	@Autowired
	private UserService userService;
	

	
	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private JwtUtil jwtUtil;

	
	@PostMapping("/register")
	public ResponseEntity<User> saveUser(@RequestBody User user){
		User registeredUser = userService.registerUser(user);
		return ResponseEntity.ok(registeredUser) ;
	}

	@PostMapping("/login")
	public ResponseEntity<String> login(@RequestBody User user) {
	    User foundUser = null;
	    if (user.getEmail() != null ) {
	        foundUser = userService.findByEmail(user.getEmail());
	    } else if (user.getUsername() != null) {
	        foundUser = userService.findByUsername(user.getUsername());
	    }
	    if (foundUser != null && passwordEncoder.matches(user.getPassword(), foundUser.getPassword())) {
	        String token = jwtUtil.generateToken(foundUser.getUsername());
	        return ResponseEntity.ok(token);
	    } else {
	        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
	    }	
      }
	
	
	@PostMapping("/loginPage")
	public ResponseEntity<String> loginpage(@RequestParam String username,@RequestParam String email,@RequestBody User user){
	    User foundUser = null;
	    if (user.getEmail() != null || user.getUsername() !=null) {
	        foundUser = userService.findByUserOrEmail(username, email);
	    } 
	    if (foundUser != null && passwordEncoder.matches(user.getPassword(), foundUser.getPassword())) {
	        String token = jwtUtil.generateToken(foundUser.getUsername());
	        return ResponseEntity.ok(token);
	    } else {
	        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
	    }		    
	}
	
//	  @PostMapping("/login")
//	  public ResponseEntity<String> login(@RequestBody User user) {
//	    User foundUser = userService.findByEmail(user.getEmail());
//	    if (foundUser != null && passwordEncoder.matches(user.getPassword(), foundUser.getPassword())) {
//	      String token = jwtUtil.generateToken(foundUser.getUsername());
//	      return ResponseEntity.ok(token);
//	    } else {
//	      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
//	    }
//	  }	
}
