package com.user.api.filter;

import java.io.IOException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.OncePerRequestFilter;
import com.user.api.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Service
public class JwtFilter extends OncePerRequestFilter {
	
	
	  @Autowired
	  private JwtUtil jwtUtil;

	  @Autowired
	  private UserDetailsService userDetailsService;

	  @Override
	  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
	      throws ServletException, IOException {
	    final String authorizationHeader = request.getHeader("Authorization");

	    String username = null;
	    String jwtToken = null;

	    if (authorizationHeader != null && authorizationHeader.startsWith("Bearer")) {
	      jwtToken = authorizationHeader.substring(7);
	      username = jwtUtil.extractUsername(jwtToken);
	    }

	    if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
	      UserDetails userDetails = userDetailsService.loadUserByUsername(username);

	      if (jwtUtil.validateToken(jwtToken, userDetails)) {
	        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
	          userDetails, null, userDetails.getAuthorities());
	        usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
	        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
	      }
	    }
	    filterChain.doFilter(request, response);
	  }
	}
