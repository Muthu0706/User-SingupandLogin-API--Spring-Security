package com.user.api.serviceImp;


import java.util.List;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.user.api.entity.User;
import com.user.api.repository.UserRepository;
import com.user.api.util.JwtUtil;


@Service
public class UserService{
   @Autowired
   private UserRepository userRepository;

   @Autowired
   private PasswordEncoder passwordEncoder;
   

	@Autowired
	private JwtUtil jwtUtil;


    public User registerUser(User user) {
     user.setPassword(passwordEncoder.encode(user.getPassword()));
      return userRepository.save(user);
    }

    public User findByUsername(String username) {
     return userRepository.findByUsername(username).orElse(null);
    }
    
    public User findByUserOrEmail(String username,String email){
    	User foundUser=null;
    	if(username == null || email == null ) {
    		throw new RuntimeException();
    	}
    	User user=userRepository.findByUsernameOrEmail(username, email);
    	if(user.equals(user)) {
    		throw new RuntimeException();
    	}	
    	return user;
    }
  
    public User getUserById(Long id) {
      Optional<User> user = userRepository.findById(id);
      return user.orElse(null);  // Return null if user is not found
    }
  
   public User findByEmail(String email) {
	  return userRepository.findByEmail(email).orElse(null);
   }
  
   public List<User> getAllUsers() {
      return userRepository.findAll();  // Retrieve all users from the database
   }
   


}
