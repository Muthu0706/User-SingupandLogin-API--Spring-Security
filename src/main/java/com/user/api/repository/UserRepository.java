package com.user.api.repository;


import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.user.api.entity.User;

@Repository
public interface UserRepository extends JpaRepository<User, Long>{

	
	  Optional<User> findByUsername(String username);
	  
	  Optional<User> findByEmail(String email);
	
	  User findByUsernameOrEmail(String username,String email);
}
