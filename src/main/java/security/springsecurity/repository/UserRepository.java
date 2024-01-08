package security.springsecurity.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import security.springsecurity.Model.User;

public interface UserRepository extends JpaRepository<User, Long> {
    public User findByUsername(String username);
}
